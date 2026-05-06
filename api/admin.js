const crypto = require('crypto');
const { authenticate, verifyPassword } = require('../lib/auth');
const { rateLimit, clientIp } = require('../lib/rate-limit');
const { captureError, reqContext } = require('../lib/sentry');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const ALLOWED_ORIGINS = [
  'https://bambeo-ivory.vercel.app',
  'https://bambeo-leonardboakye02s-projects.vercel.app',
  'https://bambeo-git-main-leonardboakye02s-projects.vercel.app'
];

const ALLOWED_TABLES = ['products', 'gallery', 'testimonials', 'faqs', 'site_settings', 'quote_requests', 'orders'];
const ALLOWED_ACTIONS = ['select', 'insert', 'update', 'delete', 'upsert'];

// Per-table column whitelists for filters and select projections
const ALLOWED_COLUMNS = {
  products:        ['id', 'name', 'display_text', 'category', 'price', 'color', 'tag', 'description', 'product_details', 'image_url', 'image_urls', 'is_active', 'sort_order', 'created_at', 'updated_at'],
  gallery:         ['id', 'title', 'image_url', 'image_urls', 'description', 'is_active', 'sort_order', 'created_at', 'updated_at'],
  testimonials:    ['id', 'author_name', 'review_text', 'rating', 'is_active', 'sort_order', 'created_at', 'updated_at'],
  faqs:            ['id', 'question', 'answer', 'is_active', 'sort_order', 'created_at', 'updated_at'],
  site_settings:   ['id', 'key', 'value', 'created_at', 'updated_at'],
  quote_requests:  ['id', 'name', 'email', 'phone', 'message', 'design_image', 'design_style', 'status', 'created_at', 'updated_at'],
  orders:          ['id', 'stripe_session_id', 'stripe_payment_id', 'customer_email', 'customer_name', 'amount_total', 'currency', 'status', 'line_items', 'shipping_address', 'billing_address', 'refunded_amount', 'dispute_status', 'tracking_number', 'shipping_carrier', 'shipped_at', 'notes', 'created_at', 'updated_at']
};

// Identifier validation: alphanum + underscore only (PostgREST column names)
const IDENT_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

// Max JSON payload (Vercel caps at ~4.5mb for serverless)
const MAX_BODY_BYTES = 4 * 1024 * 1024;

// scrypt password hashing with random salt; format: scrypt$<saltHex>$<hashHex>
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('hex')}$${derived.toString('hex')}`;
}

function validateColumns(table, cols) {
  const allowed = ALLOWED_COLUMNS[table];
  if (!allowed) return false;
  return cols.every(c => IDENT_RE.test(c) && allowed.includes(c));
}

function buildSelect(table, raw) {
  // Wildcard: let PostgREST return whatever columns the table actually has.
  // We rely on RLS + table whitelist to keep things safe; admin_password is
  // separately filtered via the &key=neq.admin_password rule below.
  if (!raw || raw === '*') return '*';
  const cols = String(raw).split(',').map(c => c.trim()).filter(Boolean);
  if (!validateColumns(table, cols)) return null;
  return cols.join(',');
}

function buildFilters(table, filters) {
  if (!filters || typeof filters !== 'object') return { ok: true, qs: '' };
  const parts = [];
  for (const [col, val] of Object.entries(filters)) {
    if (!IDENT_RE.test(col) || !ALLOWED_COLUMNS[table].includes(col)) {
      return { ok: false, error: `Invalid filter column: ${col}` };
    }
    if (val === null || val === undefined) continue;
    const sval = String(val);
    if (sval.length > 256) return { ok: false, error: 'Filter value too long' };
    parts.push(`${col}=eq.${encodeURIComponent(sval)}`);
  }
  return { ok: true, qs: parts.join('&') };
}

function sanitizeRows(table, rows) {
  if (!Array.isArray(rows)) return null;
  if (rows.length === 0 || rows.length > 200) return null;
  const allowed = ALLOWED_COLUMNS[table];
  const out = [];
  for (const r of rows) {
    if (!r || typeof r !== 'object' || Array.isArray(r)) return null;
    const clean = {};
    for (const [k, v] of Object.entries(r)) {
      if (!IDENT_RE.test(k) || !allowed.includes(k)) return null;
      clean[k] = v;
    }
    out.push(clean);
  }
  return out;
}

function readJsonBody(req) {
  // Vercel parses JSON when content-type is application/json. Validate size.
  const cl = parseInt(req.headers['content-length'] || '0', 10);
  if (cl && cl > MAX_BODY_BYTES) return { error: 'Payload too large' };
  if (req.body && typeof req.body === 'object') return { body: req.body };
  return { body: {} };
}

module.exports = async (req, res) => {
  const origin = req.headers.origin;
  const isAllowedOrigin = origin && ALLOWED_ORIGINS.includes(origin);

  // CORS — only echo allowed origins. Credentials needed for cookie-based auth.
  if (isAllowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Enforce origin to mitigate CSRF (Authorization header alone isn't sufficient if creds are cached)
  if (!isAllowedOrigin) {
    return res.status(403).json({ error: 'Forbidden origin' });
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    return res.status(500).json({ error: 'Server not configured' });
  }

  try {
    const ip = clientIp(req);
    if (!await rateLimit({ key: `admin:${ip}`, max: 60, windowSec: 60 })) {
      return res.status(429).json({ error: 'Too many requests, try again later' });
    }

    const auth = await authenticate(req);
    if (!auth.ok) {
      // Per-IP slow-down for failed auth attempts (separate stricter bucket)
      await rateLimit({ key: `admin-fail:${ip}`, max: 10, windowSec: 60 });
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const parsed = readJsonBody(req);
    if (parsed.error) return res.status(413).json({ error: parsed.error });
    const { table, action, data, filters } = parsed.body;

    if (!ALLOWED_TABLES.includes(table)) return res.status(400).json({ error: 'Invalid table' });
    if (!ALLOWED_ACTIONS.includes(action)) return res.status(400).json({ error: 'Invalid action' });

    // Block tampering with admin_password through the generic endpoint
    const touchesAdminPassword = (rows) =>
      Array.isArray(rows) && rows.some(r => r && r.key === 'admin_password');
    const filtersAdminPassword = filters && filters.key === 'admin_password';

    if (table === 'site_settings') {
      if (action === 'delete' && filtersAdminPassword) {
        return res.status(403).json({ error: 'Cannot delete admin password via this endpoint' });
      }
      if ((action === 'update' || action === 'upsert' || action === 'insert') && touchesAdminPassword(data?.rows)) {
        // Only allow if rows contain the explicit __changePassword sentinel — front-end uses a separate path otherwise.
        // For safety, require the existing password again via X-Current-Password header.
        const current = req.headers['x-current-password'];
        if (!current || !(await verifyPassword(current))) {
          return res.status(403).json({ error: 'Current password required to change admin password' });
        }
      }
    }

    const headers = {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json'
    };

    let url = `${SUPABASE_URL}/rest/v1/${table}`;
    let method = 'GET';
    let body = null;

    switch (action) {
      case 'select': {
        const cols = buildSelect(table, data?.select);
        if (!cols) return res.status(400).json({ error: 'Invalid select columns' });
        const f = buildFilters(table, filters);
        if (!f.ok) return res.status(400).json({ error: f.error });
        url += `?select=${cols}`;
        if (f.qs) url += `&${f.qs}`;
        // Hide admin_password from any select on site_settings
        if (table === 'site_settings') {
          url += `&key=neq.admin_password`;
        }
        break;
      }
      case 'insert': {
        method = 'POST';
        const rows = sanitizeRows(table, data?.rows);
        if (!rows) return res.status(400).json({ error: 'Invalid rows' });
        // Hash admin_password before storing
        if (table === 'site_settings') {
          for (const r of rows) {
            if (r.key === 'admin_password' && r.value) r.value = hashPassword(String(r.value));
          }
        }
        headers['Prefer'] = 'return=representation';
        body = JSON.stringify(rows);
        break;
      }
      case 'update': {
        method = 'PATCH';
        // Client may send a single row object or an array of one — normalize.
        const rawRows = Array.isArray(data?.rows) ? data.rows : (data?.rows ? [data.rows] : []);
        const rows = sanitizeRows(table, rawRows);
        if (!rows || rows.length !== 1) return res.status(400).json({ error: 'Invalid rows' });
        const f = buildFilters(table, filters);
        if (!f.ok || !f.qs) return res.status(400).json({ error: f.error || 'Filters required for update' });
        if (table === 'site_settings') {
          for (const r of rows) {
            if (r.key === 'admin_password' && r.value) r.value = hashPassword(String(r.value));
          }
        }
        headers['Prefer'] = 'return=representation';
        url += `?${f.qs}`;
        body = JSON.stringify(rows[0]);
        break;
      }
      case 'delete': {
        method = 'DELETE';
        const f = buildFilters(table, filters);
        if (!f.ok || !f.qs) return res.status(400).json({ error: f.error || 'Filters required for delete' });
        url += `?${f.qs}`;
        break;
      }
      case 'upsert': {
        method = 'POST';
        const rows = sanitizeRows(table, data?.rows);
        if (!rows) return res.status(400).json({ error: 'Invalid rows' });
        if (table === 'site_settings') {
          for (const r of rows) {
            if (r.key === 'admin_password' && r.value) r.value = hashPassword(String(r.value));
          }
        }
        headers['Prefer'] = 'resolution=merge-duplicates,return=representation';
        body = JSON.stringify(rows);
        break;
      }
    }

    const dbRes = await fetch(url, { method, headers, body: body || undefined });

    if (action === 'delete') {
      return res.status(dbRes.ok ? 200 : 400).json({
        data: null,
        error: dbRes.ok ? null : 'Delete failed'
      });
    }

    const text = await dbRes.text();
    let result = null;
    try { result = text ? JSON.parse(text) : null; } catch { result = null; }
    return res.status(dbRes.ok ? 200 : 400).json({
      data: dbRes.ok ? result : null,
      error: dbRes.ok ? null : (result || 'Request failed')
    });

  } catch (error) {
    console.error('Admin API error:', error);
    await captureError(error, reqContext(req, '/api/admin'));
    return res.status(500).json({ error: 'Internal server error' });
  }
};
