const crypto = require('crypto');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const ALLOWED_ORIGINS = [
  'https://bambeo-ivory.vercel.app',
  'https://bambeo-leonardboakye02s-projects.vercel.app',
  'https://bambeo-git-main-leonardboakye02s-projects.vercel.app'
];

const ALLOWED_TABLES = ['products', 'gallery', 'testimonials', 'faqs', 'site_settings', 'quote_requests'];
const ALLOWED_ACTIONS = ['select', 'insert', 'update', 'delete', 'upsert'];

// Per-table column whitelists for filters and select projections
const ALLOWED_COLUMNS = {
  products:        ['id', 'name', 'display_text', 'category', 'price', 'color', 'tag', 'description', 'image_url', 'image_urls', 'is_active', 'sort_order', 'created_at', 'updated_at'],
  gallery:         ['id', 'title', 'image_url', 'image_urls', 'description', 'is_active', 'sort_order', 'created_at', 'updated_at'],
  testimonials:    ['id', 'author_name', 'review_text', 'rating', 'is_active', 'sort_order', 'created_at', 'updated_at'],
  faqs:            ['id', 'question', 'answer', 'is_active', 'sort_order', 'created_at', 'updated_at'],
  site_settings:   ['id', 'key', 'value', 'created_at', 'updated_at'],
  quote_requests:  ['id', 'name', 'email', 'phone', 'message', 'design_image', 'design_style', 'status', 'created_at', 'updated_at']
};

// Identifier validation: alphanum + underscore only (PostgREST column names)
const IDENT_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

// Max JSON payload (Vercel default ~1mb but be defensive)
const MAX_BODY_BYTES = 256 * 1024;

// Rate limit failed login attempts: 5 per minute per IP (in-memory; replace with KV in prod)
const failMap = new Map();
function checkLoginRate(ip) {
  const now = Date.now();
  const entry = failMap.get(ip);
  if (!entry || now - entry.start > 60000) {
    failMap.set(ip, { start: now, count: 0 });
    return true;
  }
  return entry.count < 5;
}
function recordFailure(ip) {
  const entry = failMap.get(ip);
  if (entry) entry.count++;
}

// scrypt password hashing with random salt; format: scrypt$<saltHex>$<hashHex>
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('hex')}$${derived.toString('hex')}`;
}
function verifyScrypt(password, stored) {
  try {
    const parts = stored.split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    const salt = Buffer.from(parts[1], 'hex');
    const expected = Buffer.from(parts[2], 'hex');
    const derived = crypto.scryptSync(password, salt, expected.length, { N: 16384, r: 8, p: 1 });
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}
function timingSafeStringEq(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

async function fetchStoredPassword() {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/site_settings?key=eq.admin_password&select=value`,
    { headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}` } }
  );
  const data = await res.json();
  if (!Array.isArray(data) || !data[0]?.value) return null;
  return data[0].value;
}

async function verifyPassword(password) {
  const stored = await fetchStoredPassword();
  if (!stored) return false;
  if (stored.startsWith('scrypt$')) return verifyScrypt(password, stored);
  // Legacy sha256 hex (no salt) — still supported with timing-safe compare; will be migrated on next password change
  if (/^[a-f0-9]{64}$/.test(stored)) {
    const candidate = crypto.createHash('sha256').update(password).digest('hex');
    return timingSafeStringEq(candidate, stored);
  }
  // Plaintext fallback removed for security. Block.
  return false;
}

function validateColumns(table, cols) {
  const allowed = ALLOWED_COLUMNS[table];
  if (!allowed) return false;
  return cols.every(c => IDENT_RE.test(c) && allowed.includes(c));
}

function buildSelect(table, raw) {
  if (!raw || raw === '*') {
    return ALLOWED_COLUMNS[table].join(',');
  }
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

  // CORS — only echo allowed origins
  if (isAllowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
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
    const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
    if (!checkLoginRate(clientIp)) {
      return res.status(429).json({ error: 'Too many attempts, try again later' });
    }

    const password = (req.headers.authorization || '').replace('Bearer ', '');
    if (!password || password.length > 256) {
      recordFailure(clientIp);
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const valid = await verifyPassword(password);
    if (!valid) {
      recordFailure(clientIp);
      return res.status(401).json({ error: 'Invalid password' });
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
        const rows = sanitizeRows(table, data?.rows);
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
    return res.status(500).json({ error: 'Internal server error' });
  }
};
