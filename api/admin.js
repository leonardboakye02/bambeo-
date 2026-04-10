const crypto = require('crypto');

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://mlqcjkyupgayhbbdlttr.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const ALLOWED_ORIGINS = [
  'https://bambeo-ivory.vercel.app',
  'https://bambeo-leonardboakye02s-projects.vercel.app',
  'https://bambeo-git-main-leonardboakye02s-projects.vercel.app'
];

const ALLOWED_TABLES = ['products', 'gallery', 'testimonials', 'faqs', 'site_settings', 'quote_requests'];
const ALLOWED_ACTIONS = ['select', 'insert', 'update', 'delete', 'upsert'];

// Rate limit failed login attempts: 5 per minute per IP
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

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

async function verifyPassword(password) {
  if (!SUPABASE_SERVICE_KEY) return false;
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/site_settings?key=eq.admin_password&select=value`,
    { headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}` } }
  );
  const data = await res.json();
  if (!Array.isArray(data) || !data[0]?.value) return false;
  const stored = data[0].value;
  // Support both hashed (sha256 hex = 64 chars) and legacy plaintext
  if (/^[a-f0-9]{64}$/.test(stored)) {
    return sha256(password) === stored;
  }
  return password === stored;
}

module.exports = async (req, res) => {
  // CORS
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!SUPABASE_SERVICE_KEY) {
    return res.status(500).json({ error: 'Server not configured' });
  }

  try {
    const clientIp = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
    if (!checkLoginRate(clientIp)) {
      return res.status(429).json({ error: 'Too many attempts, try again later' });
    }

    const password = (req.headers.authorization || '').replace('Bearer ', '');
    if (!password) return res.status(401).json({ error: 'Unauthorized' });

    const valid = await verifyPassword(password);
    if (!valid) {
      recordFailure(clientIp);
      return res.status(401).json({ error: 'Invalid password' });
    }

    const { table, action, data, filters } = req.body;

    if (!ALLOWED_TABLES.includes(table)) return res.status(400).json({ error: 'Invalid table' });
    if (!ALLOWED_ACTIONS.includes(action)) return res.status(400).json({ error: 'Invalid action' });

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
        const cols = data?.select || '*';
        url += `?select=${cols}`;
        if (filters) {
          for (const [col, val] of Object.entries(filters)) {
            url += `&${col}=eq.${val}`;
          }
        }
        break;
      }
      case 'insert': {
        method = 'POST';
        headers['Prefer'] = 'return=representation';
        body = JSON.stringify(data?.rows);
        break;
      }
      case 'update': {
        method = 'PATCH';
        headers['Prefer'] = 'return=representation';
        if (filters) {
          const params = Object.entries(filters).map(([c, v]) => `${c}=eq.${v}`).join('&');
          url += `?${params}`;
        }
        body = JSON.stringify(data?.rows);
        break;
      }
      case 'delete': {
        method = 'DELETE';
        if (filters) {
          const params = Object.entries(filters).map(([c, v]) => `${c}=eq.${v}`).join('&');
          url += `?${params}`;
        }
        break;
      }
      case 'upsert': {
        method = 'POST';
        headers['Prefer'] = 'resolution=merge-duplicates,return=representation';
        let rows = data?.rows;
        // Hash admin_password before storing
        if (table === 'site_settings' && Array.isArray(rows)) {
          rows = rows.map(r => {
            if (r.key === 'admin_password' && r.value && !/^[a-f0-9]{64}$/.test(r.value)) {
              return { ...r, value: sha256(r.value) };
            }
            return r;
          });
        }
        body = JSON.stringify(rows);
        break;
      }
    }

    const dbRes = await fetch(url, { method, headers, body: body || undefined });

    // DELETE returns empty body
    if (action === 'delete') {
      return res.status(dbRes.ok ? 200 : 400).json({
        data: null,
        error: dbRes.ok ? null : 'Delete failed'
      });
    }

    const result = await dbRes.json();
    return res.status(dbRes.ok ? 200 : 400).json({
      data: dbRes.ok ? result : null,
      error: dbRes.ok ? null : result
    });

  } catch (error) {
    console.error('Admin API error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};
