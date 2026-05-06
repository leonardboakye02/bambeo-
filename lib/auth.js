// Shared admin authentication helpers.
// Supports both:
//   - Cookie-based sessions (preferred): HttpOnly cookie containing a random
//     32-byte token. Server stores SHA-256 hash + expiry in admin_sessions.
//   - Bearer password (legacy/fallback): Authorization: Bearer <password>
//     verified against site_settings.admin_password.

const crypto = require('crypto');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const COOKIE_NAME = 'bambeo_admin_session';
const SESSION_TTL_HOURS = 24;
const TOKEN_BYTES = 32;

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
function timingSafeStringEq(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
function verifyScrypt(password, stored) {
  try {
    const parts = stored.split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    const salt = Buffer.from(parts[1], 'hex');
    const expected = Buffer.from(parts[2], 'hex');
    const derived = crypto.scryptSync(password, salt, expected.length, { N: 16384, r: 8, p: 1 });
    return crypto.timingSafeEqual(derived, expected);
  } catch { return false; }
}

async function fetchAdminPasswordHash() {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/site_settings?key=eq.admin_password&select=value`,
    { headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}` } }
  );
  const data = await res.json();
  return Array.isArray(data) && data[0]?.value || null;
}

async function verifyPassword(password) {
  if (!password || password.length > 256) return false;
  const stored = await fetchAdminPasswordHash();
  if (!stored) return false;
  if (stored.startsWith('scrypt$')) return verifyScrypt(password, stored);
  if (/^[a-f0-9]{64}$/.test(stored)) return timingSafeStringEq(sha256Hex(password), stored);
  return false;
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const [name, ...rest] = part.split('=');
    if (!name) continue;
    out[name.trim()] = decodeURIComponent(rest.join('=').trim());
  }
  return out;
}

function buildSessionCookie(token, { maxAgeSec } = {}) {
  const parts = [
    `${COOKIE_NAME}=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Strict'
  ];
  if (typeof maxAgeSec === 'number') parts.push(`Max-Age=${maxAgeSec}`);
  else parts.push(`Max-Age=${SESSION_TTL_HOURS * 3600}`);
  return parts.join('; ');
}
function buildClearCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

async function createSession() {
  const token = crypto.randomBytes(TOKEN_BYTES).toString('base64url');
  const tokenHash = sha256Hex(token);
  const expiresAt = new Date(Date.now() + SESSION_TTL_HOURS * 3600 * 1000).toISOString();
  const res = await fetch(`${SUPABASE_URL}/rest/v1/admin_sessions`, {
    method: 'POST',
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=minimal'
    },
    body: JSON.stringify([{ token_hash: tokenHash, expires_at: expiresAt }])
  });
  if (!res.ok) throw new Error(`Session insert failed: ${res.status} ${await res.text()}`);
  return token;
}

async function deleteSession(token) {
  if (!token) return;
  const tokenHash = sha256Hex(token);
  await fetch(
    `${SUPABASE_URL}/rest/v1/admin_sessions?token_hash=eq.${encodeURIComponent(tokenHash)}`,
    { method: 'DELETE',
      headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}` }
    }
  ).catch(() => {});
}

async function verifySession(token) {
  if (!token || token.length > 128) return false;
  const tokenHash = sha256Hex(token);
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/admin_sessions?token_hash=eq.${encodeURIComponent(tokenHash)}&select=id,expires_at`,
    { headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}` } }
  );
  if (!res.ok) return false;
  const rows = await res.json();
  if (!Array.isArray(rows) || rows.length === 0) return false;
  const session = rows[0];
  if (new Date(session.expires_at).getTime() < Date.now()) {
    // Expired — best-effort cleanup
    deleteSession(token);
    return false;
  }
  // Best-effort: bump last_used_at (don't await)
  fetch(
    `${SUPABASE_URL}/rest/v1/admin_sessions?id=eq.${encodeURIComponent(session.id)}`,
    {
      method: 'PATCH',
      headers: {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ last_used_at: new Date().toISOString() })
    }
  ).catch(() => {});
  return true;
}

// Authenticate a request via cookie OR Bearer header.
// Returns { ok: true, via: 'cookie' | 'bearer' } or { ok: false }.
async function authenticate(req) {
  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME];
  if (token && await verifySession(token)) {
    return { ok: true, via: 'cookie' };
  }
  const auth = req.headers.authorization || '';
  const password = auth.replace(/^Bearer\s+/i, '');
  if (password && await verifyPassword(password)) {
    return { ok: true, via: 'bearer' };
  }
  return { ok: false };
}

module.exports = {
  COOKIE_NAME,
  authenticate,
  verifyPassword,
  verifySession,
  createSession,
  deleteSession,
  parseCookies,
  buildSessionCookie,
  buildClearCookie
};
