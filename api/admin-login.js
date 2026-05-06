const { verifyPassword, createSession, buildSessionCookie } = require('../lib/auth');
const { rateLimit, clientIp } = require('../lib/rate-limit');

const ALLOWED_ORIGINS = [
  'https://bambeo-ivory.vercel.app',
  'https://bambeo-leonardboakye02s-projects.vercel.app',
  'https://bambeo-git-main-leonardboakye02s-projects.vercel.app'
];

module.exports = async (req, res) => {
  const origin = req.headers.origin;
  const isAllowedOrigin = origin && ALLOWED_ORIGINS.includes(origin);
  if (isAllowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')    return res.status(405).json({ error: 'Method not allowed' });
  if (!isAllowedOrigin)         return res.status(403).json({ error: 'Forbidden origin' });

  const ip = clientIp(req);
  if (!await rateLimit({ key: `login:${ip}`, max: 5, windowSec: 60 })) {
    return res.status(429).json({ error: 'Too many attempts, try again later' });
  }

  try {
    const { password } = req.body || {};
    if (!password) return res.status(400).json({ error: 'Password required' });
    const valid = await verifyPassword(password);
    if (!valid) return res.status(401).json({ error: 'Invalid password' });
    const token = await createSession();
    res.setHeader('Set-Cookie', buildSessionCookie(token));
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Login failed' });
  }
};
