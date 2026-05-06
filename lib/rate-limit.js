// Rate limiter backed by Vercel KV (Upstash Redis) with in-memory fallback.
// If KV env vars are not present, falls back to per-instance memory (the old
// behavior). With KV configured, limits are shared across all serverless
// instances and survive cold starts.
//
// Usage:
//   const ok = await rateLimit({ key: `admin:${ip}`, max: 5, windowSec: 60 });
//   if (!ok) return res.status(429)...

const inMem = new Map();

function inMemoryRate(key, max, windowSec) {
  const now = Date.now();
  const entry = inMem.get(key);
  if (!entry || now - entry.start > windowSec * 1000) {
    inMem.set(key, { start: now, count: 1 });
    return true;
  }
  entry.count++;
  return entry.count <= max;
}

async function kvIncr(key, windowSec) {
  const url = process.env.KV_REST_API_URL;
  const token = process.env.KV_REST_API_TOKEN;
  const headers = { 'Authorization': `Bearer ${token}` };

  // Atomic-ish: incr first, then expire if count == 1
  const incrRes = await fetch(`${url}/incr/${encodeURIComponent(key)}`, { headers });
  if (!incrRes.ok) throw new Error(`KV INCR failed: ${incrRes.status}`);
  const { result: count } = await incrRes.json();

  if (count === 1) {
    // First hit in this window — set expiry. Best-effort; don't await failure.
    await fetch(`${url}/expire/${encodeURIComponent(key)}/${windowSec}`, { headers })
      .catch(() => {});
  }
  return count;
}

async function rateLimit({ key, max, windowSec }) {
  if (!process.env.KV_REST_API_URL || !process.env.KV_REST_API_TOKEN) {
    return inMemoryRate(key, max, windowSec);
  }
  try {
    const count = await kvIncr(key, windowSec);
    return count <= max;
  } catch (err) {
    console.error('Rate limit KV error, falling back to in-memory:', err.message);
    return inMemoryRate(key, max, windowSec);
  }
}

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress
    || 'unknown';
}

module.exports = { rateLimit, clientIp };
