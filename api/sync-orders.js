// Reconcile orders with Stripe.
// Pulls every order, fetches the matching PaymentIntent + Charge from Stripe,
// and updates status / refunded_amount / dispute_status to match Stripe's truth.
// Safe to run repeatedly. Useful when a webhook event was missed.

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { authenticate } = require('../lib/auth');
const { rateLimit, clientIp } = require('../lib/rate-limit');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const ALLOWED_ORIGINS = [
  'https://bambeo-ivory.vercel.app',
  'https://bambeo-leonardboakye02s-projects.vercel.app',
  'https://bambeo-git-main-leonardboakye02s-projects.vercel.app'
];

async function listOrders() {
  const url = `${SUPABASE_URL}/rest/v1/orders?select=id,stripe_payment_id,status,refunded_amount,dispute_status&stripe_payment_id=not.is.null`;
  const res = await fetch(url, {
    headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}` }
  });
  if (!res.ok) throw new Error(`List failed: ${res.status}`);
  return res.json();
}

async function patchOrder(id, patch) {
  const url = `${SUPABASE_URL}/rest/v1/orders?id=eq.${encodeURIComponent(id)}`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ ...patch, updated_at: new Date().toISOString() })
  });
  if (!res.ok) throw new Error(`Patch failed for ${id}: ${res.status}`);
}

function reconcile(charge) {
  const refunded = charge.amount_refunded || 0;
  const total    = charge.amount || 0;
  const out = {
    refunded_amount: refunded,
    dispute_status:  charge.dispute?.status || null
  };
  if (charge.dispute) {
    if (charge.dispute.status === 'won')              out.status = 'paid';
    else if (charge.dispute.status === 'lost')        out.status = 'dispute_lost';
    else                                              out.status = 'disputed';
  } else if (refunded >= total && total > 0) {
    out.status = 'refunded';
  } else if (refunded > 0) {
    out.status = 'partially_refunded';
  } else if (charge.status === 'succeeded') {
    out.status = 'paid';
  } else {
    out.status = charge.status || 'unknown';
  }
  return out;
}

function diff(current, fresh) {
  const changed = {};
  for (const k of ['status', 'refunded_amount', 'dispute_status']) {
    const a = current[k] ?? null;
    const b = fresh[k]   ?? null;
    if (a !== b) changed[k] = b;
  }
  return changed;
}

module.exports = async (req, res) => {
  const origin = req.headers.origin;
  const isAllowedOrigin = origin && ALLOWED_ORIGINS.includes(origin);
  if (isAllowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')    return res.status(405).json({ error: 'Method not allowed' });
  if (!isAllowedOrigin)         return res.status(403).json({ error: 'Forbidden origin' });

  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !process.env.STRIPE_SECRET_KEY) {
    return res.status(500).json({ error: 'Server not configured' });
  }

  const ip = clientIp(req);
  if (!await rateLimit({ key: `sync:${ip}`, max: 6, windowSec: 60 })) {
    return res.status(429).json({ error: 'Too many sync attempts' });
  }

  const auth = await authenticate(req);
  if (!auth.ok) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const orders = await listOrders();
    let scanned = 0, updated = 0, errors = 0;
    const changes = [];

    for (const o of orders) {
      scanned++;
      try {
        const pi = await stripe.paymentIntents.retrieve(o.stripe_payment_id, { expand: ['latest_charge'] });
        const charge = pi.latest_charge;
        if (!charge || typeof charge === 'string') continue;
        const fresh = reconcile(charge);
        const changed = diff(o, fresh);
        if (Object.keys(changed).length > 0) {
          await patchOrder(o.id, fresh);
          updated++;
          changes.push({ id: o.id, changed });
        }
      } catch (err) {
        errors++;
        console.error(`Sync error for ${o.id}:`, err.message);
      }
    }

    return res.status(200).json({ scanned, updated, errors, changes });
  } catch (err) {
    console.error('Sync failed:', err);
    return res.status(500).json({ error: 'Sync failed' });
  }
};
