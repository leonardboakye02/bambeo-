// Admin-only order operations.
// Actions: mark_shipped, set_tracking, cancel, refund, update_notes
// Auth: cookie session OR Bearer (legacy). Origin enforced.

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { authenticate } = require('../lib/auth');
const { rateLimit, clientIp } = require('../lib/rate-limit');
const { captureError, reqContext } = require('../lib/sentry');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const ALLOWED_ORIGINS = [
  'https://bambeo-ivory.vercel.app',
  'https://bambeo-leonardboakye02s-projects.vercel.app',
  'https://bambeo-git-main-leonardboakye02s-projects.vercel.app'
];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CARRIERS = ['usps', 'ups', 'fedex', 'dhl', 'other'];

const supabaseHeaders = () => ({
  'apikey': SUPABASE_SERVICE_KEY,
  'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
  'Content-Type': 'application/json'
});

async function getOrder(id) {
  const url = `${SUPABASE_URL}/rest/v1/orders?id=eq.${encodeURIComponent(id)}&select=*`;
  const res = await fetch(url, { headers: supabaseHeaders() });
  if (!res.ok) throw new Error(`Get order failed: ${res.status}`);
  const rows = await res.json();
  return Array.isArray(rows) && rows[0];
}

async function patchOrder(id, patch) {
  const url = `${SUPABASE_URL}/rest/v1/orders?id=eq.${encodeURIComponent(id)}`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { ...supabaseHeaders(), 'Prefer': 'return=representation' },
    body: JSON.stringify({ ...patch, updated_at: new Date().toISOString() })
  });
  if (!res.ok) throw new Error(`Patch failed: ${res.status} ${await res.text()}`);
  const rows = await res.json();
  return Array.isArray(rows) && rows[0];
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
  if (!await rateLimit({ key: `order-action:${ip}`, max: 30, windowSec: 60 })) {
    return res.status(429).json({ error: 'Too many requests' });
  }

  const auth = await authenticate(req);
  if (!auth.ok) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const { order_id, action, payload } = req.body || {};
    if (!UUID_RE.test(String(order_id || ''))) {
      return res.status(400).json({ error: 'Invalid order_id' });
    }
    const order = await getOrder(order_id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    let updated;
    switch (action) {
      case 'mark_shipped': {
        const tracking = (payload?.tracking_number || '').trim().slice(0, 100) || null;
        const carrier  = CARRIERS.includes(payload?.carrier) ? payload.carrier : null;
        updated = await patchOrder(order_id, {
          status: 'shipped',
          tracking_number: tracking || order.tracking_number,
          shipping_carrier: carrier || order.shipping_carrier,
          shipped_at: order.shipped_at || new Date().toISOString()
        });
        break;
      }
      case 'set_tracking': {
        const tracking = (payload?.tracking_number || '').trim().slice(0, 100);
        if (!tracking) return res.status(400).json({ error: 'tracking_number required' });
        const carrier = CARRIERS.includes(payload?.carrier) ? payload.carrier : null;
        updated = await patchOrder(order_id, {
          tracking_number: tracking,
          shipping_carrier: carrier || order.shipping_carrier
        });
        break;
      }
      case 'cancel': {
        if (order.status === 'shipped') {
          return res.status(400).json({ error: 'Cannot cancel a shipped order — issue a refund instead' });
        }
        if (order.status === 'cancelled') {
          return res.status(400).json({ error: 'Already cancelled' });
        }
        updated = await patchOrder(order_id, { status: 'cancelled' });
        break;
      }
      case 'update_notes': {
        const notes = String(payload?.notes || '').slice(0, 2000);
        updated = await patchOrder(order_id, { notes });
        break;
      }
      case 'refund': {
        if (!order.stripe_payment_id) {
          return res.status(400).json({ error: 'No stripe payment id on this order' });
        }
        // Optional partial refund amount in cents; default = remaining unrefunded balance
        const remaining = (order.amount_total || 0) - (order.refunded_amount || 0);
        if (remaining <= 0) return res.status(400).json({ error: 'Already fully refunded' });
        let amount = Number(payload?.amount);
        if (!Number.isFinite(amount) || amount <= 0) amount = remaining;
        amount = Math.min(Math.round(amount), remaining);

        // Idempotency key to prevent double-refunds on client retry
        const idempotencyKey = `refund:${order_id}:${amount}:${Math.floor(Date.now() / 5000)}`;
        const refund = await stripe.refunds.create(
          {
            payment_intent: order.stripe_payment_id,
            amount,
            reason: payload?.reason || undefined,
            metadata: { order_id }
          },
          { idempotencyKey }
        );
        // Webhook charge.refunded will also fire and reconcile, but update locally
        // immediately so the admin UI reflects the change without a round-trip.
        const newRefunded = (order.refunded_amount || 0) + amount;
        const newStatus = newRefunded >= order.amount_total ? 'refunded' : 'partially_refunded';
        updated = await patchOrder(order_id, {
          status: newStatus,
          refunded_amount: newRefunded
        });
        return res.status(200).json({ ok: true, order: updated, stripe_refund_id: refund.id });
      }
      default:
        return res.status(400).json({ error: 'Unknown action' });
    }

    return res.status(200).json({ ok: true, order: updated });
  } catch (err) {
    console.error('Order action error:', err);
    await captureError(err, reqContext(req, '/api/order-action'));
    return res.status(500).json({ error: 'Action failed' });
  }
};
