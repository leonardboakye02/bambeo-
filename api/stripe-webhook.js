// Stripe webhook for post-payment fulfillment + refunds + disputes.
// Handles: checkout.session.completed, charge.refunded, charge.dispute.created,
// charge.dispute.closed.

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// Stripe requires the RAW request body to verify the signature.
module.exports.config = { api: { bodyParser: false } };

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const supabaseHeaders = () => ({
  'apikey': SUPABASE_SERVICE_KEY,
  'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
  'Content-Type': 'application/json'
});

async function insertOrder(order) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/orders`, {
    method: 'POST',
    headers: { ...supabaseHeaders(), 'Prefer': 'return=representation,resolution=ignore-duplicates' },
    body: JSON.stringify([order])
  });
  if (!res.ok) {
    throw new Error(`Insert failed: ${res.status} ${await res.text()}`);
  }
}

async function updateOrderByPaymentIntent(paymentIntentId, patch) {
  if (!paymentIntentId) return;
  const url = `${SUPABASE_URL}/rest/v1/orders?stripe_payment_id=eq.${encodeURIComponent(paymentIntentId)}`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { ...supabaseHeaders(), 'Prefer': 'return=representation' },
    body: JSON.stringify({ ...patch, updated_at: new Date().toISOString() })
  });
  if (!res.ok) {
    throw new Error(`Update failed: ${res.status} ${await res.text()}`);
  }
  const rows = await res.json();
  if (!Array.isArray(rows) || rows.length === 0) {
    console.warn(`No order matched payment_intent ${paymentIntentId} for patch`, patch);
  }
}

async function handleCheckoutCompleted(session) {
  // Re-retrieve with line items expanded
  const full = await stripe.checkout.sessions.retrieve(session.id, {
    expand: ['line_items', 'line_items.data.price.product']
  });

  await insertOrder({
    stripe_session_id: full.id,
    stripe_payment_id: full.payment_intent || null,
    customer_email:    full.customer_details?.email || full.customer_email || null,
    customer_name:     full.customer_details?.name || null,
    amount_total:      full.amount_total,
    currency:          full.currency,
    status:            full.payment_status === 'paid' ? 'paid' : full.payment_status,
    line_items: (full.line_items?.data || []).map(li => ({
      description:  li.description,
      quantity:     li.quantity,
      unit_amount:  li.price?.unit_amount,
      product_id:   li.price?.product?.metadata?.product_id || null
    })),
    shipping_address: full.shipping_details?.address || null,
    billing_address:  full.customer_details?.address || null
  });
  console.log(`Order recorded: ${full.id}`);
}

async function handleChargeRefunded(charge) {
  const refunded = charge.amount_refunded || 0;
  const total    = charge.amount || 0;
  const status   = refunded >= total ? 'refunded' : 'partially_refunded';
  await updateOrderByPaymentIntent(charge.payment_intent, {
    status,
    refunded_amount: refunded
  });
  console.log(`Refund recorded for ${charge.payment_intent}: ${refunded}/${total}`);
}

async function handleDisputeCreated(dispute) {
  // dispute.charge is the charge ID. Retrieve to get payment_intent.
  let paymentIntent = null;
  try {
    const charge = await stripe.charges.retrieve(dispute.charge);
    paymentIntent = charge.payment_intent;
  } catch (e) {
    console.error('Failed to retrieve charge for dispute:', e.message);
  }
  await updateOrderByPaymentIntent(paymentIntent, {
    status: 'disputed',
    dispute_status: dispute.status   // e.g. 'needs_response', 'under_review'
  });
  console.log(`Dispute opened for ${paymentIntent}: ${dispute.status}`);
}

async function handleDisputeClosed(dispute) {
  let paymentIntent = null;
  try {
    const charge = await stripe.charges.retrieve(dispute.charge);
    paymentIntent = charge.payment_intent;
  } catch (e) {
    console.error('Failed to retrieve charge for dispute close:', e.message);
  }
  // Map dispute outcome to order status
  // 'won' → paid (we keep the money), 'lost' → dispute_lost (money clawed back)
  const won = dispute.status === 'won';
  await updateOrderByPaymentIntent(paymentIntent, {
    status: won ? 'paid' : 'dispute_lost',
    dispute_status: dispute.status
  });
  console.log(`Dispute closed for ${paymentIntent}: ${dispute.status}`);
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end('Method not allowed');

  if (!STRIPE_WEBHOOK_SECRET || !SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    console.error('Webhook misconfigured: missing env vars');
    return res.status(500).end('Server not configured');
  }

  let event;
  try {
    const rawBody = await readRawBody(req);
    const sig = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(rawBody, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).end(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed':
        await handleCheckoutCompleted(event.data.object);
        break;
      case 'charge.refunded':
        await handleChargeRefunded(event.data.object);
        break;
      case 'charge.dispute.created':
        await handleDisputeCreated(event.data.object);
        break;
      case 'charge.dispute.closed':
        await handleDisputeClosed(event.data.object);
        break;
      default:
        // Unhandled event type — Stripe still wants 200 so it doesn't retry
        console.log(`Unhandled event: ${event.type}`);
    }
    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('Webhook handler error:', err);
    // Stripe retries on 500. Only return 500 for transient errors so it can retry.
    return res.status(500).end('Handler error');
  }
};
