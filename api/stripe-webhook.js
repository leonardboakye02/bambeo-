// Stripe webhook for post-payment fulfillment.
// Receives checkout.session.completed, writes the order to Supabase,
// and (optionally) emails the admin.

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// Stripe requires the RAW request body to verify the signature.
// Vercel parses JSON by default, so we have to disable that.
module.exports.config = { api: { bodyParser: false } };

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function insertOrder(order) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/orders`, {
    method: 'POST',
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation,resolution=ignore-duplicates'
    },
    body: JSON.stringify([order])
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Supabase insert failed: ${res.status} ${text}`);
  }
  return res.json();
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
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;

      // Re-retrieve with line items expanded — webhook payload doesn't include them by default
      const full = await stripe.checkout.sessions.retrieve(session.id, {
        expand: ['line_items', 'line_items.data.price.product']
      });

      const order = {
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
      };

      await insertOrder(order);
      console.log(`Order recorded: ${full.id}`);
    }

    // Always acknowledge — Stripe retries on non-2xx
    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('Webhook handler error:', err);
    // Returning 500 makes Stripe retry. Only do this for transient errors.
    return res.status(500).end('Handler error');
  }
};
