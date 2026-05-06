const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const crypto = require('crypto');
const { rateLimit, clientIp } = require('../lib/rate-limit');
const { captureError, reqContext } = require('../lib/sentry');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

// Allowed origins for CORS
const ALLOWED_ORIGINS = [
  'https://bambeo-ivory.vercel.app',
  'https://bambeo-leonardboakye02s-projects.vercel.app',
  'https://bambeo-git-main-leonardboakye02s-projects.vercel.app'
];

// UUID v4-ish or integer id validator (matches Supabase default ID shapes)
const ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;

module.exports = async (req, res) => {
  const origin = req.headers.origin;
  const isAllowedOrigin = origin && ALLOWED_ORIGINS.includes(origin);

  if (isAllowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!isAllowedOrigin) {
    return res.status(403).json({ error: 'Forbidden origin' });
  }

  if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !process.env.STRIPE_SECRET_KEY) {
    return res.status(500).json({ error: 'Server not configured' });
  }

  const ip = clientIp(req);
  if (!await rateLimit({ key: `checkout:${ip}`, max: 10, windowSec: 60 })) {
    return res.status(429).json({ error: 'Too many requests, please try again later' });
  }

  try {
    const { items, customerEmail } = req.body || {};

    if (!Array.isArray(items) || items.length === 0 || items.length > 50) {
      return res.status(400).json({ error: 'No items provided' });
    }

    // Validate each item shape strictly
    for (const item of items) {
      if (!item || typeof item !== 'object') return res.status(400).json({ error: 'Invalid item' });
      if (!ID_RE.test(String(item.id || ''))) return res.status(400).json({ error: 'Invalid item id' });
      const q = Number(item.quantity);
      if (!Number.isFinite(q) || q < 1 || q > 50) return res.status(400).json({ error: 'Invalid item quantity' });
    }

    if (customerEmail && !EMAIL_RE.test(String(customerEmail))) {
      return res.status(400).json({ error: 'Invalid email' });
    }

    // SERVER-SIDE PRICE VERIFICATION using public anon key (RLS allows public read of active products)
    const productIds = [...new Set(items.map(i => String(i.id)))];
    const query = productIds.map(id => `id.eq.${encodeURIComponent(id)}`).join(',');

    const dbRes = await fetch(
      `${SUPABASE_URL}/rest/v1/products?or=(${query})&select=id,name,price,is_active`,
      {
        headers: {
          'apikey': SUPABASE_ANON_KEY,
          'Authorization': `Bearer ${SUPABASE_ANON_KEY}`
        }
      }
    );
    const dbProducts = await dbRes.json();

    if (!Array.isArray(dbProducts) || dbProducts.length === 0) {
      return res.status(400).json({ error: 'Products not found' });
    }

    const priceMap = {};
    for (const p of dbProducts) {
      if (p.is_active !== false) {
        const price = parseFloat(p.price);
        if (Number.isFinite(price) && price >= 0 && price < 100000) {
          priceMap[p.id] = { name: String(p.name || '').slice(0, 200), price };
        }
      }
    }

    const lineItems = [];
    for (const item of items) {
      const verified = priceMap[item.id];
      if (!verified) {
        return res.status(400).json({ error: `Product ${item.id} not found or inactive` });
      }
      lineItems.push({
        price_data: {
          currency: 'usd',
          product_data: {
            name: verified.name,
            description: 'Custom sign/piece',
            metadata: { product_id: String(item.id) }
          },
          unit_amount: Math.round(verified.price * 100),
        },
        quantity: Math.min(Math.max(Math.round(Number(item.quantity)), 1), 50),
      });
    }

    // Idempotency key prevents duplicate Stripe sessions on client retries
    const idempotencyKey = crypto
      .createHash('sha256')
      .update(JSON.stringify({ ip, items, email: customerEmail || '', t: Math.floor(Date.now() / 5000) }))
      .digest('hex');

    const session = await stripe.checkout.sessions.create(
      {
        payment_method_types: ['card'],
        line_items: lineItems,
        mode: 'payment',
        success_url: `${process.env.SITE_URL || 'https://bambeo-ivory.vercel.app'}/success.html?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.SITE_URL || 'https://bambeo-ivory.vercel.app'}/cancel.html`,
        customer_email: customerEmail || undefined,
        billing_address_collection: 'required',
        shipping_address_collection: { allowed_countries: ['US', 'CA'] },
        metadata: { order_source: 'bambeo_website' },
      },
      { idempotencyKey }
    );

    return res.status(200).json({ sessionId: session.id, url: session.url });

  } catch (error) {
    console.error('Stripe error:', error);
    await captureError(error, reqContext(req, '/api/create-checkout-session'));
    return res.status(500).json({ error: 'Failed to create checkout session' });
  }
};
