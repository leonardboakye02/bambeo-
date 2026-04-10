const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://mlqcjkyupgayhbbdlttr.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Allowed origins for CORS
const ALLOWED_ORIGINS = [
  'https://bambeo-ivory.vercel.app',
  'https://bambeo-leonardboakye02s-projects.vercel.app',
  'https://bambeo-git-main-leonardboakye02s-projects.vercel.app'
];

// Basic in-memory rate limiting (per serverless instance)
const rateMap = new Map();
function rateLimit(ip, maxRequests = 10, windowMs = 60000) {
  const now = Date.now();
  const entry = rateMap.get(ip);
  if (!entry || now - entry.start > windowMs) {
    rateMap.set(ip, { start: now, count: 1 });
    return true;
  }
  entry.count++;
  return entry.count <= maxRequests;
}

module.exports = async (req, res) => {
  // CORS - restrict to known origins
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Rate limit: 10 checkout attempts per minute per IP
  const clientIp = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
  if (!rateLimit(clientIp)) {
    return res.status(429).json({ error: 'Too many requests, please try again later' });
  }

  try {
    const { items, customerEmail } = req.body;

    if (!items || !items.length) {
      return res.status(400).json({ error: 'No items provided' });
    }

    // Validate quantities
    for (const item of items) {
      if (!item.id || !item.quantity || item.quantity < 1 || item.quantity > 50) {
        return res.status(400).json({ error: 'Invalid item data' });
      }
    }

    // SERVER-SIDE PRICE VERIFICATION: Fetch real prices from Supabase
    const productIds = items.map(i => i.id);
    const query = productIds.map(id => `id.eq.${id}`).join(',');
    const supabaseKey = SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY;

    const dbRes = await fetch(
      `${SUPABASE_URL}/rest/v1/products?or=(${query})&select=id,name,price,is_active`,
      {
        headers: {
          'apikey': supabaseKey,
          'Authorization': `Bearer ${supabaseKey}`
        }
      }
    );
    const dbProducts = await dbRes.json();

    if (!Array.isArray(dbProducts) || dbProducts.length === 0) {
      return res.status(400).json({ error: 'Products not found' });
    }

    // Build a lookup map of real prices
    const priceMap = {};
    for (const p of dbProducts) {
      if (p.is_active !== false) {
        priceMap[p.id] = { name: p.name, price: parseFloat(p.price) };
      }
    }

    // Build line items using SERVER-VERIFIED prices (ignore client prices)
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
            metadata: { product_id: item.id }
          },
          unit_amount: Math.round(verified.price * 100), // Use DB price, NOT client price
        },
        quantity: Math.min(Math.max(Math.round(item.quantity), 1), 50),
      });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: lineItems,
      mode: 'payment',
      success_url: `${process.env.SITE_URL || 'https://bambeo-ivory.vercel.app'}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.SITE_URL || 'https://bambeo-ivory.vercel.app'}/cancel.html`,
      customer_email: customerEmail || undefined,
      billing_address_collection: 'required',
      shipping_address_collection: {
        allowed_countries: ['US', 'CA'],
      },
      metadata: {
        order_source: 'bambeo_website'
      },
    });

    return res.status(200).json({
      sessionId: session.id,
      url: session.url
    });

  } catch (error) {
    console.error('Stripe error:', error);
    return res.status(500).json({
      error: 'Failed to create checkout session'
    });
  }
};
