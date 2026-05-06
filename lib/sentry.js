// Lightweight Sentry client — sends a single envelope per error, no SDK.
// Avoids the 100KB+ @sentry/node bundle in every lambda.
// If SENTRY_DSN is not set, captureError silently no-ops.
//
// DSN format: https://<publicKey>@<host>/<projectId>
// Envelope endpoint: https://<host>/api/<projectId>/envelope/

const crypto = require('crypto');

let _parsed = null;
function parseDsn() {
  if (_parsed !== null) return _parsed;
  const dsn = process.env.SENTRY_DSN;
  if (!dsn) { _parsed = false; return false; }
  try {
    const u = new URL(dsn);
    const projectId = u.pathname.replace(/^\//, '').split('/').pop();
    _parsed = {
      publicKey: u.username,
      host: u.host,
      projectId,
      envelopeUrl: `${u.protocol}//${u.host}/api/${projectId}/envelope/`
    };
    return _parsed;
  } catch {
    console.error('Invalid SENTRY_DSN');
    _parsed = false;
    return false;
  }
}

function eventId() {
  return crypto.randomBytes(16).toString('hex'); // 32-char hex, Sentry's expected format
}

function buildEvent(err, context = {}) {
  const e = err instanceof Error ? err : new Error(String(err));
  const stack = (e.stack || '').split('\n').slice(1).map(line => {
    const m = line.match(/at\s+(?:(.+?)\s+\()?(.+):(\d+):(\d+)\)?/);
    if (!m) return null;
    return {
      function: m[1] || '<anonymous>',
      filename: m[2],
      lineno: parseInt(m[3], 10),
      colno: parseInt(m[4], 10),
      in_app: !m[2].includes('node_modules')
    };
  }).filter(Boolean).reverse(); // Sentry expects oldest -> newest

  return {
    event_id: eventId(),
    timestamp: new Date().toISOString(),
    platform: 'node',
    level: context.level || 'error',
    server_name: process.env.VERCEL_REGION || 'vercel',
    environment: process.env.VERCEL_ENV || 'production',
    release: process.env.VERCEL_GIT_COMMIT_SHA || undefined,
    transaction: context.transaction,
    tags: context.tags || {},
    extra: context.extra || {},
    request: context.request || undefined,
    exception: {
      values: [{
        type: e.name || 'Error',
        value: e.message || String(err),
        stacktrace: { frames: stack }
      }]
    }
  };
}

async function captureError(err, context = {}) {
  const dsn = parseDsn();
  if (!dsn) return;
  try {
    const event = buildEvent(err, context);
    const envelopeHeader = JSON.stringify({
      event_id: event.event_id,
      sent_at: new Date().toISOString(),
      dsn: process.env.SENTRY_DSN
    });
    const itemHeader = JSON.stringify({ type: 'event' });
    const body = `${envelopeHeader}\n${itemHeader}\n${JSON.stringify(event)}\n`;
    await fetch(dsn.envelopeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-sentry-envelope',
        'X-Sentry-Auth': `Sentry sentry_version=7, sentry_key=${dsn.publicKey}, sentry_client=bambeo-mini/1.0`
      },
      body
    });
  } catch (e) {
    // Don't let logging break the actual handler
    console.error('Sentry capture failed:', e.message);
  }
}

// Helper to extract safe request context from a Vercel req
function reqContext(req, transaction) {
  return {
    transaction,
    request: {
      url: req.url,
      method: req.method,
      headers: {
        'user-agent': req.headers['user-agent'],
        origin:       req.headers.origin
      }
    }
  };
}

module.exports = { captureError, reqContext };
