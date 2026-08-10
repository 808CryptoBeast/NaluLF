/* =====================================================
   anthropic-proxy.js — Cloudflare Worker
   =====================================================
   The ONLY reason this file exists: api.anthropic.com's CORS policy
   rejects requests from arbitrary browser origins outright (tested —
   a direct fetch() from a webpage gets "400 Disallowed CORS origin"
   before Anthropic even looks at the API key). There is no client-side
   workaround for that; it's enforced server-side regardless of whose
   key is used or how carefully it's stored.

   This Worker's ONLY job is to sit between NaluLF (running in the
   user's browser) and Anthropic's API, fixing that CORS mismatch by
   relaying the request server-to-server (server-to-server calls have
   no CORS restriction — CORS is a browser-enforced concept).

   It is intentionally a dumb, stateless relay:
     - It does not store, log, or inspect the caller's API key.
     - It does not hold any secret of its own — there is nothing here
       to leak. Every request carries its OWN Anthropic API key
       (the end user's, pasted into NaluLF's settings), which this
       Worker forwards to Anthropic and immediately forgets.
     - Deploy this ONCE (by whoever runs the NaluLF site) and every
       user of that site shares it — nobody needs their own Worker,
       they only need their own Anthropic API key.

   Deploy (Cloudflare dashboard → Workers & Pages → Create → paste
   this file's contents → Deploy), or via Wrangler:
     npx wrangler deploy anthropic-proxy.js --name nalulf-anthropic-proxy
   Then paste the resulting *.workers.dev URL into NaluLF's
   Profile → Settings → AI Explanations section.
   ===================================================== */

const ANTHROPIC_URL = 'https://api.anthropic.com/v1/messages';

// Open to any origin on purpose: this Worker holds no secret of its own
// (see file header) — the sensitive credential is the caller-supplied
// x-api-key, which is never read, stored, or logged here, only forwarded.
// Anyone using this Worker is only ever spending their OWN Anthropic
// credits with their OWN key.
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'content-type, x-api-key, anthropic-version, anthropic-beta',
  'Access-Control-Max-Age': '86400',
};

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers: CORS_HEADERS });
    }

    const apiKey = request.headers.get('x-api-key');
    if (!apiKey) {
      return new Response(
        JSON.stringify({ error: { message: 'Missing x-api-key header.' } }),
        { status: 400, headers: { ...CORS_HEADERS, 'content-type': 'application/json' } }
      );
    }

    // Forward everything as-is — body, streaming or not, straight through
    // to Anthropic, then pipe their response straight back. No parsing,
    // no re-serializing, so this keeps working for any request shape
    // NaluLF sends without needing to update the Worker.
    const upstream = await fetch(ANTHROPIC_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': request.headers.get('anthropic-version') || '2023-06-01',
        ...(request.headers.get('anthropic-beta') ? { 'anthropic-beta': request.headers.get('anthropic-beta') } : {}),
      },
      body: request.body,
      // Cloudflare requires this when streaming a request body through.
      duplex: 'half',
    });

    const responseHeaders = new Headers(upstream.headers);
    for (const [k, v] of Object.entries(CORS_HEADERS)) responseHeaders.set(k, v);

    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders,
    });
  },
};
