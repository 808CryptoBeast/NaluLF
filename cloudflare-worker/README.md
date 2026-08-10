# NaluLF Anthropic Proxy (Cloudflare Worker)

## Why this exists

NaluLF is a client-side-only app — no backend, no server, everything runs
in your browser. The one exception is this Worker, and it's a narrow one:
Anthropic's API rejects requests made directly from a webpage's JavaScript
(`400 Disallowed CORS origin`), regardless of whose API key is used. There's
no client-side way around that — it's enforced by Anthropic's servers, not
a setting in NaluLF.

This Worker is a stateless relay that sits between your browser and
`api.anthropic.com`, forwarding requests server-to-server (which has no CORS
restriction) and piping the response straight back. It does not read, log,
or store the API key it relays — every request carries the caller's own key,
and the Worker forgets it the instant the request completes. Deploying it
does not give up "you own your keys": your Anthropic API key still only
ever lives in your own browser's encrypted vault, exactly like a wallet seed.

## Deploy it (~2 minutes, free)

**Option A — Cloudflare dashboard (no CLI):**
1. Go to [dash.cloudflare.com](https://dash.cloudflare.com) → **Workers & Pages** → **Create** → **Create Worker**.
2. Give it a name (e.g. `nalulf-anthropic-proxy`) and deploy the default template.
3. Click **Edit code**, delete everything, paste in the contents of [`anthropic-proxy.js`](./anthropic-proxy.js), and **Deploy**.
4. Copy the `*.workers.dev` URL Cloudflare gives you.

**Option B — Wrangler CLI:**
```bash
npx wrangler deploy anthropic-proxy.js --name nalulf-anthropic-proxy
```

## Use it

1. In NaluLF, go to **Profile → Settings → AI Explanations**.
2. Paste your Anthropic API key (get one at [platform.claude.com/settings/keys](https://platform.claude.com/settings/keys)) and the Worker URL from above.
3. Both are stored only in your own browser's encrypted vault — never sent anywhere except to this Worker (and from there, straight to Anthropic).

## Cost

Cloudflare Workers' free tier covers 100,000 requests/day — far more than
a single user (or a small community) inspecting XRPL accounts would ever
hit. You only separately pay for your own Anthropic API usage, same as
using Claude directly.

## If you're running your own fork/deployment of NaluLF

Deploy this once and share the Worker URL with your users (e.g. bake it in
as the default in Settings) — everyone still brings their own Anthropic key,
so you're never billed for anyone else's usage and never see anyone else's
key.
