/* =====================================================
   ai.js — Claude API client (via the CORS-relay proxy)
   =====================================================
   Anthropic's API rejects direct browser-origin requests outright
   ("Disallowed CORS origin" — confirmed empirically, not a guess), so this
   module never calls api.anthropic.com directly. Every request goes through
   the user's configured proxy (a small stateless Cloudflare Worker — see
   /cloudflare-worker) which relays it server-to-server. The API key and
   proxy URL live only in the encrypted vault (CryptoVault), exactly like a
   wallet seed — never sent anywhere except to that proxy.

   This is a thin fetch() wrapper, not the Anthropic SDK: the SDK's browser
   mode (dangerouslyAllowBrowser) only relaxes a client-side warning, it
   doesn't change the request shape or bypass Anthropic's CORS policy, and
   pulling in a full SDK via CDN import would be the only npm dependency in
   an otherwise dependency-free, no-build-step client app. The request/
   response shapes below are hand-built directly from the Messages API spec.
   ===================================================== */
import { CryptoVault } from './auth.js';

export class AiNotConfiguredError extends Error {
  constructor() { super('AI explanations aren’t set up yet — add your Anthropic API key in Profile → Settings.'); }
}

export function isAiConfigured() {
  const ai = CryptoVault.vault?.ai;
  return !!(ai?.apiKey && ai?.proxyUrl);
}

/** Send one message to Claude through the user's proxy and return the reply
 *  text. `system` is optional. Not for chat history — callers that need a
 *  multi-turn conversation should build their own `messages` array and use
 *  this module's lower-level fetch shape as a reference. */
export async function askClaude(userText, { system, maxTokens = 2048 } = {}) {
  const ai = CryptoVault.vault?.ai;
  if (!ai?.apiKey || !ai?.proxyUrl) throw new AiNotConfiguredError();

  const body = {
    model: ai.model || 'claude-opus-5',
    max_tokens: maxTokens,
    messages: [{ role: 'user', content: userText }],
  };
  if (system) body.system = system;

  let res;
  try {
    res = await fetch(ai.proxyUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': ai.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(body),
    });
  } catch {
    throw new Error('Could not reach the AI proxy — check the proxy URL in Settings and that it’s deployed and running.');
  }

  let data;
  try { data = await res.json(); } catch { data = null; }

  if (!res.ok) {
    const msg = data?.error?.message || `AI request failed (HTTP ${res.status})`;
    throw new Error(msg);
  }
  if (data?.stop_reason === 'refusal') {
    throw new Error('Claude declined to respond to this request.');
  }

  const text = (data?.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
  if (!text) throw new Error('AI response was empty.');
  return text;
}
