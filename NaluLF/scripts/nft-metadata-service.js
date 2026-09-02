/* =====================================================
   nft-metadata-service.js — transport layer for NFT metadata
   ─────────────────────────────────────────────────────
   Everything that actually touches the network for NFT metadata lives here:
   IPFS gateway cycling, Arweave retrieval, ordinary HTTPS metadata hosts,
   caching, in-flight dedup, bounded concurrency, response-size limits,
   content-type-aware JSON parsing, and gateway health tracking.

   This app has no backend (static GitHub Pages deploy) — there is no
   same-origin server to retrieve metadata for hosts that don't send CORS
   headers, and this module deliberately does NOT route around that with a
   generic public CORS proxy (corsproxy.io, allorigins.win, or similar):
   those are unreliable in practice (observed returning 403/500 during live
   testing) and, as an open relay for arbitrary third-party URLs, a broader
   trust concern than this app wants to carry for wallet-adjacent code. A
   host that refuses direct cross-origin reads is a real, disclosed
   limitation of static hosting — surfaced to the UI as CORS_BLOCKED with a
   normal placeholder + retry + "view externally" option, never silently
   swallowed and never routed through an anonymous relay.

   Design:
   - fetchNftMetadata(uri) is the one entry point. It parses the URI (via
     nft-uri-service), dispatches to the right transport per protocol, and
     returns a structured {ok, data, source, error} — never throws.
   - IPFS: gateways are tried SEQUENTIALLY (never all at once — that's both
     wasteful and how a shared gateway's own rate limit gets tripped for
     everyone using it), each bounded by its own timeout, with simple
     in-memory health tracking so a gateway that's been failing repeatedly
     gets deprioritized rather than retried first on every single NFT.
   - Arweave: one canonical host, content-addressed by transaction id — no
     cycling needed, same immutable-cache treatment as IPFS.
   - Ordinary HTTPS: a single direct attempt. If the host doesn't send CORS
     headers, the browser can't read the response body at all (this is a
     real browser security boundary, not a bug) — classified CORS_BLOCKED
     rather than misreported as "doesn't exist."
   - A module-level semaphore caps total concurrent network requests this
     service makes, regardless of how many callers or NFTs ask at once.
   - Successful IPFS/Arweave resolutions (content-addressed, immutable by
     definition) are cached indefinitely. Ordinary HTTPS responses get a
     short, configurable TTL instead, since nothing guarantees they're
     immutable. Failures are never cached, so "Retry" genuinely retries.
   - In-flight requests for the same canonical URI are deduplicated — ten
     NFTs sharing one metadata URI only cause one real fetch.
   - Responses are read with a byte cap (not trusted to Content-Length
     alone, which an adversarial or misconfigured server could omit or
     lie about) and a lenient-but-bounded JSON parse: a correct
     application/json content-type is trusted directly, anything else
     still gets a real JSON.parse() attempt on the text (some hosts serve
     valid JSON with an imperfect content-type) rather than an outright
     rejection — but a response that isn't valid JSON either way is
     reported as INVALID_JSON/INVALID_METADATA, never fabricated.
   ===================================================== */

import { parseNftUri, nftUriCacheKey, NftUriErrorCode } from './nft-uri-service.js';

export const NftErrorCode = Object.freeze({
  INVALID_URI: 'INVALID_URI',
  UNSUPPORTED_PROTOCOL: 'UNSUPPORTED_PROTOCOL',
  CORS_BLOCKED: 'CORS_BLOCKED',
  NETWORK_ERROR: 'NETWORK_ERROR',
  TIMEOUT: 'TIMEOUT',
  HTTP_403: 'HTTP_403',
  HTTP_404: 'HTTP_404',
  HTTP_429: 'HTTP_429',
  HTTP_500: 'HTTP_500',
  HTTP_ERROR: 'HTTP_ERROR',
  INVALID_JSON: 'INVALID_JSON',
  INVALID_METADATA: 'INVALID_METADATA',
  RESPONSE_TOO_LARGE: 'RESPONSE_TOO_LARGE',
  METADATA_UNAVAILABLE: 'METADATA_UNAVAILABLE',
  MEDIA_UNAVAILABLE: 'MEDIA_UNAVAILABLE',
  UNSAFE_PROTOCOL: 'UNSAFE_PROTOCOL',
});

// Errors worth a caller re-attempting later (a different gateway may still
// be tried regardless — this just tells the UI whether "Retry" is likely to
// help versus purely cosmetic for this exact source).
const _RETRYABLE = new Set([
  NftErrorCode.CORS_BLOCKED, NftErrorCode.NETWORK_ERROR, NftErrorCode.TIMEOUT,
  NftErrorCode.HTTP_429, NftErrorCode.HTTP_500, NftErrorCode.HTTP_ERROR,
  NftErrorCode.METADATA_UNAVAILABLE,
]);
function _mkError(code, message, { status = null, source = null } = {}) {
  return { code, message, status, source, retryable: _RETRYABLE.has(code) };
}

function _devLog(...args) {
  if (typeof window !== 'undefined' && window.__NALU_DEV__) console.log('[NFT]', ...args);
}

/* ─────────────────────────────
   IPFS gateway strategy (configurable, swappable) + health tracking
──────────────────────────────── */

const DEFAULT_IPFS_GATEWAYS = [
  { name: 'ipfs.io', build: (id, path) => `https://ipfs.io/ipfs/${id}${path}` },
  { name: 'dweb.link', build: (id, path) => `https://dweb.link/ipfs/${id}${path}` },
  { name: 'pinata', build: (id, path) => `https://gateway.pinata.cloud/ipfs/${id}${path}` },
  { name: 'nftstorage', build: (id, path) => `https://nftstorage.link/ipfs/${id}${path}` },
];
let _ipfsGateways = DEFAULT_IPFS_GATEWAYS.slice();

export function configureIpfsGateways(list) {
  _ipfsGateways = (Array.isArray(list) && list.length) ? list.slice() : DEFAULT_IPFS_GATEWAYS.slice();
}
export function getIpfsGateways() {
  return _ipfsGateways.slice();
}

let _arweaveGateway = { name: 'arweave.net', build: (id, path) => `https://arweave.net/${id}${path}` };
export function configureArweaveGateway(gw) {
  _arweaveGateway = gw && typeof gw.build === 'function' ? gw : { name: 'arweave.net', build: (id, path) => `https://arweave.net/${id}${path}` };
}

// Simple in-memory circuit breaker: a gateway that's failed repeatedly and
// recently gets moved to the back of the queue for a cooldown window rather
// than retried first on every subsequent NFT — cheap, no persistence needed
// (a page reload resets it, which is fine; this is about avoiding wasted
// round-trips within one session, not permanent reputation).
const _gatewayHealth = new Map(); // name -> {failCount, cooldownUntil}
const HEALTH_COOLDOWN_MS = 60_000;
const HEALTH_FAIL_THRESHOLD = 3;

function _recordGatewayResult(name, ok) {
  const h = _gatewayHealth.get(name) || { failCount: 0, cooldownUntil: 0 };
  if (ok) { h.failCount = 0; h.cooldownUntil = 0; }
  else {
    h.failCount++;
    if (h.failCount >= HEALTH_FAIL_THRESHOLD) h.cooldownUntil = Date.now() + HEALTH_COOLDOWN_MS;
  }
  _gatewayHealth.set(name, h);
}
function _orderByHealth(gateways) {
  const now = Date.now();
  const healthy = [], cooling = [];
  for (const g of gateways) {
    const h = _gatewayHealth.get(g.name);
    (h && h.cooldownUntil > now ? cooling : healthy).push(g);
  }
  // If every gateway is currently cooling down, try them anyway (better
  // than refusing outright) — otherwise skip the cooling ones this round.
  return healthy.length ? healthy : cooling;
}

/* ─────────────────────────────
   Concurrency (module-wide, not per-caller)
──────────────────────────────── */

class _Semaphore {
  constructor(max) { this.max = max; this.active = 0; this.queue = []; }
  setMax(n) { this.max = Math.max(1, n | 0); }
  run(fn) {
    return new Promise((resolve, reject) => {
      const attempt = () => {
        this.active++;
        Promise.resolve().then(fn).then(
          (v) => { this._release(); resolve(v); },
          (e) => { this._release(); reject(e); },
        );
      };
      if (this.active < this.max) attempt();
      else this.queue.push(attempt);
    });
  }
  _release() {
    this.active--;
    const next = this.queue.shift();
    if (next) next();
  }
}
// 4 concurrent requests total across every caller — chosen from a live
// incident where an unbounded Promise.all() burst tripped a shared
// gateway/proxy's own rate limit within seconds. Configurable per §12.
const _semaphore = new _Semaphore(4);
export function configureConcurrency(max) { _semaphore.setMax(max); }

/* ─────────────────────────────
   Cache + in-flight dedup
──────────────────────────────── */

const _metadataCache = new Map(); // key -> {ok:true, data, source, expiresAt}
const _inFlight = new Map();      // key -> Promise

const HTTPS_CACHE_TTL_MS = 5 * 60_000; // ordinary hosts: short, configurable — not assumed immutable
let _httpsCacheTtlMs = HTTPS_CACHE_TTL_MS;
export function configureHttpsCacheTtl(ms) { _httpsCacheTtlMs = Math.max(0, ms | 0); }

function _cacheGet(key) {
  const entry = _metadataCache.get(key);
  if (!entry) return null;
  if (entry.expiresAt != null && Date.now() > entry.expiresAt) { _metadataCache.delete(key); return null; }
  return entry;
}
function _cacheSet(key, result, protocol) {
  // IPFS/Arweave are content-addressed — a hit is valid forever. Ordinary
  // HTTPS gets a short TTL since nothing guarantees the content is static.
  const expiresAt = protocol === 'https' ? Date.now() + _httpsCacheTtlMs : null;
  _metadataCache.set(key, { ...result, expiresAt });
}

/* ─────────────────────────────
   Bounded, content-type-aware body reading
──────────────────────────────── */

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2MB — NFT metadata JSON is normally a few KB
let _maxResponseBytes = MAX_RESPONSE_BYTES;
export function configureMaxResponseBytes(n) { _maxResponseBytes = Math.max(1024, n | 0); }

/** Reads a response body up to a byte cap without trusting Content-Length
 *  alone (a server can omit or misreport it) — aborts the read itself once
 *  the cap is exceeded, rather than buffering an unbounded body first. */
async function _readBoundedText(res, source) {
  const declaredLen = Number(res.headers.get('content-length') || 0);
  if (declaredLen > _maxResponseBytes) {
    return { ok: false, error: _mkError(NftErrorCode.RESPONSE_TOO_LARGE, `Declared response size (${declaredLen} bytes) exceeds the ${_maxResponseBytes}-byte limit.`, { source }) };
  }
  if (!res.body || typeof res.body.getReader !== 'function') {
    // Environments without a streamable body (rare) — fall back to a plain
    // read; the declared-length check above still applies as a first line
    // of defense.
    const text = await res.text();
    if (text.length > _maxResponseBytes) {
      return { ok: false, error: _mkError(NftErrorCode.RESPONSE_TOO_LARGE, `Response exceeded the ${_maxResponseBytes}-byte limit.`, { source }) };
    }
    return { ok: true, text };
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let received = 0, text = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > _maxResponseBytes) {
        try { await reader.cancel(); } catch { /* best effort */ }
        return { ok: false, error: _mkError(NftErrorCode.RESPONSE_TOO_LARGE, `Response exceeded the ${_maxResponseBytes}-byte limit.`, { source }) };
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return { ok: true, text };
  } catch (err) {
    return { ok: false, error: _mkError(NftErrorCode.NETWORK_ERROR, err?.message || 'Error reading response body.', { source }) };
  }
}

function _parseJsonLeniently(text, source) {
  let json;
  try { json = JSON.parse(text); }
  catch { return { ok: false, error: _mkError(NftErrorCode.INVALID_JSON, `Response from ${source} was not valid JSON.`, { source }) }; }
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    return { ok: false, error: _mkError(NftErrorCode.INVALID_METADATA, `Response from ${source} was not a JSON object.`, { source }) };
  }
  return { ok: true, data: json };
}

/** Best-effort classification of a thrown fetch() error. Browsers
 *  deliberately don't expose *why* a cross-origin fetch failed (a CORS
 *  rejection and a DNS/connection failure both surface as the exact same
 *  opaque TypeError, for security reasons) — this is a heuristic, not a
 *  certainty: if the browser reports itself online, a same-shaped failure
 *  against a host that resolves at all is far more often a missing CORS
 *  header than a real network outage, so that's the more useful label to
 *  show, but it is a best guess, not a verified fact. */
function _classifyFetchError(err, source) {
  if (err?.name === 'AbortError') {
    return _mkError(NftErrorCode.TIMEOUT, `Timed out fetching ${source}`, { source });
  }
  const offline = typeof navigator !== 'undefined' && navigator.onLine === false;
  const code = offline ? NftErrorCode.NETWORK_ERROR : NftErrorCode.CORS_BLOCKED;
  return _mkError(code, err?.message || `Could not fetch ${source}`, { source });
}

/* ─────────────────────────────
   Low-level fetch (one URL, one attempt, bounded time)
──────────────────────────────── */

const DEFAULT_TIMEOUT_MS = 8000;

async function _fetchJsonOnce(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(url, { method: 'GET', mode: 'cors', cache: 'no-store', signal: controller.signal });
  } catch (err) {
    clearTimeout(timer);
    return { ok: false, error: _classifyFetchError(err, url) };
  }
  clearTimeout(timer);

  if (!res.ok) {
    const code = res.status === 403 ? NftErrorCode.HTTP_403
      : res.status === 404 ? NftErrorCode.HTTP_404
      : res.status === 429 ? NftErrorCode.HTTP_429
      : res.status >= 500 ? NftErrorCode.HTTP_500
      : NftErrorCode.HTTP_ERROR;
    return { ok: false, error: _mkError(code, `HTTP ${res.status} from ${url}`, { status: res.status, source: url }) };
  }

  const bodyResult = await _readBoundedText(res, url);
  if (!bodyResult.ok) return bodyResult;

  // A correct application/json content-type is trusted directly; anything
  // else still gets a real parse attempt (some hosts serve valid JSON as
  // text/plain or text/html) rather than an outright rejection — but if it
  // doesn't actually parse as a JSON object, that's reported honestly, not
  // silently accepted or fabricated.
  const parsed = _parseJsonLeniently(bodyResult.text, url);
  if (!parsed.ok) return parsed;
  return { ok: true, data: parsed.data, source: url };
}

/* ─────────────────────────────
   Per-protocol resolution
──────────────────────────────── */

async function _resolveIpfs(parsed, timeoutMs) {
  const gateways = _orderByHealth(getIpfsGateways());
  let lastError = _mkError(NftErrorCode.METADATA_UNAVAILABLE, 'No IPFS gateway returned usable data.');
  for (const gw of gateways) {
    const url = gw.build(parsed.id, parsed.path);
    _devLog('IPFS metadata request', gw.name, url);
    const attempt = await _fetchJsonOnce(url, timeoutMs);
    _recordGatewayResult(gw.name, attempt.ok);
    if (attempt.ok) return attempt;
    _devLog('fallback gateway', gw.name, '->', attempt.error.code);
    lastError = attempt.error;
  }
  return { ok: false, error: lastError };
}

async function _resolveArweave(parsed, timeoutMs) {
  const url = _arweaveGateway.build(parsed.id, parsed.path);
  _devLog('Arweave metadata request', url);
  return _fetchJsonOnce(url, timeoutMs);
}

async function _resolveHttps(parsed, timeoutMs) {
  _devLog('HTTPS metadata request', parsed.id);
  return _fetchJsonOnce(parsed.id, timeoutMs);
}

/**
 * Fetch and parse an NFT's metadata JSON. Handles per-protocol transport,
 * timeouts, caching, and request dedup internally — callers just get back
 * {ok:true, data, source} or {ok:false, error:{code, message, status, source, retryable}}.
 */
export function fetchNftMetadata(uri, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const parsed = parseNftUri(uri);
  if (parsed.error) return Promise.resolve({ ok: false, error: _mkError(parsed.error.code, parsed.error.message) });
  if (parsed.protocol === 'data') {
    return Promise.resolve({ ok: false, error: _mkError(NftErrorCode.UNSUPPORTED_PROTOCOL, 'A data: URI is not a fetchable metadata location.') });
  }

  const key = nftUriCacheKey(parsed);
  const cached = _cacheGet(key);
  if (cached) { _devLog('cache hit', key); return Promise.resolve(cached); }

  const inFlight = _inFlight.get(key);
  if (inFlight) return inFlight;

  const resolver = parsed.protocol === 'ipfs' ? _resolveIpfs
    : parsed.protocol === 'arweave' ? _resolveArweave
    : _resolveHttps;

  const promise = _semaphore.run(() => resolver(parsed, timeoutMs)).then((result) => {
    _inFlight.delete(key);
    if (result.ok) { _cacheSet(key, result, parsed.protocol); _devLog('metadata parsed', key); }
    return result;
  }).catch((err) => {
    _inFlight.delete(key);
    return { ok: false, error: _mkError(NftErrorCode.METADATA_UNAVAILABLE, err?.message || 'Unexpected error resolving metadata.') };
  });
  _inFlight.set(key, promise);
  return promise;
}

/* ─────────────────────────────
   Media/image URL resolution — no fetch, just normalize + validate
──────────────────────────────── */

const SAFE_MEDIA_PROTOCOLS = new Set(['https:', 'http:', 'data:']);

/** Turn a metadata `image`/`image_url`/`animation_url`/`thumbnail` field
 *  into a URL safe to drop straight into an <img>/<video> src. This never
 *  fetches anything — a browser doesn't need CORS to *display* a resource,
 *  only to read its bytes into JS — it just resolves ipfs://.../ar://... to
 *  a real gateway URL and rejects unsafe protocols. An inline `image_data`
 *  SVG string is base64-encoded into a data: URL rather than ever being
 *  set via innerHTML — browsers don't execute <script>/event-handler
 *  content inside an SVG loaded as an <img> src, only inline/<object>. */
export function resolveMediaUrl(rawField) {
  if (!rawField || typeof rawField !== 'string') {
    return { ok: false, error: _mkError(NftErrorCode.MEDIA_UNAVAILABLE, 'No media field in metadata.') };
  }
  const candidate = rawField.trim();
  const parsed = parseNftUri(candidate);

  let resolvedUrl;
  if (parsed.error) {
    // A genuinely unsafe scheme (javascript:, file:, etc.) is a security
    // rejection, not "couldn't find this media" — surfaced under its own
    // code so the UI can label it distinctly (e.g. "Unsafe link") instead
    // of the generic "No image" a not-found/unparseable URI gets.
    const code = parsed.error.code === NftUriErrorCode.UNSUPPORTED_PROTOCOL ? NftErrorCode.UNSAFE_PROTOCOL : NftErrorCode.MEDIA_UNAVAILABLE;
    return { ok: false, error: _mkError(code, parsed.error.message) };
  } else if (parsed.protocol === 'ipfs') {
    const gateways = getIpfsGateways();
    if (!gateways.length) return { ok: false, error: _mkError(NftErrorCode.MEDIA_UNAVAILABLE, 'No IPFS gateway configured.') };
    resolvedUrl = gateways[0].build(parsed.id, parsed.path);
  } else if (parsed.protocol === 'arweave') {
    resolvedUrl = _arweaveGateway.build(parsed.id, parsed.path);
  } else if (parsed.protocol === 'data') {
    resolvedUrl = candidate;
  } else {
    resolvedUrl = parsed.id; // https
  }

  let url;
  try { url = new URL(resolvedUrl); }
  catch { return { ok: false, error: _mkError(NftErrorCode.MEDIA_UNAVAILABLE, `Could not parse media URL: ${resolvedUrl}`) }; }
  if (!SAFE_MEDIA_PROTOCOLS.has(url.protocol)) {
    return { ok: false, error: _mkError(NftErrorCode.UNSAFE_PROTOCOL, `Rejected unsafe protocol for media URL: ${url.protocol}`) };
  }
  if (url.protocol === 'data:' && !/^data:image\//i.test(url.href) && !/^data:video\//i.test(url.href)) {
    return { ok: false, error: _mkError(NftErrorCode.UNSAFE_PROTOCOL, 'Rejected non-media data: URL.') };
  }
  return { ok: true, url: url.href };
}

/** Wraps an inline SVG string (metadata's `image_data` field) as a data:
 *  URL — never innerHTML'd, only ever used as an <img src>, where embedded
 *  scripts/event handlers do not execute per browser SVG-as-image rules. */
export function svgTextToDataUrl(svgText) {
  if (typeof svgText !== 'string' || !svgText.trim()) return null;
  try {
    const b64 = typeof btoa === 'function' ? btoa(unescape(encodeURIComponent(svgText))) : null;
    if (!b64) return null;
    return `data:image/svg+xml;base64,${b64}`;
  } catch { return null; }
}
