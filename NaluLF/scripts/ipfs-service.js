/* =====================================================
   ipfs-service.js — Centralized NFT metadata / IPFS retrieval
   ─────────────────────────────────────────────────────
   Extracted out of profile.js so IPFS resolution has one home instead of
   being reimplemented ad hoc wherever NFTs show up. Public gateways are
   treated as best-effort, swappable fallbacks — never a single point of
   trust — so this app can later add a self-hosted gateway or browser-
   verified retrieval without touching any caller.

   Design:
   - parseIpfsUri() normalizes every shape an NFT's URI field shows up in
     (ipfs://, ipfs://ipfs/, path-style gateway URLs, subdomain-style
     gateway URLs, bare CIDs) into one canonical {cid, path}.
   - Gateways are tried SEQUENTIALLY per request (never fired all at once —
     that's both wasteful and how a proxy/gateway rate limit gets tripped
     for everyone using it), each with its own AbortController timeout.
   - A single module-level semaphore caps total concurrent network requests
     this service makes, regardless of how many callers ask at once or how
     many NFTs a caller is trying to resolve in one batch.
   - Successful CID/path resolutions are cached indefinitely — content-
     addressed data is immutable by definition, a hit today is valid
     forever. Failures are never cached, so a "Retry" action genuinely
     retries instead of replaying a stale error.
   - In-flight requests for the same CID/path are deduplicated — ten NFTs
     that happen to share metadata only cause one real fetch.
   - Every public function returns a structured {ok, ...} result instead of
     throwing into caller/UI code. Errors carry one of the IpfsErrorCode
     values below so callers can react specifically (e.g. show a distinct
     message for a genuine 404 vs. a timeout) without string-matching.
   - Metadata retrieval (needs a real fetch + JSON parse) is a separate
     concern from media/image URL resolution (just normalization + a
     protocol safety check) — an <img> tag never needs CORS to display,
     only the metadata lookup that finds its URL does.
   ===================================================== */

export const IpfsErrorCode = Object.freeze({
  INVALID_URI: 'INVALID_IPFS_URI',
  TIMEOUT: 'TIMEOUT',
  HTTP_403: 'HTTP_403',
  HTTP_404: 'HTTP_404',
  HTTP_ERROR: 'HTTP_ERROR',
  INVALID_JSON: 'INVALID_JSON',
  METADATA_UNAVAILABLE: 'METADATA_UNAVAILABLE',
  MEDIA_UNAVAILABLE: 'MEDIA_UNAVAILABLE',
  UNSAFE_PROTOCOL: 'UNSAFE_PROTOCOL',
});

/* ─────────────────────────────
   URI normalization
──────────────────────────────── */

// CIDv0 (Qm... base58, 46 chars total) or CIDv1 (base32 "b...", base58btc
// "z...", or other multibase prefixes) — permissive on purpose: this only
// needs to distinguish "looks like a CID" from "definitely isn't one",
// real validation happens implicitly by whether a gateway can serve it.
function _looksLikeCid(s) {
  if (!s || typeof s !== 'string') return false;
  if (/^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(s)) return true;
  if (/^b[A-Za-z2-7]{20,}$/.test(s)) return true;
  if (/^z[1-9A-HJ-NP-Za-km-z]{20,}$/.test(s)) return true;
  return false;
}

/** Normalize any of the shapes an NFT URI field shows up in into a
 *  canonical {cid, path} (path is '' or starts with '/'), or null if the
 *  string isn't an IPFS reference at all (e.g. a plain https:// URL on a
 *  CDN, or an ar:// Arweave reference — callers fetch those directly,
 *  gateway-cycling doesn't apply to a single-endpoint resource). */
export function parseIpfsUri(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let s = raw.trim();
  if (!s) return null;

  if (s.startsWith('ipfs://')) {
    s = s.slice('ipfs://'.length);
    if (s.startsWith('ipfs/')) s = s.slice('ipfs/'.length); // some minters double up the prefix
    const parts = s.split('/');
    const cid = parts.shift();
    if (!_looksLikeCid(cid)) return null;
    return { cid, path: parts.length ? '/' + parts.join('/') : '' };
  }

  if (/^https?:\/\//i.test(s)) {
    let u;
    try { u = new URL(s); } catch { return null; }
    // Path-style: https://<any-gateway-host>/ipfs/<cid>/<path...>
    const pathMatch = u.pathname.match(/^\/ipfs\/([^/]+)(\/.*)?$/);
    if (pathMatch && _looksLikeCid(pathMatch[1])) {
      return { cid: pathMatch[1], path: pathMatch[2] || '' };
    }
    // Subdomain-style: https://<cid>.ipfs.<host>/<path...> (w3s.link, dweb.link, etc.)
    const hostMatch = u.hostname.match(/^([^.]+)\.ipfs\./i);
    if (hostMatch && _looksLikeCid(hostMatch[1])) {
      return { cid: hostMatch[1], path: u.pathname === '/' ? '' : u.pathname };
    }
    return null; // a real URL, just not an IPFS one — not this function's concern
  }

  // Bare "CID" or "CID/path" — some NFT URIs skip the ipfs:// scheme entirely
  const parts = s.split('/');
  const cid = parts[0];
  if (_looksLikeCid(cid)) {
    return { cid, path: parts.length > 1 ? '/' + parts.slice(1).join('/') : '' };
  }
  return null;
}

/* ─────────────────────────────
   Gateway strategy (configurable, swappable)
──────────────────────────────── */

const DEFAULT_GATEWAYS = [
  { name: 'ipfs.io', build: (cid, path) => `https://ipfs.io/ipfs/${cid}${path}` },
  { name: 'dweb.link', build: (cid, path) => `https://dweb.link/ipfs/${cid}${path}` },
  { name: 'pinata', build: (cid, path) => `https://gateway.pinata.cloud/ipfs/${cid}${path}` },
  { name: 'nftstorage', build: (cid, path) => `https://nftstorage.link/ipfs/${cid}${path}` },
];
let _gateways = DEFAULT_GATEWAYS.slice();

/** Replace the gateway list — e.g. to prioritize a self-hosted gateway, or
 *  restrict to a single trusted one. Pass nothing to reset to the default. */
export function configureGateways(list) {
  _gateways = (Array.isArray(list) && list.length) ? list.slice() : DEFAULT_GATEWAYS.slice();
}
export function getGateways() {
  return _gateways.slice();
}

/* ─────────────────────────────
   Concurrency (module-wide, not per-caller)
──────────────────────────────── */

class _Semaphore {
  constructor(max) { this.max = max; this.active = 0; this.queue = []; }
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
// incident where an unbounded Promise.all() burst tripped a public proxy's
// own rate limit within seconds.
const _semaphore = new _Semaphore(4);

/* ─────────────────────────────
   Cache + in-flight dedup
──────────────────────────────── */

const _metadataCache = new Map(); // key -> {ok:true, data, source}
const _inFlight = new Map();      // key -> Promise

function _cacheKeyFor(uri, parsed) {
  return parsed ? `ipfs:${parsed.cid}${parsed.path}` : `direct:${uri}`;
}

/* ─────────────────────────────
   Low-level fetch (one URL, one attempt, bounded time)
──────────────────────────────── */

const DEFAULT_TIMEOUT_MS = 8000;

async function _fetchJsonOnce(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let res;
    try {
      res = await fetch(url, { method: 'GET', mode: 'cors', cache: 'no-store', signal: controller.signal });
    } catch (err) {
      if (err?.name === 'AbortError') {
        return { ok: false, error: { code: IpfsErrorCode.TIMEOUT, message: `Timed out fetching ${url}` } };
      }
      return { ok: false, error: { code: IpfsErrorCode.METADATA_UNAVAILABLE, message: err?.message || `Network error fetching ${url}` } };
    }
    if (!res.ok) {
      const code = res.status === 403 ? IpfsErrorCode.HTTP_403
        : res.status === 404 ? IpfsErrorCode.HTTP_404
        : IpfsErrorCode.HTTP_ERROR;
      return { ok: false, error: { code, message: `HTTP ${res.status} from ${url}` } };
    }
    let json;
    try { json = await res.json(); }
    catch { return { ok: false, error: { code: IpfsErrorCode.INVALID_JSON, message: `Response from ${url} was not valid JSON` } }; }
    if (!json || typeof json !== 'object' || Array.isArray(json)) {
      return { ok: false, error: { code: IpfsErrorCode.INVALID_JSON, message: `Response from ${url} was not a JSON object` } };
    }
    return { ok: true, data: json, source: url };
  } finally {
    clearTimeout(timer);
  }
}

async function _resolveMetadata(uri, parsed, timeoutMs) {
  const candidates = parsed ? getGateways().map(g => g.build(parsed.cid, parsed.path)) : [uri];
  let lastError = { code: IpfsErrorCode.METADATA_UNAVAILABLE, message: 'No gateway returned usable data.' };
  for (const url of candidates) {
    const attempt = await _fetchJsonOnce(url, timeoutMs);
    if (attempt.ok) return attempt;
    lastError = attempt.error;
  }
  return { ok: false, error: lastError };
}

/**
 * Fetch and parse an NFT's metadata JSON. Handles IPFS gateway cycling,
 * timeouts, caching, and request dedup internally — callers just get back
 * {ok:true, data, source} or {ok:false, error:{code, message}}.
 */
export function fetchNftMetadata(uri, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (!uri || typeof uri !== 'string') {
    return Promise.resolve({ ok: false, error: { code: IpfsErrorCode.INVALID_URI, message: 'Empty or non-string URI.' } });
  }
  const parsed = parseIpfsUri(uri);
  const key = _cacheKeyFor(uri, parsed);

  const cached = _metadataCache.get(key);
  if (cached) return Promise.resolve(cached);

  const inFlight = _inFlight.get(key);
  if (inFlight) return inFlight;

  const promise = _semaphore.run(() => _resolveMetadata(uri, parsed, timeoutMs)).then((result) => {
    _inFlight.delete(key);
    if (result.ok) _metadataCache.set(key, result); // only successes are cached — see module doc
    return result;
  }).catch((err) => {
    _inFlight.delete(key);
    return { ok: false, error: { code: IpfsErrorCode.METADATA_UNAVAILABLE, message: err?.message || 'Unexpected error resolving metadata.' } };
  });
  _inFlight.set(key, promise);
  return promise;
}

/* ─────────────────────────────
   Media/image URL resolution — no fetch, just normalize + validate
──────────────────────────────── */

const SAFE_MEDIA_PROTOCOLS = new Set(['https:', 'http:', 'data:']);

/** Turn a metadata `image`/`image_url`/`thumbnail` field into a URL safe to
 *  drop straight into an <img src>. This never fetches anything — a browser
 *  doesn't need CORS to display an image, only to read its bytes into JS —
 *  it just resolves ipfs://... to a real gateway URL and rejects unsafe
 *  protocols (anything that isn't http(s) or a genuine image data: URI). */
export function resolveMediaUrl(rawField) {
  if (!rawField || typeof rawField !== 'string') {
    return { ok: false, error: { code: IpfsErrorCode.MEDIA_UNAVAILABLE, message: 'No image field in metadata.' } };
  }
  let candidate = rawField.trim();
  const parsed = parseIpfsUri(candidate);
  if (parsed) {
    const gateways = getGateways();
    if (!gateways.length) {
      return { ok: false, error: { code: IpfsErrorCode.MEDIA_UNAVAILABLE, message: 'No IPFS gateway configured.' } };
    }
    candidate = gateways[0].build(parsed.cid, parsed.path);
  }
  let url;
  try { url = new URL(candidate); }
  catch { return { ok: false, error: { code: IpfsErrorCode.MEDIA_UNAVAILABLE, message: `Could not parse image URL: ${candidate}` } }; }
  if (!SAFE_MEDIA_PROTOCOLS.has(url.protocol)) {
    return { ok: false, error: { code: IpfsErrorCode.UNSAFE_PROTOCOL, message: `Rejected unsafe protocol for media URL: ${url.protocol}` } };
  }
  if (url.protocol === 'data:' && !/^data:image\//i.test(url.href)) {
    return { ok: false, error: { code: IpfsErrorCode.UNSAFE_PROTOCOL, message: 'Rejected non-image data: URL.' } };
  }
  return { ok: true, url: url.href };
}

/**
 * The one call most UI code actually wants: metadata URI in, a flat
 * {ok, name, description, image, error} out. `ok` reflects whether
 * metadata itself was retrieved — a metadata hit with no usable image
 * still returns ok:true with image:null and an `error` describing just
 * the image side, so a caller can show the NFT's name/description even
 * when its picture can't be resolved, instead of an all-or-nothing card.
 */
export async function resolveNftDisplayData(uri) {
  const metaResult = await fetchNftMetadata(uri);
  if (!metaResult.ok) {
    return { ok: false, name: null, description: null, image: null, error: metaResult.error };
  }
  const meta = metaResult.data;
  const imageField = meta?.image || meta?.image_url || meta?.thumbnail;
  const mediaResult = imageField ? resolveMediaUrl(imageField)
    : { ok: false, error: { code: IpfsErrorCode.MEDIA_UNAVAILABLE, message: 'Metadata has no image field.' } };
  return {
    ok: true,
    name: typeof meta?.name === 'string' ? meta.name : null,
    description: typeof meta?.description === 'string' ? meta.description : null,
    image: mediaResult.ok ? mediaResult.url : null,
    error: mediaResult.ok ? null : mediaResult.error,
  };
}
