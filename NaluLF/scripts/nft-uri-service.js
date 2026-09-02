/* =====================================================
   nft-uri-service.js — canonical NFT URI parsing
   ─────────────────────────────────────────────────────
   One job: turn any of the shapes an NFT's on-ledger URI or a metadata
   image/animation_url field shows up in into one canonical shape:

     { protocol: 'ipfs' | 'arweave' | 'https' | null,
       id: string | null,       // CID for ipfs, transaction id for arweave, null for https
       path: string,            // '' or starts with '/'
       originalUri: string,
       error: {code, message} | null }

   Zero fetch, zero DOM, zero imports — pure string parsing so it can be
   unit-tested in isolation and reused by both the metadata fetcher (which
   needs to pick a transport per protocol) and media resolution (which needs
   the same normalization for a metadata's own image/animation_url field).
   ===================================================== */

export const NftUriErrorCode = Object.freeze({
  INVALID_URI: 'INVALID_URI',
  UNSUPPORTED_PROTOCOL: 'UNSUPPORTED_PROTOCOL',
});

// CIDv0 (Qm... base58, 46 chars) or CIDv1 (base32 "b...", base58btc "z...",
// or other multibase prefixes) — permissive on purpose: this only needs to
// distinguish "looks like a CID" from "definitely isn't one," real
// validation happens implicitly by whether a gateway can serve it.
function _looksLikeCid(s) {
  if (!s || typeof s !== 'string') return false;
  if (/^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(s)) return true;
  if (/^b[A-Za-z2-7]{20,}$/.test(s)) return true;
  if (/^z[1-9A-HJ-NP-Za-km-z]{20,}$/.test(s)) return true;
  return false;
}

// Arweave transaction ids are a 43-char base64url string (256-bit hash,
// unpadded) — permissive check for the same reason as CIDs above.
function _looksLikeArweaveId(s) {
  return typeof s === 'string' && /^[A-Za-z0-9_-]{43}$/.test(s);
}

function _ok(protocol, id, path, originalUri) {
  return { protocol, id, path, originalUri, error: null };
}
function _err(code, message, originalUri) {
  return { protocol: null, id: null, path: '', originalUri, error: { code, message } };
}

/** Parse any supported NFT URI/media-field shape into the canonical form
 *  described above. Never throws — always returns a shape with either a
 *  non-null protocol or a populated `.error`. */
export function parseNftUri(raw) {
  if (!raw || typeof raw !== 'string') {
    return _err(NftUriErrorCode.INVALID_URI, 'Empty or non-string URI.', raw || '');
  }
  const original = raw;
  let s = raw.trim();
  if (!s) return _err(NftUriErrorCode.INVALID_URI, 'Empty URI.', original);

  // Reject schemes that must never be treated as a fetchable/renderable
  // location for untrusted, minter-supplied content.
  if (/^(javascript|file|ftp|vbscript):/i.test(s)) {
    return _err(NftUriErrorCode.UNSUPPORTED_PROTOCOL, `Rejected unsafe scheme in URI: ${s.split(':')[0]}:`, original);
  }

  // ── IPFS ──
  if (/^ipfs:\/\//i.test(s)) {
    let rest = s.slice('ipfs://'.length);
    if (/^ipfs\//i.test(rest)) rest = rest.slice('ipfs/'.length); // some minters double up the prefix
    const parts = rest.split('/');
    const cid = parts.shift();
    if (!_looksLikeCid(cid)) return _err(NftUriErrorCode.INVALID_URI, `"${cid}" does not look like a valid IPFS CID.`, original);
    return _ok('ipfs', cid, parts.length ? '/' + parts.join('/') : '', original);
  }

  // ── Arweave ──
  if (/^ar:\/\//i.test(s)) {
    let rest = s.slice('ar://'.length);
    const parts = rest.split('/');
    const id = parts.shift();
    if (!_looksLikeArweaveId(id)) return _err(NftUriErrorCode.INVALID_URI, `"${id}" does not look like a valid Arweave transaction id.`, original);
    return _ok('arweave', id, parts.length ? '/' + parts.join('/') : '', original);
  }

  // ── data: URIs — only ever valid as an *already-resolved media value*
  // (e.g. metadata.image_data), never as a top-level NFT URI. Recognized
  // here so callers resolving a media field don't need a separate path.
  if (/^data:/i.test(s)) {
    return _ok('data', null, '', original);
  }

  if (/^https?:\/\//i.test(s)) {
    let u;
    try { u = new URL(s); } catch { return _err(NftUriErrorCode.INVALID_URI, `Could not parse URL: ${s}`, original); }

    // IPFS path-style gateway: https://<any-host>/ipfs/<cid>/<path...>
    const pathMatch = u.pathname.match(/^\/ipfs\/([^/]+)(\/.*)?$/);
    if (pathMatch && _looksLikeCid(pathMatch[1])) {
      return _ok('ipfs', pathMatch[1], pathMatch[2] || '', original);
    }
    // IPFS subdomain-style gateway: https://<cid>.ipfs.<host>/<path...>
    const hostMatch = u.hostname.match(/^([^.]+)\.ipfs\./i);
    if (hostMatch && _looksLikeCid(hostMatch[1])) {
      return _ok('ipfs', hostMatch[1], u.pathname === '/' ? '' : u.pathname, original);
    }
    // Arweave gateway forms: https://arweave.net/<id>[/path], https://www.arweave.net/<id>[/path]
    if (/^(www\.)?arweave\.net$/i.test(u.hostname)) {
      const parts = u.pathname.replace(/^\/+/, '').split('/');
      const id = parts.shift();
      if (_looksLikeArweaveId(id)) return _ok('arweave', id, parts.length ? '/' + parts.join('/') : '', original);
      return _err(NftUriErrorCode.INVALID_URI, `"${id}" does not look like a valid Arweave transaction id.`, original);
    }
    // Ordinary HTTPS metadata/media host — id carries the full URL since
    // there's no separate "gateway" concept for a single-origin resource.
    return _ok('https', s, '', original);
  }

  // Bare "CID" or "CID/path" — some NFT URIs skip the ipfs:// scheme entirely.
  const parts = s.split('/');
  const first = parts[0];
  if (_looksLikeCid(first)) {
    return _ok('ipfs', first, parts.length > 1 ? '/' + parts.slice(1).join('/') : '', original);
  }
  if (_looksLikeArweaveId(first) && parts.length === 1) {
    return _ok('arweave', first, '', original);
  }

  return _err(NftUriErrorCode.UNSUPPORTED_PROTOCOL, `Unrecognized URI scheme/shape: ${s.slice(0, 64)}`, original);
}

/** A stable cache/dedup key for a parsed URI — content-addressed protocols
 *  key off their id+path (so equivalent gateway URLs for the same CID
 *  collapse to one entry); ordinary https keys off the literal URL. */
export function nftUriCacheKey(parsed) {
  if (!parsed || parsed.error) return null;
  if (parsed.protocol === 'ipfs') return `ipfs:${parsed.id}${parsed.path}`;
  if (parsed.protocol === 'arweave') return `arweave:${parsed.id}${parsed.path}`;
  if (parsed.protocol === 'https') return `https:${parsed.id}`;
  return `${parsed.protocol}:${parsed.originalUri}`;
}
