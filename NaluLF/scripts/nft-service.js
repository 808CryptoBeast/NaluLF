/* =====================================================
   nft-service.js — NFT presentation-layer orchestration
   ─────────────────────────────────────────────────────
   The one module profile.js talks to for NFT metadata/media. Combines
   nft-uri-service (parsing) and nft-metadata-service (transport/cache) into
   flat, display-ready results, and normalizes the handful of metadata
   schemas real-world NFTs use in practice (not every minter follows the
   exact same field names, and none of these fields are required — a
   missing optional field must never fail the whole NFT).
   ===================================================== */

import { parseNftUri } from './nft-uri-service.js';
import { fetchNftMetadata, resolveMediaUrl, svgTextToDataUrl, NftErrorCode } from './nft-metadata-service.js';

export { NftErrorCode };

function _str(v) { return typeof v === 'string' && v.trim() ? v : null; }

function _normalizeAttributes(attrs) {
  if (!Array.isArray(attrs)) return [];
  const out = [];
  for (const a of attrs) {
    if (!a || typeof a !== 'object') continue;
    const trait = _str(a.trait_type) || _str(a.name) || null;
    const value = (a.value === undefined) ? null : a.value;
    if (trait == null && value == null) continue;
    // Values are rendered via textContent by the caller — plain data here,
    // never markup, but coerce to a safe primitive shape regardless.
    const safeValue = (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') ? value : (value == null ? null : String(value));
    out.push({ trait_type: trait, value: safeValue });
  }
  return out;
}

/**
 * The one call most UI code actually wants: an NFT's on-ledger URI in, a
 * flat display-ready object out:
 *   { ok, name, description, image, animationUrl, externalUrl, attributes, error }
 * `ok` reflects whether metadata itself was retrieved — a metadata hit with
 * no usable image still returns ok:true with image:null and an `error`
 * scoped to just the image side, so a caller can show the NFT's name/
 * description even when its picture can't be resolved, instead of an
 * all-or-nothing card. Never throws, never fabricates a field metadata
 * didn't actually provide.
 */
export async function resolveNftDisplayData(uri) {
  const metaResult = await fetchNftMetadata(uri);
  if (!metaResult.ok) {
    return { ok: false, name: null, description: null, image: null, animationUrl: null, externalUrl: null, attributes: [], error: metaResult.error };
  }
  const meta = metaResult.data;

  // image_data (an inline SVG string, per OpenSea's metadata convention)
  // takes priority only when there's no ordinary image URL — either way it
  // becomes a data: URL, never raw markup.
  const imageField = meta?.image || meta?.image_url || meta?.thumbnail || null;
  let mediaResult;
  if (imageField) {
    mediaResult = resolveMediaUrl(imageField);
  } else if (typeof meta?.image_data === 'string' && meta.image_data.trim()) {
    const dataUrl = svgTextToDataUrl(meta.image_data);
    mediaResult = dataUrl ? resolveMediaUrl(dataUrl) : { ok: false, error: { code: NftErrorCode.MEDIA_UNAVAILABLE, message: 'Could not encode inline image_data.' } };
  } else {
    mediaResult = { ok: false, error: { code: NftErrorCode.MEDIA_UNAVAILABLE, message: 'Metadata has no image field.' } };
  }

  const animField = meta?.animation_url || null;
  const animResult = animField ? resolveMediaUrl(animField) : null;

  const externalUrlRaw = _str(meta?.external_url);
  let externalUrl = null;
  if (externalUrlRaw) {
    const parsed = parseNftUri(externalUrlRaw);
    // external_url is a "view on the web" link, not fetched by this app —
    // only allow it through if it's an ordinary http(s) link, same safety
    // bar as any other user-facing href.
    if (!parsed.error && (parsed.protocol === 'https' || /^https?:/i.test(externalUrlRaw))) externalUrl = externalUrlRaw;
  }

  return {
    ok: true,
    name: _str(meta?.name),
    description: _str(meta?.description),
    image: mediaResult.ok ? mediaResult.url : null,
    animationUrl: (animResult && animResult.ok) ? animResult.url : null,
    externalUrl,
    attributes: _normalizeAttributes(meta?.attributes),
    error: mediaResult.ok ? null : mediaResult.error,
  };
}

/** For a URI that's already a direct media link (no metadata JSON to fetch
 *  at all) — validates and resolves it the same way an `image` field would. */
export function resolveDirectMediaAsDisplayData(uri) {
  const media = resolveMediaUrl(uri);
  return { ok: media.ok, name: null, description: null, image: media.ok ? media.url : null,
    animationUrl: null, externalUrl: null, attributes: [], error: media.ok ? null : media.error };
}
