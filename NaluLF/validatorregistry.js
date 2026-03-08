/* =====================================================
   api/v1/validatorregistry.js  —  NaluLF v3.4
   XRPScan-backed validator registry proxy

   Exposes four routes:

     GET /api/v1/validatorregistry
       Full registry — fetched from XRPScan, normalised,
       classified (unl / dunl / both / other), cached 5 min.

     GET /api/v1/validator/:key
       Individual validator detail (agreement scores, domain
       verification, UNL membership, ledger stats).

     GET /api/v1/validator/:key/reports
       Daily/historical miss reports for a single validator.

     GET /api/v1/node/:key
       Connected-node info (version, uptime, geo, peers).

   ── HOW TO MOUNT ─────────────────────────────────────

     // server.js / app.js
     import express        from 'express';
     import registryRouter from './api/v1/validatorregistry.js';

     const app = express();
     app.use('/api/v1', registryRouter);
     app.listen(3001);

   ─────────────────────────────────────────────────────
===================================================== */

import express from 'express';
import https   from 'https';
import { URL } from 'url';

const router = express.Router();
export default router;

/* ── XRPScan base ──────────────────────────────────── */
const XRPSCAN = 'https://api.xrpscan.com/api/v1';

/* ── Cache TTLs ────────────────────────────────────── */
const REGISTRY_TTL_MS  = 5  * 60 * 1000;
const VALIDATOR_TTL_MS = 10 * 60 * 1000;
const REPORTS_TTL_MS   = 30 * 60 * 1000;
const NODE_TTL_MS      = 10 * 60 * 1000;

let _registryCache   = null;
let _registryCacheAt = 0;
const _validatorCache = new Map();
const _reportsCache   = new Map();
const _nodeCache      = new Map();

/* ═══════════════════════════════════════════════════
   ROUTE 1 — GET /validatorregistry
═══════════════════════════════════════════════════ */
router.get('/validatorregistry', async (req, res) => {
  const force = req.query.refresh === '1';
  const now   = Date.now();

  if (!force && _registryCache && now - _registryCacheAt < REGISTRY_TTL_MS) {
    return res.json({ ..._registryCache, cached: true });
  }

  try {
    const data       = await buildRegistry();
    _registryCache   = data;
    _registryCacheAt = Date.now();
    return res.json({ ...data, cached: false });
  } catch (err) {
    console.error('[validatorregistry]', err.message);
    if (_registryCache) return res.json({ ..._registryCache, cached: true, stale: true });
    return res.status(502).json({ error: 'Failed to fetch validator registry', detail: err.message });
  }
});

/* ═══════════════════════════════════════════════════
   ROUTE 2 — GET /validator/:key
═══════════════════════════════════════════════════ */
router.get('/validator/:key', async (req, res) => {
  const { key } = req.params;
  if (!isValidKey(key)) return res.status(400).json({ error: 'Invalid public key format' });

  const hit = _validatorCache.get(key);
  if (hit && Date.now() - hit.cachedAt < VALIDATOR_TTL_MS) {
    return res.json({ ...hit.data, cached: true });
  }

  try {
    const raw  = await xrpscanGet(`/validator/${encodeURIComponent(key)}`);
    const data = normaliseValidator(raw);
    _validatorCache.set(key, { data, cachedAt: Date.now() });
    return res.json({ ...data, cached: false });
  } catch (err) {
    console.error(`[validator/${key.slice(0,12)}]`, err.message);
    if (hit) return res.json({ ...hit.data, cached: true, stale: true });
    return res.status(502).json({ error: 'Failed to fetch validator', detail: err.message });
  }
});

/* ═══════════════════════════════════════════════════
   ROUTE 3 — GET /validator/:key/reports
═══════════════════════════════════════════════════ */
router.get('/validator/:key/reports', async (req, res) => {
  const { key } = req.params;
  if (!isValidKey(key)) return res.status(400).json({ error: 'Invalid public key format' });

  const hit = _reportsCache.get(key);
  if (hit && Date.now() - hit.cachedAt < REPORTS_TTL_MS) {
    return res.json({ reports: hit.data, cached: true });
  }

  try {
    const raw     = await xrpscanGet(`/validator/${encodeURIComponent(key)}/reports`);
    const reports = Array.isArray(raw) ? raw : (raw.reports ?? raw.data ?? []);
    _reportsCache.set(key, { data: reports, cachedAt: Date.now() });
    return res.json({ reports, cached: false });
  } catch (err) {
    console.error(`[validator/${key.slice(0,12)}/reports]`, err.message);
    if (hit) return res.json({ reports: hit.data, cached: true, stale: true });
    return res.status(502).json({ error: 'Failed to fetch reports', detail: err.message });
  }
});

/* ═══════════════════════════════════════════════════
   ROUTE 4 — GET /node/:key
═══════════════════════════════════════════════════ */
router.get('/node/:key', async (req, res) => {
  const { key } = req.params;
  if (!isValidKey(key)) return res.status(400).json({ error: 'Invalid public key format' });

  const hit = _nodeCache.get(key);
  if (hit && Date.now() - hit.cachedAt < NODE_TTL_MS) {
    return res.json({ ...hit.data, cached: true });
  }

  try {
    const raw  = await xrpscanGet(`/node/${encodeURIComponent(key)}`);
    const data = normaliseNode(raw);
    _nodeCache.set(key, { data, cachedAt: Date.now() });
    return res.json({ ...data, cached: false });
  } catch (err) {
    console.error(`[node/${key.slice(0,12)}]`, err.message);
    if (hit) return res.json({ ...hit.data, cached: true, stale: true });
    return res.status(502).json({ error: 'Failed to fetch node', detail: err.message });
  }
});

/* ═══════════════════════════════════════════════════
   REGISTRY BUILDER
═══════════════════════════════════════════════════ */
async function buildRegistry() {
  const raw   = await xrpscanGet('/validatorregistry');
  const items = Array.isArray(raw) ? raw : (raw.validators ?? raw.data ?? []);
  if (!items.length) throw new Error('XRPScan returned empty validatorregistry');

  const universe = new Map();
  const unlKeys  = new Set();
  const dunlKeys = new Set();

  for (const item of items) {
    const v = normaliseValidator(item);
    if (!v.key) continue;
    universe.set(v.key, v);
    if (v.unl)  unlKeys.add(v.key);
    if (v.dunl) dunlKeys.add(v.key);
  }

  for (const [key, entry] of universe) {
    const inUnl  = unlKeys.has(key);
    const inDunl = dunlKeys.has(key);
    entry.category = inUnl && inDunl ? 'both'
      : inUnl  ? 'unl'
      : inDunl ? 'dunl'
      : 'other';
  }

  const validators = [...universe.values()];
  return {
    validators,
    counts: {
      total: validators.length,
      unl:   unlKeys.size,
      dunl:  dunlKeys.size,
      both:  validators.filter(v => v.category === 'both').length,
      other: validators.filter(v => v.category === 'other').length,
    },
    source:    'xrpscan',
    fetchedAt: new Date().toISOString(),
  };
}

/* ═══════════════════════════════════════════════════
   NORMALISERS
   Map XRPScan field names → canonical internal shape.

   XRPScan /validatorregistry fields:
     validation_public_key, master_key, domain, domain_verified,
     unl (bool), chain, current_index, quorum,
     agreement_1h / agreement_24h / agreement_30d
       → { missed, total, score }
     last_ledger_time, ledger_hash, account_name

   XRPScan /node/:key fields:
     node_public_key, ip, port, version, uptime,
     country, country_code, city, isp, lat, lon
═══════════════════════════════════════════════════ */
function normaliseValidator(v) {
  if (!v) return { key: null };

  const key = v.validation_public_key
    ?? v.master_key
    ?? v.signing_key
    ?? v.public_key
    ?? null;

  function agr(block) {
    if (!block) return null;
    const total  = Number(block.total  ?? block.ledgers ?? 0);
    const missed = Number(block.missed ?? 0);
    const hit    = total - missed;
    const pct    = total > 0 ? ((hit / total) * 100).toFixed(1) : null;
    return {
      total, missed, hit,
      score:    pct    ? `${pct}%`   : null,
      scoreRaw: block.score          ?? null,
    };
  }

  const label = v.account_name
    ?? v.name
    ?? v.label
    ?? (v.domain ? v.domain.replace(/^www\./, '') : null)
    ?? (key ? `${key.slice(0,10)}…${key.slice(-6)}` : null);

  return {
    key,
    label,
    domain:         v.domain          ?? null,
    domainVerified: !!(v.domain_verified),
    unl:            v.unl  === true || v.unl  === 1 || v.unl  === 'true',
    dunl:           v.dUNL === true || v.dUNL === 1 || v.dunl === true,
    chain:          v.chain           ?? 'main',
    category:       'other',
    currentIndex:   v.current_index   ?? v.ledger_index   ?? null,
    quorum:         v.quorum          ?? null,
    lastLedgerTime: v.last_ledger_time ?? null,
    agreement: {
      '1h':  agr(v.agreement_1h  ?? v.agr_1h),
      '24h': agr(v.agreement_24h ?? v.agr_24h),
      '30d': agr(v.agreement_30d ?? v.agr_30d),
    },
    geo: null,
  };
}

function normaliseNode(n) {
  if (!n) return {};
  const lat = n.lat != null ? Number(n.lat) : null;
  const lng = (n.lon ?? n.lng) != null ? Number(n.lon ?? n.lng) : null;
  return {
    key:         n.node_public_key ?? n.public_key ?? null,
    ip:          n.ip              ?? null,
    port:        n.port            ?? null,
    version:     n.version         ?? n.build_version ?? null,
    uptime:      n.uptime          ?? null,
    country:     n.country         ?? null,
    countryCode: n.country_code    ?? null,
    city:        n.city            ?? null,
    isp:         n.isp             ?? null,
    geo: (lat != null && lng != null)
      ? { lat, lng, city: n.city ?? null, country: n.country ?? null }
      : null,
  };
}

/* ═══════════════════════════════════════════════════
   HTTP HELPERS
═══════════════════════════════════════════════════ */
async function xrpscanGet(path, opts = {}) {
  const raw = await httpGet(`${XRPSCAN}${path}`, opts);
  return JSON.parse(raw);
}

function httpGet(urlStr, opts = {}) {
  return new Promise((resolve, reject) => {
    const parsed  = new URL(urlStr);
    const timeout = opts.timeout ?? 10_000;

    const req = https.request({
      hostname: parsed.hostname,
      path:     parsed.pathname + parsed.search,
      method:   'GET',
      headers: {
        'Accept':     'application/json',
        'User-Agent': 'NaluLF-ValidatorRegistry/3.4',
      },
    }, (res) => {
      if (res.statusCode === 429) {
        res.resume();
        return reject(new Error(`Rate-limited (429) — ${parsed.hostname}`));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} — ${urlStr}`));
      }
      const chunks = [];
      res.on('data',  c => chunks.push(c));
      res.on('end',   () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });

    req.setTimeout(timeout, () => {
      req.destroy();
      reject(new Error(`Timeout (${timeout}ms) — ${urlStr}`));
    });
    req.on('error', reject);
    req.end();
  });
}

/* XRPL public key: n-prefix, base58, ~52–53 chars */
function isValidKey(key) {
  return typeof key === 'string' && /^n[1-9A-HJ-NP-Za-km-z]{50,54}$/.test(key.trim());
}