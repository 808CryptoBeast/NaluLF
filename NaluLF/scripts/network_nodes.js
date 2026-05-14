/* =====================================================
   scripts/network_nodes.js — Global Node Atlas (client-only)
   - Imports large node lists (TSV)
   - Optional IP->Geo resolution (client-side + cached)
   - Clustered overlay markers on existing Leaflet map
   ===================================================== */

import { $, escHtml, toastWarn } from './utils.js';

const LS_NODES_KEY = 'nalulf_nodes_v1';
const LS_GEO_KEY   = 'nalulf_node_geo_v1';

const GEO_BATCH = 50;          // resolve per click
const GEO_GAP_MS = 350;        // throttle geo lookups (public APIs rate limit)
const CLUSTER_GRID = 1.0;      // degrees. Bigger = fewer markers.

let mounted = false;

let nodes = [];                // [{pubkey, ip, state, version, lastLedger, uptime, peers, inout, history, quorum, load, latency}]
let geoCache = {};             // ip -> {lat,lng,city,country,isp,asn,ts}
let overlayOn = true;

let mapRef = null;
let overlayMarkers = [];
let clusterMarkersByKey = {};  // clusterKey -> marker

function shortKey(k) {
  if (!k) return '—';
  const s = String(k);
  return s.length <= 18 ? s : `${s.slice(0, 10)}…${s.slice(-6)}`;
}

function normalizeIp(ipRaw) {
  if (!ipRaw) return '';
  let ip = String(ipRaw).trim();
  if (ip.startsWith('::ffff:')) ip = ip.replace('::ffff:', '');
  ip = ip.replace(/^\[|\]$/g, '');     // strip brackets if any
  ip = ip.split('%')[0];               // strip IPv6 zone index
  return ip;
}

function isPrivateIp(ip) {
  // basic checks to avoid geo lookups for private / local
  if (!ip) return true;
  if (ip === 'localhost' || ip === '::1') return true;
  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
  if (/^127\./.test(ip)) return true;
  return false;
}

function loadCache() {
  try {
    const n = localStorage.getItem(LS_NODES_KEY);
    nodes = n ? JSON.parse(n) : [];
  } catch { nodes = []; }

  try {
    const g = localStorage.getItem(LS_GEO_KEY);
    geoCache = g ? JSON.parse(g) : {};
  } catch { geoCache = {}; }
}

function saveCache() {
  try { localStorage.setItem(LS_NODES_KEY, JSON.stringify(nodes)); } catch {}
  try { localStorage.setItem(LS_GEO_KEY, JSON.stringify(geoCache)); } catch {}
}

function parseNodeTSV(text) {
  const lines = String(text || '')
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean);

  if (lines.length < 2) return [];

  // find header line that contains "node pubkey" or similar
  let headerIdx = 0;
  for (let i = 0; i < Math.min(lines.length, 8); i++) {
    if (lines[i].toLowerCase().includes('pubkey')) { headerIdx = i; break; }
  }

  const header = lines[headerIdx].split(/\t+/).map(h => h.trim());
  const normH = header.map(h => h.toLowerCase().replace(/[^\w]+/g, ''));

  const col = (nameCandidates) => {
    for (const n of nameCandidates) {
      const idx = normH.indexOf(n);
      if (idx !== -1) return idx;
    }
    return -1;
  };

  const ixPub   = col(['nodepubkey','pubkey','nodekey']);
  const ixIp    = col(['ip']);
  const ixState = col(['state','serverstate']);
  const ixVer   = col(['version','build','rippledversion']);
  const ixLast  = col(['lastledger','lastvalidatedledger','last']);
  const ixUp    = col(['uptime']);
  const ixPeers = col(['peers']);
  const ixIO    = col(['inout','inout', 'inoutpeers']); // may fail; fallback below
  const ixHist  = col(['ledgerhistory','history','ledger']);
  const ixQuo   = col(['quorum']);
  const ixLoad  = col(['load','loadfactor']);
  const ixLat   = col(['latency','ping']);

  const out = [];
  const seen = new Set();

  for (let i = headerIdx + 1; i < lines.length; i++) {
    const row = lines[i].split(/\t+/);
    const pubkey = ixPub >= 0 ? (row[ixPub] || '').trim() : '';
    if (!pubkey || pubkey.toLowerCase().includes('nodesfound')) continue;
    if (seen.has(pubkey)) continue;
    seen.add(pubkey);

    // Some exports have peers + "(in:out)" as separate columns.
    // If header didn't detect inout, try to detect a "(x:y)" token anywhere.
    let inout = '';
    for (const c of row) {
      if (/^\(\d+\s*:\s*\d+\)$/.test(String(c).trim())) { inout = String(c).trim(); break; }
    }

    const ip = normalizeIp(ixIp >= 0 ? row[ixIp] : '');
    const obj = {
      pubkey,
      ip,
      state: (ixState >= 0 ? row[ixState] : '')?.trim() || '',
      version: (ixVer >= 0 ? row[ixVer] : '')?.trim() || '',
      lastLedger: (ixLast >= 0 ? row[ixLast] : '')?.trim() || '',
      uptime: (ixUp >= 0 ? row[ixUp] : '')?.trim() || '',
      peers: (ixPeers >= 0 ? row[ixPeers] : '')?.trim() || '',
      inout,
      history: (ixHist >= 0 ? row[ixHist] : '')?.trim() || '',
      quorum: (ixQuo >= 0 ? row[ixQuo] : '')?.trim() || '',
      load: (ixLoad >= 0 ? row[ixLoad] : '')?.trim() || '',
      latency: (ixLat >= 0 ? row[ixLat] : '')?.trim() || '',
    };

    out.push(obj);
  }

  return out;
}

function mountUI() {
  const tab = document.getElementById('tab-network');
  if (!tab) return;

  if (document.getElementById('nodes-atlas-card')) return;

  const card = document.createElement('section');
  card.className = 'widget-card';
  card.id = 'nodes-atlas-card';
  card.setAttribute('aria-label', 'Global node atlas');

  card.innerHTML = `
    <div class="widget-header">
      <span class="widget-title">🌐 Global Node Atlas</span>
      <span class="widget-tag mono cut" id="nodes-atlas-badge">—</span>
    </div>

    <p class="widget-help">
      Import your node list (TSV). NaluLF will show a searchable table and (optionally) overlay nodes on the world map.
      “Unmapped” means “no coordinates yet” — you can resolve locations client-side and cache them locally.
    </p>

    <div class="nodes-atlas-actions">
      <button class="ob-btn" id="nodesImportBtn">Import paste</button>
      <button class="ob-btn ghost" id="nodesClearBtn">Clear</button>
      <button class="ob-btn ghost" id="nodesGeoBtn">Resolve geo (${GEO_BATCH})</button>
      <button class="ob-btn ghost" id="nodesOverlayBtn">Overlay: ON</button>
    </div>

    <textarea class="ob-input nodes-atlas-textarea" id="nodesPasteBox"
      placeholder="Paste TSV here (header + rows)…"></textarea>

    <div class="nodes-atlas-stats" id="nodesAtlasStats"></div>

    <div class="ob-controls" style="margin-top:10px;">
      <div class="ob-row" style="grid-template-columns:64px 1fr;">
        <label>Search</label>
        <input class="ob-input" id="nodesSearch" placeholder="pubkey, ip, version, state…" />
      </div>
    </div>

    <div class="nodes-table-wrap">
      <table class="ob-table nodes-table">
        <thead>
          <tr>
            <th>Pubkey</th>
            <th>IP</th>
            <th>State</th>
            <th>Ver</th>
            <th>Peers</th>
            <th>Hist</th>
          </tr>
        </thead>
        <tbody id="nodesTableBody">
          <tr><td colspan="6" style="opacity:.7;padding:10px;">No nodes loaded yet.</td></tr>
        </tbody>
      </table>
      <div class="ob-note">Tip: click a row to fly to it (if mapped) and open a popup.</div>
    </div>
  `;

  const anchor = document.getElementById('world-map-container');
  if (anchor) anchor.insertAdjacentElement('afterend', card);
  else tab.appendChild(card);

  $('#nodesImportBtn')?.addEventListener('click', () => {
    const t = $('#nodesPasteBox')?.value || '';
    const parsed = parseNodeTSV(t);
    if (!parsed.length) {
      toastWarn?.('Paste a valid TSV export (with a header row).');
      return;
    }
    nodes = parsed;
    saveCache();
    renderAll();
  });

  $('#nodesClearBtn')?.addEventListener('click', () => {
    nodes = [];
    geoCache = {};
    overlayOff();
    saveCache();
    renderAll();
  });

  $('#nodesGeoBtn')?.addEventListener('click', async () => {
    await resolveGeoBatch(GEO_BATCH);
  });

  $('#nodesOverlayBtn')?.addEventListener('click', () => {
    overlayOn = !overlayOn;
    const b = $('#nodesOverlayBtn');
    if (b) b.textContent = `Overlay: ${overlayOn ? 'ON' : 'OFF'}`;
    if (!overlayOn) overlayOff();
    else renderOverlay();
  });

  $('#nodesSearch')?.addEventListener('input', () => renderTable());

  // row click delegation
  card.addEventListener('click', (e) => {
    const tr = e.target.closest?.('tr[data-pub]');
    if (!tr) return;
    const pub = tr.getAttribute('data-pub');
    const n = nodes.find(x => x.pubkey === pub);
    if (!n) return;
    flyToNode(n);
  });
}

function renderAll() {
  renderStats();
  renderTable();
  if (overlayOn) renderOverlay();
}

function renderStats() {
  const badge = $('#nodes-atlas-badge');
  const stats = $('#nodesAtlasStats');

  const total = nodes.length;

  let mapped = 0;
  let unmapped = 0;
  let noip = 0;

  const byState = {};
  const byVer = {};

  for (const n of nodes) {
    const ip = normalizeIp(n.ip);
    if (!ip) { noip++; continue; }
    const g = geoCache[ip];
    if (g?.lat != null && g?.lng != null) mapped++;
    else unmapped++;

    const st = (n.state || 'unknown').toLowerCase();
    byState[st] = (byState[st] || 0) + 1;

    const v = (n.version || '—');
    byVer[v] = (byVer[v] || 0) + 1;
  }

  if (badge) badge.textContent = total ? `${total} nodes · ${mapped} mapped · ${unmapped} unmapped` : '—';

  if (stats) {
    const topStates = Object.entries(byState).sort((a,b)=>b[1]-a[1]).slice(0,5);
    const topVers = Object.entries(byVer).sort((a,b)=>b[1]-a[1]).slice(0,5);

    stats.innerHTML = `
      <div class="ob-subgrid" style="margin:0;">
        <div class="ob-subbox">
          <div class="ob-subh">Counts</div>
          <div class="ob-list">
            <div class="ob-rowline"><span>Total</span><b class="mono">${total}</b></div>
            <div class="ob-rowline"><span>Mapped</span><b class="mono">${mapped}</b></div>
            <div class="ob-rowline"><span>Unmapped</span><b class="mono">${unmapped}</b></div>
            <div class="ob-rowline"><span>No IP</span><b class="mono">${noip}</b></div>
          </div>
        </div>
        <div class="ob-subbox">
          <div class="ob-subh">Top states / versions</div>
          <div class="ob-list">
            <div style="opacity:.8;font-weight:900;margin-bottom:6px;">States</div>
            ${topStates.length ? topStates.map(([k,v])=>`<div class="ob-rowline"><span>${escHtml(k)}</span><span class="mono">${v}</span></div>`).join('') : `<div style="opacity:.7">—</div>`}
            <div style="opacity:.8;font-weight:900;margin:10px 0 6px;">Versions</div>
            ${topVers.length ? topVers.map(([k,v])=>`<div class="ob-rowline"><span class="cut">${escHtml(k)}</span><span class="mono">${v}</span></div>`).join('') : `<div style="opacity:.7">—</div>`}
          </div>
        </div>
      </div>
    `;
  }
}

function renderTable() {
  const body = $('#nodesTableBody');
  if (!body) return;

  const q = ($('#nodesSearch')?.value || '').trim().toLowerCase();

  const filtered = !q
    ? nodes
    : nodes.filter(n => {
        const s = [
          n.pubkey, n.ip, n.state, n.version, n.lastLedger,
          n.uptime, n.peers, n.inout, n.history
        ].join(' ').toLowerCase();
        return s.includes(q);
      });

  const rows = filtered.slice(0, 80);

  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="6" style="opacity:.7;padding:10px;">No matches.</td></tr>`;
    return;
  }

  body.innerHTML = rows.map(n => `
    <tr data-pub="${escHtml(n.pubkey)}" style="cursor:pointer;">
      <td class="mono cut" title="${escHtml(n.pubkey)}">${escHtml(shortKey(n.pubkey))}</td>
      <td class="mono cut">${escHtml(n.ip || '')}</td>
      <td class="cut">${escHtml(n.state || '')}</td>
      <td class="mono cut">${escHtml(n.version || '')}</td>
      <td class="mono">${escHtml(n.peers || '')} ${escHtml(n.inout || '')}</td>
      <td class="mono cut">${escHtml(n.history || '')}</td>
    </tr>
  `).join('');
}

async function resolveGeoBatch(maxN) {
  // collect up to maxN IPs missing geo
  const ips = [];
  for (const n of nodes) {
    const ip = normalizeIp(n.ip);
    if (!ip || isPrivateIp(ip)) continue;
    if (geoCache[ip]?.lat != null && geoCache[ip]?.lng != null) continue;
    ips.push(ip);
    if (ips.length >= maxN) break;
  }

  if (!ips.length) {
    toastWarn?.('No unmapped public IPs to resolve (or they are private/missing).');
    return;
  }

  // simple throttle loop
  for (let i = 0; i < ips.length; i++) {
    const ip = ips[i];
    await resolveOneIp(ip);
    saveCache();
    renderStats();
    if (overlayOn) renderOverlay();
    await delay(GEO_GAP_MS);
  }

  renderAll();
}

async function resolveOneIp(ip) {
  // Client-only geo lookup: ipwho.is (CORS-friendly, free-tier limits apply)
  // If you want a different provider later, we can swap it.
  try {
    const url = `https://ipwho.is/${encodeURIComponent(ip)}?fields=success,latitude,longitude,city,country,connection`;
    const r = await fetch(url, { method: 'GET' });
    const j = await r.json();

    if (!j?.success || j.latitude == null || j.longitude == null) {
      geoCache[ip] = { lat: null, lng: null, ts: Date.now() };
      return;
    }

    geoCache[ip] = {
      lat: Number(j.latitude),
      lng: Number(j.longitude),
      city: j.city || '',
      country: j.country || '',
      isp: j.connection?.isp || '',
      asn: j.connection?.asn || '',
      ts: Date.now(),
    };
  } catch {
    geoCache[ip] = { lat: null, lng: null, ts: Date.now() };
  }
}

function delay(ms) {
  return new Promise(r => setTimeout(r, ms));
}

/* ─────────────────────────────
   Map overlay (clustered)
──────────────────────────────── */
function overlayOff() {
  overlayMarkers.forEach(m => { try { m.remove(); } catch {} });
  overlayMarkers = [];
  clusterMarkersByKey = {};
}

function colorForState(st) {
  const s = String(st || '').toLowerCase();
  if (s === 'full') return { c:'#00fff0', g:'rgba(0,255,240,.35)' };
  if (s === 'connected') return { c:'#ffb86c', g:'rgba(255,184,108,.35)' };
  if (s === 'syncing') return { c:'#ff5555', g:'rgba(255,85,85,.35)' };
  return { c:'rgba(255,255,255,.7)', g:'rgba(255,255,255,.15)' };
}

function clusterKey(lat, lng) {
  const la = (Math.round(lat / CLUSTER_GRID) * CLUSTER_GRID).toFixed(2);
  const lo = (Math.round(lng / CLUSTER_GRID) * CLUSTER_GRID).toFixed(2);
  return `${la},${lo}`;
}

function renderOverlay() {
  if (!overlayOn) return;
  if (!mapRef || !window.L) return;

  overlayOff();

  // build clusters from mapped nodes
  const clusters = new Map();

  for (const n of nodes) {
    const ip = normalizeIp(n.ip);
    if (!ip) continue;
    const g = geoCache[ip];
    if (!g || g.lat == null || g.lng == null) continue;

    const ck = clusterKey(g.lat, g.lng);
    if (!clusters.has(ck)) {
      clusters.set(ck, {
        lat: g.lat,
        lng: g.lng,
        nodes: [],
      });
    }
    clusters.get(ck).nodes.push(n);
  }

  // create markers
  clusters.forEach((cl, ck) => {
    const count = cl.nodes.length;

    // dominant state for color
    const stateTally = {};
    cl.nodes.forEach(n => {
      const s = (n.state || 'unknown').toLowerCase();
      stateTally[s] = (stateTally[s] || 0) + 1;
    });
    const domState = Object.entries(stateTally).sort((a,b)=>b[1]-a[1])[0]?.[0] || 'unknown';
    const { c, g } = colorForState(domState);

    const r = count > 50 ? 15 : count > 20 ? 12 : count > 8 ? 10 : 8;

    const icon = window.L.divIcon({
      className: '',
      iconSize: [(r+10)*2, (r+10)*2],
      iconAnchor: [r+10, r+10],
      html: `
        <div class="wm-lmarker wm-lmarker-val" style="--mc:${c};--mg:${g};">
          <div class="wm-lring"></div>
          <div class="wm-ldot" style="width:${r*2}px;height:${r*2}px;">
            ${count > 1 ? `<span>${count}</span>` : ''}
          </div>
        </div>
      `
    });

    const top = cl.nodes
      .slice(0, 14)
      .map(n => `
        <div class="wm-popup-row" style="justify-content:space-between;gap:10px;">
          <span class="mono">${escHtml(shortKey(n.pubkey))}</span>
          <span style="opacity:.85;">${escHtml(n.state || '')}</span>
          <span class="mono" style="opacity:.75;">${escHtml(n.version || '')}</span>
        </div>
      `).join('');

    const popup = `
      <div class="wm-popup-inner">
        <div class="wm-popup-badge wm-popup-badge-cluster">${count} node${count!==1?'s':''} in area</div>
        <div class="wm-popup-name">${escHtml(domState)} cluster</div>
        <div class="wm-popup-divider"></div>
        ${top}
        ${count > 14 ? `<div style="opacity:.7;margin-top:8px;">+${count-14} more… (filter/search in table)</div>` : ''}
      </div>
    `;

    const marker = window.L.marker([cl.lat, cl.lng], { icon })
      .bindPopup(popup, { maxWidth: 360, className: 'wm-popup-wrap' })
      .addTo(mapRef);

    overlayMarkers.push(marker);
    clusterMarkersByKey[ck] = marker;
  });
}

function flyToNode(n) {
  if (!mapRef || !window.L) return;

  const ip = normalizeIp(n.ip);
  const g = geoCache[ip];
  if (!g || g.lat == null || g.lng == null) {
    toastWarn?.('This node is not mapped yet. Click “Resolve geo (50)” to map more IPs.');
    return;
  }

  const ck = clusterKey(g.lat, g.lng);
  const marker = clusterMarkersByKey[ck];

  mapRef.flyTo([g.lat, g.lng], 6, { duration: 1.2 });

  // open marker popup after fly
  setTimeout(() => {
    try { marker?.openPopup(); } catch {}
  }, 1300);
}

/* ─────────────────────────────
   Init + map hookup
──────────────────────────────── */
export function initNodeAtlas() {
  if (mounted) return;
  mounted = true;

  loadCache();
  mountUI();
  renderAll();

  // Listen for the map being created/rebuilt by network.js
  window.addEventListener('nalulf-network-map', (e) => {
    mapRef = e?.detail?.map || null;
    if (overlayOn) renderOverlay();
  });
}