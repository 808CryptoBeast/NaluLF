/* =============================================================
   NaluXRP — app.js
   =============================================================*/

/* ─────────────────────────────────────────────────────────────
   PUBLIC API — true function declarations so they are hoisted
   to window scope before any inline onclick can fire.
   These are the ONLY names that need to be globally visible.
───────────────────────────────────────────────────────────────*/
function openAuth(m)             { _openAuth(m);       }
function closeAuth()             { _closeAuth();       }
function setAuthMode(m)          { _setAuthMode(m);    }
function submitAuth()            { _submitAuth();      }
function logout()                { _logout();          }
function switchTab(b, id)        { _switchTab(b, id);  }
function runInspect()            { _runInspect();      }
function goHome()                { _showLandingPage(); }
function showLandingPage()       { _showLandingPage(); }
function closeCommandPalette()   { _closeCmdk();       }
function switchPage(id)          { _switchPage(id);    }
function setTheme(t)             { _setTheme(t);       }
function cycleTheme()            { _cycleTheme();      }

/* ─────────────────────────────────────────────────────────────
   GLOBAL UI STATE  (mirrors ui.js window.UI shape)
───────────────────────────────────────────────────────────────*/
window.UI = {
  currentPage: 'dashboard',
  currentTheme: 'gold',
  themes: ['gold','cosmic','starry','hawaiian'],
  observers: { reveal: null },
  landing: { active: false }
};

/* ─────────────────────────────────────────────────────────────
   UIX  (mirrors ui.js window.UIX shape)
───────────────────────────────────────────────────────────────*/
window.UIX = {
  runSearch:          (q)    => _globalSearch(q),
  openCommandPalette: (pre)  => _openCmdk(pre),
  saveAddress:        (a)    => _saveAddress(a),
  removeSaved:        (a)    => _removeSaved(a),
  getSaved:           ()     => _getSaved(),
  pinAddress:         (a)    => _pinAddress(a),
  unpinAddress:       ()     => _unpinAddress(),
  getPinned:          ()     => _getPinned()
};

/* ─────────────────────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────────────────────────*/
const XRPL_ENDPOINTS = [
  { name: 'XRPL Mainnet', url: 'wss://xrplcluster.com', network: 'xrpl-mainnet' },
  { name: 'Ripple s1',    url: 'wss://s1.ripple.com',   network: 'xrpl-mainnet' },
  { name: 'xrpl.ws',      url: 'wss://xrpl.ws',         network: 'xrpl-mainnet' },
  { name: 'Testnet',      url: 'wss://s.altnet.rippletest.net:51233', network: 'xrpl-testnet' },
  { name: 'Xahau',        url: 'wss://xahau.network',   network: 'xahau-mainnet' }
];
const ENDPOINTS_BY_NETWORK = {
  'xrpl-mainnet':  XRPL_ENDPOINTS.filter(e => e.network === 'xrpl-mainnet'),
  'xrpl-testnet':  XRPL_ENDPOINTS.filter(e => e.network === 'xrpl-testnet'),
  'xahau-mainnet': XRPL_ENDPOINTS.filter(e => e.network === 'xahau-mainnet')
};
const MAX_TX_BUFFER   = 300;
const CHART_WINDOW    = 32;
const LEDGER_LOG_MAX  = 150;

const LS_SAVED  = 'naluxrp_saved_addresses';
const LS_PINNED = 'naluxrp_pinned_address';
const LS_THEME  = 'naluxrp_theme';

/* ─────────────────────────────────────────────────────────────
   STATE
───────────────────────────────────────────────────────────────*/
let session = null;      // { name, email }
let wsConn  = null;      // active WebSocket
let wsRetry = 0;
let currentNetwork = 'xrpl-mainnet';
let endpointIdx    = 0;
let reconnectTimer = null;
let pendingReqs    = {};  // id → { resolve, reject, timer }
let reqId          = 0;

let tpsHistory  = [];
let feeHistory  = [];
let ledgerLog   = [];
let txMixAccum  = {};
let lastCloseTs = null;

// window.connectionState mirrors ui.js check
window.connectionState = 'disconnected';

/* ─────────────────────────────────────────────────────────────
   UTILITIES
───────────────────────────────────────────────────────────────*/
function $(id) { return document.getElementById(id); }

function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function safeGet(key) {
  try { return localStorage.getItem(key); } catch(_) { return null; }
}
function safeSet(key, val) {
  try { localStorage.setItem(key, val); } catch(_) {}
}
function safeJson(s, fb) {
  try { return JSON.parse(s); } catch(_) { return fb; }
}

function isValidXrpAddress(a) {
  return /^r[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(String(a ?? '').trim());
}
function isTxHash(h) {
  return /^[A-Fa-f0-9]{64}$/.test(String(h ?? '').trim());
}
function isLedgerIndex(v) {
  const s = String(v ?? '').trim();
  if (!/^\d{1,10}$/.test(s)) return false;
  const n = Number(s);
  return Number.isFinite(n) && n > 0;
}

function xrpFromDrops(drops) {
  return (Number(drops) / 1_000_000).toFixed(6);
}
function fmt(n, decimals = 2) {
  if (n == null || !Number.isFinite(n)) return '—';
  return n.toLocaleString(undefined, { maximumFractionDigits: decimals });
}

/* ─────────────────────────────────────────────────────────────
   TOAST NOTIFICATIONS  (window.showNotification → dashboard.js)
───────────────────────────────────────────────────────────────*/
window.showNotification = function(msg, type = 'info', duration = 3500) {
  const box = $('notifications');
  if (!box) return;
  const div = document.createElement('div');
  div.className = `notification ${type}`;
  div.textContent = msg;
  box.appendChild(div);
  setTimeout(() => div.remove(), duration);
};

function toast(msg) { window.showNotification(msg, 'info', 2500); }
function toastWarn(msg) { window.showNotification(msg, 'warn', 4000); }
function toastErr(msg) { window.showNotification(msg, 'err', 5000); }

/* ─────────────────────────────────────────────────────────────
   THEME  (setTheme / cycleTheme — exported for ui.js)
───────────────────────────────────────────────────────────────*/
function _setTheme(t) {
  const themes = window.UI.themes;
  if (!themes.includes(t)) t = 'gold';
  window.UI.currentTheme = t;
  themes.forEach(th => document.body.classList.remove(`theme-${th}`));
  document.body.classList.add(`theme-${t}`);
  safeSet(LS_THEME, t);
}
function _cycleTheme() {
  const themes = window.UI.themes;
  const idx = themes.indexOf(window.UI.currentTheme);
  _setTheme(themes[(idx + 1) % themes.length]);
  toast(`Theme: ${window.UI.currentTheme}`);
}

/* ─────────────────────────────────────────────────────────────
   SAVED / PINNED  (mirrors ui.js UIX methods exactly)
───────────────────────────────────────────────────────────────*/
function _getSaved() {
  const raw = safeGet(LS_SAVED);
  const arr = safeJson(raw || '[]', []);
  return Array.isArray(arr) ? arr.filter(isValidXrpAddress) : [];
}
function _setSaved(list) {
  const uniq = [];
  const seen = new Set();
  (list || []).forEach(a => {
    a = String(a || '').trim();
    if (!isValidXrpAddress(a) || seen.has(a)) return;
    seen.add(a);
    uniq.push(a);
  });
  safeSet(LS_SAVED, JSON.stringify(uniq.slice(0, 25)));
  window.dispatchEvent(new CustomEvent('naluxrp:savedchange'));
  return uniq;
}
function _saveAddress(a) {
  a = String(a || '').trim();
  if (!isValidXrpAddress(a)) return false;
  const list = _getSaved();
  if (!list.includes(a)) list.unshift(a);
  _setSaved(list);
  return true;
}
function _removeSaved(a) {
  a = String(a || '').trim();
  _setSaved(_getSaved().filter(x => x !== a));
}
function _getPinned() {
  const p = safeGet(LS_PINNED);
  return p && isValidXrpAddress(p) ? p : null;
}
function _pinAddress(a) {
  a = String(a || '').trim();
  if (!isValidXrpAddress(a)) return false;
  safeSet(LS_PINNED, a);
  window.dispatchEvent(new CustomEvent('naluxrp:savedchange'));
  return true;
}
function _unpinAddress() {
  safeSet(LS_PINNED, '');
  window.dispatchEvent(new CustomEvent('naluxrp:savedchange'));
}

/* ─────────────────────────────────────────────────────────────
   PARTICLE ENGINE  (landing bg)
───────────────────────────────────────────────────────────────*/
function initParticles() {
  const canvas = $('particle-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H, particles;

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  window.addEventListener('resize', resize);
  resize();

  function mkParticle() {
    return {
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - .5) * .35,
      vy: (Math.random() - .5) * .35,
      r: 1 + Math.random() * 2,
      a: .1 + Math.random() * .35
    };
  }
  particles = Array.from({ length: 55 }, mkParticle);

  function draw() {
    ctx.clearRect(0, 0, W, H);
    particles.forEach(p => {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0) p.x = W;
      if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H;
      if (p.y > H) p.y = 0;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0,255,240,${p.a})`;
      ctx.fill();
    });

    // Connection lines
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx*dx + dy*dy);
        if (dist < 110) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(0,255,240,${(.12 * (1 - dist/110)).toFixed(3)})`;
          ctx.lineWidth = .6;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
}

/* ─────────────────────────────────────────────────────────────
   PAGE SWITCHER  (switchPage — ui.js exports this interface)
───────────────────────────────────────────────────────────────*/
function _applyPageClass(pageId) {
  document.body.classList.remove('dashboard', 'inspector', 'landing-page');
  if (pageId === 'inspector') document.body.classList.add('inspector');
  else if (pageId === 'landing')   document.body.classList.add('landing-page');
  else document.body.classList.add('dashboard');
}

function _switchPage(id) {
  window.UI.currentPage = id;
  const landing   = $('landing');
  const dashboard = $('dashboard');
  if (!landing || !dashboard) return;

  if (id === 'landing' || !session) {
    landing.style.display = '';
    dashboard.style.display = 'none';
    _applyPageClass('landing');
    document.getElementById('navbar-landing-actions').style.display = '';
    document.getElementById('navbar-dash-actions').style.display = 'none';
    const conn = $('navbar-conn');
    if (conn) conn.style.display = 'none';
    const hint = $('cmdk-hint');
    if (hint) hint.style.display = 'none';
  } else {
    landing.style.display = 'none';
    dashboard.style.display = '';
    _applyPageClass(id === 'inspector' ? 'inspector' : 'dashboard');
    document.getElementById('navbar-landing-actions').style.display = 'none';
    document.getElementById('navbar-dash-actions').style.display = '';
    const conn = $('navbar-conn');
    if (conn) conn.style.display = '';
    const hint = $('cmdk-hint');
    if (hint) hint.style.display = '';
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
  window.dispatchEvent(new CustomEvent('naluxrp:pagechange', { detail: { pageId: id } }));
}

function _showLandingPage() {
  _switchPage('landing');
}

/* ─────────────────────────────────────────────────────────────
   DASHBOARD TABS  (switchTab called from HTML onclick)
───────────────────────────────────────────────────────────────*/
function _switchTab(btn, tabId) {
  // Update tab buttons
  document.querySelectorAll('.dash-tab').forEach(b => {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  });
  btn.classList.add('active');
  btn.setAttribute('aria-selected', 'true');

  // Show/hide panels
  ['stream','inspector','network'].forEach(id => {
    const el = $(`tab-${id}`);
    if (el) el.style.display = id === tabId ? '' : 'none';
  });

  // Body class for inspector background (style.css)
  if (tabId === 'inspector') {
    document.body.classList.remove('dashboard');
    document.body.classList.add('inspector');
  } else {
    document.body.classList.remove('inspector');
    document.body.classList.add('dashboard');
  }

  window.UI.currentPage = tabId;
  window.dispatchEvent(new CustomEvent('naluxrp:pagechange', { detail: { pageId: tabId } }));
}

/* ─────────────────────────────────────────────────────────────
   GLOBAL SEARCH  (mirrors ui.js runGlobalSearch)
───────────────────────────────────────────────────────────────*/
function _globalSearch(q) {
  q = String(q ?? '').trim();
  if (!q || !session) return;
  if (isValidXrpAddress(q)) {
    _openCmdk(q);
  } else if (isTxHash(q)) {
    toast('TX hash: open in Explorer');
  } else if (isLedgerIndex(q)) {
    toast(`Ledger #${q} queued`);
  }
}

/* ─────────────────────────────────────────────────────────────
   COMMAND PALETTE  (matches ui.js ensurePalette + openCommandPalette)
   IDs: cmdkOverlay, cmdkInput, cmdkList
───────────────────────────────────────────────────────────────*/
const PAGE_META = {
  stream:    { crumb:'Live Stream',    sub:'Ledger Overview' },
  inspector: { crumb:'Inspector',      sub:'Tree • Trace • Quick Inspect' },
  network:   { crumb:'Network Health', sub:'Patterns & Metrics' }
};

let paletteItems = [];
let paletteIndex = 0;

function _buildPaletteItems(q) {
  q = String(q ?? '').trim();
  const pages = Object.keys(PAGE_META).map(id => ({
    type: 'page',
    label: `Go to ${PAGE_META[id].crumb}`,
    hint: PAGE_META[id].sub,
    keywords: `${id} ${PAGE_META[id].crumb} ${PAGE_META[id].sub}`,
    run: () => {
      const btn = document.querySelector(`.dash-tab[data-tab="${id}"]`);
      if (btn) _switchTab(btn, id);
    }
  }));

  const quick = [];
  if (isValidXrpAddress(q)) {
    quick.push({
      type:'action', label:'Open in Inspector (Quick Inspect)', hint:q, keywords:'inspector quick inspect',
      run: () => {
        const btn = document.querySelector('.dash-tab[data-tab="inspector"]');
        if (btn) _switchTab(btn, 'inspector');
        setTimeout(() => {
          const inp = $('inspect-addr');
          if (inp) { inp.value = q; _runInspect(); }
        }, 100);
      }
    });
    quick.push({
      type:'action', label:'Save address', hint:q, keywords:'save bookmark',
      run: () => { _saveAddress(q); toast('Saved'); }
    });
    quick.push({
      type:'action', label:'Pin to Inspector', hint:q, keywords:'pin inspector',
      run: () => { _pinAddress(q); toast('Pinned'); }
    });
  } else if (isTxHash(q)) {
    quick.push({
      type:'action', label:'Open TX Hash', hint:q, keywords:'tx hash explorer',
      run: () => { toastWarn(`TX: ${q.slice(0,16)}…`); }
    });
  } else if (isLedgerIndex(q)) {
    quick.push({
      type:'action', label:'Open Ledger Index', hint:q, keywords:'ledger index explorer',
      run: () => { toastWarn(`Ledger: #${q}`); }
    });
  }

  quick.push(
    { type:'action', label:'Cycle Theme', hint:'🎨', keywords:'theme cycle gold cosmic', run: _cycleTheme },
    { type:'action', label:'Disconnect / Reconnect', hint:'⚡', keywords:'reconnect disconnect ws', run: () => { _reconnect(true); } }
  );

  return quick.concat(pages);
}

function _renderPalette(q) {
  paletteItems = _buildPaletteItems(q);
  const ql = String(q ?? '').trim().toLowerCase();
  if (ql) {
    paletteItems = paletteItems.filter(it => {
      const hay = (it.keywords + it.label + (it.hint || '')).toLowerCase();
      return hay.includes(ql);
    });
  }
  if (!paletteItems.length) {
    paletteItems = [{ type:'info', label:'No matches — try a page name, address, tx hash, or ledger index.', hint:'', run: null }];
  }
  paletteIndex = 0;
  _paintPalette();
}

function _paintPalette() {
  const list = $('cmdkList');
  if (!list) return;
  list.innerHTML = paletteItems.slice(0, 18).map((it, i) => `
    <button class="cmdk-item ${i === paletteIndex ? 'is-active' : ''}" type="button" data-i="${i}">
      <div class="cmdk-label">${escHtml(it.label)}</div>
      <div class="cmdk-hint2">${escHtml(it.hint || '')}</div>
    </button>
  `).join('');
  list.querySelectorAll('.cmdk-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const i = Number(btn.getAttribute('data-i'));
      _runPaletteItem(i);
    });
  });
}

function _runPaletteItem(i) {
  const item = paletteItems[i];
  if (!item || typeof item.run !== 'function') return;
  _closeCmdk();
  item.run();
}

function _openCmdk(prefill = '') {
  const overlay = $('cmdkOverlay');
  const inp     = $('cmdkInput');
  if (!overlay || !inp) return;
  overlay.classList.add('show');
  inp.value = String(prefill || '');
  inp.focus();
  inp.setSelectionRange(inp.value.length, inp.value.length);
  _renderPalette(inp.value);
}

function _closeCmdk() {
  const overlay = $('cmdkOverlay');
  if (overlay) overlay.classList.remove('show');
}

function _setupCmdkListeners() {
  const inp = $('cmdkInput');
  if (!inp) return;
  inp.addEventListener('input', () => _renderPalette(inp.value));
  inp.addEventListener('keydown', e => {
    if (e.key === 'Escape') { _closeCmdk(); return; }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      paletteIndex = Math.min(paletteIndex + 1, Math.min(17, paletteItems.length - 1));
      _paintPalette();
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      paletteIndex = Math.max(paletteIndex - 1, 0);
      _paintPalette();
      return;
    }
    if (e.key === 'Enter') { e.preventDefault(); _runPaletteItem(paletteIndex); }
  });

  // Click outside to close
  $('cmdkOverlay').addEventListener('click', e => {
    if (e.target === $('cmdkOverlay')) _closeCmdk();
  });

  // Global keyboard shortcuts (Ctrl/Cmd+K  or  /)
  document.addEventListener('keydown', e => {
    const active = document.activeElement;
    const tag = (active?.tagName || '').toLowerCase();
    const editing = tag === 'input' || tag === 'textarea' || active?.isContentEditable;

    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      _openCmdk();
    }
    if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey && !editing) {
      e.preventDefault();
      _openCmdk();
    }
  });
}

/* ─────────────────────────────────────────────────────────────
   AUTH MODAL
───────────────────────────────────────────────────────────────*/
let authMode = 'login';

function _openAuth(mode = 'login') {
  const overlay = $('auth-overlay');
  if (!overlay) return;
  _setAuthMode(mode);
  overlay.classList.add('show');
  setTimeout(() => {
    const inp = mode === 'login' ? $('inp-email') : $('inp-handle');
    if (inp) inp.focus();
  }, 80);
}

function _closeAuth() {
  const overlay = $('auth-overlay');
  if (overlay) overlay.classList.remove('show');
}

function _setAuthMode(mode) {
  authMode = mode;
  const loginBtn  = $('tab-login-btn');
  const signupBtn = $('tab-signup-btn');
  const handleFld = $('field-handle');
  const title     = $('auth-modal-title');
  const sub       = $('auth-sub');
  const submitBtn = $('auth-submit');

  if (loginBtn)  loginBtn.classList.toggle('active',  mode === 'login');
  if (signupBtn) signupBtn.classList.toggle('active', mode === 'signup');
  if (handleFld) handleFld.style.display = mode === 'signup' ? '' : 'none';
  if (title)     title.textContent  = mode === 'login' ? 'Welcome back' : 'Create account';
  if (sub)       sub.textContent    = mode === 'login' ? 'Sign in to access your dashboard.' : 'Join NaluXRP — it\'s free and private.';
  if (submitBtn) submitBtn.textContent = mode === 'login' ? 'Sign In →' : 'Create Account →';
  const err = $('auth-error');
  if (err) err.textContent = '';
}

function _submitAuth() {
  const email = ($('inp-email')?.value || '').trim();
  const pass  = ($('inp-pass')?.value  || '').trim();
  const handle = ($('inp-handle')?.value || '').trim();
  const errEl = $('auth-error');
  if (errEl) errEl.textContent = '';

  if (!email || !pass) {
    if (errEl) errEl.textContent = 'Email and password are required.';
    return;
  }
  if (authMode === 'signup' && !handle) {
    if (errEl) errEl.textContent = 'Display name is required.';
    return;
  }

  // Simulated session (no backend)
  session = {
    email,
    name: authMode === 'signup' ? handle : email.split('@')[0]
  };
  window.UI.currentPage = 'dashboard';

  const av   = $('user-avatar');
  const nm   = $('user-name');
  if (av) av.textContent  = session.name[0].toUpperCase();
  if (nm) nm.textContent  = session.name;

  _closeAuth();
  _switchPage('dashboard');
  _connectXRPL();
  window.dispatchEvent(new Event('xrpl:manual-connect'));
}

function _logout() {
  session = null;
  _disconnectXRPL();
  _showLandingPage();
}

/* ─────────────────────────────────────────────────────────────
   XRPL WEBSOCKET ENGINE
   Fires: xrpl-connected / xrpl-disconnected / xrpl-ledger / xrpl-connection
   Checks window.connectionState (ui.js setupConnectionMonitoring polls this)
───────────────────────────────────────────────────────────────*/
function _endpointsForNetwork() {
  return ENDPOINTS_BY_NETWORK[currentNetwork] || ENDPOINTS_BY_NETWORK['xrpl-mainnet'];
}

function _nextEndpoint() {
  const eps = _endpointsForNetwork();
  const ep  = eps[endpointIdx % eps.length];
  endpointIdx++;
  return ep;
}

function _connectXRPL() {
  if (wsConn && wsConn.readyState <= 1) return;
  const ep = _nextEndpoint();
  console.log(`🌊 Connecting to ${ep.name} (${ep.url})`);

  _setConnState('connecting', ep.name);

  wsConn = new WebSocket(ep.url);
  wsConn.onopen = () => {
    console.log(`✅ Connected: ${ep.name}`);
    wsRetry = 0;
    window.connectionState = 'connected';
    _setConnState('connected', ep.name);
    window.dispatchEvent(new Event('xrpl-connected'));
    window.dispatchEvent(new Event('naluxrp:connected'));
    _subscribeStream();
  };
  wsConn.onclose = () => {
    console.log(`🔌 Disconnected from ${ep.name}`);
    window.connectionState = 'disconnected';
    _setConnState('disconnected', '');
    window.dispatchEvent(new Event('xrpl-disconnected'));
    window.dispatchEvent(new Event('naluxrp:disconnected'));
    _scheduleReconnect();
  };
  wsConn.onerror = () => {
    wsConn.close();
  };
  wsConn.onmessage = e => {
    try { _handleMessage(JSON.parse(e.data)); }
    catch(_) {}
  };
}

function _disconnectXRPL() {
  clearTimeout(reconnectTimer);
  if (wsConn) { wsConn.onclose = null; wsConn.close(); wsConn = null; }
  window.connectionState = 'disconnected';
  _setConnState('disconnected', '');
}

function _scheduleReconnect() {
  if (reconnectTimer) return;
  const delay = Math.min(30000, 1500 * Math.pow(1.6, wsRetry++));
  console.log(`⏳ Reconnect in ${(delay/1000).toFixed(1)}s`);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    if (session) _connectXRPL();
  }, delay);
}

function _reconnect(forced = false) {
  _disconnectXRPL();
  wsRetry = forced ? 0 : wsRetry;
  if (session) setTimeout(_connectXRPL, 200);
}

function _setConnState(state, name) {
  // For navbar mini-status
  const dot  = $('connDot');
  const text = $('connText');
  if (dot) {
    dot.classList.toggle('live', state === 'connected');
  }
  if (text) {
    if (state === 'connected')   { text.textContent = `LIVE – ${name}`; text.style.color = '#50fa7b'; }
    else if (state === 'connecting') { text.textContent = 'Connecting…'; text.style.color = '#ffb86c'; }
    else                         { text.textContent = 'Disconnected'; text.style.color = '#ff5555'; }
  }

  // Also fire xrpl-connection event that dashboard.js listens to
  window.dispatchEvent(new CustomEvent('xrpl-connection', {
    detail: {
      connected: state === 'connected',
      server: name,
      modeReason: state === 'connecting' ? 'Network switched' : ''
    }
  }));

  // Inspector button availability
  const inspBtn = $('inspect-btn');
  if (inspBtn) inspBtn.disabled = state !== 'connected';
  const inspWarn = $('inspect-warn');
  if (inspWarn) inspWarn.style.display = state !== 'connected' ? '' : 'none';
}

function _subscribeStream() {
  if (!wsConn || wsConn.readyState !== 1) return;
  wsConn.send(JSON.stringify({ id: 'sub_ledger', command: 'subscribe', streams: ['ledger'] }));
}

/* ─────────────────────────────────────────────────────────────
   WEBSOCKET MESSAGE HANDLER
───────────────────────────────────────────────────────────────*/
function _handleMessage(msg) {
  // Resolve pending request
  if (msg.id && pendingReqs[msg.id]) {
    const { resolve, reject, timer } = pendingReqs[msg.id];
    clearTimeout(timer);
    delete pendingReqs[msg.id];
    if (msg.status === 'error') reject(new Error(msg.error_message || msg.error || 'XRPL error'));
    else resolve(msg);
    return;
  }

  // Ledger stream event
  if (msg.type === 'ledgerClosed') {
    _requestLedger(msg.ledger_index);
    return;
  }

  // Subscription confirmation
  if (msg.type === 'response' && msg.result?.ledger_index) {
    _requestLedger(msg.result.ledger_index);
  }
}

/* ─────────────────────────────────────────────────────────────
   PROMISE-BASED WS REQUEST (12s timeout)
───────────────────────────────────────────────────────────────*/
function _wsSend(payload) {
  return new Promise((resolve, reject) => {
    if (!wsConn || wsConn.readyState !== 1) {
      return reject(new Error('Not connected'));
    }
    const id = `req_${++reqId}`;
    payload.id = id;
    const timer = setTimeout(() => {
      delete pendingReqs[id];
      reject(new Error('Timeout'));
    }, 12000);
    pendingReqs[id] = { resolve, reject, timer };
    wsConn.send(JSON.stringify(payload));
  });
}

/* ─────────────────────────────────────────────────────────────
   LEDGER PROCESSING
───────────────────────────────────────────────────────────────*/
function _requestLedger(ledgerIndex) {
  _wsSend({
    command: 'ledger',
    ledger_index: ledgerIndex,
    transactions: true,
    expand: true
  })
  .then(msg => _processLedger(msg.result))
  .catch(err => console.warn('Ledger request failed:', err.message));
}

function _processLedger(result) {
  const ledger = result?.ledger;
  if (!ledger) return;

  const li     = Number(ledger.ledger_index ?? 0);
  const txs    = Array.isArray(ledger.transactions) ? ledger.transactions : [];
  const now    = new Date();
  const closeT = new Date((Number(ledger.close_time ?? 0) + 946684800) * 1000);

  let closeTimeSec = null;
  if (lastCloseTs) {
    const delta = closeT - lastCloseTs;
    if (delta > 0 && delta < 30000) closeTimeSec = delta / 1000;
  }
  lastCloseTs = closeT;

  const tps = closeTimeSec ? txs.length / closeTimeSec : null;

  // Categorise transactions (all 34 types from dashboard.js normalizeTxTypes)
  const typeCounts = {};
  let totalFees = 0;
  let successCount = 0;

  txs.forEach(tx => {
    const t = tx.TransactionType || 'Other';
    typeCounts[t] = (typeCounts[t] || 0) + 1;
    const fee = Number(tx.Fee || 0);
    totalFees += fee;
    if ((tx.metaData?.TransactionResult || tx.meta?.TransactionResult) === 'tesSUCCESS') {
      successCount++;
    }
  });

  const avgFee = txs.length ? totalFees / txs.length : 0;
  const successRate = txs.length ? (successCount / txs.length) * 100 : 100;

  // Rolling chart data
  if (tps !== null) {
    tpsHistory.push(tps);
    if (tpsHistory.length > CHART_WINDOW) tpsHistory.shift();
  }
  feeHistory.push(avgFee);
  if (feeHistory.length > CHART_WINDOW) feeHistory.shift();

  // Accumulate TX mix
  Object.entries(typeCounts).forEach(([t,c]) => {
    txMixAccum[t] = (txMixAccum[t] || 0) + c;
  });

  // Ledger log entry
  const logEntry = {
    ledgerIndex: li,
    txCount: txs.length,
    tps: tps != null ? tps.toFixed(2) : '—',
    closeTimeSec: closeTimeSec != null ? closeTimeSec.toFixed(2) : '—',
    time: now.toLocaleTimeString()
  };
  ledgerLog.unshift(logEntry);
  if (ledgerLog.length > LEDGER_LOG_MAX) ledgerLog.pop();

  // Build state object for dashboard.js
  const state = {
    ledgerIndex: li,
    ledgerTime: closeT,
    tps: tps,
    txPerLedger: txs.length,
    avgFee: avgFee / 1e6, // in XRP
    successRate,
    txTypes: typeCounts,
    latestLedger: {
      ledgerIndex: li,
      closeTime: closeT,
      closeTimeSec,
      totalTx: txs.length,
      txTypes: typeCounts,
      avgFee: avgFee / 1e6,
      successRate
    },
    recentTransactions: txs.slice(0, 50).map(tx => ({
      hash: tx.hash,
      type: tx.TransactionType,
      account: tx.Account,
      destination: tx.Destination,
      fee: Number(tx.Fee || 0),
      ledgerIndex: li,
      result: tx.metaData?.TransactionResult || tx.meta?.TransactionResult
    }))
  };

  // Fire xrpl-ledger event → dashboard.js window.addEventListener('xrpl-ledger')
  window.dispatchEvent(new CustomEvent('xrpl-ledger', { detail: state }));

  // Update our own UI elements
  _updateMetricCards(li, closeTimeSec, tps, txs.length, avgFee, successRate, typeCounts);
  _updateCharts();
  _updateTxMix();
  _updateLedgerLog();
}

/* ─────────────────────────────────────────────────────────────
   METRIC CARD UPDATERS  (d2- IDs match dashboard.js)
───────────────────────────────────────────────────────────────*/
function _set(id, val) {
  const el = $(id);
  if (el) el.textContent = val;
}

function _updateMetricCards(li, closeTimeSec, tps, txCount, avgFeeDrops, successRate, typeCounts) {
  _set('d2-ledger-index', li ? li.toLocaleString() : '—');
  _set('d2-ledger-age', closeTimeSec != null ? `Close: ${closeTimeSec.toFixed(2)}s` : 'Waiting…');

  if (tps != null) {
    _set('d2-tps', tps.toFixed(2));
    const trend = tps < 5 ? 'Low Activity' : tps < 15 ? 'Normal' : tps < 30 ? 'High' : 'Very High';
    _set('d2-tps-trend', trend);
  }

  const maxTpl = 1000;
  const capPct = Math.min(100, (txCount / maxTpl) * 100);
  _set('d2-network-capacity', `${capPct.toFixed(1)}%`);
  _set('d2-capacity-note', capPct < 30 ? 'Low Usage' : capPct < 60 ? 'Moderate' : capPct < 85 ? 'High' : 'Near Capacity');

  _set('d2-tx-per-ledger', txCount);
  const spread = txCount < 10 ? 'Very Light' : txCount < 50 ? 'Light' : txCount < 150 ? 'Normal' : 'High Volume';
  _set('d2-tx-spread', spread);

  const feeXrp = avgFeeDrops / 1e6;
  const pressure = feeXrp < 0.00001 ? 'Low' : feeXrp < 0.00002 ? 'Normal' : feeXrp < 0.00005 ? 'Medium' : 'High';
  _set('d2-fee-pressure', pressure);
  _set('d2-fee-note', `${avgFeeDrops.toFixed(0)} drops avg`);

  _set('d2-close-time', closeTimeSec != null ? `${closeTimeSec.toFixed(2)}s` : '—');
  const srColor = successRate >= 98 ? '#50fa7b' : successRate >= 95 ? '#ffb86c' : '#ff5555';
  const srEl = $('d2-success-rate');
  if (srEl) { srEl.textContent = `${successRate.toFixed(1)}%`; srEl.style.color = srColor; }

  // Hide stream-loading once we have data
  const sl = $('stream-loading');
  if (sl) sl.style.display = 'none';
}

/* ─────────────────────────────────────────────────────────────
   TX TYPE MIX (fills #tx-mix)
───────────────────────────────────────────────────────────────*/
const TX_COLORS = {
  Payment:'#50fa7b', OfferCreate:'#ffb86c', OfferCancel:'#ff6b6b',
  TrustSet:'#50a8ff', NFTokenMint:'#bd93f9', NFTokenBurn:'#ff6b6b',
  NFTokenCreateOffer:'#bd93f9', NFTokenCancelOffer:'#f472b6', NFTokenAcceptOffer:'#8b5cf6',
  AMMCreate:'#00d4ff', AMMDeposit:'#00ffaa', AMMWithdraw:'#ffd700',
  AMMVote:'#00fff0', AMMBid:'#ff79c6', AMMDelete:'#ff6b6b',
  EscrowCreate:'#4ade80', EscrowFinish:'#34d399', EscrowCancel:'#fb923c',
  PaymentChannelCreate:'#60a5fa', PaymentChannelFund:'#38bdf8', PaymentChannelClaim:'#818cf8',
  CheckCreate:'#a78bfa', CheckCash:'#c084fc', CheckCancel:'#f472b6',
  AccountSet:'#94a3b8', AccountDelete:'#ef4444', SetRegularKey:'#78716c',
  SignerListSet:'#71717a', Clawback:'#dc2626', Other:'#6b7280'
};

function _updateTxMix() {
  const el = $('tx-mix');
  if (!el) return;

  const entries = Object.entries(txMixAccum)
    .filter(([,v]) => v > 0)
    .sort(([,a],[,b]) => b - a)
    .slice(0, 10);

  const total = entries.reduce((s,[,v]) => s + v, 0);
  if (!total) return;

  el.innerHTML = entries.map(([type, count]) => {
    const pct = (count / total * 100).toFixed(1);
    const color = TX_COLORS[type] || '#6b7280';
    return `
      <div class="tx-mix-row">
        <span class="tx-mix-label">${escHtml(type)}</span>
        <div class="tx-mix-bar">
          <div class="tx-mix-fill" style="width:${pct}%;background:${color}"></div>
        </div>
        <span class="tx-mix-pct">${pct}%</span>
      </div>
    `;
  }).join('');
}

/* ─────────────────────────────────────────────────────────────
   MINI-CHART ENGINE  (pure Canvas 2D, no deps)
───────────────────────────────────────────────────────────────*/
class MiniChart {
  constructor(canvasId, color = '#00fff0', mode = 'area') {
    this.canvas = $(canvasId);
    this.color  = color;
    this.mode   = mode;
  }
  draw(data) {
    if (!this.canvas) return;
    const ctx = this.canvas.getContext('2d');
    const W = this.canvas.width  = this.canvas.offsetWidth  || 300;
    const H = this.canvas.height = this.canvas.offsetHeight || 180;
    ctx.clearRect(0, 0, W, H);

    if (!data || data.length < 2) return;
    const min = Math.min(...data) * .9;
    const max = Math.max(...data) * 1.05 || 1;
    const norm = v => 1 - (v - min) / (max - min || 1);
    const pad  = { l:8, r:8, t:10, b:10 };
    const cw   = W - pad.l - pad.r;
    const ch   = H - pad.t - pad.b;
    const step = cw / (data.length - 1);

    const pts = data.map((v, i) => [pad.l + i * step, pad.t + norm(v) * ch]);

    if (this.mode === 'bar') {
      const bw = Math.max(1, step - 3);
      data.forEach((v, i) => {
        const h = norm(v) * ch;
        const x = pad.l + i * step - bw/2;
        const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + ch);
        grad.addColorStop(0, this.color);
        grad.addColorStop(1, this.color + '33');
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.roundRect ? ctx.roundRect(x, pad.t + ch - h, bw, h, 2) : ctx.rect(x, pad.t + ch - h, bw, h);
        ctx.fill();
      });
      return;
    }

    // Area + line
    const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + ch);
    grad.addColorStop(0, this.color + 'aa');
    grad.addColorStop(1, this.color + '11');

    ctx.beginPath();
    pts.forEach(([x,y],i) => i === 0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y));
    ctx.lineTo(pts[pts.length-1][0], pad.t + ch);
    ctx.lineTo(pts[0][0], pad.t + ch);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    pts.forEach(([x,y],i) => i === 0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y));
    ctx.strokeStyle = this.color;
    ctx.lineWidth   = 2;
    ctx.lineJoin    = 'round';
    ctx.stroke();

    // Last dot
    const [lx,ly] = pts[pts.length-1];
    ctx.beginPath();
    ctx.arc(lx, ly, 3.5, 0, Math.PI*2);
    ctx.fillStyle = this.color;
    ctx.fill();
  }
}

let charts = {};
function _initCharts() {
  charts.tps  = new MiniChart('chart-tps',  '#50fa7b', 'area');
  charts.fee  = new MiniChart('chart-fee',  '#ffb86c', 'area');
  charts.tps2 = new MiniChart('chart-tps2', '#50fa7b', 'bar');
  charts.fee2 = new MiniChart('chart-fee2', '#ffb86c', 'area');
}
function _updateCharts() {
  charts.tps?.draw(tpsHistory);
  charts.fee?.draw(feeHistory);
  charts.tps2?.draw(tpsHistory);
  charts.fee2?.draw(feeHistory);
}

/* ─────────────────────────────────────────────────────────────
   LEDGER LOG  (#ledger-log in Network Health tab)
───────────────────────────────────────────────────────────────*/
function _updateLedgerLog() {
  const logEl    = $('ledger-log');
  const loadEl   = $('ledger-log-loading');
  const countEl  = $('ledger-log-count');
  if (!logEl) return;

  if (ledgerLog.length === 0) return;
  if (loadEl) loadEl.style.display = 'none';
  logEl.style.display = '';
  if (countEl) countEl.textContent = ledgerLog.length;

  // Only update when network tab visible (perf)
  const netTab = $('tab-network');
  if (!netTab || netTab.style.display === 'none') return;

  logEl.innerHTML = `
    <div class="ledger-log-row log-head">
      <span>Ledger</span><span>TX Count</span><span>TPS</span><span>Close</span><span>Time</span>
    </div>
    ${ledgerLog.slice(0, 60).map(r => `
      <div class="ledger-log-row">
        <span class="log-index">#${r.ledgerIndex.toLocaleString()}</span>
        <span class="log-tx">${r.txCount}</span>
        <span class="log-tps">${r.tps}</span>
        <span class="log-close">${r.closeTimeSec}s</span>
        <span class="log-time">${r.time}</span>
      </div>
    `).join('')}
  `;
}

/* ─────────────────────────────────────────────────────────────
   ACCOUNT INSPECTOR  (runInspect called from HTML onclick)
───────────────────────────────────────────────────────────────*/
async function _runInspect() {
  const input  = $('inspect-addr');
  const addr   = (input?.value || '').trim();
  const errEl  = $('inspect-err');
  const resEl  = $('inspect-result');
  const emptyEl = $('inspect-empty');
  const loadEl = $('inspect-loading');
  const warnEl = $('inspect-warn');

  if (errEl)  errEl.style.display = 'none';
  if (resEl)  resEl.style.display = 'none';
  if (emptyEl) emptyEl.style.display = 'none';

  if (!addr) {
    if (emptyEl) emptyEl.style.display = '';
    return;
  }

  if (!isValidXrpAddress(addr)) {
    if (errEl) { errEl.textContent = `⚠ Invalid XRPL address: ${escHtml(addr)}`; errEl.style.display = ''; }
    return;
  }

  if (window.connectionState !== 'connected') {
    if (warnEl) warnEl.style.display = '';
    return;
  }
  if (warnEl) warnEl.style.display = 'none';

  if (loadEl) loadEl.style.display = '';

  try {
    const [infoRes, linesRes] = await Promise.all([
      _wsSend({ command: 'account_info', account: addr, ledger_index: 'validated' }),
      _wsSend({ command: 'account_lines', account: addr, ledger_index: 'validated' })
    ]);

    if (loadEl) loadEl.style.display = 'none';

    const info  = infoRes?.result?.account_data  || {};
    const lines = linesRes?.result?.lines        || [];

    _renderInspectResult(addr, info, lines);
    if (resEl) resEl.style.display = '';

    // Save address on successful inspect
    _saveAddress(addr);

  } catch(err) {
    if (loadEl) loadEl.style.display = 'none';
    if (errEl) {
      errEl.textContent = `Error: ${escHtml(err.message)}`;
      errEl.style.display = '';
    }
  }
}

function _renderInspectResult(addr, info, lines) {
  // Address badge
  const badge = $('inspect-addr-badge');
  if (badge) badge.textContent = `${addr.slice(0,8)}…${addr.slice(-6)}`;

  const balDrops = Number(info.Balance || 0);
  const balXrp   = balDrops / 1e6;
  const reserve  = 10 + (Number(info.OwnerCount || 0) * 2);

  const grid = $('inspect-acct-grid');
  if (grid) {
    const cells = [
      { label:'Address',     value: addr },
      { label:'Balance',     value: `${balXrp.toFixed(6)} XRP` },
      { label:'Sequence',    value: info.Sequence ?? '—' },
      { label:'Owner Count', value: info.OwnerCount ?? '—' },
      { label:'Est. Reserve',value: `${reserve} XRP` },
      { label:'Flags',       value: info.Flags ?? 0 }
    ];
    grid.innerHTML = cells.map(c => `
      <div class="acct-cell">
        <div class="acct-cell-label">${escHtml(c.label)}</div>
        <div class="acct-cell-value">${escHtml(String(c.value))}</div>
      </div>
    `).join('');
  }

  const trustBadge = $('trust-count-badge');
  if (trustBadge) trustBadge.textContent = lines.length;

  const trustBody = $('inspect-trust-body');
  if (trustBody) {
    if (!lines.length) {
      trustBody.innerHTML = '<div class="widget-label" style="padding:12px 0">No trustlines found.</div>';
    } else {
      trustBody.innerHTML = lines.map(l => `
        <div class="trustline-row">
          <span class="trustline-currency">${escHtml(l.currency)}</span>
          <span class="trustline-issuer">${l.account ? `${l.account.slice(0,8)}…${l.account.slice(-6)}` : ''}</span>
          <span class="trustline-balance">${escHtml(l.balance)} / ${escHtml(l.limit)}</span>
        </div>
      `).join('');
    }
  }
}

/* ─────────────────────────────────────────────────────────────
   NETWORK SELECTOR BUTTONS  (data-network attr)
───────────────────────────────────────────────────────────────*/
function _bindNetworkButtons() {
  document.querySelectorAll('.net-btn[data-network]').forEach(btn => {
    btn.addEventListener('click', () => {
      const net = btn.getAttribute('data-network');
      if (net === currentNetwork) return;

      document.querySelectorAll('.net-btn').forEach(b => {
        b.classList.toggle('active', b === btn);
        b.setAttribute('aria-pressed', String(b === btn));
      });

      currentNetwork = net;
      endpointIdx = 0;
      wsRetry = 0;
      ledgerLog = [];
      tpsHistory = [];
      feeHistory = [];
      txMixAccum = {};
      lastCloseTs = null;

      _reconnect(true);
      window.dispatchEvent(new CustomEvent('xrpl-connection', {
        detail: { connected: false, server: '', modeReason: 'Network switched' }
      }));

      // Notify dashboard.js
      if (typeof window.setXRPLNetwork === 'function') {
        window.setXRPLNetwork(net);
      }
    });
  });
}

/* ─────────────────────────────────────────────────────────────
   LANDING FEATURE GRID  (populated from JS, not hardcoded HTML)
───────────────────────────────────────────────────────────────*/
const FEATURES = [
  {
    icon: '⚡',
    title: 'Real-Time Ledger Stream',
    desc: 'WebSocket subscription to every ledger closing on XRPL. All 34 transaction types colour-coded with neon aura ledger cards.',
    link: 'Explore stream →'
  },
  {
    icon: '🔍',
    title: 'Account Inspector',
    desc: 'Deep-dive any XRPL address. Balances, trustlines, token holdings, flags, reserve, and sequence — no wallet required.',
    link: 'Inspect address →'
  },
  {
    icon: '🧠',
    title: 'Forensic Breadcrumbs',
    desc: 'Detects wallet pairs that repeatedly transact together across ledger windows — identifying routing hubs and coordinated activity.',
    link: 'View forensics →'
  },
  {
    icon: '🕸️',
    title: 'Cluster Inference',
    desc: 'Graph-based grouping of wallets with high transaction density. Persistence scores reveal networks operating over time.',
    link: 'Explore clusters →'
  },
  {
    icon: '📖',
    title: 'Delta Narratives',
    desc: 'Explains how transaction activity changed from one ledger to the next in plain language. "Payments surged 47%."',
    link: 'Read narratives →'
  },
  {
    icon: '🌐',
    title: 'Multi-Network',
    desc: 'Switch between XRPL Mainnet, Testnet, and Xahau in one click. Auto-reconnects to the best available endpoint.',
    link: 'Switch network →'
  }
];

const VALUE_CARDS = [
  {
    num: 1,
    title: 'Watch money move live',
    body: 'See every transaction on the XRP Ledger as it happens — payments, offers, NFTs, and DeFi — no delay, no polling.'
  },
  {
    num: 2,
    title: 'Investigate any wallet',
    body: 'Enter any XRPL address to instantly see its balance, all tokens held, and every trustline it has opened.'
  },
  {
    num: 3,
    title: 'Detect unusual patterns',
    body: 'Automated forensic analysis spots repeated wallet flows, clustered networks, and unusual concentration in real time.'
  }
];

function _buildLandingContent() {
  const grid = $('features-grid');
  if (grid) {
    grid.innerHTML = FEATURES.map(f => `
      <div class="feature-card" role="listitem">
        <span class="feature-icon">${f.icon}</span>
        <h3>${escHtml(f.title)}</h3>
        <p>${escHtml(f.desc)}</p>
        <div class="feature-link">${escHtml(f.link)}</div>
      </div>
    `).join('');
  }

  const valueGrid = $('value-grid');
  if (valueGrid) {
    valueGrid.innerHTML = VALUE_CARDS.map(v => `
      <div class="value-card">
        <div class="value-number">${v.num}</div>
        <h3>${escHtml(v.title)}</h3>
        <p>${escHtml(v.body)}</p>
      </div>
    `).join('');
  }
}

/* ─────────────────────────────────────────────────────────────
   SCROLL REVEAL  (IntersectionObserver → .reveal.visible)
───────────────────────────────────────────────────────────────*/
function _initReveal() {
  const obs = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); });
  }, { threshold: 0.15 });

  document.querySelectorAll('.reveal').forEach(el => obs.observe(el));
  window.UI.observers.reveal = obs;
}

/* ─────────────────────────────────────────────────────────────
   KEYBOARD SHORTCUT: close overlays on Escape
───────────────────────────────────────────────────────────────*/
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    _closeCmdk();
    _closeAuth();
  }
});

/* Close auth when clicking overlay backdrop */
document.addEventListener('click', e => {
  const overlay = $('auth-overlay');
  if (overlay && e.target === overlay) _closeAuth();
});

/* ─────────────────────────────────────────────────────────────
   DASHBOARD RENDER  (window.renderDashboard matches dashboard.js API)
   dashboard.js also exports window.NaluDashboard — we don't override
   that, we just make sure our HTML provides the right IDs so it works
───────────────────────────────────────────────────────────────*/
window.renderDashboard = function() {
  console.log('🌊 renderDashboard called');
  _initCharts();
};

/* ─────────────────────────────────────────────────────────────
   CONNECTION MONITOR  (replicates ui.js setupConnectionMonitoring)
   Fires naluxrp:connected / naluxrp:disconnected so ui.js stays in sync
───────────────────────────────────────────────────────────────*/
function _connectionMonitor() {
  let wasConnected = false;
  setInterval(() => {
    const now = window.connectionState === 'connected';
    if (now && !wasConnected) {
      window.dispatchEvent(new Event('xrpl-connected'));
      window.dispatchEvent(new Event('naluxrp:connected'));
      wasConnected = true;
    } else if (!now && wasConnected) {
      window.dispatchEvent(new Event('xrpl-disconnected'));
      window.dispatchEvent(new Event('naluxrp:disconnected'));
      wasConnected = false;
    }
  }, 2000);
}

/* ─────────────────────────────────────────────────────────────
   DOM READY
───────────────────────────────────────────────────────────────*/
document.addEventListener('DOMContentLoaded', () => {
  console.log('🌊 NaluXRP: DOM loaded');

  // Restore theme
  const savedTheme = safeGet(LS_THEME);
  if (savedTheme) _setTheme(savedTheme);
  else             _setTheme('gold');

  // Landing starts visible, dashboard hidden
  _showLandingPage();

  // Build landing page dynamic content
  _buildLandingContent();

  // Scroll reveal
  _initReveal();

  // Particle background
  initParticles();

  // Charts
  _initCharts();

  // Command palette listeners
  _setupCmdkListeners();

  // Network buttons
  _bindNetworkButtons();

  // Inspector Enter key
  const inspInput = $('inspect-addr');
  if (inspInput) {
    inspInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') _runInspect();
    });
  }

  // Inspector button disabled until connected
  const inspBtn = $('inspect-btn');
  if (inspBtn) inspBtn.disabled = true;

  // Connection monitoring
  _connectionMonitor();

  console.log('✅ NaluXRP: initialized');
});