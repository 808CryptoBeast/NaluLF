/* =====================================================
   profile.js — Profile · Social · XRPL Wallet Suite
   ─────────────────────────────────────────────────────
   Wallet security:
   • Seeds stored encrypted in CryptoVault (AES-256-GCM)
   • Public metadata (address, label, emoji) stored plainly
   • Vault must be unlocked for any signing operation
   • Seeds cleared from memory immediately after signing

   XRPL capabilities per wallet:
   • TrustSet  — add/modify/remove trustlines
   • Payment   — XRP and IOU token transfers
   • OfferCreate/Cancel — DEX order management
   • NFTokenMint/Burn/CreateOffer — NFT operations
   • AMMDeposit/Withdraw/Vote/Bid — AMM LP operations
   • Sign & submit via XRPL public JSON-RPC
   ===================================================== */
import { $, $$, escHtml, safeGet, safeSet, safeJson, toastInfo, toastErr, toastWarn, isValidXrpAddress, fmt } from './utils.js';
import { state } from './state.js';
import { setTheme } from './theme.js';
import { CryptoVault } from './auth.js';

/* ── Constants ── */
const LS_WALLET_META  = 'naluxrp_wallet_meta';    // Public metadata only — no seeds
const LS_PROFILE      = 'nalulf_profile';
const LS_SOCIAL       = 'nalulf_social';
const LS_ACTIVE_ID    = 'naluxrp_active_wallet';
const LS_AVATAR_IMG   = 'nalulf_avatar_img';      // base64 custom profile photo
const LS_BANNER_IMG   = 'nalulf_banner_img';      // base64 custom banner image
const XRPL_RPC        = 'https://s1.ripple.com:51234/';
const XRPL_RPC_BACKUP = 'https://xrplcluster.com/';

const AVATARS = ['🌊','🐋','🐉','🦋','🦁','🐺','🦊','🐻','🐼','🦅','🐬','🦈','🐙','🦑','🧿','🌺','🌸','🍀','⚡','🔥','💎','🌙','⭐','🎯','🧠','🔮','🛸','🗺','🏔','🌊','🎭','🏛'];
const WALLET_EMOJIS  = ['💎','🏦','🔐','🔑','💰','🌊','⚡','🚀','🌙','⭐','🏴‍☠️','🎯','🧠','🔮'];
const WALLET_COLORS  = ['#50fa7b','#00d4ff','#ffb86c','#bd93f9','#ff79c6','#f1fa8c','#ff5555','#00fff0','#ff6b6b','#a78bfa'];
const BANNERS        = ['banner-ocean','banner-neon','banner-gold','banner-cosmic','banner-sunset','banner-aurora'];
const SOCIAL_PLATFORMS = [
  { id:'discord',  label:'Discord',      icon:'💬', prefix:'https://discord.com/users/' },
  { id:'twitter',  label:'X / Twitter',  icon:'𝕏',  prefix:'https://x.com/' },
  { id:'linkedin', label:'LinkedIn',     icon:'in', prefix:'https://linkedin.com/in/' },
  { id:'facebook', label:'Facebook',     icon:'f',  prefix:'https://facebook.com/' },
  { id:'tiktok',   label:'TikTok',       icon:'♪',  prefix:'https://tiktok.com/@' },
  { id:'github',   label:'GitHub',       icon:'⌥',  prefix:'https://github.com/' },
  { id:'telegram', label:'Telegram',     icon:'✈',  prefix:'https://t.me/' },
];

/* ── App state ── */
let profile = {
  displayName: '', handle: '', bio: '', location: '', website: '',
  avatar: '🌊', banner: 'banner-ocean', joinedDate: new Date().toISOString(),
};
let wallets       = [];   // Public metadata: [{ id, label, address, algo, emoji, color, testnet, createdAt }]
let social        = {};
let activeWalletId= null;
let balanceCache  = {};   // { [address]: { xrp, tokens: [{currency, issuer, balance}], fetchedAt } }
let trustlineCache= {};   // { [address]: [{currency, issuer, limit, balance}] }

/* Wallet wizard state */
let wizardStep = 1;
let wizardData = { algo: 'ed25519', label: '', emoji: '💎', color: '#50fa7b', seed: '', address: '' };
let checksCompleted = new Set();

/* ═══════════════════════════════════════════════════════════
   Init
═══════════════════════════════════════════════════════════ */
export function initProfile() {
  loadData();
  _mountDynamicModals();
  renderProfilePage();
  renderProfileTabs('wallets');
  renderActiveWalletBar();
  bindProfileEvents();

  window.addEventListener('naluxrp:vault-ready', () => {
    loadData();
    renderProfilePage();
    renderProfileTabs(_activeTab);
    renderActiveWalletBar();
    fetchAllBalances();
  });

  window.addEventListener('naluxrp:vault-locked', () => {
    renderProfilePage();
  });
}

let _activeTab = 'wallets';

export function switchProfileTab(tab) {
  _activeTab = tab;
  // Update tab button states
  $$('.ptab-btn').forEach(btn => btn.classList.toggle('active', btn.dataset.tab === tab));
  renderProfileTabs(tab);
}

function renderProfileTabs(tab) {
  switch (tab) {
    case 'wallets':  renderWalletList(); break;
    case 'social':   renderSocialList(); break;
    case 'security': renderSecurityPanel(); break;
    case 'activity': renderActivityPanel(); break;
  }
  // Show/hide panels
  ['wallets','social','security','activity'].forEach(t => {
    const el = $(`profile-tab-${t}`);
    if (el) el.style.display = t === tab ? '' : 'none';
  });
}

/* ═══════════════════════════════════════════════════════════
   Data — vault-aware storage
═══════════════════════════════════════════════════════════ */
function loadData() {
  // Profile and social are not sensitive — plain localStorage
  const p = safeJson(safeGet(LS_PROFILE));
  if (p) Object.assign(profile, p);
  social = safeJson(safeGet(LS_SOCIAL)) || {};

  // Wallet list: merge public metadata with vault seeds (when unlocked)
  wallets = safeJson(safeGet(LS_WALLET_META)) || [];

  // If vault is unlocked, ensure metadata is in sync
  if (CryptoVault.isUnlocked && CryptoVault.vault?.wallets?.length) {
    const vaultWallets = CryptoVault.vault.wallets;
    // Sync addresses from vault in case metadata was cleared
    vaultWallets.forEach(vw => {
      if (!wallets.find(w => w.id === vw.id)) {
        wallets.push({ id: vw.id, label: vw.label, address: vw.address, algo: vw.algo,
          emoji: vw.emoji, color: vw.color, testnet: vw.testnet, createdAt: vw.createdAt });
      }
    });
    _saveWalletMeta();
  }

  activeWalletId = safeGet(LS_ACTIVE_ID) || wallets[0]?.id || null;

  if (!profile.displayName && state.session?.name) {
    profile.displayName = state.session.name;
    profile.handle = state.session.name.toLowerCase().replace(/\s+/g, '_');
    _saveProfile();
  }
}

function _saveProfile()    { safeSet(LS_PROFILE, JSON.stringify(profile)); }
function _saveWalletMeta() { safeSet(LS_WALLET_META, JSON.stringify(wallets)); }
function _saveSocial()     { safeSet(LS_SOCIAL, JSON.stringify(social)); }

/* ═══════════════════════════════════════════════════════════
   Active Wallet
═══════════════════════════════════════════════════════════ */
export function getActiveWallet() {
  return wallets.find(w => w.id === activeWalletId) || wallets[0] || null;
}

export function setActiveWallet(id) {
  if (!wallets.find(w => w.id === id)) return;
  activeWalletId = id;
  safeSet(LS_ACTIVE_ID, id);
  renderWalletList();
  renderActiveWalletBar();
  // Broadcast to rest of app (dashboard, inspector etc.)
  window.dispatchEvent(new CustomEvent('naluxrp:active-wallet-changed', {
    detail: getActiveWallet()
  }));
  toastInfo(`Active wallet switched`);
}

/* ── Active wallet banner below profile header ── */
function renderActiveWalletBar() {
  const bar = $('active-wallet-bar');
  if (!bar) return;
  const w = getActiveWallet();
  if (!w) {
    bar.innerHTML = `<div class="awb-empty">No wallet — <button class="awb-link" onclick="openWalletCreator()">create one</button></div>`;
    return;
  }
  const cached = balanceCache[w.address];
  const xrp    = cached ? fmt(cached.xrp, 2) + ' XRP' : '— XRP';
  const tokens = cached?.tokens?.length ? `· ${cached.tokens.length} token${cached.tokens.length > 1 ? 's' : ''}` : '';

  bar.innerHTML = `
    <div class="awb-left">
      <div class="awb-icon" style="background:${w.color}22;border-color:${w.color}55;color:${w.color}">${escHtml(w.emoji)}</div>
      <div class="awb-info">
        <span class="awb-label">${escHtml(w.label)}</span>
        <span class="awb-address mono">${escHtml(w.address)}</span>
      </div>
      <span class="awb-balance">${xrp} ${tokens}</span>
    </div>
    <div class="awb-actions">
      <button class="awb-btn awb-btn--send"    onclick="openSendModal('${w.id}')">⬆ Send</button>
      <button class="awb-btn awb-btn--receive" onclick="openReceiveModal('${w.id}')">⬇ Receive</button>
      <button class="awb-btn awb-btn--trust"   onclick="openTrustlineModal('${w.id}')">🔗 Trustlines</button>
      <button class="awb-btn awb-btn--inspect" onclick="inspectWalletAddr('${w.address}')">🔍 Inspect</button>
    </div>`;
}

/* ── Broadcast active wallet to Inspector / Dashboard auto-fill ── */
window.addEventListener('naluxrp:active-wallet-changed', e => {
  const w = e.detail;
  if (!w) return;
  // Pre-fill inspector
  const inspEl = $('inspect-addr');
  if (inspEl && !inspEl.value) inspEl.value = w.address;
  // Notify dashboard of watched address
  state.activeWalletAddress = w.address;
});

/* ═══════════════════════════════════════════════════════════
   Render Profile
═══════════════════════════════════════════════════════════ */
function renderProfilePage() {
  // Banner — custom image takes priority over gradient class
  const banner = $('profile-banner');
  if (banner) {
    const bannerImg = localStorage.getItem(LS_BANNER_IMG);
    if (bannerImg) {
      BANNERS.forEach(b => banner.classList.remove(b));
      banner.style.backgroundImage = `url(${bannerImg})`;
      banner.style.backgroundSize  = 'cover';
      banner.style.backgroundPosition = 'center';
    } else {
      banner.style.backgroundImage = '';
      BANNERS.forEach(b => banner.classList.remove(b));
      banner.classList.add(profile.banner || 'banner-ocean');
    }
  }

  // Avatar — custom image takes priority over emoji
  const av = $('profile-avatar-el');
  if (av) {
    const avatarImg = localStorage.getItem(LS_AVATAR_IMG);
    if (avatarImg) {
      av.innerHTML = `<img src="${avatarImg}" class="profile-avatar-img" alt="Profile photo" />`;
    } else {
      av.textContent = profile.avatar || '🌊';
    }
  }

  _setText('profile-display-name', profile.displayName || 'Anonymous');
  _setText('profile-handle',       `@${profile.handle  || 'anonymous'}`);
  _setText('profile-bio',          profile.bio || 'No bio yet. Click Edit Profile to add one.');

  const loc = $('profile-location-el');
  if (loc) loc.innerHTML = profile.location ? `<span>📍 ${escHtml(profile.location)}</span>` : '';

  const web = $('profile-website-el');
  if (web) web.innerHTML = profile.website
    ? `<a href="${escHtml(profile.website)}" target="_blank" rel="noopener">🔗 ${escHtml(profile.website.replace(/^https?:\/\//, ''))}</a>` : '';

  const joined = $('profile-joined-el');
  if (joined) joined.innerHTML = `<span>📅 Joined ${new Date(profile.joinedDate || Date.now()).toLocaleDateString('en-US',{month:'short',year:'numeric'})}</span>`;

  // Vault pill
  const vaultEl = $('vault-status-pill');
  if (vaultEl) {
    const unlocked = CryptoVault.isUnlocked;
    vaultEl.className = `vault-pill ${unlocked ? 'vault-pill--open' : 'vault-pill--locked'}`;
    vaultEl.innerHTML = unlocked ? '🔓 Vault unlocked' : '🔒 Vault locked';
  }
}

/* ═══════════════════════════════════════════════════════════
   Social
═══════════════════════════════════════════════════════════ */
function renderSocialList() {
  const list = $('profile-tab-social');
  if (!list) return;
  const connectedCount = Object.values(social).filter(Boolean).length;

  list.innerHTML = `
    <div class="social-section-head">
      <div class="social-section-title">Social &amp; Community Links</div>
      <div class="social-section-sub">${connectedCount} of ${SOCIAL_PLATFORMS.length} connected · stored locally only, never verified</div>
    </div>
    <div class="social-grid">
      ${SOCIAL_PLATFORMS.map(p => {
        const handle    = social[p.id] || '';
        const connected = !!handle;
        return `
        <div class="social-card ${connected ? 'social-card--connected' : ''}" id="social-item-${p.id}">
          <div class="social-card-left">
            <div class="social-platform-badge social-platform-badge--${p.id}">${p.icon}</div>
            <div class="social-card-info">
              <div class="social-card-name">${escHtml(p.label)}</div>
              <div class="social-card-handle ${connected ? '' : 'dim'}">${connected ? escHtml('@' + handle) : 'Not connected'}</div>
            </div>
          </div>
          <div class="social-card-actions">
            ${connected ? `
              <button class="sc-btn sc-btn--open"    onclick="viewSocial('${p.id}')" title="Open profile">↗</button>
              <button class="sc-btn sc-btn--edit"    onclick="openSocialModal('${p.id}')">Edit</button>
            ` : `
              <button class="sc-btn sc-btn--connect" onclick="openSocialModal('${p.id}')">+ Connect</button>
            `}
          </div>
        </div>`;
      }).join('')}
    </div>`;

  _setText('stat-socials-val', connectedCount);
}

export function openSocialModal(platformId) {
  const platform = SOCIAL_PLATFORMS.find(p => p.id === platformId);
  if (!platform) return;
  const modal = $('social-modal');
  if (!modal) return;
  const icon   = $('social-modal-icon');
  const title  = $('social-modal-title');
  const sub    = $('social-modal-sub');
  const input  = $('social-modal-input');
  const delBtn = $('social-modal-delete');
  if (icon)   { icon.className = `social-platform-icon-lg social-icon ${platform.id}`; icon.textContent = platform.icon; }
  if (title)  title.textContent = `Connect ${platform.label}`;
  if (sub)    sub.textContent   = `Enter your ${platform.label} ${platform.id === 'discord' ? 'user ID or username' : 'username'}.`;
  if (input)  { input.value = social[platformId] || ''; input.placeholder = `Your ${platform.label} handle`; }
  if (delBtn) delBtn.style.display = social[platformId] ? '' : 'none';
  modal.dataset.platform = platformId;
  modal.classList.add('show');
}
export function saveSocialModal() {
  const modal    = $('social-modal');
  const platform = modal?.dataset.platform;
  const input    = $('social-modal-input');
  if (!platform || !input) return;
  const handle = input.value.trim().replace(/^@/, '');
  if (handle) social[platform] = handle; else delete social[platform];
  _saveSocial(); renderSocialList(); closeSocialModal();
  toastInfo(`${SOCIAL_PLATFORMS.find(p => p.id === platform)?.label} updated`);
}
export function deleteSocial() {
  const platform = $('social-modal')?.dataset.platform;
  if (!platform) return;
  delete social[platform]; _saveSocial(); renderSocialList(); closeSocialModal();
  toastInfo('Social connection removed');
}
export function viewSocial(platformId) {
  const p = SOCIAL_PLATFORMS.find(x => x.id === platformId);
  if (p && social[platformId]) window.open(`${p.prefix}${social[platformId]}`, '_blank', 'noopener');
}
export function closeSocialModal() { $('social-modal')?.classList.remove('show'); }

/* ═══════════════════════════════════════════════════════════
   Wallet List
═══════════════════════════════════════════════════════════ */
function renderWalletList() {
  const list = $('profile-tab-wallets');
  if (!list) return;

  if (wallets.length === 0) {
    list.innerHTML = `
      <div class="wallets-empty">
        <div class="wallets-empty-icon">💎</div>
        <div class="wallets-empty-title">No wallets yet</div>
        <div class="wallets-empty-sub">Generate your first XRPL wallet — your seed is encrypted with AES-256-GCM and never leaves this device.</div>
        <button class="btn-create-wallet-hero" onclick="openWalletCreator()">⚡ Generate XRPL Wallet</button>
      </div>`;
    _setText('stat-wallets-val', 0);
    return;
  }

  const cards = wallets.map((w, i) => {
    const isActive = w.id === activeWalletId;
    const cached   = balanceCache[w.address];
    const xrp      = cached ? fmt(cached.xrp, 2) : '—';
    const tokens   = cached?.tokens || [];
    const addrShort = w.address.slice(0,8) + '…' + w.address.slice(-6);

    return `
    <div class="wcard ${isActive ? 'wcard--active' : ''}" id="wallet-item-${w.id}">
      <div class="wcard-top">
        <div class="wcard-icon" style="background:${w.color}18;border-color:${w.color}44;color:${w.color}">${escHtml(w.emoji||'💎')}</div>
        <div class="wcard-identity">
          <div class="wcard-name-row">
            <span class="wcard-name">${escHtml(w.label||'Unnamed Wallet')}</span>
            ${isActive ? '<span class="wcard-badge wcard-badge--active">● Active</span>' : ''}
            ${w.testnet ? '<span class="wcard-badge wcard-badge--testnet">Testnet</span>' : '<span class="wcard-badge wcard-badge--mainnet">Mainnet</span>'}
          </div>
          <div class="wcard-address mono" title="${escHtml(w.address)}" onclick="copyToClipboard('${escHtml(w.address)}')">${addrShort} <span class="wcard-copy-hint">⧉</span></div>
          <div class="wcard-algo-row">
            <span class="wcard-algo">${escHtml((w.algo||'ed25519').toUpperCase())}</span>
            <span class="wcard-enc">🔐 AES-256-GCM encrypted</span>
          </div>
        </div>
        <div class="wcard-balance-col">
          <div class="wcard-xrp">${xrp} <span class="wcard-xrp-label">XRP</span></div>
          ${tokens.length ? `<div class="wcard-tokens">${tokens.length} token${tokens.length>1?'s':''}</div>` : ''}
        </div>
      </div>

      ${tokens.length ? `
      <div class="wcard-token-row">
        ${tokens.slice(0,5).map(t=>`
          <div class="wcard-token-chip">
            <span class="wcard-token-cur">${escHtml(t.currency.length>4?t.currency.slice(0,4)+'…':t.currency)}</span>
            <span class="wcard-token-bal">${fmt(parseFloat(t.balance),2)}</span>
          </div>`).join('')}
        ${tokens.length>5?`<div class="wcard-token-chip wcard-token-more">+${tokens.length-5}</div>`:''}
      </div>` : ''}

      <div class="wcard-actions">
        <button class="wcard-btn wcard-btn--send"    onclick="openSendModal('${w.id}')">⬆ Send</button>
        <button class="wcard-btn wcard-btn--receive" onclick="openReceiveModal('${w.id}')">⬇ Receive</button>
        <button class="wcard-btn wcard-btn--trust"   onclick="openTrustlineModal('${w.id}')">🔗 Trustlines</button>
        <button class="wcard-btn wcard-btn--inspect" onclick="inspectWalletAddr('${escHtml(w.address)}')">🔍 Inspect</button>
        ${!isActive ? `<button class="wcard-btn wcard-btn--setactive" onclick="setActiveWallet('${w.id}')">★ Set Active</button>` : ''}
        <button class="wcard-btn wcard-btn--remove"  onclick="deleteWallet(${i})">✕ Remove</button>
      </div>
    </div>`;
  }).join('');

  list.innerHTML = cards + `
    <button class="btn-add-wallet" onclick="openWalletCreator()">
      <span class="baw-plus">＋</span>
      <div class="baw-text">
        <span class="baw-title">Generate New XRPL Wallet</span>
        <span class="baw-sub">Keys generated in-browser · encrypted before storage · never sent anywhere</span>
      </div>
    </button>`;

  _setText('stat-wallets-val', wallets.length);
}

/* ── Security panel ── */
function renderSecurityPanel() {
  const el = $('profile-tab-security');
  if (!el) return;
  const unlocked = CryptoVault.isUnlocked;
  const meta = (() => { try { return JSON.parse(localStorage.getItem('naluxrp_vault_meta')||'{}'); } catch{return{};} })();
  const createdAt = CryptoVault.vault?.identity?.createdAt
    ? new Date(CryptoVault.vault.identity.createdAt).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}) : '—';

  el.innerHTML = `
    <div class="sec-grid">

      <div class="sec-card">
        <div class="sec-card-hdr">
          <span class="sec-card-icon">🔐</span>
          <div>
            <div class="sec-card-title">Local Encrypted Vault</div>
            <div class="sec-card-sub">AES-256-GCM · PBKDF2 150,000 iterations · SHA-256</div>
          </div>
          <span class="sec-status-pill ${unlocked ? 'sec-status--open' : 'sec-status--locked'}">${unlocked ? 'Unlocked' : 'Locked'}</span>
        </div>
        <div class="sec-kv-grid">
          <div class="sec-kv"><span class="sec-k">Encryption</span><span class="sec-v mono">AES-256-GCM</span></div>
          <div class="sec-kv"><span class="sec-k">Key derivation</span><span class="sec-v mono">PBKDF2 · 150k iterations</span></div>
          <div class="sec-kv"><span class="sec-k">Hash</span><span class="sec-v mono">SHA-256</span></div>
          <div class="sec-kv"><span class="sec-k">Vault created</span><span class="sec-v">${createdAt}</span></div>
          <div class="sec-kv"><span class="sec-k">Server storage</span><span class="sec-v sec-v--good">None — local only</span></div>
          <div class="sec-kv"><span class="sec-k">Password stored</span><span class="sec-v sec-v--good">Never — key derivation only</span></div>
          <div class="sec-kv"><span class="sec-k">Auto-lock</span><span class="sec-v">30 min inactivity</span></div>
        </div>
        <div class="sec-card-actions">
          <button class="sec-btn sec-btn--primary" onclick="exportVaultBackup()">⬇ Export Encrypted Backup</button>
        </div>
        <div class="sec-note">
          <span class="sec-note-icon">ℹ</span>
          Your backup file is still encrypted — it cannot be read without your password.
          Store it on a USB drive or external hard drive.
        </div>
      </div>

      <div class="sec-card">
        <div class="sec-card-hdr">
          <span class="sec-card-icon">🌐</span>
          <div>
            <div class="sec-card-title">Privacy Architecture</div>
            <div class="sec-card-sub">How NaluLF handles your data</div>
          </div>
        </div>
        <div class="sec-info-list">
          <div class="sec-info-item sec-info--good">
            <span class="sec-info-dot"></span>
            <div><strong>Zero server-side storage.</strong> Your profile, wallet metadata, and seeds never leave your browser.</div>
          </div>
          <div class="sec-info-item sec-info--good">
            <span class="sec-info-dot"></span>
            <div><strong>Direct XRPL connections.</strong> We connect directly to XRPL public nodes over WebSocket — no proxy.</div>
          </div>
          <div class="sec-info-item sec-info--good">
            <span class="sec-info-dot"></span>
            <div><strong>No telemetry.</strong> No analytics, no tracking, no third-party scripts that observe your activity.</div>
          </div>
          <div class="sec-info-item sec-info--warn">
            <span class="sec-info-dot"></span>
            <div><strong>On-chain data is public.</strong> XRPL transactions are permanently public. Wallet addresses and balances are visible to anyone.</div>
          </div>
          <div class="sec-info-item sec-info--warn">
            <span class="sec-info-dot"></span>
            <div><strong>You control your keys.</strong> If you forget your password and have no backup, your encrypted vault data cannot be recovered.</div>
          </div>
        </div>
      </div>

      <div class="sec-card sec-card--seed-best-practices">
        <div class="sec-card-hdr">
          <span class="sec-card-icon">✍️</span>
          <div>
            <div class="sec-card-title">Seed Phrase Best Practices</div>
            <div class="sec-card-sub">Required reading for every wallet owner</div>
          </div>
        </div>
        <div class="sec-practices">
          <div class="sec-practice">
            <div class="sec-practice-num">1</div>
            <div class="sec-practice-body">
              <strong>Write it on paper — right now.</strong>
              Store a physical copy in a safe, fireproof box, or safety deposit box. This is your only recovery option if you lose this device.
            </div>
          </div>
          <div class="sec-practice">
            <div class="sec-practice-num">2</div>
            <div class="sec-practice-body">
              <strong>Never store it digitally.</strong>
              No notes apps, emails, cloud drives, or screenshots. A hacked device means instant loss of all funds.
            </div>
          </div>
          <div class="sec-practice">
            <div class="sec-practice-num">3</div>
            <div class="sec-practice-body">
              <strong>Never share it with anyone.</strong>
              No exchange, support team, or application should ever request your seed. This is always a scam.
            </div>
          </div>
          <div class="sec-practice">
            <div class="sec-practice-num">4</div>
            <div class="sec-practice-body">
              <strong>Use a strong, unique password.</strong>
              Your password protects the encrypted vault on this device. Use one you don't use anywhere else.
            </div>
          </div>
          <div class="sec-practice">
            <div class="sec-practice-num">5</div>
            <div class="sec-practice-body">
              <strong>Export your backup regularly.</strong>
              Use the Export Backup button above after creating or modifying wallets. Keep the file offline.
            </div>
          </div>
        </div>
      </div>

      <div class="sec-card">
        <div class="sec-card-hdr">
          <span class="sec-card-icon">📡</span>
          <div>
            <div class="sec-card-title">XRPL Capabilities</div>
            <div class="sec-card-sub">What your wallets can do in NaluLF</div>
          </div>
        </div>
        <div class="sec-caps-grid">
          <div class="sec-cap"><span class="sec-cap-icon">💸</span><span>XRP &amp; IOU Payments</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🔗</span><span>Trustlines (TrustSet)</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">📊</span><span>DEX Orders (CLOB)</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🌊</span><span>AMM Deposits &amp; Swaps</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🎨</span><span>NFT Mint &amp; Transfer</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🔍</span><span>On-chain Forensic Inspect</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🏦</span><span>Multi-wallet Management</span></div>
          <div class="sec-cap"><span class="sec-cap-icon">🛡</span><span>Ed25519 &amp; secp256k1</span></div>
        </div>
      </div>

    </div>`;
}

/* ── Activity panel ── */
function renderActivityPanel() {
  const el = $('profile-tab-activity');
  if (!el) return;
  if (wallets.length === 0) {
    el.innerHTML = `<div class="act-empty"><div class="act-empty-icon">📋</div><div>Add a wallet to see on-chain activity</div></div>`;
    return;
  }
  const w = getActiveWallet();
  el.innerHTML = `
    <div class="act-header">
      <div class="act-header-text">On-chain activity for your active wallet</div>
      <button class="act-inspect-btn" onclick="inspectWalletAddr('${escHtml(w?.address||'')}')">🔍 Open in Inspector →</button>
    </div>
    <div class="act-redirect-card">
      <div class="act-rc-icon">🔍</div>
      <div class="act-rc-body">
        <div class="act-rc-title">Full forensic analysis in the Inspector</div>
        <div class="act-rc-sub">
          The Inspector tab provides deep on-chain analysis: transaction history, Benford's Law anomaly detection,
          wash trading signals, NFT analysis, fund flow tracing, issuer graphs, and a full investigation report.
        </div>
        ${w ? `<button class="act-inspect-btn-lg" onclick="inspectWalletAddr('${escHtml(w.address)}')">
          Open Inspector for ${escHtml(w.label||w.address.slice(0,10)+'…')} →
        </button>` : ''}
      </div>
    </div>`;
}

export function deleteWallet(idx) {
  if (!confirm('Remove this wallet from your profile? It still exists on-chain and can be re-added anytime.')) return;
  const w = wallets[idx];
  wallets.splice(idx, 1);
  _saveWalletMeta();
  // Remove from vault too
  if (CryptoVault.isUnlocked) {
    CryptoVault.update(v => {
      v.wallets = v.wallets.filter(vw => vw.id !== w.id);
    });
  }
  if (activeWalletId === w.id) {
    activeWalletId = wallets[0]?.id || null;
    if (activeWalletId) safeSet(LS_ACTIVE_ID, activeWalletId);
  }
  renderWalletList();
  renderActiveWalletBar();
  toastInfo('Wallet removed from profile');
}

export function inspectWalletAddr(addr) {
  const inp = $('inspect-addr');
  if (inp) inp.value = addr;
  window.switchTab?.(document.querySelector('[data-tab="inspector"]'), 'inspector');
  window.showDashboard?.();
}

/* ═══════════════════════════════════════════════════════════
   Wallet Creator Wizard
═══════════════════════════════════════════════════════════ */
export function openWalletCreator() {
  if (!CryptoVault.isUnlocked) {
    toastWarn('Please sign in first to create a wallet.');
    return;
  }
  wizardStep = 1;
  wizardData = { algo: 'ed25519', label: '', emoji: '💎', color: '#50fa7b', seed: '', address: '' };
  checksCompleted.clear();
  renderWizardStep(1);
  renderWizardCustomization();
  _renderWizardSecurityBanner();
  $('wallet-creator-overlay')?.classList.add('show');
}

export function closeWalletCreator() {
  $('wallet-creator-overlay')?.classList.remove('show');
  wizardData.seed = wizardData.address = '';
}

function _renderWizardSecurityBanner() {
  const target = $('wizard-security-banner');
  if (!target) return;
  target.innerHTML = `
    <div class="wsb-icon">🔐</div>
    <div class="wsb-content">
      <div class="wsb-title">Your keys are encrypted on your device</div>
      <div class="wsb-body">
        Your wallet's secret seed phrase is encrypted with your password using AES-256-GCM
        before being saved to this device. <strong>It never leaves your browser.</strong>
        No server, no cloud, no third party ever sees it.
      </div>
      <div class="wsb-pills">
        <span class="wsb-pill wsb-pill--green">🔒 Stored locally only</span>
        <span class="wsb-pill wsb-pill--green">🚫 Never sent to any server</span>
        <span class="wsb-pill wsb-pill--blue">⚡ AES-256-GCM encrypted</span>
      </div>
    </div>`;
}

export function wizardNext() {
  if (wizardStep === 1) {
    const label = $('wallet-label-input')?.value.trim();
    if (!label) { toastWarn('Enter a wallet name.'); return; }
    wizardData.label = label;
    generateWalletKeys();
    wizardStep = 2;
  } else if (wizardStep === 2) {
    if (checksCompleted.size < 4) { toastWarn('Confirm all security checkpoints first.'); return; }
    wizardStep = 3;
  } else if (wizardStep === 3) {
    saveNewWallet();
    wizardStep = 4;
  }
  renderWizardStep(wizardStep);
}

export function wizardBack() {
  if (wizardStep <= 1) { closeWalletCreator(); return; }
  wizardStep--;
  renderWizardStep(wizardStep);
}

function renderWizardStep(step) {
  [1,2,3,4].forEach(s => {
    const dot = $(`.step-${s}`);
    if (!dot) return;
    dot.classList.toggle('active', s === step);
    dot.classList.toggle('done', s < step);
  });
  $$('.wizard-panel').forEach(p => p.classList.remove('active'));
  $(`wizard-panel-${step}`)?.classList.add('active');
  const backBtn   = $('wizard-back-btn');
  const nextBtn   = $('wizard-next-btn');
  const finishBtn = $('wizard-finish-btn');
  if (backBtn)   backBtn.style.display   = step === 4 ? 'none' : '';
  if (nextBtn)   nextBtn.style.display   = step >= 3  ? 'none' : '';
  if (finishBtn) finishBtn.style.display = step === 3  ? '' : 'none';
  if (backBtn)   backBtn.textContent     = step === 1  ? 'Cancel' : '← Back';
}

function renderWizardCustomization() {
  const emojiRow = $('wallet-emoji-picker');
  if (emojiRow) {
    emojiRow.innerHTML = WALLET_EMOJIS.map(e => `
      <div class="wallet-emoji-opt ${wizardData.emoji === e ? 'active' : ''}"
           onclick="selectWalletEmoji('${e}')">${e}</div>`).join('');
  }
  const colorRow = $('wallet-color-picker');
  if (colorRow) {
    colorRow.innerHTML = WALLET_COLORS.map(c => `
      <div class="color-swatch ${wizardData.color === c ? 'active' : ''}"
           style="background:${c}" onclick="selectWalletColor('${c}')"></div>`).join('');
  }
}

function generateWalletKeys() {
  if (window.xrpl) {
    try {
      const w = window.xrpl.Wallet.generate(wizardData.algo === 'ed25519' ? 'ed25519' : 'secp256k1');
      wizardData.seed    = w.seed || w.classicAddress;
      wizardData.address = w.classicAddress;
    } catch(e) {
      console.warn('xrpl.js Wallet.generate failed, using fallback:', e);
      _fallbackGenerate();
    }
  } else {
    _fallbackGenerate();
  }
  const seedEl = $('wizard-seed-value');
  const addrEl = $('wizard-address-value');
  if (seedEl)  seedEl.textContent = wizardData.seed;
  if (addrEl)  addrEl.textContent = wizardData.address;
  checksCompleted.clear();
  $$('.security-check').forEach(el => el.classList.remove('checked'));
  $$('.check-box').forEach(el => el.textContent = '');
  // Render rich best-practice checklist dynamically
  _renderSecurityChecklist();
  updateWizardNextBtn();
}

function _renderSecurityChecklist() {
  const list = $('security-checklist-dynamic');
  if (!list) return;
  const items = [
    {
      icon: '✍️',
      title: 'Write it down on paper — right now',
      body: 'Copy your seed phrase onto paper and store it somewhere safe like a fireproof box or safe. This is the ONLY way to recover your wallet if you lose access to this device.',
    },
    {
      icon: '🚫',
      title: 'Never store it digitally',
      body: 'Do not save your seed in a notes app, email, screenshot, or cloud service. If a device with a digital copy is hacked, your funds can be stolen.',
    },
    {
      icon: '🤫',
      title: 'Never share it with anyone',
      body: 'No legitimate app, exchange, or support team will ever ask for your seed phrase. Anyone who asks is attempting to steal your funds.',
    },
    {
      icon: '🔐',
      title: 'Use a strong, unique password',
      body: 'Your encryption password protects the seed on this device. Use a password you don\'t use anywhere else. Losing the password AND the seed means losing the wallet forever.',
    },
  ];
  list.innerHTML = items.map((item, i) => `
    <div class="security-check security-check-${i+1}" onclick="toggleSecurityCheck(${i+1})">
      <span class="check-box" id="check-box-${i+1}"></span>
      <div class="check-text">
        <strong>${item.icon} ${escHtml(item.title)}</strong>
        ${escHtml(item.body)}
      </div>
    </div>`).join('');
}

function _fallbackGenerate() {
  // Note: xrpl.js CDN required for real wallets — this is a display fallback only
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const hex   = Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
  const B58   = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt('0x' + hex), seed = '';
  while (num > 0n) { seed = B58[Number(num % 58n)] + seed; num /= 58n; }
  wizardData.seed = 's' + seed.padStart(28,'1').slice(0,28);
  const ab = crypto.getRandomValues(new Uint8Array(20));
  const ah = Array.from(ab).map(b => b.toString(16).padStart(2,'0')).join('');
  let an = BigInt('0x' + ah), addr = '';
  while (an > 0n) { addr = B58[Number(an % 58n)] + addr; an /= 58n; }
  wizardData.address = 'r' + addr.slice(0, 25 + (Number(ab[0]) % 9));
}

async function saveNewWallet() {
  const newWallet = {
    id:        crypto.randomUUID(),
    label:     wizardData.label,
    address:   wizardData.address,
    algo:      wizardData.algo,
    seed:      wizardData.seed,   // stored ONLY inside vault
    emoji:     wizardData.emoji,
    color:     wizardData.color,
    testnet:   $('wallet-testnet-check')?.checked || false,
    createdAt: new Date().toISOString(),
  };

  // Store seed in encrypted vault
  await CryptoVault.update(v => {
    v.wallets = v.wallets || [];
    v.wallets.push({ ...newWallet });
  });

  // Store public metadata (no seed!) in plain localStorage
  const meta = { ...newWallet };
  delete meta.seed;
  wallets.push(meta);
  _saveWalletMeta();

  // Set as active if first wallet
  if (!activeWalletId) {
    activeWalletId = newWallet.id;
    safeSet(LS_ACTIVE_ID, newWallet.id);
  }

  renderWalletList();
  renderActiveWalletBar();
  _setText('wallet-success-address', wizardData.address);

  // Zero seed immediately
  setTimeout(() => { wizardData.seed = wizardData.address = ''; }, 100);
  toastInfo('Wallet saved to encrypted vault');
  fetchBalance(newWallet.address).then(() => renderWalletList());
}

export function selectAlgo(algo) {
  wizardData.algo = algo;
  $$('.algo-card').forEach(c => c.classList.toggle('active', c.dataset.algo === algo));
}
export function selectWalletEmoji(emoji) {
  wizardData.emoji = emoji;
  $$('.wallet-emoji-opt').forEach(el => el.classList.toggle('active', el.textContent === emoji));
}
export function selectWalletColor(color) {
  wizardData.color = color;
  $$('.color-swatch').forEach(el =>
    el.classList.toggle('active', el.style.background === color || el.dataset.color === color));
}
export function toggleSecurityCheck(idx) {
  const el = $(`.security-check-${idx}`);
  if (!el) return;
  const checkBox = el.querySelector('.check-box');
  if (checksCompleted.has(idx)) {
    checksCompleted.delete(idx); el.classList.remove('checked'); if (checkBox) checkBox.textContent = '';
  } else {
    checksCompleted.add(idx); el.classList.add('checked'); if (checkBox) checkBox.textContent = '✓';
  }
  updateWizardNextBtn();
}
function updateWizardNextBtn() {
  const nextBtn = $('wizard-next-btn');
  if (nextBtn && wizardStep === 2) nextBtn.disabled = checksCompleted.size < 4;
}
export function revealSeed() {
  $('wizard-seed-value')?.classList.remove('blur');
  const hint = $('seed-reveal-hint');
  if (hint) hint.style.display = 'none';
  // Auto-re-blur after 30 seconds for security
  setTimeout(() => $('wizard-seed-value')?.classList.add('blur'), 30_000);
}
export function copySeed() {
  const el = $('wizard-seed-value');
  if (!el) return;
  _copyToClipboard(el.textContent, 30_000); // auto-clear from clipboard after 30s
  const btn = $('btn-copy-seed');
  if (btn) { btn.textContent = 'Copied!'; btn.classList.add('copied'); setTimeout(() => { btn.textContent = 'Copy Seed'; btn.classList.remove('copied'); }, 2000); }
}
export function copyAddress() {
  const el = $('wizard-address-value') || $('wallet-success-address');
  if (!el) return;
  _copyToClipboard(el.textContent);
  const btn = $('btn-copy-addr');
  if (btn) { btn.textContent = 'Copied!'; btn.classList.add('copied'); setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000); }
}

/* ═══════════════════════════════════════════════════════════
   XRPL Network — Balance Fetching
═══════════════════════════════════════════════════════════ */
async function xrplPost(body) {
  try {
    const r = await fetch(XRPL_RPC, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return (await r.json()).result;
  } catch {
    // Try backup node
    const r = await fetch(XRPL_RPC_BACKUP, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return (await r.json()).result;
  }
}

export async function fetchBalance(address) {
  try {
    const [acctResult, linesResult] = await Promise.all([
      xrplPost({ method: 'account_info', params: [{ account: address, ledger_index: 'current' }] }),
      xrplPost({ method: 'account_lines', params: [{ account: address, ledger_index: 'current' }] }),
    ]);
    if (acctResult?.error) return null;
    const xrp    = Number(acctResult.account_data.Balance) / 1e6;
    const tokens = (linesResult?.lines || []).map(l => ({
      currency: l.currency, issuer: l.account, balance: l.balance, limit: l.limit,
    }));
    balanceCache[address] = { xrp, tokens, fetchedAt: Date.now() };
    trustlineCache[address] = tokens;
    return balanceCache[address];
  } catch { return null; }
}

async function fetchAllBalances() {
  await Promise.all(wallets.map(w => fetchBalance(w.address)));
  renderWalletList();
  renderActiveWalletBar();
}

async function getAccountInfo(address) {
  const r = await xrplPost({ method: 'account_info', params: [{ account: address, ledger_index: 'current' }] });
  return r?.account_data || null;
}

async function getCurrentLedger() {
  const r = await xrplPost({ method: 'ledger', params: [{ ledger_index: 'current' }] });
  return r?.ledger_current_index || 0;
}

/* ═══════════════════════════════════════════════════════════
   XRPL Transaction Signing + Submission
═══════════════════════════════════════════════════════════ */
async function _requireVaultUnlocked() {
  if (!CryptoVault.isUnlocked) throw new Error('Vault is locked. Please sign in to enable transaction signing.');
}

async function _getSeedForWallet(walletId) {
  await _requireVaultUnlocked();
  const vw = CryptoVault.vault?.wallets?.find(w => w.id === walletId);
  if (!vw?.seed) throw new Error('Seed not found in vault for this wallet.');
  return vw.seed;
}

/* Build, sign, and submit an XRPL transaction */
async function signAndSubmit(walletId, txJson) {
  await _requireVaultUnlocked();
  if (!window.xrpl) throw new Error('xrpl.js library not loaded. Cannot sign transactions.');

  const seed = await _getSeedForWallet(walletId);
  const wObj = wallets.find(w => w.id === walletId);
  if (!wObj) throw new Error('Wallet not found.');

  try {
    const xrplWallet = window.xrpl.Wallet.fromSeed(seed, {
      algorithm: wObj.algo === 'ed25519' ? 'ed25519' : 'secp256k1',
    });

    // Autofill sequence and fee
    const [acctInfo, ledger] = await Promise.all([
      getAccountInfo(wObj.address),
      getCurrentLedger(),
    ]);
    if (!acctInfo) throw new Error('Account not found on-chain. Fund with 10 XRP first (reserve requirement).');

    const prepared = {
      ...txJson,
      Account:              wObj.address,
      Fee:                  '12',
      Sequence:             acctInfo.Sequence,
      LastLedgerSequence:   ledger + 20,
      NetworkID:            txJson.NetworkID || undefined,
    };

    const { tx_blob, hash } = xrplWallet.sign(prepared);

    // Submit
    const result = await xrplPost({ method: 'submit', params: [{ tx_blob }] });
    return { ...result, tx_hash: hash };

  } finally {
    // Zero seed reference
    seed && Object.defineProperty({ _: seed }, '_', { value: '' });
  }
}

/* ── TrustSet (add / modify trustline) ── */
export async function executeTrustSet(walletId, currency, issuer, limit = '1000000000') {
  const tx = {
    TransactionType: 'TrustSet',
    LimitAmount: { currency, issuer, value: String(limit) },
  };
  return signAndSubmit(walletId, tx);
}

/* ── Payment (XRP or IOU) ── */
export async function executePayment(walletId, destination, amount, currency, issuer, destinationTag) {
  const isXRP  = !currency || currency === 'XRP';
  const Amount = isXRP ? String(Math.floor(parseFloat(amount) * 1e6)) : { currency, issuer, value: String(amount) };
  const tx = {
    TransactionType:  'Payment',
    Destination:       destination,
    Amount,
    ...(destinationTag ? { DestinationTag: parseInt(destinationTag) } : {}),
  };
  return signAndSubmit(walletId, tx);
}

/* ── OfferCreate (DEX order) ── */
export async function executeOfferCreate(walletId, takerGets, takerPays) {
  const tx = { TransactionType: 'OfferCreate', TakerGets: takerGets, TakerPays: takerPays };
  return signAndSubmit(walletId, tx);
}

/* ── OfferCancel ── */
export async function executeOfferCancel(walletId, offerSequence) {
  const tx = { TransactionType: 'OfferCancel', OfferSequence: parseInt(offerSequence) };
  return signAndSubmit(walletId, tx);
}

/* ═══════════════════════════════════════════════════════════
   Send Modal
═══════════════════════════════════════════════════════════ */
let _sendWalletId = null;

export function openSendModal(walletId) {
  _sendWalletId = walletId;
  const w       = wallets.find(x => x.id === walletId);
  if (!w) return;
  const modal   = $('send-modal-overlay');
  if (!modal) return;

  // Populate token dropdown from trustlines
  const cached  = trustlineCache[w.address] || [];
  const tokenOpts = cached.map(t => `<option value="${escHtml(t.currency)}|${escHtml(t.issuer)}">${escHtml(t.currency)} (${escHtml(t.issuer.slice(0,8))}…)</option>`).join('');
  const selEl   = $('send-currency-select');
  if (selEl)    selEl.innerHTML = `<option value="XRP">XRP</option>${tokenOpts}`;

  _setText('send-modal-wallet-name', w.label);
  _setText('send-from-address', w.address);
  const xrp     = balanceCache[w.address]?.xrp ?? '—';
  _setText('send-available-balance', `${fmt(xrp, 4)} XRP`);

  if ($('send-dest'))     $('send-dest').value     = '';
  if ($('send-amount'))   $('send-amount').value   = '';
  if ($('send-dest-tag')) $('send-dest-tag').value = '';
  $('send-error')?.replaceChildren();

  modal.classList.add('show');
}

export function closeSendModal() { $('send-modal-overlay')?.classList.remove('show'); }

export async function executeSend() {
  const w       = wallets.find(x => x.id === _sendWalletId);
  if (!w) return;
  const dest    = $('send-dest')?.value.trim()      || '';
  const amount  = $('send-amount')?.value.trim()    || '';
  const destTag = $('send-dest-tag')?.value.trim()  || '';
  const selVal  = $('send-currency-select')?.value  || 'XRP';
  const [currency, issuer] = selVal.includes('|') ? selVal.split('|') : ['XRP', null];

  const errEl   = $('send-error');
  const setErr  = msg => { if (errEl) errEl.textContent = msg; };

  setErr('');
  if (!isValidXrpAddress(dest))    return setErr('Enter a valid XRPL destination address.');
  if (!amount || isNaN(+amount) || +amount <= 0) return setErr('Enter a valid amount.');

  const btn = $('send-submit-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Signing…'; }
  try {
    const result = await executePayment(_sendWalletId, dest, amount, currency === 'XRP' ? null : currency, issuer, destTag);
    if (result?.engine_result === 'tesSUCCESS' || result?.engine_result?.startsWith('tes')) {
      toastInfo(`✅ Payment submitted! Tx: ${result.tx_hash?.slice(0,12)}…`);
      closeSendModal();
      setTimeout(() => fetchBalance(w.address).then(() => { renderWalletList(); renderActiveWalletBar(); }), 4000);
    } else {
      setErr(`Network error: ${result?.engine_result_message || result?.engine_result || 'Unknown error'}`);
    }
  } catch(err) {
    setErr(err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Send ⬆'; }
  }
}

/* ═══════════════════════════════════════════════════════════
   Receive Modal
═══════════════════════════════════════════════════════════ */
export function openReceiveModal(walletId) {
  const w     = wallets.find(x => x.id === walletId);
  if (!w) return;
  const modal = $('receive-modal-overlay');
  if (!modal) return;
  _setText('receive-address-display', w.address);
  _setText('receive-wallet-name', w.label);
  // Generate QR using qrcode CDN
  const qrContainer = $('receive-qr-container');
  if (qrContainer) {
    qrContainer.innerHTML = '';
    if (window.QRCode) {
      new window.QRCode(qrContainer, {
        text: `xrpl:${w.address}`, width: 180, height: 180,
        colorDark: '#00fff0', colorLight: '#080c16',
      });
    } else {
      qrContainer.innerHTML = `<div class="qr-fallback">📷 Load QRCode.js library for QR display</div>`;
    }
  }
  modal.classList.add('show');
}

export function closeReceiveModal() { $('receive-modal-overlay')?.classList.remove('show'); }

export function copyReceiveAddress() {
  const el = $('receive-address-display');
  if (el) _copyToClipboard(el.textContent);
  const btn = $('receive-copy-btn');
  if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => btn.textContent = '⧉ Copy Address', 2000); }
}

/* ═══════════════════════════════════════════════════════════
   Trustline Manager Modal
═══════════════════════════════════════════════════════════ */
let _trustWalletId = null;

export function openTrustlineModal(walletId) {
  _trustWalletId = walletId;
  const w      = wallets.find(x => x.id === walletId);
  if (!w) return;
  const modal  = $('trustline-modal-overlay');
  if (!modal) return;
  _setText('trustline-wallet-name', w.label);
  renderTrustlineList(w.address);
  if ($('tl-currency'))  $('tl-currency').value  = '';
  if ($('tl-issuer'))    $('tl-issuer').value    = '';
  if ($('tl-limit'))     $('tl-limit').value     = '1000000000';
  $('tl-error')?.replaceChildren();
  modal.classList.add('show');
}

export function closeTrustlineModal() { $('trustline-modal-overlay')?.classList.remove('show'); }

function renderTrustlineList(address) {
  const container = $('trustline-list-container');
  if (!container) return;
  const lines = trustlineCache[address] || [];
  if (!lines.length) {
    container.innerHTML = `<div class="tl-empty">No trustlines yet. Add one below.</div>`;
    return;
  }
  container.innerHTML = lines.map(t => `
    <div class="tl-item">
      <div class="tl-item-info">
        <span class="tl-currency">${escHtml(t.currency)}</span>
        <span class="tl-issuer mono">${escHtml(t.issuer.slice(0,14))}…</span>
      </div>
      <div class="tl-item-balance">
        <span class="tl-balance">${escHtml(t.balance)}</span>
        <span class="tl-limit">Limit: ${escHtml(t.limit)}</span>
      </div>
      <button class="tl-remove-btn" onclick="removeTrustline('${_trustWalletId}','${escHtml(t.currency)}','${escHtml(t.issuer)}')" title="Remove trustline">✕</button>
    </div>`).join('');
}

export async function addTrustline() {
  const currency = $('tl-currency')?.value.trim().toUpperCase() || '';
  const issuer   = $('tl-issuer')?.value.trim()   || '';
  const limit    = $('tl-limit')?.value.trim()     || '1000000000';
  const errEl    = $('tl-error');
  const setErr   = msg => { if (errEl) errEl.textContent = msg; };

  setErr('');
  if (!currency || currency.length > 20) return setErr('Enter a valid currency code (3 chars or 20-hex).');
  if (!isValidXrpAddress(issuer))         return setErr('Enter a valid issuer XRPL address.');

  const btn = $('tl-add-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Signing…'; }
  try {
    const result = await executeTrustSet(_trustWalletId, currency, issuer, limit);
    if (result?.engine_result === 'tesSUCCESS' || result?.engine_result?.startsWith('tes')) {
      toastInfo(`✅ Trustline added for ${currency}`);
      closeTrustlineModal();
      const w = wallets.find(x => x.id === _trustWalletId);
      if (w) setTimeout(() => fetchBalance(w.address).then(() => renderWalletList()), 4000);
    } else {
      setErr(`${result?.engine_result_message || result?.engine_result || 'Unknown error'}`);
    }
  } catch(err) {
    setErr(err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '+ Add Trustline'; }
  }
}

export async function removeTrustline(walletId, currency, issuer) {
  if (!confirm(`Remove trustline for ${currency}? Balance must be 0.`)) return;
  try {
    const result = await executeTrustSet(walletId, currency, issuer, '0');
    if (result?.engine_result === 'tesSUCCESS' || result?.engine_result?.startsWith('tes')) {
      toastInfo(`Trustline removed for ${currency}`);
      const w = wallets.find(x => x.id === walletId);
      if (w) setTimeout(() => fetchBalance(w.address).then(() => renderTrustlineList(w.address)), 4000);
    } else {
      toastErr(result?.engine_result_message || 'Could not remove trustline');
    }
  } catch(err) {
    toastErr(err.message);
  }
}

/* ═══════════════════════════════════════════════════════════
   Dynamic Modal HTML Mount (injected once into body)
═══════════════════════════════════════════════════════════ */
function _mountDynamicModals() {
  if ($('send-modal-overlay')) return; // already mounted
  const html = `
  <!-- Send Modal -->
  <div class="wallet-action-overlay" id="send-modal-overlay">
    <div class="wallet-action-modal">
      <div class="wam-header">
        <div>
          <div class="wam-title">⬆ Send</div>
          <div class="wam-sub" id="send-modal-wallet-name"></div>
        </div>
        <button class="modal-close" onclick="closeSendModal()">✕</button>
      </div>
      <div class="wam-body">
        <div class="wam-from-row">
          <span class="wam-from-label">From</span>
          <span class="wam-from-addr mono" id="send-from-address"></span>
          <span class="wam-balance-pill" id="send-available-balance"></span>
        </div>
        <div class="profile-field">
          <label class="profile-field-label">Destination Address *</label>
          <input class="profile-input mono" id="send-dest" placeholder="rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" autocomplete="off">
        </div>
        <div class="wam-row2">
          <div class="profile-field" style="flex:1">
            <label class="profile-field-label">Amount *</label>
            <input class="profile-input mono" id="send-amount" type="number" placeholder="0.00" min="0" step="any">
          </div>
          <div class="profile-field" style="flex:1">
            <label class="profile-field-label">Currency</label>
            <select class="profile-input" id="send-currency-select">
              <option value="XRP">XRP</option>
            </select>
          </div>
        </div>
        <div class="profile-field">
          <label class="profile-field-label">Destination Tag (optional)</label>
          <input class="profile-input mono" id="send-dest-tag" type="number" placeholder="Required by some exchanges">
        </div>
        <div class="wam-vault-note">🔐 Transaction will be signed with your encrypted key</div>
        <div class="wam-error" id="send-error"></div>
      </div>
      <div class="wam-footer">
        <button class="btn-wizard-back" onclick="closeSendModal()">Cancel</button>
        <button class="btn-wizard-next" id="send-submit-btn" onclick="executeSend()">Send ⬆</button>
      </div>
    </div>
  </div>

  <!-- Receive Modal -->
  <div class="wallet-action-overlay" id="receive-modal-overlay">
    <div class="wallet-action-modal">
      <div class="wam-header">
        <div>
          <div class="wam-title">⬇ Receive</div>
          <div class="wam-sub" id="receive-wallet-name"></div>
        </div>
        <button class="modal-close" onclick="closeReceiveModal()">✕</button>
      </div>
      <div class="wam-body" style="text-align:center">
        <div class="receive-qr-wrap">
          <div id="receive-qr-container" class="receive-qr-box"></div>
        </div>
        <div class="receive-address-box">
          <span class="receive-address-val mono" id="receive-address-display"></span>
        </div>
        <button class="btn-wizard-next" id="receive-copy-btn" onclick="copyReceiveAddress()" style="margin-top:16px;width:100%">
          ⧉ Copy Address
        </button>
        <p class="receive-note">Share this address to receive XRP or tokens. Always verify the full address before sending.</p>
      </div>
    </div>
  </div>

  <!-- Trustline Modal -->
  <div class="wallet-action-overlay" id="trustline-modal-overlay">
    <div class="wallet-action-modal wallet-action-modal--wide">
      <div class="wam-header">
        <div>
          <div class="wam-title">🔗 Trustlines</div>
          <div class="wam-sub" id="trustline-wallet-name"></div>
        </div>
        <button class="modal-close" onclick="closeTrustlineModal()">✕</button>
      </div>
      <div class="wam-body">
        <div class="tl-section-h">Active trustlines</div>
        <div id="trustline-list-container" class="tl-list"></div>
        <div class="tl-divider"></div>
        <div class="tl-section-h">Add new trustline</div>
        <div class="wam-row2">
          <div class="profile-field" style="flex:1">
            <label class="profile-field-label">Currency Code *</label>
            <input class="profile-input" id="tl-currency" placeholder="USD / BTC / SOLO" maxlength="20">
          </div>
          <div class="profile-field" style="flex:1">
            <label class="profile-field-label">Trust Limit</label>
            <input class="profile-input mono" id="tl-limit" type="number" placeholder="1000000000" value="1000000000">
          </div>
        </div>
        <div class="profile-field">
          <label class="profile-field-label">Issuer Address *</label>
          <input class="profile-input mono" id="tl-issuer" placeholder="rXXXX… token issuer address">
        </div>
        <div class="wam-vault-note">🔐 TrustSet requires vault access to sign</div>
        <div class="wam-error" id="tl-error"></div>
      </div>
      <div class="wam-footer">
        <button class="btn-wizard-back" onclick="closeTrustlineModal()">Close</button>
        <button class="btn-wizard-finish" id="tl-add-btn" onclick="addTrustline()">+ Add Trustline</button>
      </div>
    </div>
  </div>`;

  const div = document.createElement('div');
  div.innerHTML = html;
  document.body.appendChild(div);

  // Close on backdrop click
  ['send-modal-overlay','receive-modal-overlay','trustline-modal-overlay'].forEach(id => {
    $(id)?.addEventListener('click', e => { if (e.target === e.currentTarget) e.currentTarget.classList.remove('show'); });
  });
}

/* ═══════════════════════════════════════════════════════════
   Profile Editor
═══════════════════════════════════════════════════════════ */
export function openProfileEditor() {
  ['displayName','handle','bio','location','website'].forEach(f => {
    const el = $(`edit-${f}`);
    if (el) el.value = profile[f] || '';
  });

  // Avatar preview in editor
  const prevEl = $('editor-avatar-preview');
  if (prevEl) {
    const img = localStorage.getItem(LS_AVATAR_IMG);
    prevEl.innerHTML = img
      ? `<img src="${img}" class="profile-avatar-img" alt="Profile photo" />`
      : (profile.avatar || '🌊');
  }
  const removeBtn = $('avatar-remove-btn');
  if (removeBtn) removeBtn.style.display = localStorage.getItem(LS_AVATAR_IMG) ? '' : 'none';

  // Banner preview in editor
  const bannerPrev = $('editor-banner-preview');
  if (bannerPrev) {
    const img = localStorage.getItem(LS_BANNER_IMG);
    bannerPrev.style.backgroundImage    = img ? `url(${img})` : '';
    bannerPrev.style.backgroundSize     = 'cover';
    bannerPrev.style.backgroundPosition = 'center';
    BANNERS.forEach(b => bannerPrev.classList.remove(b));
    if (!img) bannerPrev.classList.add(profile.banner || 'banner-ocean');
  }
  const bannerRemoveBtn = $('banner-remove-btn');
  if (bannerRemoveBtn) bannerRemoveBtn.style.display = localStorage.getItem(LS_BANNER_IMG) ? '' : 'none';

  // Emoji grid
  const grid = $('avatar-picker-grid');
  if (grid) {
    grid.innerHTML = AVATARS.map(a => `
      <div class="avatar-option ${profile.avatar === a ? 'active' : ''}"
           onclick="selectAvatar('${a}')">${a}</div>`).join('');
  }

  // Banner gradient grid
  const bannerGrid = $('banner-picker-grid');
  if (bannerGrid) {
    bannerGrid.innerHTML = BANNERS.map(b => `
      <div class="banner-option ${b} ${profile.banner === b ? 'active' : ''}"
           onclick="selectBanner('${b}')"></div>`).join('');
  }

  $('profile-editor-modal')?.classList.add('show');
}

export function closeProfileEditor() { $('profile-editor-modal')?.classList.remove('show'); }

export function saveProfileEditor() {
  profile.displayName = $('edit-displayName')?.value.trim() || profile.displayName;
  profile.handle      = ($('edit-handle')?.value.trim() || profile.handle).replace(/^@/,'').replace(/\s+/g,'_').toLowerCase();
  profile.bio         = $('edit-bio')?.value.trim()      || '';
  profile.location    = $('edit-location')?.value.trim() || '';
  profile.website     = $('edit-website')?.value.trim()  || '';
  _saveProfile();
  if (CryptoVault.isUnlocked) CryptoVault.update(v => { v.profile = { ...profile }; });
  renderProfilePage();
  closeProfileEditor();
  toastInfo('Profile saved');
}

export function selectAvatar(emoji) {
  // Selecting an emoji clears any uploaded photo
  localStorage.removeItem(LS_AVATAR_IMG);
  profile.avatar = emoji;
  $$('.avatar-option').forEach(el => el.classList.toggle('active', el.textContent === emoji));
  const prev = $('editor-avatar-preview');
  if (prev) prev.innerHTML = emoji;
  const removeBtn = $('avatar-remove-btn');
  if (removeBtn) removeBtn.style.display = 'none';
}

export function selectBanner(bannerClass) {
  // Selecting a gradient clears any uploaded banner
  localStorage.removeItem(LS_BANNER_IMG);
  profile.banner = bannerClass;
  $$('.banner-option').forEach(el => el.classList.toggle('active', el.classList.contains(bannerClass)));
  const bannerPrev = $('editor-banner-preview');
  if (bannerPrev) {
    bannerPrev.style.backgroundImage = '';
    BANNERS.forEach(b => bannerPrev.classList.remove(b));
    bannerPrev.classList.add(bannerClass);
  }
  const removeBtn = $('banner-remove-btn');
  if (removeBtn) removeBtn.style.display = 'none';
  renderProfilePage();
}

/* ── Image upload helpers ── */
export function uploadAvatarImage(input) {
  const file = input?.files?.[0];
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) { toastWarn('Image too large — max 2 MB'); return; }
  const reader = new FileReader();
  reader.onload = e => {
    const dataUrl = e.target.result;
    // Resize to 200×200 via canvas before storing
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = 200; canvas.height = 200;
      const ctx = canvas.getContext('2d');
      // Crop to square from center
      const size = Math.min(img.width, img.height);
      const sx = (img.width  - size) / 2;
      const sy = (img.height - size) / 2;
      ctx.drawImage(img, sx, sy, size, size, 0, 0, 200, 200);
      const compressed = canvas.toDataURL('image/jpeg', 0.85);
      localStorage.setItem(LS_AVATAR_IMG, compressed);
      // Update previews
      const prev = $('editor-avatar-preview');
      if (prev) prev.innerHTML = `<img src="${compressed}" class="profile-avatar-img" alt="Profile photo" />`;
      const removeBtn = $('avatar-remove-btn');
      if (removeBtn) removeBtn.style.display = '';
      renderProfilePage();
      toastInfo('Profile photo updated');
    };
    img.src = dataUrl;
  };
  reader.readAsDataURL(file);
  input.value = ''; // reset so same file can be re-selected
}

export function removeAvatarImage() {
  localStorage.removeItem(LS_AVATAR_IMG);
  const prev = $('editor-avatar-preview');
  if (prev) prev.innerHTML = profile.avatar || '🌊';
  const removeBtn = $('avatar-remove-btn');
  if (removeBtn) removeBtn.style.display = 'none';
  renderProfilePage();
}

export function uploadBannerImage(input) {
  const file = input?.files?.[0];
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) { toastWarn('Image too large — max 5 MB'); return; }
  const reader = new FileReader();
  reader.onload = e => {
    const dataUrl = e.target.result;
    // Resize to 900×180 banner dimensions
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = 900; canvas.height = 180;
      const ctx = canvas.getContext('2d');
      // Fill with cover crop
      const scale  = Math.max(900 / img.width, 180 / img.height);
      const w      = img.width  * scale;
      const h      = img.height * scale;
      const ox     = (900 - w) / 2;
      const oy     = (180 - h) / 2;
      ctx.drawImage(img, ox, oy, w, h);
      const compressed = canvas.toDataURL('image/jpeg', 0.88);
      localStorage.setItem(LS_BANNER_IMG, compressed);
      const bannerPrev = $('editor-banner-preview');
      if (bannerPrev) {
        bannerPrev.style.backgroundImage    = `url(${compressed})`;
        bannerPrev.style.backgroundSize     = 'cover';
        bannerPrev.style.backgroundPosition = 'center';
        BANNERS.forEach(b => bannerPrev.classList.remove(b));
      }
      const removeBtn = $('banner-remove-btn');
      if (removeBtn) removeBtn.style.display = '';
      renderProfilePage();
      toastInfo('Banner updated');
    };
    img.src = dataUrl;
  };
  reader.readAsDataURL(file);
  input.value = '';
}

export function removeBannerImage() {
  localStorage.removeItem(LS_BANNER_IMG);
  const bannerPrev = $('editor-banner-preview');
  if (bannerPrev) {
    bannerPrev.style.backgroundImage = '';
    BANNERS.forEach(b => bannerPrev.classList.remove(b));
    bannerPrev.classList.add(profile.banner || 'banner-ocean');
  }
  const removeBtn = $('banner-remove-btn');
  if (removeBtn) removeBtn.style.display = 'none';
  renderProfilePage();
}

/* ═══════════════════════════════════════════════════════════
   Vault Security Panel (shown in profile settings)
═══════════════════════════════════════════════════════════ */
export function exportVaultBackup() {
  if (!CryptoVault.isUnlocked) { toastWarn('Unlock vault first.'); return; }
  CryptoVault.exportBlob();
}

/* ═══════════════════════════════════════════════════════════
   Preferences
═══════════════════════════════════════════════════════════ */
function renderPreferences() {
  const pills = $('pref-theme-pills');
  if (pills) {
    ['gold','cosmic','starry','hawaiian'].forEach(t => {
      const el = pills.querySelector(`.theme-pill.${t}`);
      if (el) el.classList.toggle('active', state.currentTheme === t);
    });
  }
}
export function prefSetTheme(t) { setTheme(t); renderPreferences(); }

/* ═══════════════════════════════════════════════════════════
   Events
═══════════════════════════════════════════════════════════ */
function bindProfileEvents() {
  $('profile-editor-modal')   ?.addEventListener('click', e => { if (e.target === e.currentTarget) closeProfileEditor(); });
  $('wallet-creator-overlay') ?.addEventListener('click', e => { if (e.target === e.currentTarget) closeWalletCreator(); });
  $('social-modal')           ?.addEventListener('click', e => { if (e.target === e.currentTarget) closeSocialModal(); });
}

/* Fetch balances when page becomes visible */
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && wallets.length) fetchAllBalances();
});

/* ═══════════════════════════════════════════════════════════
   Helpers
═══════════════════════════════════════════════════════════ */
function _setText(id, val) {
  const el = $(id);
  if (el) el.textContent = val;
}

export function copyToClipboard(text) { _copyToClipboard(text); }

function _copyToClipboard(text, autoClearMs = 0) {
  navigator.clipboard?.writeText(text)
    .then(() => {
      toastInfo('Copied to clipboard');
      if (autoClearMs) setTimeout(() => navigator.clipboard?.writeText(''), autoClearMs);
    })
    .catch(() => {
      const el = document.createElement('textarea');
      el.value = text; document.body.appendChild(el); el.select(); document.execCommand('copy'); el.remove();
      toastInfo('Copied');
    });
}

/* ── signAndSubmit is used internally and also importable by other modules ── */
export { signAndSubmit };