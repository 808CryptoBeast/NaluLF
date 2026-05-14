/* =====================================================
   main.js — Application Entry Point
   ===================================================== */
import { restoreTheme, setTheme, cycleTheme } from './theme.js';
import { showLandingPage, showDashboard, showProfile, switchTab } from './nav.js';
import { openAuth, closeAuth, setAuthMode, submitAuth, logout, restoreSession } from './auth.js';
import { initDashboard } from './dashboard.js';
import { initInspector, runInspect } from './inspector.js';
import { initNetwork, measureLatency } from './network.js';
import { initProfile, openProfileEditor, closeProfileEditor, saveProfileEditor,
         openWalletCreator, closeWalletCreator, wizardNext, wizardBack,
         openSocialModal, closeSocialModal, saveSocialModal, deleteSocial,
         viewSocial, deleteWallet, inspectWalletAddr, selectAlgo,
         selectWalletEmoji, selectWalletColor, toggleSecurityCheck,
         revealSeed, copySeed, copyAddress, copyToClipboard,
         selectAvatar, selectBanner, prefSetTheme } from './profile.js';
import { buildLandingContent, initReveal } from './landing.js';
import { initParticles } from './particles.js';
import { openCmdk, closeCmdk, setupCmdkListeners } from './cmdk.js';

/* ── Global onclick bridges ── */
window.openAuth            = m    => openAuth(m);
window.closeAuth           = ()   => closeAuth();
window.setAuthMode         = m    => setAuthMode(m);
window.submitAuth          = ()   => submitAuth();
window.logout              = ()   => logout();
window.goHome              = ()   => showLandingPage();
window.showLandingPage     = ()   => showLandingPage();
window.showProfile         = ()   => showProfile();
window.switchTab           = (b,id) => switchTab(b, id);
window.runInspect          = ()   => runInspect();
window.closeCommandPalette = ()   => closeCmdk();
window.setTheme            = t    => setTheme(t);
window.cycleTheme          = ()   => cycleTheme();
window.measureLatency      = ()   => measureLatency();

// Profile
window.openProfileEditor   = ()   => openProfileEditor();
window.closeProfileEditor  = ()   => closeProfileEditor();
window.saveProfileEditor   = ()   => saveProfileEditor();
window.selectAvatar        = e    => selectAvatar(e);
window.selectBanner        = b    => selectBanner(b);
window.prefSetTheme        = t    => prefSetTheme(t);

// Wallet creator
window.openWalletCreator   = ()   => openWalletCreator();
window.closeWalletCreator  = ()   => closeWalletCreator();
window.wizardNext          = ()   => wizardNext();
window.wizardBack          = ()   => wizardBack();
window.selectAlgo          = a    => selectAlgo(a);
window.selectWalletEmoji   = e    => selectWalletEmoji(e);
window.selectWalletColor   = c    => selectWalletColor(c);
window.toggleSecurityCheck = i    => toggleSecurityCheck(i);
window.revealSeed          = ()   => revealSeed();
window.copySeed            = ()   => copySeed();
window.copyAddress         = ()   => copyAddress();
window.copyToClipboard     = t    => copyToClipboard(t);
window.deleteWallet        = i    => deleteWallet(i);
window.inspectWalletAddr   = a    => inspectWalletAddr(a);

// Social
window.openSocialModal     = id   => openSocialModal(id);
window.closeSocialModal    = ()   => closeSocialModal();
window.saveSocialModal     = ()   => saveSocialModal();
window.deleteSocial        = ()   => deleteSocial();
window.viewSocial          = id   => viewSocial(id);

// cmdk internal refs
window._openAuth   = openAuth;
window._goHome     = showLandingPage;
window._cycleTheme = cycleTheme;
window._showProfile = showProfile;

/* ── Boot ── */
document.addEventListener('DOMContentLoaded', () => {
  console.log('🌊 NaluLF: booting…');

  restoreTheme();
  showLandingPage();
  buildLandingContent();
  initReveal();
  initParticles();
  initDashboard();
  initInspector();
  initNetwork();
  setupCmdkListeners();
  initXrpPrice(); // ← XRP price ticker

  document.addEventListener('keydown', e => {
    const inInput = ['INPUT','TEXTAREA'].includes(document.activeElement?.tagName);
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); openCmdk(); return; }
    if (e.key === '/' && !inInput) { e.preventDefault(); openCmdk(); return; }
    if (e.key === 'Escape') { closeCmdk(); closeAuth(); closeProfileEditor(); closeWalletCreator(); closeSocialModal(); }
  });

  document.getElementById('auth-overlay')?.addEventListener('click', e => {
    if (e.target === e.currentTarget) closeAuth();
  });

  if (restoreSession()) {
    showDashboard();
    import('./xrpl.js').then(({ connectXRPL }) => connectXRPL());
    initProfile();
  }

  console.log('✅ NaluLF: ready');
});

/* ─────────────────────────────
   XRP Price Ticker (CoinGecko)
──────────────────────────────── */
function initXrpPrice() {
  fetchXrpPrice();
  setInterval(fetchXrpPrice, 30_000);
}

async function fetchXrpPrice() {
  try {
    const res  = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=ripple&vs_currencies=usd&include_24hr_change=true');
    const data = await res.json();
    if (data?.ripple) {
      const price  = data.ripple.usd;
      const change = data.ripple.usd_24h_change;
      const priceEl  = document.getElementById('xrpPrice');
      const changeEl = document.getElementById('xrpChange');
      if (priceEl)  priceEl.textContent  = `$${Number(price).toFixed(3)}`;
      if (changeEl) {
        const up = change >= 0;
        changeEl.textContent = `${up ? '+' : ''}${Number(change).toFixed(2)}%`;
        changeEl.className   = `xrp-price-change ${Math.abs(change) < 0.1 ? 'flat' : up ? 'up' : 'down'}`;
      }
    }
  } catch {
    // silently fail — keep last value
  }
}