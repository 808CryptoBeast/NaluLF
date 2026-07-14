/* =====================================================
   main.js — Application Entry Point
   ===================================================== */
import { restoreTheme, setTheme, cycleTheme } from './theme.js';
import { state } from './state.js';
import { showLandingPage, showDashboard, showProfile, switchTab } from './nav.js';
import {
  openAuth, closeAuth, showAuthView, authKeydown,
  submitSignIn, submitSignUp, refreshCaptcha,
  showForgotView, forgotRestoreFromFile, forgotWipeConfirm,
  forgotWipeExecute, forgotBackToOptions,
  submitSyncImport, exportVaultSyncCode, syncImportFromFile,
  signupNext, signupBack,
  logout, restoreSession
} from './auth.js';
import { initDashboard, setDashboardActive } from './dashboard.js';
import { initInspector, runInspect, setInspectorActive } from './inspector.js';
import { initNetwork, measureLatency, setNetworkActive } from './network.js';
import {
  initProfile, switchProfileTab, openProfileEditor, closeProfileEditor, saveProfileEditor,
  openWalletCreator, closeWalletCreator, wizardNext, wizardBack,
  openSocialModal, closeSocialModal, saveSocialModal, deleteSocial,
  viewSocial, deleteWallet, inspectWalletAddr, selectAlgo,
  selectWalletEmoji, selectWalletColor, toggleSecurityCheck,
  revealSeed, copySeed, copyAddress, copyToClipboard,
  selectAvatar, selectBanner,
  uploadAvatarImage, removeAvatarImage,
  uploadBannerImage, removeBannerImage, prefSetTheme,
  setPrefCurrency, setPrefNetwork, setPrefAutoLock,
  openPublicProfilePreview,
  logActivity, exportVaultBackup,
  toggleWalletDrawer, switchWalletDrawerTab, cancelOffer,
  fetchBalance, setActiveWallet,
  openImportAddressModal, closeImportAddressModal, importWatchOnlyWallet,
  openImportSeedModal, closeImportSeedModal, executeImportFromSeed,
  openTokenDetailsModal, closeTokenDetailsModal,
  refreshXrplDashboard, refreshMarketData, refreshNftGallery,
  refreshAmmPools, refreshPoolExplorer, loadCustomAmmPool, sendNft,
  toggleSeedBackupStatus, setDexPair, setDexInterval, setDexChartType, refreshDexChart,
  setComparePair, toggleIndicator, toggleTerminalTheme, toggleChartFullscreen,
  exportChartPng, saveChartLayoutPreset, loadChartLayoutPreset,
  setIndicatorFromDropdown, setDrawingTool, clearAllDrawings,
  toggleIndicatorMenu, toggleChartMoreMenu, setIndicatorQuery, addIndicatorFromMenu, removeIndicator, openIndicatorSettings,
  closeIndicatorSettings, applyIndicatorSettings, resetIndicatorSettings,
  copyChartLink, toggleThreeEffects, setThreeEffects,
  zoomChartIn, zoomChartOut, panChartLeft, panChartRight,
  toggleEducationPanel, selectEducationTab,
  searchTokens, addTokenToWatchlist, removeTokenFromWatchlist, openTokenOnChart, lookupIssuedAsset,
  loadToken,
  refreshTokenDiscovery, refreshRecentTransactions,
  setTokenFilter, selectTokenDetails,
  showMoreIssuedTokens, showAllIssuedTokens, resetIssuedTokenLimit
} from './profile.js';
import { buildLandingContent, initReveal } from './landing.js';
import { initParticles } from './particles.js';
import { openCmdk, closeCmdk, setupCmdkListeners } from './cmdk.js';
import { isReactProfileEnabled, mountReactProfile } from './profile-react-bridge.js';

// Exposed so the separately-built React Profile app (a different module graph
// entirely — see vite.profile-app.config.ts) can read live shared state
// without bundling its own divergent copy of state.js. Mutate `state`
// in-place elsewhere as usual; this reference stays valid.
window.NaluLF = { state };

let appModulesInitialized = false;

function syncModuleLifecycle() {
  const page = state.currentPage;
  const tab = state.currentTab;
  const onDashboardStream = page === 'dashboard' && tab === 'stream';
  const onDashboardInspector = page === 'dashboard' && tab === 'inspector';
  const onDashboardNetwork = page === 'dashboard' && tab === 'network';

  setDashboardActive(onDashboardStream);
  setInspectorActive(onDashboardInspector);
  setNetworkActive(onDashboardNetwork);
}

function ensureAppModulesInitialized() {
  if (appModulesInitialized) return;
  initDashboard();
  initInspector();
  initNetwork();
  if (isReactProfileEnabled()) mountReactProfile();
  else initProfile();
  syncModuleLifecycle();
  appModulesInitialized = true;
}

/* ── Global onclick bridges ── */

// Auth
window.openAuth              = m    => openAuth(m);
window.closeAuth             = ()   => closeAuth();
window.showAuthView          = v    => showAuthView(v);
window.authKeydown           = e    => authKeydown(e);
window.submitSignIn          = ()   => submitSignIn();
window.submitSignUp          = ()   => submitSignUp();
window.refreshCaptcha        = ()   => refreshCaptcha();
window.showForgotView        = ()   => showForgotView();
window.forgotRestoreFromFile = ()   => forgotRestoreFromFile();
window.forgotWipeConfirm     = ()   => forgotWipeConfirm();
window.forgotWipeExecute     = ()   => forgotWipeExecute();
window.forgotBackToOptions   = ()   => forgotBackToOptions();
window.submitSyncImport      = ()   => submitSyncImport();
window.exportVaultSyncCode   = ()   => exportVaultSyncCode();
window.syncImportFromFile    = ()   => syncImportFromFile();
window.signupNext            = ()   => signupNext();
window.signupBack            = ()   => signupBack();
window.logout                = ()   => logout();

// Nav
window.goHome              = ()     => showLandingPage();
window.showLandingPage     = ()     => showLandingPage();
window.showProfile         = ()     => showProfile();
window.switchTab           = (b,id) => switchTab(b, id);

// Dashboard / Inspector / Network
window.runInspect          = ()   => runInspect();
window.closeCommandPalette = ()   => closeCmdk();
window.setTheme            = t    => setTheme(t);
window.cycleTheme          = ()   => cycleTheme();
window.measureLatency      = ()   => measureLatency();

// Profile
window.switchProfileTab         = t       => switchProfileTab(t);
window.openProfileEditor        = ()      => openProfileEditor();
window.closeProfileEditor       = ()      => closeProfileEditor();
window.saveProfileEditor        = ()      => saveProfileEditor();
window.selectAvatar             = e       => selectAvatar(e);
window.selectBanner             = b       => selectBanner(b);
window.uploadAvatarImage        = el      => uploadAvatarImage(el);
window.removeAvatarImage        = ()      => removeAvatarImage();
window.uploadBannerImage        = el      => uploadBannerImage(el);
window.removeBannerImage        = ()      => removeBannerImage();
window.prefSetTheme             = t       => prefSetTheme(t);
window.setPrefCurrency          = c       => setPrefCurrency(c);
window.setPrefNetwork           = n       => setPrefNetwork(n);
window.setPrefAutoLock          = m       => setPrefAutoLock(m);
window.openPublicProfilePreview = ()      => openPublicProfilePreview();
window.exportVaultBackup        = ()      => exportVaultBackup();
window.logActivity              = (t,d)   => logActivity(t,d);
window.toggleWalletDrawer       = id      => toggleWalletDrawer(id);
window.switchWalletDrawerTab    = (id,tab)=> switchWalletDrawerTab(id,tab);
window.cancelOffer              = (w,s,b) => cancelOffer(w,s,b);
window.fetchBalance             = addr    => fetchBalance(addr);
window.setActiveWallet          = id      => setActiveWallet(id);
window.openImportAddressModal   = ()      => openImportAddressModal();
window.closeImportAddressModal  = ()      => closeImportAddressModal();
window.importWatchOnlyWallet    = ()      => importWatchOnlyWallet();
window.openImportSeedModal      = ()      => openImportSeedModal();
window.closeImportSeedModal     = ()      => closeImportSeedModal();
window.executeImportFromSeed    = ()      => executeImportFromSeed();
window.openTokenDetailsModal    = (c,i,a) => openTokenDetailsModal(c,i,a);
window.closeTokenDetailsModal   = ()      => closeTokenDetailsModal();
window.refreshXrplDashboard     = ()      => refreshXrplDashboard();
window.refreshMarketData        = ()      => refreshMarketData();
window.refreshNftGallery        = ()      => refreshNftGallery();
window.refreshAmmPools          = ()      => refreshAmmPools();
window.refreshPoolExplorer      = ()      => refreshPoolExplorer();
window.loadCustomAmmPool        = ()      => loadCustomAmmPool();
window.sendNft                  = id      => sendNft(id);
window.toggleSeedBackupStatus   = ()       => toggleSeedBackupStatus();
window.setDexPair               = pair     => setDexPair(pair);
window.setDexInterval           = interval => setDexInterval(interval);
window.setDexChartType          = type     => setDexChartType(type);
window.refreshDexChart          = ()       => refreshDexChart();
window.setComparePair           = pair     => setComparePair(pair);
window.toggleIndicator          = (k, v)   => toggleIndicator(k, v);
window.toggleTerminalTheme      = ()       => toggleTerminalTheme();
window.toggleChartFullscreen    = ()       => toggleChartFullscreen();
window.exportChartPng           = ()       => exportChartPng();
window.saveChartLayoutPreset    = ()       => saveChartLayoutPreset();
window.loadChartLayoutPreset    = ()       => loadChartLayoutPreset();
window.setIndicatorFromDropdown = k        => setIndicatorFromDropdown(k);
window.toggleIndicatorMenu      = ()       => toggleIndicatorMenu();
window.toggleChartMoreMenu      = ()       => toggleChartMoreMenu();
window.setIndicatorQuery        = v        => setIndicatorQuery(v);
window.addIndicatorFromMenu     = k        => addIndicatorFromMenu(k);
window.removeIndicator          = k        => removeIndicator(k);
window.openIndicatorSettings    = k        => openIndicatorSettings(k);
window.closeIndicatorSettings   = ()       => closeIndicatorSettings();
window.applyIndicatorSettings   = k        => applyIndicatorSettings(k);
window.resetIndicatorSettings   = k        => resetIndicatorSettings(k);
window.copyChartLink            = ()       => copyChartLink();
window.toggleThreeEffects       = ()       => toggleThreeEffects();
window.setThreeEffects          = v        => setThreeEffects(v);
window.setDrawingTool           = t        => setDrawingTool(t);
window.clearAllDrawings         = ()       => clearAllDrawings();
window.zoomChartIn              = ()       => zoomChartIn();
window.zoomChartOut             = ()       => zoomChartOut();
window.panChartLeft             = ()       => panChartLeft();
window.panChartRight            = ()       => panChartRight();
window.toggleEducationPanel     = ()       => toggleEducationPanel();
window.selectEducationTab       = t        => selectEducationTab(t);
window.searchTokens             = q        => searchTokens(q);
window.lookupIssuedAsset        = ()       => lookupIssuedAsset();
window.addTokenToWatchlist      = s        => addTokenToWatchlist(s);
window.removeTokenFromWatchlist = s        => removeTokenFromWatchlist(s);
window.openTokenOnChart         = s        => openTokenOnChart(s);
window.loadToken                = s        => loadToken(s);
window.refreshTokenDiscovery    = ()       => refreshTokenDiscovery();
window.refreshRecentTransactions= ()       => refreshRecentTransactions();
window.setTokenFilter           = (f, v)   => setTokenFilter(f, v);
window.selectTokenDetails       = k        => selectTokenDetails(k);
window.showMoreIssuedTokens     = ()       => showMoreIssuedTokens();
window.showAllIssuedTokens      = ()       => showAllIssuedTokens();
window.resetIssuedTokenLimit    = ()       => resetIssuedTokenLimit();

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
window.openSocialModal  = id => openSocialModal(id);
window.closeSocialModal = ()  => closeSocialModal();
window.saveSocialModal  = ()  => saveSocialModal();
window.deleteSocial     = ()  => deleteSocial();
window.viewSocial       = id  => viewSocial(id);

// cmdk internal refs
window._openAuth    = openAuth;
window._goHome      = showLandingPage;
window._cycleTheme  = cycleTheme;
window._showProfile = showProfile;

/* ── Boot ── */
document.addEventListener('DOMContentLoaded', () => {
  console.log('🌊 NaluLF: booting…');

  restoreTheme();
  showLandingPage();
  buildLandingContent();
  initReveal();
  initParticles();
  setupCmdkListeners();
  initXrpPrice();

  window.addEventListener('naluxrp:pagechange', e => {
    const pageId = e?.detail?.pageId;
    if (pageId === 'dashboard' || pageId === 'inspector' || pageId === 'profile') {
      ensureAppModulesInitialized();
    }
    if (appModulesInitialized) syncModuleLifecycle();
  });

  window.addEventListener('naluxrp:tabchange', () => {
    if (appModulesInitialized) syncModuleLifecycle();
  });

  document.addEventListener('keydown', e => {
    const inInput = ['INPUT','TEXTAREA'].includes(document.activeElement?.tagName);
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); openCmdk(); return; }
    if (e.key === '/' && !inInput) { e.preventDefault(); openCmdk(); return; }
    if (e.key === 'Escape') {
      closeCmdk();
      closeAuth();
      closeProfileEditor();
      closeWalletCreator();
      closeSocialModal();
    }
  });

  document.getElementById('auth-overlay')?.addEventListener('click', e => {
    if (e.target === e.currentTarget) closeAuth();
  });

  if (restoreSession()) {
    ensureAppModulesInitialized();
    showDashboard();
    import('./xrpl.js').then(({ connectXRPL }) => connectXRPL());
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

async function fetchJsonWithCorsFallback(url) {
  const proxies = [
    (u) => `https://corsproxy.io/?${encodeURIComponent(u)}`,
    (u) => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
  ];
  const attempt = async (target) => {
    const signal = typeof AbortSignal?.timeout === 'function' ? AbortSignal.timeout(7000) : undefined;
    const res = await fetch(target, { mode: 'cors', cache: 'no-store', signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  };

  try { return await attempt(url); }
  catch {
    for (const mk of proxies) {
      try { return await attempt(mk(url)); }
      catch { /* continue */ }
    }
    throw new Error('Price feed unreachable');
  }
}

async function fetchXrpPrice() {
  try {
    const ticker = await fetchJsonWithCorsFallback('https://api.exchange.coinbase.com/products/XRP-USD/ticker');
    const candles = await fetchJsonWithCorsFallback('https://api.exchange.coinbase.com/products/XRP-USD/candles?granularity=86400');
    if (ticker?.price) {
      const price = Number(ticker.price);
      const day = Array.isArray(candles) && candles.length ? candles[0] : null;
      const open = day ? Number(day[3] || price) : price;
      const change = open ? ((price - open) / open) * 100 : 0;
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
    // silently fail — keep last value displayed
  }
}