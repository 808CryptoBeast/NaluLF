/* =====================================================
   nav.js — Page Switching · Tab Navigation · Body Classes
   ===================================================== */
import { $, $$ } from './utils.js';
import { state } from './state.js';

const PAGE_BODY_CLASS = {
  landing:   'landing-page',
  dashboard: 'dashboard',
  inspector: 'inspector',
  profile:   'dashboard',
};

export function switchPage(pageId) {
  // Defensive unlock in case a modal was closed during/after route changes on mobile.
  document.body.classList.remove('modal-open');

  Object.values(PAGE_BODY_CLASS).forEach(c => document.body.classList.remove(c));
  document.body.classList.add(PAGE_BODY_CLASS[pageId] || 'dashboard');

  const landingEl   = $('landing');
  const dashboardEl = $('dashboard');
  const profileEl   = $('profile-page');

  if (landingEl)   landingEl.style.display   = pageId === 'landing'   ? '' : 'none';
  if (dashboardEl) dashboardEl.style.display = pageId === 'dashboard' ? '' : 'none';
  if (profileEl)   profileEl.style.display   = pageId === 'profile'   ? '' : 'none';

  const isLanding = pageId === 'landing';
  const els = {
    landingActions: $('navbar-landing-actions'),
    dashActions:    $('navbar-dash-actions'),
    navConn:        $('navbar-conn'),
    cmdkHint:       $('cmdk-hint'),
    helpBtn:        $('help-trigger'),
  };
  if (els.landingActions) els.landingActions.style.display = isLanding ? '' : 'none';
  if (els.dashActions)    els.dashActions.style.display    = isLanding ? 'none' : '';
  if (els.navConn)        els.navConn.style.display        = isLanding ? 'none' : '';
  if (els.cmdkHint)       els.cmdkHint.style.display       = isLanding ? 'none' : '';
  if (els.helpBtn)        els.helpBtn.style.display        = isLanding ? 'none' : '';

  state.currentPage = pageId;
  window.scrollTo({ top: 0, behavior: 'smooth' });
  closeMobileNav();
  window.dispatchEvent(new CustomEvent('naluxrp:pagechange', { detail: { pageId } }));
}

export function showLandingPage() { switchPage('landing'); }
export function showDashboard()   { switchPage('dashboard'); }
export function showProfile()     { switchPage('profile'); }

export function switchTab(btn, tabId) {
  $$('.dash-tab').forEach(b => {
    b.classList.toggle('active', b === btn);
    b.setAttribute('aria-selected', String(b === btn));
  });
  ['stream', 'inspector', 'network'].forEach(id => {
    const el = $(`tab-${id}`);
    if (el) el.style.display = id === tabId ? '' : 'none';
  });
  if (tabId === 'inspector') {
    document.body.classList.remove('dashboard');
    document.body.classList.add('inspector');
  } else {
    document.body.classList.remove('inspector');
    document.body.classList.add('dashboard');
  }
  state.currentTab = tabId;
  window.dispatchEvent(new CustomEvent('naluxrp:tabchange', { detail: { tabId } }));
}

/* ── Mobile drawer (collapses the price/connection/⌘K/help/Resources
   cluster below ~768px instead of hiding those items piecemeal) ── */
export function toggleMobileNav(forceOpen) {
  const navEl = $('main-nav');
  const btn = $('navbar-hamburger');
  if (!navEl) return;
  const open = typeof forceOpen === 'boolean' ? forceOpen : !navEl.classList.contains('nav-open');
  navEl.classList.toggle('nav-open', open);
  if (btn) btn.setAttribute('aria-expanded', String(open));
  if (!open) closeResourcesMenu();
}
export function closeMobileNav() { toggleMobileNav(false); }

export function toggleResourcesMenu(e) {
  e?.stopPropagation();
  const menu = $('navbar-resources-menu');
  const btn = $('navbar-resources-btn');
  if (!menu) return;
  const willOpen = menu.hasAttribute('hidden');
  menu.toggleAttribute('hidden', !willOpen);
  if (btn) btn.setAttribute('aria-expanded', String(willOpen));
}
export function closeResourcesMenu() {
  $('navbar-resources-menu')?.setAttribute('hidden', '');
  $('navbar-resources-btn')?.setAttribute('aria-expanded', 'false');
}

export function setupNavGlobalListeners() {
  document.addEventListener('click', e => {
    if (!$('navbar-resources')?.contains(e.target)) closeResourcesMenu();
    if (!$('main-nav')?.contains(e.target)) closeMobileNav();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') { closeResourcesMenu(); closeMobileNav(); }
  });
  window.addEventListener('resize', () => {
    if (window.innerWidth > 768) closeMobileNav();
  });
}