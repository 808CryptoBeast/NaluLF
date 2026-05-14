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
  };
  if (els.landingActions) els.landingActions.style.display = isLanding ? '' : 'none';
  if (els.dashActions)    els.dashActions.style.display    = isLanding ? 'none' : '';
  if (els.navConn)        els.navConn.style.display        = isLanding ? 'none' : '';
  if (els.cmdkHint)       els.cmdkHint.style.display       = isLanding ? 'none' : '';

  state.currentPage = pageId;
  window.scrollTo({ top: 0, behavior: 'smooth' });
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