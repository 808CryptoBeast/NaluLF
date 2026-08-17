/* =====================================================
   tour.js — First-Run Onboarding Tour
   ===================================================== */
import { $, safeGet, safeSet } from './utils.js';

const LS_TOUR_SEEN = 'naluxrp_tour_seen';

const STEPS = [
  {
    title: 'Welcome to NaluLF 🌊',
    body: 'A 20-second tour of the three things people miss most. Skip anytime.',
  },
  {
    selector: '#cmdk-hint',
    title: 'Jump anywhere, instantly',
    body: 'Press <kbd>Ctrl</kbd>+<kbd>K</kbd> (or <kbd>/</kbd>) from any page. Paste an address in and it offers to inspect it directly — no need to navigate first.',
  },
  {
    selector: '#dash-tab-inspector',
    title: 'Inspect any wallet',
    body: 'Full forensic suite — trust lines, fund flow, convergence signals, AI-assisted explanations — for any XRPL address, not just your own.',
  },
  {
    selector: '.user-chip',
    title: 'Your Profile has more than wallets',
    body: 'Portfolio analytics, activity history, and Project Intelligence — liquidity depth, holder concentration, and issuer-risk scoring for any token — all live there.',
  },
];

let stepIndex = 0;
let active = false;
let highlighted = null;
let repositionHandler = null;

export function maybeStartTour() {
  if (safeGet(LS_TOUR_SEEN)) return;
  setTimeout(startTour, 700);
}

export function startTour() {
  if (active) return;
  active = true;
  stepIndex = 0;
  _ensureDom();
  _renderStep();
}

function _ensureDom() {
  if ($('tourOverlay')) return;
  const overlay = document.createElement('div');
  overlay.id = 'tourOverlay';
  overlay.className = 'tour-overlay';
  overlay.innerHTML = `<div class="tour-card" id="tour-card"></div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) tourSkip(); });
}

function _liveAnchor(sel) {
  if (!sel) return null;
  const el = document.querySelector(sel);
  if (!el) return null;
  const r = el.getBoundingClientRect();
  return (r.width > 0 || r.height > 0) ? el : null;
}

function _clearHighlight() {
  highlighted?.classList.remove('tour-highlight');
  highlighted = null;
}

function _renderStep() {
  // Anchors can legitimately be absent (e.g. cmdk-hint is CSS-hidden on
  // narrow viewports) — skip past those steps rather than pointing a
  // tooltip at nothing.
  while (stepIndex < STEPS.length && STEPS[stepIndex].selector && !_liveAnchor(STEPS[stepIndex].selector)) {
    stepIndex++;
  }
  if (stepIndex >= STEPS.length) return _finish();

  const step = STEPS[stepIndex];
  const overlay = $('tourOverlay');
  const card = $('tour-card');
  overlay.classList.add('show');

  _clearHighlight();
  const anchor = _liveAnchor(step.selector);
  if (anchor) {
    anchor.scrollIntoView({ block: 'center', behavior: 'smooth' });
    anchor.classList.add('tour-highlight');
    highlighted = anchor;
  }

  card.innerHTML = `
    <div class="tour-step-count">${stepIndex + 1} / ${STEPS.length}</div>
    <div class="tour-title">${step.title}</div>
    <div class="tour-body">${step.body}</div>
    <div class="tour-actions">
      <button class="tour-btn tour-btn--ghost" onclick="tourSkip()">Skip tour</button>
      <div class="tour-actions-right">
        ${stepIndex > 0 ? `<button class="tour-btn tour-btn--ghost" onclick="tourPrev()">Back</button>` : ''}
        <button class="tour-btn tour-btn--primary" onclick="tourNext()">${stepIndex === STEPS.length - 1 ? 'Done' : 'Next'}</button>
      </div>
    </div>`;

  _positionCard(anchor, card);

  if (repositionHandler) {
    window.removeEventListener('resize', repositionHandler);
    window.removeEventListener('scroll', repositionHandler, true);
  }
  repositionHandler = () => _positionCard(_liveAnchor(step.selector), card);
  window.addEventListener('resize', repositionHandler);
  window.addEventListener('scroll', repositionHandler, true);
}

function _positionCard(anchor, card) {
  if (!anchor) {
    card.classList.add('tour-card--centered');
    return;
  }
  card.classList.remove('tour-card--centered');
  card.style.visibility = 'hidden';
  requestAnimationFrame(() => {
    const r = anchor.getBoundingClientRect();
    const cw = card.offsetWidth || 320, ch = card.offsetHeight || 160;
    const spaceBelow = window.innerHeight - r.bottom;
    const top = spaceBelow > ch + 28 ? r.bottom + 16 : Math.max(16, r.top - ch - 16);
    let left = r.left + r.width / 2 - cw / 2;
    left = Math.min(Math.max(16, left), window.innerWidth - cw - 16);
    card.style.top = `${top}px`;
    card.style.left = `${left}px`;
    card.style.visibility = 'visible';
  });
}

export function tourNext() {
  stepIndex++;
  stepIndex >= STEPS.length ? _finish() : _renderStep();
}
export function tourPrev() {
  stepIndex = Math.max(0, stepIndex - 1);
  _renderStep();
}
export function tourSkip() { _finish(); }

function _finish() {
  active = false;
  safeSet(LS_TOUR_SEEN, '1');
  _clearHighlight();
  $('tourOverlay')?.classList.remove('show');
  if (repositionHandler) {
    window.removeEventListener('resize', repositionHandler);
    window.removeEventListener('scroll', repositionHandler, true);
    repositionHandler = null;
  }
}
