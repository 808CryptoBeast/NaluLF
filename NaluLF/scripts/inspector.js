/* =====================================================
   inspector.js — Account Inspector Tab
   ===================================================== */
import { $, escHtml, isValidXrpAddress, shortAddr } from './utils.js';
import { state } from './state.js';
import { wsSend } from './xrpl.js';

export function initInspector() {
  // Enter key on address field
  $('inspect-addr')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') runInspect();
  });
}

export async function runInspect() {
  const input   = $('inspect-addr');
  const addr    = input?.value.trim() || '';

  // UI refs
  const errEl   = $('inspect-err');
  const resEl   = $('inspect-result');
  const emptyEl = $('inspect-empty');
  const loadEl  = $('inspect-loading');
  const warnEl  = $('inspect-warn');

  // Reset
  if (errEl)   errEl.style.display   = 'none';
  if (resEl)   resEl.style.display   = 'none';
  if (emptyEl) emptyEl.style.display = 'none';

  if (!addr) {
    if (emptyEl) emptyEl.style.display = '';
    return;
  }

  if (!isValidXrpAddress(addr)) {
    if (errEl) { errEl.textContent = `⚠ Invalid address: ${escHtml(addr)}`; errEl.style.display = ''; }
    return;
  }

  if (state.connectionState !== 'connected') {
    if (warnEl) warnEl.style.display = '';
    return;
  }
  if (warnEl) warnEl.style.display = 'none';
  if (loadEl) loadEl.style.display = '';

  try {
    const [infoRes, linesRes] = await Promise.all([
      wsSend({ command: 'account_info',  account: addr, ledger_index: 'validated' }),
      wsSend({ command: 'account_lines', account: addr, ledger_index: 'validated' }),
    ]);

    if (loadEl) loadEl.style.display = 'none';
    renderResult(addr, infoRes?.result?.account_data || {}, linesRes?.result?.lines || []);
    if (resEl) resEl.style.display = '';

  } catch(err) {
    if (loadEl) loadEl.style.display = 'none';
    if (errEl) { errEl.textContent = `Error: ${escHtml(err.message)}`; errEl.style.display = ''; }
  }
}

function renderResult(addr, info, lines) {
  // Address badge
  const badge = $('inspect-addr-badge');
  if (badge) badge.textContent = shortAddr(addr);

  const balXrp  = Number(info.Balance || 0) / 1e6;
  const reserve = 10 + Number(info.OwnerCount || 0) * 2;

  // Account data grid
  const grid = $('inspect-acct-grid');
  if (grid) {
    const cells = [
      { label: 'Address',      value: addr },
      { label: 'Balance',      value: `${balXrp.toFixed(6)} XRP` },
      { label: 'Sequence',     value: info.Sequence ?? '—' },
      { label: 'Owner Count',  value: info.OwnerCount ?? '—' },
      { label: 'Est. Reserve', value: `${reserve} XRP` },
      { label: 'Flags',        value: info.Flags ?? 0 },
    ];
    grid.innerHTML = cells.map(c => `
      <div class="acct-cell">
        <div class="acct-cell-label">${escHtml(c.label)}</div>
        <div class="acct-cell-value">${escHtml(String(c.value))}</div>
      </div>`).join('');
  }

  // Trustline count badge
  const countBadge = $('trust-count-badge');
  if (countBadge) countBadge.textContent = lines.length;

  // Trustlines table
  const tbody = $('inspect-trust-body');
  if (tbody) {
    tbody.innerHTML = lines.length
      ? lines.map(l => `
          <div class="trustline-row">
            <span class="trustline-currency">${escHtml(l.currency)}</span>
            <span class="trustline-issuer">${l.account ? shortAddr(l.account) : ''}</span>
            <span class="trustline-balance">${escHtml(l.balance)} / ${escHtml(l.limit)}</span>
          </div>`).join('')
      : `<div class="widget-label" style="padding:12px 0">No trustlines found.</div>`;
  }
}