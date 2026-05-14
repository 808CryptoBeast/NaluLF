# NaluLF Project Cleanup Notes

Date: 2026-05-14

## Summary
This cleanup focused on three areas:
1. Mobile scroll reliability
2. Duplicate legacy asset removal
3. Naming consistency in visible UI copy

## Changes Made

### 0) Deep pass (ledger stream reliability)
- Reworked `NaluLF/scripts/dashboard.js` stream insertion logic:
  - New ledger cards are appended (chronological order).
  - Duplicate or older ledger indexes are ignored to prevent reconnect race disorder.
  - Stream resets cleanly on network change.
- Reworked `NaluLF/css/dashboard.css` stream container behavior:
  - Horizontal scroll is now native and stable (`overflow-x: auto`).
  - Auto-scroll targets the right side so the latest ledger remains visible.
- Result: stream now progresses left-to-right in creation order.

### 1) Mobile scroll reliability
- Updated `NaluLF/css/base.css` to enforce stable vertical scrolling on mobile:
  - `overflow-y: auto`
  - `-webkit-overflow-scrolling: touch`
  - `touch-action: pan-y`
- Centralized modal lock behavior in `NaluLF/css/base.css` with:
  - `body.modal-open { overflow: hidden; touch-action: none; }`
- Added a defensive unlock in `NaluLF/scripts/nav.js` so route/page switches clear stale modal lock state.

### 2) Duplicate file cleanup
Removed legacy files that were no longer referenced by the app entrypoint:
- `NaluLF/styles.css`
- `NaluLF/app.js/app.js`

The app already loads:
- `NaluLF/css/main.css`
- `NaluLF/scripts/main.js`

### 3) UI naming consistency
Updated visible content in `NaluLF/scripts/landing.js` from legacy product text to `NaluLF` for consistency.

## Validation Performed
- Verified JS syntax for the active scripts bundle (`NaluLF/scripts/*.js`) using `node --check`.
- Confirmed `NaluLF/index.html` references modular entrypoints (`css/main.css`, `scripts/main.js`).

## Follow-up (Optional)
- Rename legacy localStorage/event keys prefixed with `naluxrp_` only if a migration plan is acceptable.
- Add a lightweight CI check for JS syntax and style regressions.
