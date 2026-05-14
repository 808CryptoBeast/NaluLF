# ==============================
# FILE: README.md
# ==============================
# NaluLF
Client-only XRPL forensic intelligence dashboard with real-time ledger streaming, account inspection, and pattern-driven investigation views.

No backend. No API keys. No wallet required.

## What NaluLF does
- Streams validated XRPL ledger activity in near real-time.
- Inspects account state (balances, trustlines, flags, reserves).
- Surfaces behavioral signals (churn, concentration, repeated interactions).
- Presents readable summaries for faster incident triage.

Signals in this app are heuristics, not attribution proof.

## Tech stack
- HTML + CSS + vanilla JavaScript (ES modules)
- WebSocket connections to XRPL endpoints
- Client-side localStorage session/profile state

## Run locally
1. Open the repository in VS Code.
2. Serve [NaluLF/index.html](NaluLF/index.html) through HTTP (for ES module loading).
3. Recommended: Live Server extension, then open [NaluLF/index.html](NaluLF/index.html) with Live Server.

Do not open with file:// because module imports and browser security rules will fail.

## Project layout
- [NaluLF/index.html](NaluLF/index.html): Application shell and page sections.
- [NaluLF/css/main.css](NaluLF/css/main.css): CSS entrypoint importing modular styles.
- [NaluLF/css/base.css](NaluLF/css/base.css): Reset, themes, shared layout tokens.
- [NaluLF/scripts/main.js](NaluLF/scripts/main.js): Application bootstrap and global handlers.
- [NaluLF/scripts/xrpl.js](NaluLF/scripts/xrpl.js): XRPL connectivity and streaming.
- [NaluLF/scripts/dashboard.js](NaluLF/scripts/dashboard.js): Live stream dashboard rendering.
- [NaluLF/scripts/inspector.js](NaluLF/scripts/inspector.js): Address inspection workflows.
- [NaluLF/scripts/network.js](NaluLF/scripts/network.js): Network health telemetry.

## Recent cleanup
- Removed unused legacy duplicates:
1. NaluLF/styles.css
2. NaluLF/app.js/app.js
- Hardened mobile scrolling behavior by centralizing modal scroll-lock rules in [NaluLF/css/base.css](NaluLF/css/base.css).
- Added defensive modal unlock during page switches in [NaluLF/scripts/nav.js](NaluLF/scripts/nav.js).
- Standardized user-facing product naming in [NaluLF/scripts/landing.js](NaluLF/scripts/landing.js).

## XRPL docs
- https://xrpl.org/docs/concepts/ledgers
- https://xrpl.org/docs/references/http-websocket-apis/
- https://xrpl.org/docs/concepts/tokens/decentralized-exchange
- https://xrpl.org/docs/concepts/tokens/decentralized-exchange/automated-market-makers
- https://learn.xrpl.org/

## Security and use policy
Built for defensive monitoring, analytics, and research workflows. Not intended for abuse, theft, or unauthorized access.

## License
See [LICENSE](LICENSE).
