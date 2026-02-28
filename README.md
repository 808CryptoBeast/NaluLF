# NaluLF 🌊🛡️
**Client-only XRPL forensic analytics suite** — real-time validated ledger streaming, address inspection, pattern/risk signals, and readable narratives.

No backend • No API keys • No wallet required

---

## What this is for
NaluLF helps you:
- Watch validated ledger activity live (stream + dominant activity highlights)
- Inspect any XRPL address (balances, trustlines, flags, reserve signals)
- Detect *signals* of unusual behavior (repeats, clustering, churn, concentration, timing)
- Produce readable summaries of “what changed” across recent ledgers

> Signals are heuristics to guide investigation — not identity proof or automatic accusations.

---

## Features
### 🌊 Real-Time Stream
- Live WebSocket connection to XRPL endpoints
- Ledger-by-ledger summaries (dominant TX activity, fee pressure, etc.)

### 🔍 Account Inspector
- Quick lookup of an address
- Intended for context pivots from stream/patterns → address details

### 🧠 Patterns & Signals (Heuristics)
- Repeating counterparties (“who touches who”)
- Co-activity clustering (behavior grouping, not identity)
- DEX/offer churn proxies (OfferCreate/OfferCancel activity patterns)
- AMM/LP bursts (create/deposit/withdraw waves)
- Concentration and bot-like timing proxies

### 📖 Narratives
- Human-readable reporting of changes across recent ledgers
- Designed for faster comprehension and incident workflows

---

## Getting started
### Option A: VS Code Live Server (recommended)
1. Open the project folder in VS Code
2. Install **Live Server**
3. Right-click `index.html` → **Open with Live Server**

### Option B: Any static server
ES modules require HTTP (not `file://`), so use any static server.

---

## Project structure (typical)
- `index.html` — app shell
- `css/` — styling (base/landing/dashboard/etc.)
- `scripts/` — ES modules (main, xrpl, dashboard, inspector, nav, auth…)

---

## Learning resources (XRPL)
- https://xrpl.org/docs/concepts/ledgers
- https://xrpl.org/docs/references/http-websocket-apis/
- https://xrpl.org/docs/concepts/tokens/decentralized-exchange
- https://xrpl.org/docs/concepts/tokens/decentralized-exchange/automated-market-makers
- https://learn.xrpl.org/

---

## Ethics / Use policy
NaluLF is built for **defensive analysis, monitoring, and research**.  
It is **not** intended for theft, unauthorized access, or wrongdoing.

---

## License
Add your preferred license (MIT is common), or specify “All rights reserved”.
