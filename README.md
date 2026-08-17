# 🌊 NaluLF (NaluXRP) — XRPL Forensic Intelligence & Self-Custodied Wallet

A real-time XRPL ledger explorer, deep account inspector, encrypted self-custody wallet, and
portfolio analytics platform. Runs entirely client-side — no backend, no server, no custody.
Deployable as a PWA or native iOS app via Capacitor + TestFlight.

No backend. No API keys required to browse. Signals surfaced by the inspector are heuristics,
not attribution proof.

## What It Does
- Streams validated XRPL ledger activity in near real-time.
- Inspects account state (balances, trustlines, flags, reserves).
- Surfaces behavioral signals (churn, concentration, repeated interactions, wash trading, drain risk).
- Manages an encrypted, self-custodied multi-wallet vault entirely in the browser.
- Presents readable summaries for faster incident triage.

## Core Principles

| Principle | What It Means |
|-----------|--------------|
| **Zero Server Storage** | Vault, keys, and profile data never leave your browser |
| **You Own Your Keys** | Seeds encrypted with AES-256-GCM before written to localStorage |
| **Direct Network Access** | Connects directly to XRPL validators — no proxy, no API middleman |
| **Offline-Capable Design** | Core wallet functions work without a persistent connection |
| **Open & Auditable** | No obfuscated backend — everything runs in your browser and can be inspected |

---

## Tech Stack
- HTML + CSS + vanilla JavaScript (ES modules) — no build step required
- WebSocket connections to XRPL endpoints
- Web Crypto API (AES-256-GCM + PBKDF2) for the local vault
- Client-side localStorage for session/profile/wallet state
- Capacitor for the native iOS shell

## Run Locally
1. Open the repository in VS Code.
2. Serve [index.html](index.html) through HTTP (required for ES module loading — do not open with `file://`).
3. Recommended: the Live Server extension, then open `index.html` with Live Server.

```bash
npx serve .
# or
python3 -m http.server 8080
```

> Must be served over `http://localhost` or `https://` — the Web Crypto API requires a secure context.

---

## Feature Overview

### 🔐 Authentication & Vault
- **AES-256-GCM** encrypted vault with **PBKDF2 (150,000 iterations)** key derivation
- 3-step account creation: Identity → Security → Sync Awareness
- Domain / `@handle` registration alongside display name and email
- Auto-lock after 30 minutes of inactivity with dismissible lock banner
- Vault export / backup to `.json` file
- Cross-device sync via encrypted vault code (paste code or load backup file)
- Canvas-based CAPTCHA on registration
- Password strength meter with real-time scoring

### 💎 Multi-Wallet Management
- **Generate new wallets** — Ed25519 or secp256k1, entirely in-browser
- **Import from seed** — family seed or hex seed, encrypted before storage
- **Watch-only wallets** — track any XRPL address without a seed (`👁 Watch-only` badge)
- Per-wallet balance with **reserve breakdown** (base 10 XRP + owner count × 2 XRP)
- Available vs. reserved balance shown separately on every card
- Clickable token chips per wallet → Token Details modal with issuer, limit, DEX link
- One-click address copy with visual confirmation

### 📊 Portfolio Analytics
- Total portfolio value in XRP and estimated USD (live price feed)
- **Balance history sparklines** — snapshots stored per address automatically
- **26-week on-chain activity heatmap** (GitHub-style calendar)
- **Transaction type breakdown** bar chart
- **XRP flow analysis** — inflow, outflow, net across all wallets
- **Token allocation bars** — visual breakdown of trustline holdings
- **Benford's Law fraud detection** — mathematical anomaly analysis of transaction amounts

### 🔍 XRPL Account Inspector
- Deep-dive any XRPL address, transaction hash, or ledger object
- **Security Audit** — master key, regular key age, account flags, signer list
- **Drain Risk Analysis** — 4-level drain classification (Low → Critical)
- **NFT Analysis** — free sell offers, no-URI mints, burn patterns, transfer fees
- **Wash Trading Detection** — 5-signal scoring: cancel ratio, round-trips, pair concentration, burst activity, fill rate
- **Token Issuer Analysis** — obligations, freeze state, black hole detection
- **AMM & Liquidity** — LP positions, fee votes, auction bids
- **Risk Score (0–100)** — composite score with color bands (green / amber / orange / red)
- Recent inspection history (last 8 addresses with saved risk scores)
- **AI-generated explanation** of an account's findings, on demand, two ways: via your own Anthropic API key
  (through a stateless proxy — see Profile → Settings → AI Explanations) or entirely in-browser via a small
  open-weight model (WebGPU, no key, no server — larger one-time download, weaker answers than Claude)

### 🔬 Project Intelligence
Token/project-level analysis — distinct from the account-level Inspector above: point a currency + issuer at it
instead of a wallet address, and it answers "is this project structurally sound," not "what did this wallet do."
- **Project Strength score (0–100)** — five inspectable sub-scores (Liquidity, Distribution, Market Quality,
  LP Stability, Issuer Risk), each weighted, each clickable to reveal the exact numbers it was computed from.
  Methodology is disclosed in-app: it's a computed score under this app's own rules, not investment advice, and
  three dimensions (Network Activity, Treasury Health, Transparency) are deliberately left out until historical
  tracking exists to support them honestly.
- **Liquidity Intelligence** — AMM reserves, LP token supply, trading fee, auction slot and fee-vote data via
  `amm_info`, plus real **DEX order-book depth**: XRP required to move the price 1/2/5/10/25% in either direction,
  walked from live `book_offers` data (using each offer's actually-funded amount, not its stated face value) —
  a materially different, more honest picture of exit liquidity than AMM TVL alone.
- **Holder Concentration** — top 1/5/10 holder share of supply, derived by paginating the issuer's own
  `account_lines` (trustlines connect symmetrically, so this lists every holder).
- **LP Token Concentration** — same concentration math applied to the AMM's own LP token, so "$500K of liquidity
  controlled by one wallet that funded the pool yesterday" and "$220K held by 180 long-term LPs" read differently.
- **Issuer Risk flags** — freeze, global freeze, require-auth, clawback (`lsfAllowTrustLineClawback`), and
  blackhole state, each with a neutral, factual explanation rather than a verdict.

### ⚡ Live Ledger Stream
- Real-time ledger log — every new ledger and transaction as it closes (~3–4 seconds)
- TPS, average fee, success rate, dominant TX type metric cards
- TX Mix chart — live breakdown of transaction types in current session
- Fee pressure bar: Low → Normal → Elevated → High → Congested

### 🌐 Network Monitor
- Latency probe across all XRPL endpoints
- Auto-reconnect with exponential backoff (max 30s)
- Endpoint cycling on failure (s1 → s2 → xrplcluster → xrpl.ws)
- Switch between Mainnet, Testnet, and Xahau

### ⌨️ Command Palette
- `⌘K` / `/` keyboard shortcut
- Search wallets, navigate sections, trigger actions, inspect any address

### 🎨 Profile & Identity
- Display name + `@handle` + `.xrpl` domain chip in profile header
- Avatar: uploaded image, linked NFT, or DID reference
- Banner image with gradient presets
- Metrics row: Total XRP · Est. USD · Transactions · Wallet Age · Tokens · Reserved XRP
- Social links (Twitter/X, GitHub, Discord, etc.) with verified badges
- Activity log with 26-week heatmap
- Public profile preview mode

---

## Security Model

```
Your Password
     │
     ▼
PBKDF2 (SHA-256 · 150,000 iterations · 32-byte random salt)
     │
     ▼
AES-256-GCM Key  (non-exportable CryptoKey — never persisted)
     │
     ▼
Encrypt(vault JSON)  ──►  localStorage["naluxrp_vault_data"]
                                        (ciphertext + IV only)
```

- **Salt** — unique per account, stored separately in `naluxrp_vault_meta`
- **IV** — unique per save operation (fresh 12-byte random value each write)
- **Key** — exists only in RAM during an active session, never written to disk
- **Auto-lock** — clears key from memory after 30 minutes of inactivity
- **No key material** — never transmitted over the network under any circumstance

See [Whitepaper.html](Whitepaper.html) for the full cryptographic specification.

---

## Project Layout

```
NaluLF/
├── index.html                  # App shell — all modals, auth, profile, tabs, page sections
├── build.mjs                   # Regenerates www/ from index.html + NaluLF/ (see Build below)
├── package.json                # Build tooling only (esbuild) — the app itself has no build step
├── capacitor.config.json       # Capacitor config (native iOS shell)
├── codemagic.yaml              # CI build/signing/TestFlight pipeline
├── Roadmap.html / Whitepaper.html
├── ios/                        # Native Capacitor iOS project (Xcode workspace)
├── www/                        # Capacitor web asset directory — GENERATED by `npm run build`,
│                                # do not hand-edit; changes belong in index.html / NaluLF/ instead
└── NaluLF/                     # Application source
    ├── css/
    │   ├── main.css            # CSS entrypoint importing modular styles
    │   ├── base.css            # Reset, themes, shared layout tokens
    │   ├── auth.css / profile.css / dashboard.css / inspector.css / network.css / landing.css / navbar.css / ui.css
    ├── scripts/
    │   ├── main.js              # Application bootstrap and global window handlers
    │   ├── state.js             # Global shared state (one source of truth)
    │   ├── config.js            # XRPL endpoints, constants, localStorage keys, TX colors
    │   ├── utils.js             # DOM helpers ($), validators, formatters, safe localStorage
    │   ├── xrpl.js              # WebSocket connection, ledger subscription, event dispatch
    │   ├── auth.js               # CryptoVault, 3-step signup, session, cross-device sync
    │   ├── profile.js            # Wallets, analytics, NFTs, DEX, token details, metrics
    │   ├── project-intel.js      # Project Intelligence — AMM/order-book/holder/LP fetching + scoring, no UI
    │   ├── ai.js                 # AI-generated explanations via the user's own Claude API key + proxy
    │   ├── local-ai.js           # AI-generated explanations via an in-browser model (WebLLM) — no key needed
    │   ├── dashboard.js          # Live stream tab — ledger log, TPS, TX mix, metric cards
    │   ├── inspector.js          # XRPL deep inspector — risk scoring (~7,400 lines)
    │   ├── network.js            # Network status, latency probe, endpoint cycling
    │   ├── nav.js                # Page routing (landing / dashboard / profile)
    │   ├── theme.js              # Theme switching + persistence
    │   ├── landing.js            # Landing page hero content, scroll reveal
    │   ├── particles.js          # Animated particle background
    │   └── cmdk.js               # Command palette (⌘K)
    └── images/                  # Backgrounds, network icons
```

> `xrpl-wallet/` at the repository root is a separate React + TypeScript + Vite project
> (its own `package.json`/`node_modules`) and is not wired into the Capacitor iOS build above.

### Build

The app itself needs no build step — `index.html` and `NaluLF/` run directly from source (see Run Locally above).
`www/` (the Capacitor iOS asset dir) is different: it's generated output, not hand-maintained.

```bash
npm install   # once, installs esbuild
npm run build # regenerates www/ from index.html + NaluLF/ — bundled, minified, path-rewritten
```

Run this after any change that should ship to iOS. Never hand-edit files under `www/` — they're overwritten
on the next build.

---

## Building for iOS (TestFlight)

The app ships via Capacitor. `capacitor.config.json` points `webDir` at `www/`, and
[codemagic.yaml](codemagic.yaml) drives the CI build:

```bash
npx cap sync ios
npx cap open ios
```

In Xcode: set Team → Bundle ID → Deployment Target → Archive → Distribute → TestFlight.

### PWA Install (without TestFlight)
In Safari on iPhone: **Share → Add to Home Screen**. Launches full-screen like a native app.

---

## XRPL Network Endpoints

| Endpoint | Provider | Use |
|----------|----------|-----|
| `wss://s1.ripple.com` | Ripple | Primary |
| `wss://s2.ripple.com` | Ripple | Secondary |
| `wss://xrplcluster.com` | XRPL Foundation | Fallback |
| `wss://xrpl.ws` | Community | Fallback |
| `wss://s.altnet.rippletest.net:51233` | Ripple | Testnet |
| `wss://xahau.network` | Xahau | Hooks sidechain |

---

## localStorage Keys

| Key | Content |
|-----|---------|
| `naluxrp_vault_data` | AES-256-GCM ciphertext (wallets, seeds, identity) |
| `naluxrp_vault_meta` | Salt, iteration count, vault version |
| `naluxrp_session` | Active session name/email (plaintext convenience) |
| `nalulf_wallets` | Watch-only wallet metadata (no secrets) |
| `nalulf_inspect_history` | Last 8 inspected addresses + risk scores |
| `nalulf_profile` | Public profile data |
| `nalulf_social` | Social links |
| `nalulf_activity_log` | On-chain activity log entries |
| `nalulf_balhist_[addr]` | Balance history snapshots per address |
| `naluxrp_theme` | Current theme name |
| `naluxrp_network` | Selected network (mainnet / testnet / xahau) |

---

## Browser Compatibility

| Browser | Version | Status |
|---------|---------|--------|
| Chrome / Edge | 90+ | ✅ Full |
| Safari | 15+ | ✅ Full (PWA on iOS) |
| Firefox | 88+ | ✅ Full |
| Safari iOS | 15.4+ | ✅ Full (PWA + WKWebView) |

Requires: **Web Crypto API · ES Modules · localStorage · WebSocket**

---

## iOS-Specific Optimisations

| Feature | Implementation |
|---------|---------------|
| Safe area insets | `env(safe-area-inset-*)` on all wraps + nav |
| Tap highlight removal | `-webkit-tap-highlight-color: transparent` |
| Tap active states | `@media (hover: none)` `:active` rules |
| Momentum scroll | `-webkit-overflow-scrolling: touch` on modals |
| Input zoom prevention | `font-size: max(16px, .9rem)` on all inputs |
| Minimum touch targets | 44×44pt minimum (Apple HIG) on all buttons |
| Retina borders | `0.5px` on `@media (-webkit-min-device-pixel-ratio: 2)` |
| Dynamic Island | `env(safe-area-inset-top)` respected |
| iPhone SE support | `max-width: 374px` breakpoint |
| iPad layout | `768px–1024px` 3-column grids |

---

## Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | This file — project overview and technical reference |
| [Whitepaper.html](Whitepaper.html) | Architecture, cryptography, fraud detection methodology |
| [Roadmap.html](Roadmap.html) | Planned features and development timeline |

---

## Contributing

1. Constants and endpoints → `NaluLF/scripts/config.js`
2. New inspector modules → add to `renderAll()` and `_mountInspectorHTML()` in `NaluLF/scripts/inspector.js`
3. CSS → `NaluLF/css/inspector.css` (`.section-` for sections, `.isd-` for initial dashboard)
4. All `onclick` handlers registered on `window` in `initInspector()` or `NaluLF/scripts/main.js`

---

## Security and Use Policy
Built for defensive monitoring, analytics, and research workflows. Not intended for abuse, theft, or unauthorized access.

## Disclaimer
NaluLF is experimental software. You are solely responsible for the security of your seed phrases and vault password. Always maintain offline backups. The authors assume no liability for lost funds.

## License
MIT — see [LICENSE](LICENSE).

---

<div align="center">Built with 🌊 for the XRPL community · Not affiliated with Ripple Labs</div>
