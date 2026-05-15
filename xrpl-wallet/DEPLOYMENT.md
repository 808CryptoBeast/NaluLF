# Nalu XRPL Web Wallet – Deployment Guide

## 🚀 Overview

**Nalu** is a professional, production-ready **XRPL web wallet** built with React, TypeScript, Vite, Tailwind CSS, and Zustand. It provides:

- ✅ **Secure local wallet generation & import** (Ed25519 keys, seed phrases, encrypted keystores)
- ✅ **Full XRPL asset management** (XRP, issued tokens, NFTs, MPTs)
- ✅ **Complete payment flows** (XRP, tokens, NFTs with reserve warnings)
- ✅ **DeFi/AMM operations** (AMMCreate, AMMDeposit, AMMWithdraw, AMMVote, AMMBid)
- ✅ **Advanced features** (Escrow, Payment Channels, compliance placeholders)
- ✅ **Live WebSocket subscriptions** (real-time balance/transaction updates)
- ✅ **Professional, responsive UI** (desktop, tablet, mobile-optimized)

## 📦 Project Structure

```
xrpl-wallet/
├── src/
│   ├── components/        # React UI modules (Dashboard, Assets, Send, DeFi, Advanced)
│   ├── services/          # xrpl.js integration & price feeds
│   ├── store/             # Zustand wallet state management
│   ├── lib/               # Utilities (crypto, errors, formatting)
│   ├── types/             # TypeScript type definitions
│   ├── App.tsx            # Main app shell with navigation
│   ├── main.tsx           # Entry point
│   └── index.css          # Tailwind + custom styles
├── dist/                  # Production build output (ready to deploy)
├── public/                # Static assets
├── package.json           # Dependencies
├── vite.config.ts         # Vite build configuration
├── tailwind.config.js     # Tailwind CSS config
└── tsconfig.json          # TypeScript configuration
```

## 🛠️ Development

### Prerequisites

- **Node.js**: 18.x or later
- **npm**: 9.x or later

### Install & Run

```bash
# Install dependencies
npm install

# Start development server (hot reload)
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Lint code
npm run lint
```

## 📋 Features in Depth

### 1. **Wallet Generation & Security**

- **Ed25519 keypair generation** (modern XRPL standard)
- **Seed phrase import** (restore from backup)
- **Secret numbers import** (alternative recovery)
- **Encrypted keystore export** (AES-GCM with PBKDF2, passphrase-protected)
- **Mandatory security checklist** (confirms user understanding of reserve, seed storage)
- **Session locking** (clears sensitive data after inactivity/user choice)

### 2. **Dashboard**

- **Real-time portfolio value** (XRP balance + USD conversion via CoinGecko API)
- **XRP reserve breakdown** (liquid vs. reserved)
- **QR code for receiving** (copy address to clipboard)
- **Recent transaction history** (up to 20 most recent transactions)
- **Live metrics widget** (trustline count, NFT count, reserve, recent TX count)

### 3. **Asset Manager**

- **Trustline list** (all issued tokens from `account_lines`)
- **NFT gallery** (all NFTs from `account_nfts`)
- **Create trustlines** (with reserve impact warnings ~2 XRP per trustline)
- **Send issued tokens** (destination, amount, destination tag support)
- **Send NFTs** (via NFTokenCreateOffer)

### 4. **Send Payment Panel**

- **Unified asset picker** (XRP, tokens, NFTs)
- **Destination validation** (with optional destination tag)
- **Amount input** (with real-time fee estimation)
- **Reserve-aware checks** (warns before dropping below minimum)
- **Plain-English error messages** (translates XRPL errors to user-friendly text)

### 5. **DeFi / AMM**

- **Create AMM pools** (select two assets, set trading fee)
- **Deposit liquidity** (add to existing pools, earn LP tokens)
- **Withdraw liquidity** (redeem LP tokens)
- **Vote on fees** (AMMVote transaction)
- **Bid for auction slots** (AMMBid for reduced trading fees)

### 6. **Advanced Features**

- **Escrow timelocks** (create & finish conditional XRP payments)
- **Payment channels** (micropayment channels for high-throughput flows)
- **Compliance stub** (placeholder for Permissioned Domains / XLS-80)

### 7. **Network Switching**

- **Testnet** (for development/testing) – wss://s.altnet.rippletest.net:51233
- **Mainnet** (production) – wss://xrplcluster.com

## 🔐 Security Architecture

### Local-Only Key Management

- ✅ **All private keys remain in the browser** – never sent to any server
- ✅ **All transactions signed locally** using xrpl.js wallet signing
- ✅ **RPC calls only include** public account address and signed transaction blobs
- ✅ **Encrypted keystore export** – AES-GCM with user-supplied passphrase

### Transaction Signing Flow

1. User inputs transaction details in the UI
2. App constructs transaction object locally
3. **xrpl.js `wallet.sign()`** signs the prepared transaction blob
4. Signed blob submitted to XRPL via WebSocket RPC (`submitAndWait`)
5. Response returned to UI; app updates state via WebSocket subscription

### Error Handling

- Robust XRPL error translation (see `src/lib/errors.ts`)
- User-friendly messages instead of raw JSON responses
- Clear warnings before reserve-consuming actions (trustline creation, escrow, etc.)

## 🚀 Deployment

### Option A: Static Hosting (Recommended for production)

```bash
# Build production assets
npm run build

# Deploy the `dist/` folder to any static hosting:
# - Vercel: `vercel deploy`
# - Netlify: `netlify deploy --prod --dir=dist`
# - AWS S3 + CloudFront
# - GitHub Pages
# - Self-hosted nginx / Apache
```

### Option B: Docker

```dockerfile
# Dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

Build and run:
```bash
docker build -t nalu-xrpl-wallet .
docker run -p 8080:80 nalu-xrpl-wallet
```

### Option C: Self-Hosted Node.js

```bash
# Install globally or use pm2
npm install -g pm2

# Start preview server
pm2 start "npm run preview" --name xrpl-wallet
pm2 save
```

## 📋 Environment & Configuration

### Network Configuration

Modify `src/services/xrplService.ts` to add custom networks:

```typescript
export const NETWORKS: Record<NetworkType, NetworkConfig> = {
  // ... existing testnet/mainnet
  custom: {
    wsUrl: 'wss://your-rippled-server.com',
    label: 'Custom Network',
    explorerTxBase: 'https://your-explorer.com/tx/',
  },
}
```

### Price Feed

The app uses CoinGecko API for XRP/USD pricing (no authentication required). To use a different provider, edit `src/services/priceService.ts`.

## 🎯 Key Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `react` | ^19.x | UI framework |
| `typescript` | ~6.x | Type safety |
| `xrpl` | ^2.14.x | XRPL protocol library |
| `zustand` | ^5.x | State management |
| `tailwindcss` | ^3.x | Styling |
| `lucide-react` | ^1.x | Icons |
| `qrcode.react` | ^4.x | QR code generation |
| `zod` | ^4.x | Schema validation |
| `axios` | ^1.x | HTTP client |

## 🧪 Testing Checklist

- [ ] **Generation**: Create new Ed25519 wallet → confirm seed display
- [ ] **Import**: Import existing seed → verify address match
- [ ] **Dashboard**: Check balance, USD conversion, recent TX list
- [ ] **Assets**: List tokens, NFTs; create trustline (testnet)
- [ ] **Send**: Send XRP → verify fee estimation & error handling
- [ ] **DeFi**: Create AMM pool (testnet) → check transaction submission
- [ ] **Export**: Export encrypted keystore → re-import with passphrase
- [ ] **Network switch**: Toggle testnet ↔ mainnet → confirm URL change
- [ ] **Mobile**: Test on iPhone/Android → verify responsive layout
- [ ] **Error handling**: Attempt insufficient funds → verify user-friendly message

## 📝 Build Output

After `npm run build`, the `dist/` folder contains:

- `index.html` – Single-page app entry point
- `assets/index-*.js` – Minified, tree-shaken React app (~100–150 KB gzipped)
- `assets/index-*.css` – Compiled Tailwind styles
- `icons.svg` – SVG sprite (optional, can be removed if not used)

## 🔗 Useful Links

- **XRPL Documentation**: https://xrpl.org/
- **xrpl.js GitHub**: https://github.com/XRPLF/xrpl-lib-js
- **XRPL Testnet Faucet**: https://testnet.xrpl.org/
- **XRPL Explorer (Testnet)**: https://testnet.xrpl.org/
- **XRPL Explorer (Mainnet)**: https://livenet.xrpl.org/

## 📞 Support & Troubleshooting

### "Insufficient XRP for transaction fee"

- Fund your testnet account via the faucet
- Wait for ledger validation (typically 4–5 seconds)

### "No trustline" error

- Create a trustline first in the Assets panel
- Confirm the currency code and issuer address

### WebSocket connection timeouts

- Check rippled server availability
- Verify CORS headers on your rippled instance (if self-hosted)
- Try switching to mainnet or an alternative network

### Build fails with native binding errors

- Delete `node_modules/` and `package-lock.json`
- Run `npm cache clean --force`
- Re-run `npm install && npm run build`

---

**Built with care for XRPL developers. Secure. Professional. Ready for production. 🚀**
