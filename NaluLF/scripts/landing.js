// ==============================
// FILE: scripts/landing.js
// ==============================
/* =====================================================
   landing.js — Learning Landing Content · Scroll Reveal
   Update:
   - Cards open a learning modal with detailed explanations + trusted links
   - Restores/keeps the Split Panels section (Real-Time Stream / Privacy by Design)
   - Removes the literal phrase “plain English” in UI copy (still clear + layman-friendly)
   ===================================================== */
import { $, escHtml } from './utils.js';

const TOPICS = {
  'xrpl-ledger': {
    title: 'XRPL Ledger',
    subtitle: 'What a ledger is, what validated means, and how to interpret ledger snapshots.',
    sections: [
      {
        heading: 'In simple terms',
        paragraphs: [
          'Think of the XRP Ledger (XRPL) as a public spreadsheet that the whole network agrees on.',
          'A “ledger version” is one snapshot of that spreadsheet: balances, trustlines, offers, AMMs, and more.',
          'When a ledger becomes “validated”, it’s final—analytics based on validated ledgers reflect settled history.',
        ],
        bullets: [
          'Ledger Index = the ledger number (sequence).',
          'Ledger Hash = fingerprint of that ledger’s contents.',
          'Open → Closed → Validated = in-progress → proposed snapshot → final snapshot.',
        ],
      },
      {
        heading: 'How NaluXRP uses this',
        paragraphs: [
          'NaluXRP listens to validated ledger events, then summarizes what changed and what patterns are emerging.',
          'You can quickly see dominant transaction types, fee pressure, DEX/AMM bursts, and concentration signals.',
        ],
        bullets: [
          'Live stream cards summarize each ledger close.',
          'Narratives turn raw changes into readable reporting.',
          'Signals are heuristics (useful indicators, not proof).',
        ],
      },
    ],
    links: [
      { label: 'XRPL Docs: Ledgers (overview)', url: 'https://xrpl.org/docs/concepts/ledgers' },
      { label: 'Open / Closed / Validated Ledgers', url: 'https://xrpl.org/docs/concepts/ledgers/open-closed-validated-ledgers' },
      { label: 'Ledger Structure', url: 'https://xrpl.org/docs/concepts/ledgers/ledger-structure' },
      { label: 'Ledger Header (hash/index basics)', url: 'https://xrpl.org/docs/references/protocol/ledger-data/ledger-header' },
    ],
    ctas: [
      { label: 'Launch Dashboard →', action: 'auth:signup' },
      { label: 'Close', action: 'modal:close' },
    ],
  },

  'accounts-trustlines': {
    title: 'Accounts, Reserves, and Trustlines',
    subtitle: 'How addresses work, why reserves exist, and what trustlines mean for tokens.',
    sections: [
      {
        heading: 'In simple terms',
        paragraphs: [
          'An XRPL account is a public address with a balance and settings (flags).',
          'Reserves exist to prevent ledger spam: certain objects (offers, trustlines, signer lists) require reserved XRP.',
          'Trustlines are “permission slips” that prevent you from receiving random issued tokens you didn’t opt into.',
        ],
        bullets: [
          'Reserves: base reserve + owner reserve for certain objects.',
          'Trustlines: define limits and balances for issued tokens.',
          'Flags/settings: control behaviors like Deposit Authorization.',
        ],
      },
      {
        heading: 'Why this matters for investigations',
        paragraphs: [
          'During compromises, account settings and objects can change quickly.',
          'Trustlines and offers can reveal what tokens/markets are being targeted.',
        ],
        bullets: [
          'Inspector helps you read balances, flags, and trustlines.',
          'Reserve signals can hint at heavy offer/trustline usage.',
        ],
      },
    ],
    links: [
      { label: 'AccountRoot (ledger entry)', url: 'https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/accountroot' },
      { label: 'Reserves (why they exist)', url: 'https://xrpl.org/docs/concepts/accounts/reserves' },
      { label: 'Trust Line Tokens (concept)', url: 'https://xrpl.org/docs/concepts/tokens/fungible-tokens/trust-line-tokens' },
      { label: 'account_lines API (trustlines)', url: 'https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_lines' },
      { label: 'Deposit Authorization (DepositAuth)', url: 'https://xrpl.org/docs/concepts/accounts/depositauth' },
      { label: 'XRPL: Cryptographic Keys', url: 'https://xrpl.org/docs/concepts/accounts/cryptographic-keys' },
    ],
    ctas: [
      { label: 'Inspect an Address →', action: 'auth:login' },
      { label: 'Close', action: 'modal:close' },
    ],
  },

  'dex-amm': {
    title: 'DEX, Offers, and AMMs',
    subtitle: 'How trading works on XRPL and how AMM liquidity moves show up on-ledger.',
    sections: [
      {
        heading: 'How XRPL trading works',
        paragraphs: [
          'XRPL has a built-in decentralized exchange (DEX). People place “offers” (limit orders) to trade between XRP and tokens, or token-to-token.',
          'AMMs (Automated Market Makers) hold pools of two assets. Liquidity providers deposit/withdraw and traders swap against the pool.',
        ],
        bullets: [
          'OfferCreate = place an order (limit order).',
          'OfferCancel = remove an order (may still succeed even if nothing cancels).',
          'AMMCreate/Deposit/Withdraw = liquidity lifecycle signals.',
        ],
      },
      {
        heading: 'Manipulation signals (heuristics)',
        paragraphs: [
          'On-ledger “spoofing” isn’t identical to centralized exchanges, but suspicious churn can still stand out.',
          'Rapid OfferCreate/OfferCancel bursts, concentrated actors, and repeated short-lived behavior can indicate bot-driven or staged activity.',
        ],
        bullets: [
          'Offer churn: creates vs cancels intensity.',
          'Concentration: whether a small set of accounts dominates.',
          'AMM bursts: sudden waves of deposits/withdraws.',
        ],
      },
    ],
    links: [
      { label: 'DEX (concept)', url: 'https://xrpl.org/docs/concepts/tokens/decentralized-exchange' },
      { label: 'Offers (concept)', url: 'https://xrpl.org/docs/concepts/tokens/decentralized-exchange/offers' },
      { label: 'OfferCreate (tx type)', url: 'https://xrpl.org/docs/references/protocol/transactions/types/offercreate' },
      { label: 'OfferCancel (tx type)', url: 'https://xrpl.org/docs/references/protocol/transactions/types/offercancel' },
      { label: 'AMMs (concept)', url: 'https://xrpl.org/docs/concepts/tokens/decentralized-exchange/automated-market-makers' },
      { label: 'book_offers API (order book)', url: 'https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/path-and-order-book-methods/book_offers' },
    ],
    ctas: [
      { label: 'Launch Dashboard →', action: 'auth:signup' },
      { label: 'Close', action: 'modal:close' },
    ],
  },

  'security-drains': {
    title: 'Wallet Safety + Compromise Response (Defensive)',
    subtitle: 'How to read suspicious patterns safely and what to watch for during incident response.',
    sections: [
      {
        heading: 'What a “drain” usually means',
        paragraphs: [
          'A wallet drain typically follows a compromise: stolen keys, malicious signing requests, phishing, or unsafe approvals.',
          'NaluXRP is designed for defensive investigation and monitoring—NOT for unauthorized access or theft.',
        ],
        bullets: [
          'Watch for sudden outbound bursts from a previously quiet account.',
          'Look for new trustlines/offers right before the loss.',
          'Check transaction result codes and whether actions are validated.',
        ],
      },
      {
        heading: 'How NaluXRP helps (defensive)',
        paragraphs: [
          'Inspect the address, review counterparties, and watch for repeated interactions or suspicious churn.',
          'Use narratives to communicate what changed and what to check next.',
        ],
        bullets: [
          'Inspector: balances, trustlines, flags, reserve signals.',
          'Breadcrumbs: repeating “who touches who” pairs.',
          'Signals: concentration + churn + bot-like timing proxies.',
        ],
      },
    ],
    links: [
      { label: 'XRPL Learning: Security Best Practices', url: 'https://learn.xrpl.org/lesson/security-best-practices-for-xrp/' },
      { label: 'XRPL Learning: DeFi Security 101', url: 'https://learn.xrpl.org/course/blockchain-for-business/lesson/defi-security-101-staying-safe-in-the-new-decentralized-world/' },
      { label: 'XRPL: Secure Signing', url: 'https://xrpl.org/docs/concepts/transactions/secure-signing' },
      { label: 'Transaction Results', url: 'https://xrpl.org/docs/references/protocol/transactions/transaction-results' },
      { label: 'tesSUCCESS', url: 'https://xrpl.org/docs/references/protocol/transactions/transaction-results/tes-success' },
    ],
    ctas: [
      { label: 'Inspect an Address →', action: 'auth:login' },
      { label: 'Close', action: 'modal:close' },
    ],
  },

  'bots-data': {
    title: 'Bots on the Data (Monitoring / Alerts)',
    subtitle: 'How to build legit automation on top of public XRPL data.',
    sections: [
      {
        heading: 'What to automate',
        paragraphs: [
          'XRPL is public, so you can build monitoring bots for events: whale payments, DEX churn spikes, AMM liquidity changes, or sudden flag updates.',
          'Good bots explain what they saw and provide confidence/validation steps.',
        ],
        bullets: [
          'Use WebSocket subscriptions for live events.',
          'Use API methods for snapshots (account_info, account_lines, book_offers).',
          'Treat signals as indicators and confirm with multiple checks.',
        ],
      },
      {
        heading: 'How NaluXRP fits',
        paragraphs: [
          'NaluXRP is the “human dashboard” to validate what the bot flags.',
          'You can click addresses (breadcrumbs/clusters) and open Inspector for context.',
        ],
        bullets: ['Bots: alerting, reporting, research, and risk monitoring.', 'Not for unauthorized access.'],
      },
    ],
    links: [
      { label: 'subscribe (WebSocket)', url: 'https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/subscription-methods/subscribe' },
      { label: 'Monitor Incoming Payments (tutorial)', url: 'https://xrpl.org/docs/tutorials/http-websocket-apis/build-apps/monitor-incoming-payments-with-websocket' },
      { label: 'account_info API', url: 'https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_info' },
      { label: 'account_lines API', url: 'https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_lines' },
      { label: 'book_offers API', url: 'https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/path-and-order-book-methods/book_offers' },
    ],
    ctas: [
      { label: 'Launch Dashboard →', action: 'auth:signup' },
      { label: 'Close', action: 'modal:close' },
    ],
  },

  'crypto-basics': {
    title: 'Crypto Basics: Keys + Signing',
    subtitle: 'Why keys matter, what signing does, and why validated actions are final.',
    sections: [
      {
        heading: 'Key concepts',
        paragraphs: [
          'Your private key proves ownership. If someone has it, they can sign actions as you.',
          'A digital signature is a tamper-proof stamp: the network can verify it, but nobody can forge it without the private key.',
          'This is why phishing is so dangerous: a valid signature is usually final once validated.',
        ],
        bullets: ['Public key: shareable.', 'Private key: never share.', 'Hashing: detects tampering.'],
      },
    ],
    links: [
      { label: 'XRPL: Cryptographic Keys', url: 'https://xrpl.org/docs/concepts/accounts/cryptographic-keys' },
      { label: 'XRPL: Secure Signing', url: 'https://xrpl.org/docs/concepts/transactions/secure-signing' },
      { label: 'Cloudflare: Public key cryptography', url: 'https://www.cloudflare.com/learning/ssl/how-does-public-key-encryption-work/' },
      { label: 'Cloudflare: What is a cryptographic key?', url: 'https://www.cloudflare.com/learning/ssl/what-is-a-cryptographic-key/' },
    ],
    ctas: [{ label: 'Close', action: 'modal:close' }],
  },

  'about-naluxrp': {
    title: 'What is NaluXRP?',
    subtitle: 'Client-only XRPL forensic & analytics suite: readable reporting + manipulation signals + investigation workflow.',
    sections: [
      {
        heading: 'The goal',
        paragraphs: [
          'NaluXRP turns raw ledger firehose data into something you can understand quickly:',
          'what happened, who seems involved, what changed, and what looks unusual.',
        ],
        bullets: [
          'Live stream: what the network is doing right now.',
          'Inspector: what’s going on with this address.',
          'Signals: what looks unusual or coordinated (heuristics).',
        ],
      },
      {
        heading: 'How it helps defenders',
        paragraphs: [
          'When investigating suspicious activity (compromises, scams, wash-like churn), you need context fast.',
          'NaluXRP helps you gather data, pivot between entities, and produce a clear report of what the ledger shows.',
        ],
        bullets: [
          'Pattern windows (repeat pairs, cluster-like co-activity).',
          'DEX churn signals (OfferCreate/Cancel intensity + concentration).',
          'AMM/LP bursts (deposit/withdraw waves).',
        ],
      },
      {
        heading: 'Ethics',
        paragraphs: [
          'Designed for defensive monitoring, research, and investigations.',
          'Not for stealing funds or unauthorized access.',
        ],
      },
    ],
    links: [
      { label: 'XRPL Docs: Transactions', url: 'https://xrpl.org/docs/concepts/transactions' },
      { label: 'XRPL Docs: DEX', url: 'https://xrpl.org/docs/concepts/tokens/decentralized-exchange' },
      { label: 'XRPL Docs: AMMs', url: 'https://xrpl.org/docs/concepts/tokens/decentralized-exchange/automated-market-makers' },
      { label: 'XRPL Learning: Scam safety checklist', url: 'https://learn.xrpl.org/blog/safeguarding-your-crypto-wallet-your-essential-checklist-against-defi-scams/' },
    ],
    ctas: [
      { label: 'Launch Dashboard →', action: 'auth:signup' },
      { label: 'Close', action: 'modal:close' },
    ],
  },
};

const LEARN_TILES = [
  { icon: '📘', title: 'XRPL Ledgers', body: 'Ledgers, validation, and indices.', topic: 'xrpl-ledger' },
  { icon: '👤', title: 'Accounts', body: 'Balances, reserves, flags, and keys.', topic: 'accounts-trustlines' },
  { icon: '🪙', title: 'Trustlines', body: 'Token safety model on XRPL.', topic: 'accounts-trustlines' },
  { icon: '🔁', title: 'DEX + Offers', body: 'OfferCreate/Cancel + churn signals.', topic: 'dex-amm' },
  { icon: '💧', title: 'AMMs / LPs', body: 'Liquidity lifecycle and bursts.', topic: 'dex-amm' },
  { icon: '🛡️', title: 'Security', body: 'Defensive investigation workflow.', topic: 'security-drains' },
];

const FEATURE_CARDS = [
  { icon: '🛡️', title: 'NaluXRP Overview', desc: 'What the app does, how it helps investigations, and what signals mean.', topic: 'about-naluxrp' },
  { icon: '📘', title: 'XRPL Ledger', desc: 'Ledgers, validated finality, and how to interpret snapshots.', topic: 'xrpl-ledger' },
  { icon: '👤', title: 'Accounts + Trustlines', desc: 'Reserves, flags, and trustline fundamentals for tokens.', topic: 'accounts-trustlines' },
  { icon: '🔁', title: 'DEX / Offers / AMMs', desc: 'Trading primitives + what churn signals can indicate.', topic: 'dex-amm' },
  { icon: '🧯', title: 'Compromise Response', desc: 'How to read suspicious flows defensively and safely.', topic: 'security-drains' },
  { icon: '🤖', title: 'Bots + Monitoring', desc: 'Legit automation ideas using public XRPL data + validation steps.', topic: 'bots-data' },
  { icon: '🔐', title: 'Keys + Signing', desc: 'Why signatures matter and how to stay safe.', topic: 'crypto-basics' },
];

const USE_CASE_CARDS = [
  { num: 1, title: 'Learn the ecosystem with real sources', body: 'Open learning cards with detailed explanations and trusted references.', topic: 'xrpl-ledger' },
  { num: 2, title: 'Investigate suspicious wallet activity (defensive)', body: 'Inspector + counterparties + patterns to build a clear timeline.', topic: 'security-drains' },
  { num: 3, title: 'Monitor DEX/AMM churn for anomaly signals', body: 'OfferCreate/Cancel bursts, concentration, and LP waves.', topic: 'dex-amm' },
  { num: 4, title: 'Build monitoring bots on public data', body: 'Subscriptions + APIs for alerts, reporting, and research.', topic: 'bots-data' },
];

let actionsBound = false;

function ensureLearnModal() {
  if (document.getElementById('learnModalOverlay')) return;

  const overlay = document.createElement('div');
  overlay.id = 'learnModalOverlay';
  overlay.className = 'learn-modal-overlay';
  overlay.innerHTML = `
    <div class="learn-modal" role="dialog" aria-modal="true" aria-labelledby="learnModalTitle">
      <button class="learn-close" type="button" data-action="modal:close" aria-label="Close">✕</button>
      <div class="learn-head">
        <div class="learn-title" id="learnModalTitle"></div>
        <div class="learn-sub" id="learnModalSub"></div>
      </div>
      <div class="learn-body" id="learnModalBody"></div>
      <div class="learn-links-wrap">
        <div class="learn-links-title">Learning sources</div>
        <div class="learn-links" id="learnModalLinks"></div>
      </div>
      <div class="learn-cta-row" id="learnModalCtas"></div>
    </div>
  `;
  document.body.appendChild(overlay);

  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeTopicModal();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && overlay.classList.contains('show')) closeTopicModal();
  });
}

function openTopicModal(topicId) {
  const topic = TOPICS[topicId];
  if (!topic) return;

  ensureLearnModal();

  const overlay = document.getElementById('learnModalOverlay');
  const titleEl = document.getElementById('learnModalTitle');
  const subEl = document.getElementById('learnModalSub');
  const bodyEl = document.getElementById('learnModalBody');
  const linksEl = document.getElementById('learnModalLinks');
  const ctasEl = document.getElementById('learnModalCtas');

  if (!overlay || !titleEl || !subEl || !bodyEl || !linksEl || !ctasEl) return;

  titleEl.textContent = topic.title;
  subEl.textContent = topic.subtitle || '';

  bodyEl.innerHTML = (topic.sections || []).map((s) => `
    <section class="learn-sec">
      <h4>${escHtml(s.heading || '')}</h4>
      ${(s.paragraphs || []).map((p) => `<p>${escHtml(p)}</p>`).join('')}
      ${(s.bullets && s.bullets.length)
        ? `<ul>${s.bullets.map((b) => `<li>${escHtml(b)}</li>`).join('')}</ul>`
        : ''}
    </section>
  `).join('');

  linksEl.innerHTML = (topic.links || []).map((l) => `
    <a class="learn-link" href="${escHtml(l.url)}" target="_blank" rel="noopener noreferrer">
      ${escHtml(l.label)}
      <span aria-hidden="true">↗</span>
    </a>
  `).join('');

  ctasEl.innerHTML = (topic.ctas || []).map((c) => `
    <button class="learn-cta ${c.action === 'auth:signup' ? 'primary' : ''}" type="button" data-action="${escHtml(c.action)}">
      ${escHtml(c.label)}
    </button>
  `).join('');

  overlay.classList.add('show');
  document.body.classList.add('modal-open');
}

function closeTopicModal() {
  document.getElementById('learnModalOverlay')?.classList.remove('show');
  document.body.classList.remove('modal-open');
}

function runAction(action) {
  if (action === 'modal:close') return closeTopicModal();

  if (action === 'auth:signup') {
    closeTopicModal();
    window.openAuth?.('signup');
    return;
  }

  if (action === 'auth:login') {
    closeTopicModal();
    window.openAuth?.('login');
    return;
  }

  if (action.startsWith('topic:')) return openTopicModal(action.split(':')[1]);

  if (action.startsWith('scroll:')) {
    const id = action.split(':')[1];
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function bindLandingActions() {
  if (actionsBound) return;
  actionsBound = true;

  document.addEventListener('click', (e) => {
    const el = e.target.closest?.('[data-action]');
    if (!el) return;

    const action = el.getAttribute('data-action') || '';
    if (!action) return;

    e.preventDefault();
    runAction(action);
  });
}

export function buildLandingContent() {
  bindLandingActions();

  document.querySelector('.landing-features')?.setAttribute('id', 'learn');
  document.querySelector('.landing-simple-value')?.setAttribute('id', 'use-cases');
  document.querySelector('.landing-cta')?.setAttribute('id', 'about');

  // Improve readability: add a “kicker-like” container to the tagline via CSS hook class
  document.querySelector('.landing-tagline')?.classList.add('tagline-pill');

  const strip = document.querySelector('.landing-stats-strip');
  if (strip) {
    strip.classList.add('landing-learn-strip');
    strip.innerHTML = LEARN_TILES.map((t) => `
      <button class="learn-tile reveal" type="button" data-action="topic:${escHtml(t.topic)}" aria-label="${escHtml(t.title)}">
        <div class="learn-tile-ico">${t.icon}</div>
        <div class="learn-tile-t">${escHtml(t.title)}</div>
        <div class="learn-tile-b">${escHtml(t.body)}</div>
      </button>
    `).join('');
  }

  const featGrid = $('features-grid');
  if (featGrid) {
    featGrid.innerHTML = FEATURE_CARDS.map((f) => `
      <div class="feature-card reveal">
        <span class="feature-icon">${f.icon}</span>
        <h3>${escHtml(f.title)}</h3>
        <p>${escHtml(f.desc)}</p>
        <button class="feature-cta" type="button" data-action="topic:${escHtml(f.topic)}">
          Learn more →
        </button>
      </div>
    `).join('');
  }

  const learnSection = document.querySelector('.landing-simple-value');
  const learnTitle = learnSection?.querySelector('h2');
  if (learnTitle) learnTitle.textContent = 'What you can do with NaluXRP';

  const valueGrid = $('value-grid');
  if (valueGrid) {
    valueGrid.innerHTML = USE_CASE_CARDS.map((v) => `
      <div class="value-card reveal">
        <div class="value-number">${v.num}</div>
        <h3>${escHtml(v.title)}</h3>
        <p>${escHtml(v.body)}</p>
        <div class="value-actions">
          <button class="value-cta" type="button" data-action="topic:${escHtml(v.topic)}">Open guide →</button>
          <button class="value-cta primary" type="button" data-action="auth:signup">Launch Dashboard →</button>
        </div>
      </div>
    `).join('');
  }

  // Footer: use shield icon image + fallback
  const footerBrand = document.querySelector('.landing-footer-bar .footer-brand');
  if (footerBrand) {
    footerBrand.innerHTML = `
      <img class="footer-icon" src="images/shield.png" alt="" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline-flex';" />
      <span class="footer-icon-fallback" style="display:none">🛡️</span>
      <span class="brand-name">NaluXRP</span>
    `;
  }

  const footerTagline = document.querySelector('.landing-footer-bar .footer-tagline');
  if (footerTagline) {
    footerTagline.textContent =
      'Client-only XRPL analytics + decentralized cybersecurity signals — readable reporting, investigation workflow, and heuristic anomaly detection.';
  }

  const footerTags = document.querySelector('.landing-footer-bar .footer-tags');
  if (footerTags) {
    footerTags.innerHTML = `
      <span class="ftag">XRPL Analytics</span>
      <span class="ftag">Forensics</span>
      <span class="ftag">DEX / AMM</span>
      <span class="ftag">Manipulation Signals</span>
      <span class="ftag">Incident Response</span>
      <span class="ftag">Client-Only</span>
      <span class="ftag">No Tracking</span>
    `;
  }
}

export function initReveal() {
  const obs = new IntersectionObserver(
    (entries) => entries.forEach((e) => { if (e.isIntersecting) e.target.classList.add('visible'); }),
    { threshold: 0.12 }
  );
  document.querySelectorAll('.reveal').forEach((el) => obs.observe(el));
}