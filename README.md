# ForgeSuite Studio (`youthmy11-ai.github.io`)

Zero-backend, static GitHub Pages storefront & Micro-SaaS web app hub by **youthmy11-ai**.

Live target URL: `https://youthmy11-ai.github.io/`

## Included Tools & Products

1. **CryptoBill Forge (`cryptobill.html`)** — Free & Pro ($15 Lifetime)
   - Serverless freelance crypto & PayPal invoice builder with A4 print-to-PDF styling (`@media print`).
   - Deterministic offline QR Code Version 1–10 generator (`assets/qr.js`, pure ES module JS, zero external QR APIs).
   - Shareable client links via URL fragment (`#inv=<base64url>`), switching automatically into read-only client payment mode.
   - JSON invoice import/export, saved browser templates (`localStorage`), and Pro features (unlimited line items, white-label footer removal, custom accent/logo, bulk batch JSON presets).
2. **AutoShorts Studio Pro** — $19 Lifetime ([Community Edition Repo](https://github.com/youthmy11-ai/autoshorts-studio))
   - Automated 9:16, 16:9 & 1:1 batch short-form video creator with SHA-256 clip deduplication and beat-milestone audio trimming.
3. **WebLead & Table Extractor Pro** — $15 Lifetime ([Lite Edition Repo](https://github.com/youthmy11-ai/weblead-extractor))
   - Privacy-first Chrome Manifest V3 extension for extracting HTML tables, emails, and structured directory lists into clean CSV/JSON.
4. **All-Access Creator & Freelancer Bundle** — $35 Lifetime (Save $14).

## Architecture

- `index.html` — Storefront, live sandbox demo, pricing matrix, checkout modal, and on-chain license verifier.
- `cryptobill.html` — Full CryptoBill Forge web application.
- `assets/styles.css` — Responsive dark/light theme system + A4 print stylesheet.
- `assets/qr.js` — Pure ES module ISO/IEC 18004 QR Code Version 1–10 Byte-mode matrix generator + SVG/Canvas renderers.
- `assets/checkout.js` — Client-side BSC USDT (BEP20) JSON-RPC receipt verification (`eth_getTransactionReceipt`), deterministic checksummed license keys, PayPal checkout URL builder, and mailto receipt helper.
- `assets/cryptobill.js` — Invoice totals engine, `#inv=` Base64URL codec, Free/Pro gating, and UI controller.
- `assets/store.js` — Storefront sandbox, theme toggle, and license state management.
- `tests/suite.test.mjs` — Automated Node test suite (`node --test`).

## Running Automated Tests

Requires Node.js v20+ (tested on Node v26):

```bash
node --test tests/suite.test.mjs
```

## Local Static Preview

Serve the repository folder with any static file server:

```bash
npx serve .
```

## Support

- Email: `youthmy11@gmail.com`
- License: MIT (`LICENSE`)
