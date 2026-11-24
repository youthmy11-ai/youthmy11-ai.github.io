# ForgeSuite Studio (`youthmy11-ai.github.io`)

Zero-backend, privacy-first static GitHub Pages storefront & Micro-SaaS / Web3 Security developer toolkit by **youthmy11-ai**.

Live Site: **`https://youthmy11-ai.github.io/`**

![ForgeSuite Studio Storefront](assets/og-banner.png)
![CryptoBill Forge Workspace](assets/cryptobill-preview.png)

## Live Web Tools (`7` Client-Side Utilities)

All web tools execute **100% inside local browser memory** with zero ForgeSuite backend servers or telemetry:

1. **[CryptoBill Forge](https://youthmy11-ai.github.io/cryptobill.html)** (`cryptobill.html`) — **Free & Pro ($15 Lifetime)**
   - Serverless freelance crypto & PayPal invoice builder with A4 print-to-PDF layout (`@media print`), offline QR codes (`assets/qr.js`), and `#inv=<base64url>` shareable links.
2. **[TokenGuard Risk Scanner](https://youthmy11-ai.github.io/tokenaudit.html)** (`tokenaudit.html`) — **Free Single Scans + Pro Batch Watchlist ($35 Bundle)**
   - Live browser EVM (`Base`, `Ethereum`, `BSC`, `Arbitrum`) & Solana (`SPL Token` & `Token-2022`) token/contract scanner with PUSH-aware opcode disassembler (`SELFDESTRUCT`, `DELEGATECALL`), EIP-1967/1167 proxy inspection, honeypot tax checks, Token-2022 `permanentDelegate` / `transferFeeConfig` detection, and Pro `<= 25` Batch Watchlist JSON/CSV Risk Dossier export.
3. **[TokenCost Lab](https://youthmy11-ai.github.io/tokencalc.html)** (`tokencalc.html`) — **Free**
   - Multi-turn AI agent & LLM token cost, prompt-cache savings, and SaaS API pricing estimator with 1-click export to CryptoBill invoices.
4. **[JSON2Sheet & PII Masker](https://youthmy11-ai.github.io/json2sheet.html)** (`json2sheet.html`) — **Free**
   - Flattens nested JSON arrays cleanly into RFC-4180 CSV spreadsheets while masking sensitive emails, phones, and tokens locally.
5. **[ScopeGuard SOW Builder](https://youthmy11-ai.github.io/sowbuilder.html)** (`sowbuilder.html`) — **Free**
   - Interactive Statement of Work & milestone payment split generator with instant 1-click handoff into CryptoBill Forge (`#inv=`).
6. **[Calldata Lens](https://youthmy11-ai.github.io/txdecode.html)** (`txdecode.html`) — **Free**
   - Offline Ethereum & BSC EVM hex calldata decoder (`ERC-20`, `MAX_UINT256` infinite approval risk warnings, `EIP-2612` permits, `ERC-4626`, `Safe` multisig) with zero RPC logging.
7. **[EnvShield Secret Scanner](https://youthmy11-ai.github.io/envshield.html)** (`envshield.html`) — **Free**
   - Instant client-side `.env`, JSON, and transcript secret scanner & safe redactor covering OpenAI, Anthropic, GitHub, AWS, Google, Telegram, EVM private keys, JWTs, DB URIs, and high-entropy credentials.

## ForgeSuite MCP Server (`mcp/forgesuite-mcp.mjs` · v1.1.0 · 6 Tools · Zero Dependencies)

Connect Claude Code, Cursor, Antigravity, or Windsurf to **6 developer, FinOps & Web3 security tools** (`envshield_scan`, `calldata_decode`, `tokencost_estimate`, `cryptobill_quote`, `evm_token_risk_scan`, `solana_mint_risk_scan`) — docs at **[mcp.html](https://youthmy11-ai.github.io/mcp.html)**:

```bash
mkdir -p ~/.forgesuite-mcp && curl -fsSL https://youthmy11-ai.github.io/mcp/forgesuite-mcp.mjs -o ~/.forgesuite-mcp/forgesuite-mcp.mjs
claude mcp add forgesuite -- node "$HOME/.forgesuite-mcp/forgesuite-mcp.mjs"
```

## Packaged Pro Editions & Bundle (`Save $14`)

- **CryptoBill Forge Pro** — `$15` Lifetime (Unlimited line items, white-label PDF, custom branding, batch presets)
- **[AutoShorts Studio Pro](https://github.com/youthmy11-ai/autoshorts-studio)** — `$19` Lifetime (Python + FFmpeg 9:16/16:9/1:1 batch shorts builder with SHA-256 deduplication; Free Community Edition on GitHub)
- **[WebLead & Table Extractor Pro](https://github.com/youthmy11-ai/weblead-extractor)** — `$15` Lifetime (Chrome MV3 DOM table, email & list scraper; Free Lite Edition on GitHub)
- **All-Access Creator & Freelancer Bundle** — **`$35` Lifetime** (Unlocks all 3 Pro products + TokenGuard 25-token Batch Watchlist & CSV/JSON Risk Dossier export; Save `$14`)
- **[Forge AI Agent (A2A + x402)](https://market.near.ai/a/forge-ai-agent)** — **`$5.00 USDC` / call** (Autonomous deep line-by-line Solidity/Rust source audits & engineering tasks)

## Verification & Zero-Backend Checkout (`assets/checkout.js`)

- **Instant On-Chain Solana USDC (SPL) & BSC USDT (BEP20):** Queries CORS-safe public RPCs (`getTransaction` / `eth_getTransactionReceipt`) and deterministically generates checksummed `FS-PRO-...` license keys in browser.
- **Alternative Payment Channels:** USDT (TRC20), Binance Pay, and direct PayPal checkout helpers.

## Running Automated Tests

Requires Node.js v22+ (`0` external npm dependencies):

```bash
node --test tests/suite.test.mjs
```

## Support & License

- Support Email: `youthmy11@gmail.com`
- License: MIT (`LICENSE`)
