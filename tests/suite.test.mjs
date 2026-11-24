import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  BSC_RPC_ENDPOINTS,
  buildMailtoReceiptUrl,
  buildPaypalCheckoutUrl,
  ERC20_TRANSFER_TOPIC0,
  generateLicenseKey,
  OFFICIAL_CHANNELS,
  parseLicenseKey,
  verifyBscUsdtReceipt,
  verifyBscUsdtTxOnChain,
  validateLicenseKeyFormat,
} from "../assets/checkout.js";

import {
  calculateInvoiceTotals,
  decodeInvoicePayload,
  encodeInvoicePayload,
  FREE_TIER_LIMITS,
  resolvePrimaryQrPayload,
  validateInvoiceLimits,
} from "../assets/cryptobill.js";

import { encodeQr, generateQrMatrix, renderQrSvg } from "../assets/qr.js";
import {
  buildCryptoBillQuotePayload,
  calculateRunCosts,
  estimateTokenCount,
  MODEL_PRICING,
} from "../assets/tokencalc.js";
import {
  extractRecordArray,
  flattenObject,
  maskSensitiveText,
  recordsToCsv,
  recordsToMarkdownTable,
} from "../assets/json2sheet.js";
import {
  buildMilestoneInvoicePayload,
  computeSowTotals,
  decodeSowHandoffPayload,
  renderSowMarkdown,
  SOW_PRESETS,
} from "../assets/sowbuilder.js";
import {
  buildReviewInvoicePayload,
  CALLDATA_SAMPLES,
  decodeCalldata,
} from "../assets/txdecode.js";
import {
  buildSanitizationInvoice,
  ENVSHIELD_SAMPLES,
  scanSecrets,
  shannonEntropy,
} from "../assets/envshield.js";
import {
  SOLANA_RPC_ENDPOINTS,
  verifySolanaUsdcTx,
  verifySolanaUsdcTxOnChain,
} from "../assets/checkout.js";
import {
  analyzeEvmBytecodeHex,
  buildAuditInvoicePayload,
  EVM_CHAIN_CONFIG as TOKENGUARD_EVM_CHAINS,
  exportBatchReportsCsv,
  parseTokenAuditQueryParams,
  parseWatchlistEntries,
  runBatchWatchlistScan,
  scanEvmTokenOnChain,
  scanSolanaMintOnChain,
  scoreEvmTokenRisk,
  scoreSolanaMintRisk,
  SLOT_ZEPPELINOS_ADMIN,
  SLOT_ZEPPELINOS_IMPL,
  SOLANA_RPC_ENDPOINTS as TOKENGUARD_SOLANA_RPCS,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
} from "../assets/tokenaudit.js";
import {
  SERVER_INFO as MCP_SERVER_INFO,
  auditSubtitleCaptions,
  classifyWalletEvmBytecode,
  deriveSolanaAssociatedTokenAddress,
  handleJsonRpcMessage,
  normalizeBrandCandidate,
  scanBrandDomainAndHandles,
  scanMultiChainWallets,
} from "../mcp/forgesuite-mcp.mjs";
import { createForgeSuiteMcpbBuffer } from "../mcp/pack-mcpb.mjs";
import {
  MAX_WATCHLIST_WALLETS,
  NEAR_WALLET_SCANNER_URL,
  WALLETLENS_EVM_CHAINS,
  WALLETLENS_SOLANA_CONFIG,
  buildWalletAuditInvoicePayload,
  buildWalletSowState,
  classifyEvmCodeStatic as walletLensClassifyCode,
  deriveSolanaAta,
  exportWalletWatchlistCsv,
  inspectSingleWallet,
  isValidEvmAddress as walletLensValidEvm,
  isValidSolanaAddress as walletLensValidSol,
  parseWalletCheckQueryParams,
  parseWalletWatchlistEntries,
  runBatchWalletWatchlist,
} from "../assets/walletcheck.js";
import {
  BRANDGUARD_DEFAULT_TLDS,
  CORS_RDAP_BY_TLD,
  FREE_VARIATION_LIMIT,
  MAX_BATCH_BRANDS,
  NEAR_BRAND_CHECKER_URL,
  buildBrandAuditInvoicePayload,
  buildBrandSowState,
  checkDomainBrowserCors,
  encodeSowHandoffPayload,
  exportBrandMatrixCsv,
  generateBrandVariations,
  normalizeBrandName,
  parseBatchBrandList,
  parseBrandCheckQueryParams,
  runBatchBrandScan,
  scanBrandVariations,
  scanSingleBrand,
  scoreBrandReadiness,
  validateLicenseKeyFormat as brandGuardValidateKey,
} from "../assets/brandcheck.js";
import {
  ASS_STYLE_PRESETS,
  DEFAULT_MAX_CPS,
  DEFAULT_MAX_LINE_CHARS,
  MAX_BATCH_SUBTITLE_FILES,
  NEAR_VIDEO_CLIPPER_URL,
  NEAR_VIDEO_DUBBER_URL,
  SRTLAB_SAMPLES,
  applyTimingTransform,
  auditSubtitles,
  autoFixSubtitleCues,
  buildCaptionLocalizationInvoicePayload,
  buildCaptionSowState,
  detectSubtitleFormat,
  exportBatchSubtitleCsv,
  formatAssTimestamp,
  formatSrtTimestamp,
  formatVttTimestamp,
  parseSrtLabQueryParams,
  parseSubtitles,
  parseTimestampMs,
  runBatchSubtitleAudit,
  serializeToSrt,
  serializeToTranscriptTxt,
  serializeToVerticalAss,
  serializeToVtt,
} from "../assets/srtlab.js";

test("verifySolanaUsdcTx and verifySolanaUsdcTxOnChain validate SPL USDC transfers and issue keys", async () => {
  const sampleTx = {
    transaction: {
      signatures: ["5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"],
    },
    meta: {
      err: null,
      preTokenBalances: [
        {
          accountIndex: 2,
          mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
          owner: "BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx",
          uiTokenAmount: { amount: "10000000", decimals: 6 },
        },
      ],
      postTokenBalances: [
        {
          accountIndex: 2,
          mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
          owner: "BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx",
          uiTokenAmount: { amount: "45000000", decimals: 6 },
        },
      ],
    },
  };

  const ok = verifySolanaUsdcTx(sampleTx, 35);
  assert.equal(ok.verified, true);
  assert.equal(ok.amountUsd, 35);
  assert.equal(ok.tier, "BUNDLE");
  assert.match(ok.licenseKey, /^FS-PRO-BUNDLE-[A-Z0-9]{8}-[0-9A-F]{4}$/);

  const low = verifySolanaUsdcTx(sampleTx, 50);
  assert.equal(low.verified, false);
  assert.match(low.reason, /Insufficient USDC/);

  const rpcRes = await verifySolanaUsdcTxOnChain(
    sampleTx.transaction.signatures[0],
    35,
    {
      fetchImpl: async () => ({
        ok: true,
        json: async () => ({ jsonrpc: "2.0", id: 1, result: sampleTx }),
      }),
    }
  );
  assert.equal(rpcRes.verified, true);
  assert.equal(rpcRes.licenseKey, ok.licenseKey);
});

test("verifySolanaUsdcTx handles newly created destination ATA (real mainnet shape), blocks self-transfer inflation, and falls back across RPC errors/nulls", async () => {
  // Real Solana Mainnet tx shape where destination ATA (accountIndex 2) is created in-tx and absent from preTokenBalances
  const mainnetNewAtaSig =
    "Axbuzxysfc819mEoCPCHA7st4xN4oE1JEfw9d9YRmF6vmg2vuLwTAzGVQS2Bu4X5Wc7XS2MmhFgJa3BrnZT6cXi";
  const mainnetNewAtaTx = {
    slot: 473085555,
    version: "legacy",
    transaction: { signatures: [mainnetNewAtaSig] },
    meta: {
      err: null,
      preTokenBalances: [
        {
          accountIndex: 1,
          mint: OFFICIAL_CHANNELS.solanaUsdcMint,
          owner: "4zRgaH7p9zSRnKR8Yyj6irjZT7hLPjjf2VzYVT5EX3RQ",
          uiTokenAmount: { amount: "609001383", decimals: 6, uiAmountString: "609.001383" },
        },
      ],
      postTokenBalances: [
        {
          accountIndex: 1,
          mint: OFFICIAL_CHANNELS.solanaUsdcMint,
          owner: "4zRgaH7p9zSRnKR8Yyj6irjZT7hLPjjf2VzYVT5EX3RQ",
          uiTokenAmount: { amount: "608751383", decimals: 6, uiAmountString: "608.751383" },
        },
        {
          accountIndex: 2,
          mint: OFFICIAL_CHANNELS.solanaUsdcMint,
          owner: OFFICIAL_CHANNELS.solanaUsdc,
          uiTokenAmount: { amount: "250000", decimals: 6, uiAmountString: "0.25" },
        },
      ],
    },
  };

  const verifiedNewAta = verifySolanaUsdcTx(mainnetNewAtaTx, 0.25);
  assert.equal(verifiedNewAta.verified, true);
  assert.equal(verifiedNewAta.amountUsd, 0.25);
  assert.equal(verifiedNewAta.amountMicro, "250000");
  assert.equal(verifiedNewAta.to, OFFICIAL_CHANNELS.solanaUsdc);
  assert.equal(validateLicenseKeyFormat(verifiedNewAta.licenseKey), true);

  // Underpayment check against $15 Pro tier
  const underpaid = verifySolanaUsdcTx(mainnetNewAtaTx, 15);
  assert.equal(underpaid.verified, false);
  assert.match(underpaid.reason, /0\.25 USDC received, expected \$15\.00/);

  // Self-transfer between two ATAs of the same owner yields 0 net credit and must be rejected
  const selfTransferTx = {
    transaction: { signatures: [mainnetNewAtaSig] },
    meta: {
      err: null,
      preTokenBalances: [
        {
          accountIndex: 1,
          mint: OFFICIAL_CHANNELS.solanaUsdcMint,
          owner: OFFICIAL_CHANNELS.solanaUsdc,
          uiTokenAmount: { amount: "20000000", decimals: 6 },
        },
      ],
      postTokenBalances: [
        {
          accountIndex: 1,
          mint: OFFICIAL_CHANNELS.solanaUsdcMint,
          owner: OFFICIAL_CHANNELS.solanaUsdc,
          uiTokenAmount: { amount: "5000000", decimals: 6 },
        },
        {
          accountIndex: 2,
          mint: OFFICIAL_CHANNELS.solanaUsdcMint,
          owner: OFFICIAL_CHANNELS.solanaUsdc,
          uiTokenAmount: { amount: "15000000", decimals: 6 },
        },
      ],
    },
  };
  assert.equal(verifySolanaUsdcTx(selfTransferTx, 15).verified, false);

  // Multi-endpoint CORS-safe default list + fallback across HTTP 403 and pruned null result
  assert.ok(SOLANA_RPC_ENDPOINTS.length >= 2);
  assert.notEqual(
    SOLANA_RPC_ENDPOINTS[0],
    "https://api.mainnet-beta.solana.com",
    "Primary Solana RPC must be browser-CORS friendly instead of 403-blocking api.mainnet-beta.solana.com"
  );

  const calls = [];
  let capturedBody = null;
  const fallbackRes = await verifySolanaUsdcTxOnChain(mainnetNewAtaSig, 0.25, {
    endpoints: ["https://rpc-403.test", "https://rpc-pruned.test", "https://rpc-ok.test"],
    fetchImpl: async (url, init) => {
      calls.push(url);
      capturedBody = JSON.parse(init.body);
      if (url === "https://rpc-403.test") {
        return { ok: false, status: 403, json: async () => ({ error: { code: 403 } }) };
      }
      if (url === "https://rpc-pruned.test") {
        return { ok: true, status: 200, json: async () => ({ jsonrpc: "2.0", id: 1, result: null }) };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: "2.0", id: 1, result: mainnetNewAtaTx }),
      };
    },
  });
  assert.deepEqual(calls, ["https://rpc-403.test", "https://rpc-pruned.test", "https://rpc-ok.test"]);
  assert.equal(capturedBody.params[1].commitment, "confirmed");
  assert.equal(capturedBody.params[1].encoding, "jsonParsed");
  assert.equal(capturedBody.params[1].maxSupportedTransactionVersion, 0);
  assert.equal(fallbackRes.verified, true);
  assert.equal(fallbackRes.licenseKey, verifiedNewAta.licenseKey);
});

function padAddressTopic(address) {
  return "0x" + "0".repeat(24) + address.replace(/^0x/i, "").toLowerCase();
}

function encodeUint256Wei18(amountIntegerOrFloat) {
  const micro = BigInt(Math.round(amountIntegerOrFloat * 1_000_000));
  const wei = micro * 10n ** 12n;
  return "0x" + wei.toString(16).padStart(64, "0");
}

const SAMPLE_TX_HASH =
  "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
const SENDER_ADDR = "0x1111111111111111111111111111111111111111";
const OTHER_ADDR = "0x2222222222222222222222222222222222222222";
const FAKE_CONTRACT = "0x9999999999999999999999999999999999999999";

/* ============================================================================
 * 1. BSC USDT Receipt & On-Chain Verification Tests
 * ========================================================================== */

test("verifyBscUsdtReceipt verifies exact 18-decimal USDT transfer and issues deterministic key", () => {
  const receipt = {
    status: "0x1",
    transactionHash: SAMPLE_TX_HASH,
    logs: [
      {
        address: OFFICIAL_CHANNELS.bscUsdtContract.toLowerCase(),
        topics: [
          ERC20_TRANSFER_TOPIC0,
          padAddressTopic(SENDER_ADDR),
          padAddressTopic(OFFICIAL_CHANNELS.usdtBep20),
        ],
        data: encodeUint256Wei18(15),
      },
    ],
  };

  const res1 = verifyBscUsdtReceipt(
    receipt,
    15,
    OFFICIAL_CHANNELS.usdtBep20
  );
  const res2 = verifyBscUsdtReceipt(
    receipt,
    15,
    OFFICIAL_CHANNELS.usdtBep20
  );

  assert.equal(res1.verified, true);
  assert.equal(res1.amountUsd, 15);
  assert.equal(res1.txHash, SAMPLE_TX_HASH);
  assert.equal(res1.token, "USDT-BEP20");
  assert.equal(res1.licenseKey, res2.licenseKey);
  assert.equal(validateLicenseKeyFormat(res1.licenseKey), true);
  assert.match(
    res1.licenseKey,
    /^FS-PRO-CB-[A-Z0-9]{8}(-[A-Z0-9]{4})?$/
  );
});

test("verifyBscUsdtReceipt accepts higher amount and 0.5% tolerance", () => {
  const receiptHigher = {
    status: "0x1",
    transactionHash: SAMPLE_TX_HASH,
    logs: [
      {
        address: OFFICIAL_CHANNELS.bscUsdtContract.toUpperCase().replace("0X", "0x"),
        topics: [
          ERC20_TRANSFER_TOPIC0,
          padAddressTopic(SENDER_ADDR),
          padAddressTopic(OFFICIAL_CHANNELS.usdtBep20),
        ],
        data: encodeUint256Wei18(35.5),
      },
    ],
  };

  const higher = verifyBscUsdtReceipt(
    receiptHigher,
    35,
    OFFICIAL_CHANNELS.usdtBep20,
    { tier: "BUNDLE" }
  );
  assert.equal(higher.verified, true);
  assert.equal(higher.amountUsd, 35.5);
  assert.equal(higher.tier, "BUNDLE");
  assert.equal(validateLicenseKeyFormat(higher.licenseKey), true);

  const receiptTolerance = {
    status: "0x1",
    transactionHash: SAMPLE_TX_HASH,
    logs: [
      {
        address: OFFICIAL_CHANNELS.bscUsdtContract,
        topics: [
          ERC20_TRANSFER_TOPIC0,
          padAddressTopic(SENDER_ADDR),
          padAddressTopic(OFFICIAL_CHANNELS.usdtBep20),
        ],
        data: encodeUint256Wei18(14.95),
      },
    ],
  };
  const tol = verifyBscUsdtReceipt(
    receiptTolerance,
    15,
    OFFICIAL_CHANNELS.usdtBep20
  );
  assert.equal(tol.verified, true);
  assert.equal(tol.amountUsd, 14.95);
});

test("verifyBscUsdtReceipt picks matching Transfer event from multi-log receipt", () => {
  const receipt = {
    status: "0x1",
    transactionHash: SAMPLE_TX_HASH,
    logs: [
      // Approval event (different topic0)
      {
        address: OFFICIAL_CHANNELS.bscUsdtContract,
        topics: [
          "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
          padAddressTopic(SENDER_ADDR),
          padAddressTopic(OTHER_ADDR),
        ],
        data: encodeUint256Wei18(100),
      },
      // Transfer of fake token to our address
      {
        address: FAKE_CONTRACT,
        topics: [
          ERC20_TRANSFER_TOPIC0,
          padAddressTopic(SENDER_ADDR),
          padAddressTopic(OFFICIAL_CHANNELS.usdtBep20),
        ],
        data: encodeUint256Wei18(19),
      },
      // Real USDT transfer to an unrelated router/fee wallet
      {
        address: OFFICIAL_CHANNELS.bscUsdtContract,
        topics: [
          ERC20_TRANSFER_TOPIC0,
          padAddressTopic(SENDER_ADDR),
          padAddressTopic(OTHER_ADDR),
        ],
        data: encodeUint256Wei18(0.25),
      },
      // Actual qualifying USDT transfer to official receiving address
      {
        address: OFFICIAL_CHANNELS.bscUsdtContract,
        topics: [
          ERC20_TRANSFER_TOPIC0,
          padAddressTopic(SENDER_ADDR),
          padAddressTopic(OFFICIAL_CHANNELS.usdtBep20),
        ],
        data: encodeUint256Wei18(19),
      },
    ],
  };

  const res = verifyBscUsdtReceipt(receipt, 19, OFFICIAL_CHANNELS.usdtBep20, {
    tier: "AS",
  });
  assert.equal(res.verified, true);
  assert.equal(res.amountUsd, 19);
  assert.equal(res.tier, "AS");
  assert.equal(validateLicenseKeyFormat(res.licenseKey), true);
});

test("verifyBscUsdtReceipt rejects failed status, wrong contract, wrong recipient, insufficient amount, and malformed logs", () => {
  // 1. status 0x0
  const failedStatus = verifyBscUsdtReceipt(
    {
      status: "0x0",
      logs: [
        {
          address: OFFICIAL_CHANNELS.bscUsdtContract,
          topics: [
            ERC20_TRANSFER_TOPIC0,
            padAddressTopic(SENDER_ADDR),
            padAddressTopic(OFFICIAL_CHANNELS.usdtBep20),
          ],
          data: encodeUint256Wei18(15),
        },
      ],
    },
    15,
    OFFICIAL_CHANNELS.usdtBep20
  );
  assert.equal(failedStatus.verified, false);

  // 2. wrong token contract
  const wrongContract = verifyBscUsdtReceipt(
    {
      status: "0x1",
      logs: [
        {
          address: FAKE_CONTRACT,
          topics: [
            ERC20_TRANSFER_TOPIC0,
            padAddressTopic(SENDER_ADDR),
            padAddressTopic(OFFICIAL_CHANNELS.usdtBep20),
          ],
          data: encodeUint256Wei18(15),
        },
      ],
    },
    15,
    OFFICIAL_CHANNELS.usdtBep20
  );
  assert.equal(wrongContract.verified, false);

  // 3. wrong recipient
  const wrongRecipient = verifyBscUsdtReceipt(
    {
      status: "0x1",
      logs: [
        {
          address: OFFICIAL_CHANNELS.bscUsdtContract,
          topics: [
            ERC20_TRANSFER_TOPIC0,
            padAddressTopic(SENDER_ADDR),
            padAddressTopic(OTHER_ADDR),
          ],
          data: encodeUint256Wei18(15),
        },
      ],
    },
    15,
    OFFICIAL_CHANNELS.usdtBep20
  );
  assert.equal(wrongRecipient.verified, false);

  // 4. insufficient amount
  const insufficient = verifyBscUsdtReceipt(
    {
      status: "0x1",
      logs: [
        {
          address: OFFICIAL_CHANNELS.bscUsdtContract,
          topics: [
            ERC20_TRANSFER_TOPIC0,
            padAddressTopic(SENDER_ADDR),
            padAddressTopic(OFFICIAL_CHANNELS.usdtBep20),
          ],
          data: encodeUint256Wei18(14.5),
        },
      ],
    },
    15,
    OFFICIAL_CHANNELS.usdtBep20
  );
  assert.equal(insufficient.verified, false);
  assert.match(insufficient.reason, /Insufficient/i);

  // 5. malformed log (empty 0x data & bad topics[2])
  const malformedData = verifyBscUsdtReceipt(
    {
      status: "0x1",
      logs: [
        {
          address: OFFICIAL_CHANNELS.bscUsdtContract,
          topics: [
            ERC20_TRANSFER_TOPIC0,
            padAddressTopic(SENDER_ADDR),
            padAddressTopic(OFFICIAL_CHANNELS.usdtBep20),
          ],
          data: "0x",
        },
      ],
    },
    15,
    OFFICIAL_CHANNELS.usdtBep20
  );
  assert.equal(malformedData.verified, false);

  const malformedTopic = verifyBscUsdtReceipt(
    {
      status: "0x1",
      logs: [
        {
          address: OFFICIAL_CHANNELS.bscUsdtContract,
          topics: [
            ERC20_TRANSFER_TOPIC0,
            padAddressTopic(SENDER_ADDR),
            "0x1234",
          ],
          data: encodeUint256Wei18(15),
        },
      ],
    },
    15,
    OFFICIAL_CHANNELS.usdtBep20
  );
  assert.equal(malformedTopic.verified, false);
});

test("verifyBscUsdtTxOnChain falls back across BSC RPC endpoints and validates txHash", async () => {
  const invalidHash = await verifyBscUsdtTxOnChain("0x1234", 15);
  assert.equal(invalidHash.verified, false);

  const calls = [];
  const mockFetch = async (url) => {
    calls.push(url);
    if (url === BSC_RPC_ENDPOINTS[0]) {
      throw new Error("Simulated primary timeout");
    }
    return {
      ok: true,
      async json() {
        return {
          jsonrpc: "2.0",
          id: 1,
          result: {
            status: "0x1",
            transactionHash: SAMPLE_TX_HASH,
            logs: [
              {
                address: OFFICIAL_CHANNELS.bscUsdtContract,
                topics: [
                  ERC20_TRANSFER_TOPIC0,
                  padAddressTopic(SENDER_ADDR),
                  padAddressTopic(OFFICIAL_CHANNELS.usdtBep20),
                ],
                data: encodeUint256Wei18(15),
              },
            ],
          },
        };
      },
    };
  };

  const res = await verifyBscUsdtTxOnChain(SAMPLE_TX_HASH, 15, {
    fetchImpl: mockFetch,
    tier: "WL",
  });
  assert.equal(calls.length, 2);
  assert.equal(res.verified, true);
  assert.equal(res.tier, "WL");
  assert.equal(validateLicenseKeyFormat(res.licenseKey), true);
});

/* ============================================================================
 * 2. PayPal Checkout URL & Mailto Receipt URL Tests
 * ========================================================================== */

test("buildPaypalCheckoutUrl builds exact official PayPal URL with min4444st@gmail.com", () => {
  const urlStr = buildPaypalCheckoutUrl({
    itemName: "CryptoBill Forge Pro",
    amountUsd: 15,
    sku: "CB",
  });
  const parsed = new URL(urlStr);
  assert.equal(parsed.origin, "https://www.paypal.com");
  assert.equal(parsed.pathname, "/cgi-bin/webscr");
  assert.equal(parsed.searchParams.get("cmd"), "_xclick");
  assert.equal(parsed.searchParams.get("business"), "min4444st@gmail.com");
  assert.equal(parsed.searchParams.get("item_name"), "CryptoBill Forge Pro");
  assert.equal(parsed.searchParams.get("amount"), "15.00");
  assert.equal(parsed.searchParams.get("currency_code"), "USD");
  assert.equal(parsed.searchParams.get("no_shipping"), "1");
  assert.equal(parsed.searchParams.get("item_number"), "CB");
  assert.match(urlStr, /business=min4444st%40gmail\.com/);
});

test("buildMailtoReceiptUrl targets youthmy11@gmail.com with exact order details", () => {
  const mailto = buildMailtoReceiptUrl({
    productName: "AutoShorts Studio Pro",
    sku: "AS",
    amountUsd: 19,
    paymentMethod: "USDT (TRC20)",
    referenceId: "tron-tx-998877",
    customerEmail: "buyer@example.com",
  });
  assert.ok(mailto.startsWith("mailto:youthmy11@gmail.com?"));
  const decoded = decodeURIComponent(mailto);
  assert.match(decoded, /AutoShorts Studio Pro/);
  assert.match(decoded, /\[AS\]/);
  assert.match(decoded, /\$19\.00 USD/);
  assert.match(decoded, /USDT \(TRC20\)/);
  assert.match(decoded, /tron-tx-998877/);
  assert.match(decoded, /buyer@example\.com/);
});

/* ============================================================================
 * 3. Pure-JS QR Code Generator Tests
 * ========================================================================== */

test("qr.js generates valid square boolean matrices (>= 21x21) for URLs, TRC20 & BEP20", () => {
  const payloads = [
    "https://youthmy11-ai.github.io/",
    OFFICIAL_CHANNELS.usdtTrc20,
    OFFICIAL_CHANNELS.usdtBep20,
    "https://youthmy11-ai.github.io/cryptobill.html#inv=" + "A".repeat(180),
  ];

  for (const payload of payloads) {
    const info = encodeQr(payload);
    const matrix = generateQrMatrix(payload);

    assert.equal(matrix.length, info.size);
    assert.ok(matrix.length >= 21, `Expected matrix >= 21x21, got ${matrix.length}`);
    for (const row of matrix) {
      assert.equal(row.length, matrix.length);
      for (const cell of row) {
        assert.equal(typeof cell, "boolean");
      }
    }

    // Verify top-left 7x7 finder outer border is dark and separator col/row 7 is light
    for (let i = 0; i < 7; i += 1) {
      assert.equal(matrix[0][i], true);
      assert.equal(matrix[6][i], true);
      assert.equal(matrix[i][0], true);
      assert.equal(matrix[i][6], true);
      assert.equal(matrix[7][i], false);
      assert.equal(matrix[i][7], false);
    }
    // Verify mandatory dark module at (4*version + 9, 8)
    assert.equal(matrix[4 * info.version + 9][8], true);

    // Deterministic output check
    assert.deepEqual(generateQrMatrix(payload), matrix);
  }
});

test("qr.js throws on empty strings and renders valid SVG markup", () => {
  assert.throws(() => generateQrMatrix(""), /non-empty string/i);
  assert.throws(() => generateQrMatrix("   "), /non-empty string/i);
  assert.throws(() => generateQrMatrix(null), /non-empty string/i);
  assert.throws(() => generateQrMatrix("X".repeat(300)), /exceeds/i);

  const svg = renderQrSvg(OFFICIAL_CHANNELS.usdtTrc20, {
    size: 180,
    margin: 3,
    label: "TRC20 Payment QR",
  });
  assert.ok(svg.startsWith("<svg "));
  assert.ok(svg.endsWith("</svg>"));
  assert.match(svg, /viewBox="0 0 \d+ \d+"/);
  assert.match(svg, /<rect /);
  assert.match(svg, /<path d="M/);
  assert.match(svg, /TRC20 Payment QR/);
});

/* ============================================================================
 * 4. CryptoBill Invoice Calculations, Hash Roundtrip & Limits Tests
 * ========================================================================== */

test("encodeInvoicePayload and decodeInvoicePayload perform lossless UTF-8 roundtrip", () => {
  const invoice = {
    businessName: "Studio Éclair — Freelance",
    businessEmail: "billing@eclair.dev",
    clientName: "Kōji Analytics GmbH",
    clientEmail: "ap@koji.de",
    invoiceNumber: "INV-2026-099",
    issueDate: "2026-11-15",
    dueDate: "2026-11-30",
    currency: "EUR",
    taxPercent: 19,
    discountPercent: 10,
    notes: "Pay via USDT or PayPal € — thank you!",
    paymentMethods: {
      solana: "BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx",
      bep20: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
      trc20: "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
      paypalEmail: "billing@eclair.dev",
      binancePayId: "554433221",
    },
    qrMethod: "trc20",
    branding: {
      accentColor: "#10b981",
      logoText: "EC",
      hideFooterBadge: true,
    },
    items: [
      { description: "UI Design System (€)", qty: 2, unitPrice: 350.5 },
      { description: "API Integration & QA", qty: 5, unitPrice: 80 },
    ],
  };

  const token = encodeInvoicePayload(invoice);
  assert.match(token, /^[A-Za-z0-9\-_]+$/);

  const decodedFromHash = decodeInvoicePayload(`#inv=${token}`);
  const decodedFromRaw = decodeInvoicePayload(token);

  assert.deepEqual(decodedFromHash, invoice);
  assert.deepEqual(decodedFromRaw, invoice);

  // Corrupted or empty payloads fail gracefully with null
  assert.equal(decodeInvoicePayload(""), null);
  assert.equal(decodeInvoicePayload("#inv=!!!not-base64!!!"), null);
  assert.equal(decodeInvoicePayload("#inv=e30"), null); // {} missing items
});

test("calculateInvoiceTotals computes subtotal, discount, tax, and grand total accurately", () => {
  const totals = calculateInvoiceTotals(
    [
      { description: "Design", qty: 2, unitPrice: 150.25 }, // 300.50
      { description: "Build", qty: 3, unitPrice: 200 }, // 600.00
    ],
    10, // 10% tax
    20 // 20% discount
  );

  // Subtotal = 900.50; 20% discount = 180.10; taxable = 720.40; 10% tax = 72.04; grand = 792.44
  assert.equal(totals.subtotal, 900.5);
  assert.equal(totals.discountAmount, 180.1);
  assert.equal(totals.taxableAmount, 720.4);
  assert.equal(totals.taxAmount, 72.04);
  assert.equal(totals.grandTotal, 792.44);

  const empty = calculateInvoiceTotals([], 15, 5);
  assert.equal(empty.subtotal, 0);
  assert.equal(empty.grandTotal, 0);
});

test("validateInvoiceLimits enforces Free vs Pro line item limits and resolves QR payload", () => {
  const threeItems = {
    items: [
      { description: "A", qty: 1, unitPrice: 10 },
      { description: "B", qty: 1, unitPrice: 20 },
      { description: "C", qty: 1, unitPrice: 30 },
    ],
    paymentMethods: { bep20: "", trc20: "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb" },
    qrMethod: "auto",
  };
  const fourItems = {
    ...threeItems,
    items: [...threeItems.items, { description: "D", qty: 1, unitPrice: 40 }],
  };

  assert.equal(FREE_TIER_LIMITS.maxLineItems, 3);
  assert.equal(validateInvoiceLimits(threeItems, false).allowed, true);
  assert.equal(validateInvoiceLimits(fourItems, false).allowed, false);
  assert.equal(validateInvoiceLimits(fourItems, true).allowed, true);

  const qr = resolvePrimaryQrPayload(threeItems, { grandTotal: 60 });
  assert.equal(qr.method, "trc20");
  assert.equal(qr.qrString, "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb");

  const solanaInvoice = {
    ...threeItems,
    currency: "USDC",
    paymentMethods: { solana: "BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx", bep20: "", trc20: "" },
    qrMethod: "solana",
  };
  const solQr = resolvePrimaryQrPayload(solanaInvoice, { grandTotal: 125.5 });
  assert.equal(solQr.method, "solana");
  assert.equal(
    solQr.qrString,
    "solana:BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx?amount=125.50&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
  );
  assert.ok(generateQrMatrix(solQr.qrString).length >= 21);
});

/* ============================================================================
 * 5. Deterministic Checksummed License Key Validation Tests
 * ========================================================================== */

test("validateLicenseKeyFormat accepts generated keys and rejects guesses or tampered keys", () => {
  for (const tier of ["CB", "AS", "WL", "BUNDLE"]) {
    const key = generateLicenseKey(tier, `seed-${tier}-001`);
    assert.match(key, /^FS-PRO-(CB|AS|WL|BUNDLE)-[A-Z0-9]{8}(-[A-Z0-9]{4})?$/);
    assert.equal(validateLicenseKeyFormat(key), true);
    assert.equal(validateLicenseKeyFormat(key.toLowerCase()), true);

    // 8-char prefix form without trailing -XXXX also passes checksum
    const shortForm = key.slice(0, key.lastIndexOf("-"));
    assert.equal(validateLicenseKeyFormat(shortForm), true);

    // Tamper 1 char -> must fail
    const lastChar = key.at(-1);
    const alteredLast = lastChar === "F" ? "A" : "F";
    assert.equal(validateLicenseKeyFormat(key.slice(0, -1) + alteredLast), false);
  }

  const parsedBundle = parseLicenseKey(generateLicenseKey("BUNDLE", "bundle-tx"));
  assert.equal(parsedBundle.valid, true);
  assert.deepEqual(parsedBundle.unlocks, ["CB", "AS", "WL", "BUNDLE"]);

  // Random/arbitrary guesses must fail
  const invalidGuesses = [
    "",
    null,
    undefined,
    "FS-PRO-CB-12345678",
    "FS-PRO-CB-12345678-ABCD",
    "FS-PRO-CB-AAAAAAAA-BBBB",
    "FS-PRO-XX-12345678-ABCD",
    "RANDOM-LICENSE-KEY",
  ];
  for (const bad of invalidGuesses) {
    assert.equal(
      validateLicenseKeyFormat(bad),
      false,
      `Expected invalid key "${bad}" to be rejected`
    );
  }
});

/* ============================================================================
 * 6. TokenCost Lab Estimator & CryptoBill Quote Handoff Tests
 * ========================================================================== */

test("estimateTokenCount handles empty, ASCII prose, code, and Unicode consistently", () => {
  const empty = estimateTokenCount("");
  assert.equal(empty.tokens, 0);
  assert.equal(empty.bytesUtf8, 0);

  const code = estimateTokenCount("export function sum(a: number, b: number) { return a + b; }");
  assert.ok(code.tokens >= 10 && code.tokens <= 30);
  assert.equal(code.lines, 1);

  const vi = estimateTokenCount("Hệ thống thanh toán hóa đơn tự động");
  assert.ok(vi.tokens > 5);
  assert.ok(vi.bytesUtf8 > vi.chars);
});

test("calculateRunCosts prices cached vs uncached tokens and builds CryptoBill handoff", () => {
  const gpt5 = MODEL_PRICING.find((m) => m.id === "gpt-5");
  const res = calculateRunCosts({
    model: gpt5,
    inputTokens: 2000,
    cachedRatioPct: 50,
    outputTokens: 500,
    requestsPerDay: 1000,
    daysPerMonth: 30,
    marginMultiplier: 1.5,
  });

  // 1000 uncached ($1.25/1M) + 1000 cached ($0.125/1M) + 500 output ($10/1M)
  const expectedPerReq = 0.00125 + 0.000125 + 0.005;
  assert.ok(Math.abs(res.costPerReqTotal - expectedPerReq) < 1e-9);
  assert.ok(Math.abs(res.monthlyRawCost - expectedPerReq * 30_000) < 1e-6);
  assert.ok(Math.abs(res.monthlyClientQuote - res.monthlyRawCost * 1.5) < 1e-6);

  const inv = buildCryptoBillQuotePayload({
    modelName: res.modelName,
    requestsPerDay: 1000,
    daysPerMonth: 30,
    inputTokens: 2000,
    outputTokens: 500,
    monthlyRawCost: res.monthlyRawCost,
    monthlyClientQuote: res.monthlyClientQuote,
  });
  const decoded = decodeInvoicePayload(encodeInvoicePayload(inv));
  assert.equal(decoded.items.length, 2);
  const totals = calculateInvoiceTotals(decoded.items, decoded.taxPercent, decoded.discountPercent);
  assert.ok(Math.abs(totals.grandTotal - res.monthlyClientQuote) < 0.02);
});

/* ============================================================================
 * 7. JSON2Sheet & PII Privacy Masker Tests
 * ========================================================================== */

test("extractRecordArray flattens nested wrappers and arrays cleanly", () => {
  const payload = {
    data: [
      { id: 1, customer: { name: "Ada", contact: { email: "ada@example.org" } }, tags: ["a", "b"] },
      { id: 2, customer: { name: "Bob" }, extra: "=HYPERLINK(1)" },
    ],
  };
  const flat = extractRecordArray(payload);
  assert.equal(flat.length, 2);
  assert.equal(flat[0]["customer.contact.email"], "ada@example.org");
  assert.equal(flat[0].tags, "a; b");
  assert.deepEqual(flattenObject({ a: { b: 2 } }), { "a.b": 2 });
});

test("recordsToCsv and recordsToMarkdownTable apply PII masking and formula guard", () => {
  const rows = extractRecordArray([
    {
      email: "user@secret.io",
      ip: "192.168.1.55",
      token: "Bearer abcdef1234567890xyz",
      formula: "=SUM(A1:A9)",
    },
  ]);

  const csv = recordsToCsv(rows, { maskPii: true, guardFormula: true });
  assert.match(csv.text, /\[REDACTED_EMAIL\]/);
  assert.match(csv.text, /\[REDACTED_IP\]/);
  assert.match(csv.text, /\[REDACTED_TOKEN\]/);
  assert.match(csv.text, /'=SUM\(A1:A9\)/);

  const md = recordsToMarkdownTable(rows, { maskPii: true });
  assert.ok(md.startsWith("| email | ip | token | formula |"));
  assert.match(md, /\[REDACTED_EMAIL\]/);
  assert.equal(maskSensitiveText("Call +84 912 345 678 now", { phones: true }), "Call [REDACTED_PHONE] now");
});

/* ============================================================================
 * 8. ScopeGuard SOW & Milestone Escrow Builder Tests
 * ========================================================================== */

test("computeSowTotals, renderSowMarkdown, and buildMilestoneInvoicePayload stay aligned", () => {
  const preset = SOW_PRESETS.ai_mvp;
  const calc = computeSowTotals(preset);
  assert.equal(calc.isBalanced, true);
  assert.equal(calc.totalPercent, 100);
  assert.equal(calc.allocatedUsd, 2400);
  assert.equal(calc.milestones[0].amountUsd, 960);

  const md = renderSowMarkdown(preset);
  assert.match(md, /STATEMENT OF WORK & MILESTONE ESCROW AGREEMENT/);
  assert.match(md, /Acme SaaS Labs Inc\./);
  assert.match(md, /\$960\.00/);

  const inv = buildMilestoneInvoicePayload(preset, 0);
  const decoded = decodeInvoicePayload(encodeInvoicePayload(inv));
  assert.equal(decoded.clientName, "Acme SaaS Labs Inc.");
  const totals = calculateInvoiceTotals(decoded.items, decoded.taxPercent, decoded.discountPercent);
  assert.equal(totals.grandTotal, 960);
});

/* ============================================================================
 * 9. Calldata Lens EVM ABI & Approval Risk Decoder Tests
 * ========================================================================== */

test("decodeCalldata parses ERC-20 transfer, detects MAX_UINT256 approvals, and builds invoice payload", () => {
  const tx = decodeCalldata(CALLDATA_SAMPLES.usdt_transfer);
  assert.equal(tx.ok, true);
  assert.equal(tx.selector, "0xa9059cbb");
  assert.equal(tx.args[0].formatted, "0x0a1e9c96755a7962306cf2ca9a80113a61559852");
  assert.match(tx.args[1].note, /18dp: 35/);

  const inf = decodeCalldata(CALLDATA_SAMPLES.max_approve);
  assert.equal(inf.ok, true);
  assert.equal(inf.risk, "ALLOWANCE");
  assert.match(inf.args[1].formatted, /MAX_UINT256/);
  assert.match(inf.args[1].note, /UNLIMITED/);

  assert.equal(decodeCalldata("not-hex").ok, false);

  const inv = buildReviewInvoicePayload(tx);
  const roundtrip = decodeInvoicePayload(encodeInvoicePayload(inv));
  assert.equal(roundtrip.items[0].unitPrice, 150);
});

/* ============================================================================
 * 10. EnvShield Secret Leak Scanner & Safe Redactor Tests
 * ========================================================================== */

test("scanSecrets detects keys/URIs/private keys deterministically, masks previews, and builds invoice payload", () => {
  const dirty = scanSecrets(ENVSHIELD_SAMPLES.agent_env);
  assert.equal(dirty.totalFindings, 6);
  assert.equal(dirty.criticalCount, 3);
  assert.equal(dirty.highCount, 3);
  assert.match(dirty.redactedText, /<REDACTED:OPENAI_KEY>/);
  assert.match(dirty.redactedText, /<REDACTED:GITHUB_TOKEN>/);
  assert.match(dirty.redactedText, /<REDACTED:EVM_PRIVATE_KEY>/);
  assert.match(dirty.redactedText, /<REDACTED:DB_URI_CREDENTIALS>/);
  assert.match(dirty.redactedText, /<REDACTED:TELEGRAM_BOT_TOKEN>/);
  assert.match(dirty.redactedText, /<REDACTED:HIGH_ENTROPY_SECRET>/);
  assert.doesNotMatch(dirty.redactedText, /4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318/);
  assert.doesNotMatch(dirty.redactedText, /S3cur3Passw0rd/);

  const clean = scanSecrets(ENVSHIELD_SAMPLES.clean_config);
  assert.equal(clean.totalFindings, 0);
  assert.ok(shannonEntropy("aaaaaaaaaa") === 0);
  assert.ok(shannonEntropy("k9QmL8vX2pR7nW4zJ6cT1bY5hF3sD0aG") > 4.0);

  const inv = buildSanitizationInvoice(dirty);
  const roundtrip = decodeInvoicePayload(encodeInvoicePayload(inv));
  assert.equal(roundtrip.items[0].unitPrice, 95);
});

/* ============================================================================
 * 11. AI-Search (llms.txt) & Per-Page SEO / JSON-LD Integrity Tests
 * ========================================================================== */

test("llms.txt, llms-full.txt, robots.txt, sitemap.xml and all HTML pages carry valid SEO and JSON-LD metadata", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

  const llmsTxt = fs.readFileSync(path.join(repoRoot, "llms.txt"), "utf8");
  const llmsFull = fs.readFileSync(path.join(repoRoot, "llms-full.txt"), "utf8");
  assert.ok(llmsTxt.startsWith("# ForgeSuite Studio\n"), "llms.txt must start with H1 per llmstxt.org");
  assert.match(llmsTxt, /^> /m, "llms.txt must contain blockquote summary per llmstxt.org");
  assert.match(llmsFull, /CryptoBill Forge/);
  assert.match(llmsFull, /AutoShorts Studio/);
  assert.match(llmsFull, /WebLead & Table Extractor/);
  assert.match(llmsFull, /All-Access Creator & Freelancer Bundle/);
  assert.match(llmsFull, /TokenCost Lab/);
  assert.match(llmsFull, /JSON2Sheet & PII Masker/);
  assert.match(llmsFull, /ScopeGuard SOW Builder/);
  assert.match(llmsFull, /Calldata Lens/);
  assert.match(llmsFull, /EnvShield Secret Scanner/);
  assert.match(llmsFull, /TokenGuard/);
  assert.match(llmsFull, /BrandGuard/);
  assert.match(llmsFull, /WalletLens/);
  assert.match(llmsFull, /ClipCaption Lab/);
  assert.match(llmsFull, /ForgeSuite MCP Server/);
  assert.doesNotMatch(llmsTxt, /\b7 web (applications|utilities|tools)\b/i);
  assert.doesNotMatch(llmsFull, /\b7 web (applications|utilities|tools)\b/i);
  assert.match(llmsTxt, /All 10 web applications/);
  assert.match(llmsFull, /All 10 web applications/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/mcp\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/srtlab\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/tiktok-reels-9-16-subtitle-safe-zone-checker\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/youtube-most-replayed-clipper-ai-dubbing-guide\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/tokenaudit\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/solana-token-2022-scanner\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/evm-proxy-honeypot-scanner\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/brandcheck\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/uspto-trademark-domain-brand-checker\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/walletcheck\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/eip-7702-delegation-gnosis-safe-checker\.html/);
  assert.match(llmsTxt, /https:\/\/market\.near\.ai\/agents\/wallet-activity-scanner/);
  assert.match(llmsTxt, /https:\/\/market\.near\.ai\/agents\/short-video-clipper/);
  assert.match(llmsTxt, /https:\/\/market\.near\.ai\/agents\/multi-lang-video-dubber/);
  assert.match(llmsTxt, /https:\/\/market\.near\.ai\/agents\/forge-brand-checker/);
  assert.match(llmsTxt, /https:\/\/market\.near\.ai\/a\/forge-ai-agent/);
  assert.match(llmsFull, /srtlab\.html/);
  assert.match(llmsFull, /tiktok-reels-9-16-subtitle-safe-zone-checker\.html/);
  assert.match(llmsFull, /youtube-most-replayed-clipper-ai-dubbing-guide\.html/);
  assert.match(llmsFull, /solana-token-2022-scanner\.html/);
  assert.match(llmsFull, /evm-proxy-honeypot-scanner\.html/);
  assert.match(llmsFull, /eip-7702-delegation-gnosis-safe-checker\.html/);
  assert.match(llmsFull, /uspto-trademark-domain-brand-checker\.html/);
  assert.match(llmsFull, /BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx/);

  const robots = fs.readFileSync(path.join(repoRoot, "robots.txt"), "utf8");
  assert.match(robots, /Allow:\s*\/llms\.txt/);
  assert.match(robots, /Sitemap:\s*https:\/\/youthmy11-ai\.github\.io\/sitemap\.xml/);

  const sitemap = fs.readFileSync(path.join(repoRoot, "sitemap.xml"), "utf8");
  assert.match(sitemap, /https:\/\/youthmy11-ai\.github\.io\/llms\.txt/);
  assert.match(sitemap, /https:\/\/youthmy11-ai\.github\.io\/llms-full\.txt/);

  const toolPages = [
    { file: "cryptobill.html", url: "https://youthmy11-ai.github.io/cryptobill.html", category: "BusinessApplication" },
    { file: "tokenaudit.html", url: "https://youthmy11-ai.github.io/tokenaudit.html", category: "SecurityApplication" },
    { file: "solana-token-2022-scanner.html", url: "https://youthmy11-ai.github.io/solana-token-2022-scanner.html", category: "SecurityApplication" },
    { file: "evm-proxy-honeypot-scanner.html", url: "https://youthmy11-ai.github.io/evm-proxy-honeypot-scanner.html", category: "SecurityApplication" },
    { file: "eip-7702-delegation-gnosis-safe-checker.html", url: "https://youthmy11-ai.github.io/eip-7702-delegation-gnosis-safe-checker.html", category: "SecurityApplication" },
    { file: "brandcheck.html", url: "https://youthmy11-ai.github.io/brandcheck.html", category: "BusinessApplication" },
    { file: "uspto-trademark-domain-brand-checker.html", url: "https://youthmy11-ai.github.io/uspto-trademark-domain-brand-checker.html", category: "BusinessApplication" },
    { file: "tokencalc.html", url: "https://youthmy11-ai.github.io/tokencalc.html", category: "DeveloperApplication" },
    { file: "json2sheet.html", url: "https://youthmy11-ai.github.io/json2sheet.html", category: "DeveloperApplication" },
    { file: "sowbuilder.html", url: "https://youthmy11-ai.github.io/sowbuilder.html", category: "BusinessApplication" },
    { file: "txdecode.html", url: "https://youthmy11-ai.github.io/txdecode.html", category: "DeveloperApplication" },
    { file: "envshield.html", url: "https://youthmy11-ai.github.io/envshield.html", category: "SecurityApplication" },
    { file: "srtlab.html", url: "https://youthmy11-ai.github.io/srtlab.html", category: "MultimediaApplication" },
    { file: "tiktok-reels-9-16-subtitle-safe-zone-checker.html", url: "https://youthmy11-ai.github.io/tiktok-reels-9-16-subtitle-safe-zone-checker.html", category: "MultimediaApplication" },
    { file: "youtube-most-replayed-clipper-ai-dubbing-guide.html", url: "https://youthmy11-ai.github.io/youtube-most-replayed-clipper-ai-dubbing-guide.html", category: "MultimediaApplication" },
    { file: "mcp.html", url: "https://youthmy11-ai.github.io/mcp.html", category: "DeveloperApplication" },
  ];

  for (const page of toolPages) {
    const html = fs.readFileSync(path.join(repoRoot, page.file), "utf8");
    assert.ok(html.includes(`<link rel="canonical" href="${page.url}">`), `${page.file} missing canonical`);
    assert.match(html, /<meta property="og:title" content="[^"]+">/, `${page.file} missing og:title`);
    assert.match(html, /<meta property="og:description" content="[^"]+">/, `${page.file} missing og:description`);
    assert.ok(html.includes(`<meta property="og:url" content="${page.url}">`), `${page.file} missing og:url`);
    assert.match(html, /<meta property="og:type" content="website">/, `${page.file} missing og:type`);
    assert.match(html, /<meta name="twitter:card" content="summary_large_image">/, `${page.file} missing twitter:card`);
    assert.ok(sitemap.includes(`<loc>${page.url}</loc>`), `sitemap.xml missing ${page.url}`);

    const ldMatch = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
    assert.ok(ldMatch, `${page.file} missing JSON-LD script`);
    const ld = JSON.parse(ldMatch[1]);
    assert.equal(ld["@type"], "SoftwareApplication", `${page.file} JSON-LD must be SoftwareApplication`);
    assert.equal(ld.url, page.url, `${page.file} JSON-LD url mismatch`);
    assert.equal(ld.applicationCategory, page.category, `${page.file} JSON-LD category mismatch`);
    assert.ok(ld.offers, `${page.file} JSON-LD missing offers`);
  }

  const indexHtml = fs.readFileSync(path.join(repoRoot, "index.html"), "utf8");
  assert.ok(indexHtml.includes('<link rel="canonical" href="https://youthmy11-ai.github.io/">'));
  assert.ok(indexHtml.includes('href="tokenaudit.html"'), "index.html must link to tokenaudit.html");
  assert.ok(indexHtml.includes('href="brandcheck.html"'), "index.html must link to brandcheck.html");
  const indexLdMatch = indexHtml.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
  assert.ok(indexLdMatch, "index.html missing JSON-LD script");
  const indexLd = JSON.parse(indexLdMatch[1]);
  assert.ok(Array.isArray(indexLd["@graph"]) && indexLd["@graph"].length >= 13, "index.html @graph should list WebSite + all products including TokenGuard, BrandGuard & MCP Server");
});

/* ============================================================================
 * 12. ForgeSuite MCP Server End-to-End Stdio JSON-RPC 2.0 Tests
 * ========================================================================== */

function runMcpStdioSession(rawWrites) {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const serverPath = path.join(repoRoot, "mcp", "forgesuite-mcp.mjs");

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [serverPath], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (d) => {
      stdout += d;
    });
    child.stderr.on("data", (d) => {
      stderr += d;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      const lines = stdout
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      try {
        const messages = lines.map((l) => JSON.parse(l));
        resolve({ code, stderr, messages });
      } catch (err) {
        reject(new Error(`Invalid JSON on MCP stdout: ${stdout}\nErr: ${err.message}`));
      }
    });

    for (const chunk of rawWrites) {
      child.stdin.write(chunk);
    }
    child.stdin.end();
  });
}

test("ForgeSuite MCP stdio server handles initialize, notifications/initialized, ping, and tools/list", async () => {
  const writes = [
    JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "test-harness", version: "1.0.0" },
      },
    }) + "\n",
    // Notification (no id) must NOT produce any response
    JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n",
    JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }) + "\n",
    JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list" }) + "\n",
  ];

  const { code, stderr, messages } = await runMcpStdioSession(writes);
  assert.equal(code, 0);
  assert.equal(stderr, "");
  assert.equal(messages.length, 3, "Notification must produce zero responses");

  assert.equal(messages[0].id, 1);
  assert.equal(messages[0].result.protocolVersion, "2024-11-05");
  assert.equal(messages[0].result.serverInfo.name, "forgesuite-mcp");
  assert.equal(messages[0].result.serverInfo.version, "1.4.0");
  assert.equal(MCP_SERVER_INFO.version, "1.4.0");
  assert.ok(messages[0].result.capabilities.tools);

  assert.equal(messages[1].id, 2);
  assert.deepEqual(messages[1].result, {});

  assert.equal(messages[2].id, 3);
  assert.equal(messages[2].result.tools.length, 9);
  const toolNames = messages[2].result.tools.map((t) => t.name).sort();
  assert.deepEqual(toolNames, [
    "brand_domain_handle_scan",
    "calldata_decode",
    "cryptobill_quote",
    "envshield_scan",
    "evm_token_risk_scan",
    "multi_chain_wallet_scan",
    "solana_mint_risk_scan",
    "subtitle_caption_audit",
    "tokencost_estimate",
  ]);
  for (const tool of messages[2].result.tools) {
    assert.equal(tool.inputSchema.type, "object");
    assert.ok(tool.description.length > 20);
  }
});

test("ForgeSuite MCP stdio server executes all 4 offline tools end-to-end", async () => {
  const uniswapV2Swap =
    "0x38ed1739" +
    "0000000000000000000000000000000000000000000000000de0b6b3a7640000" +
    "0000000000000000000000000000000000000000000000000000000005f5e100" +
    "00000000000000000000000000000000000000000000000000000000000000a0" +
    "0000000000000000000000000a1e9c96755a7962306cf2ca9a80113a61559852" +
    "0000000000000000000000000000000000000000000000000000000067890abc";

  const envSampleWithJwtAndMnemonic = [
    ENVSHIELD_SAMPLES.agent_env,
    "SEED_PHRASE=\"abandon ability able about above absent absorb abstract absurd abuse access accident\"",
    "JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
  ].join("\n");

  const reqs = [
    {
      jsonrpc: "2.0",
      id: "env",
      method: "tools/call",
      params: { name: "envshield_scan", arguments: { text: envSampleWithJwtAndMnemonic } },
    },
    {
      jsonrpc: "2.0",
      id: "approve",
      method: "tools/call",
      params: { name: "calldata_decode", arguments: { calldata: CALLDATA_SAMPLES.max_approve } },
    },
    {
      jsonrpc: "2.0",
      id: "swap",
      method: "tools/call",
      params: { name: "calldata_decode", arguments: { calldata: uniswapV2Swap } },
    },
    {
      jsonrpc: "2.0",
      id: "tokens",
      method: "tools/call",
      params: {
        name: "tokencost_estimate",
        arguments: {
          inputTokens: 2000,
          outputTokens: 500,
          turns: 4,
          cachedRatioPct: 50,
          requestsPerDay: 200,
          daysPerMonth: 30,
          marginMultiplier: 1.5,
        },
      },
    },
    {
      jsonrpc: "2.0",
      id: "quote",
      method: "tools/call",
      params: {
        name: "cryptobill_quote",
        arguments: {
          businessName: "Forge AI Labs",
          clientName: "Protocol DAO",
          invoiceNumber: "INV-MCP-2026",
          currency: "USDT",
          discountPercent: 10,
          taxPercent: 0,
          items: [
            { description: "Smart Contract Security Audit", qty: 1, unitPrice: 1000 },
            { description: "MCP Automation Setup", qty: 2, unitPrice: 250 },
          ],
          paymentMethods: {
            bep20: OFFICIAL_CHANNELS.usdtBep20,
            solanaUsdc: OFFICIAL_CHANNELS.solanaUsdc,
          },
        },
      },
    },
  ];

  const { code, stderr, messages } = await runMcpStdioSession(
    reqs.map((r) => JSON.stringify(r) + "\n")
  );
  assert.equal(code, 0);
  assert.equal(stderr, "");
  assert.equal(messages.length, 5);

  // 1. envshield_scan
  const envRes = messages[0].result;
  assert.equal(envRes.isError, false);
  assert.equal(envRes.structuredContent.totalFindings, 8);
  assert.match(envRes.structuredContent.redactedText, /<REDACTED:OPENAI_KEY>/);
  assert.match(envRes.structuredContent.redactedText, /<REDACTED:EVM_PRIVATE_KEY>/);
  assert.match(envRes.structuredContent.redactedText, /<REDACTED:MNEMONIC_PHRASE>/);
  assert.match(envRes.structuredContent.redactedText, /<REDACTED:JWT_TOKEN>/);
  assert.match(envRes.structuredContent.redactedText, /<REDACTED:DB_URI_CREDENTIALS>/);
  assert.doesNotMatch(envRes.structuredContent.redactedText, /S3cur3Passw0rd/);
  assert.doesNotMatch(envRes.structuredContent.redactedText, /abandon ability able/);

  // 2. calldata_decode (MaxUint256 unlimited approval)
  const approveRes = messages[1].result;
  assert.equal(approveRes.isError, false);
  assert.equal(approveRes.structuredContent.selector, "0x095ea7b3");
  assert.equal(approveRes.structuredContent.unlimitedApprovalRisk, true);
  assert.equal(approveRes.structuredContent.risk, "UNLIMITED_APPROVAL_RISK");
  assert.ok(approveRes.structuredContent.warnings.length >= 1);
  assert.match(approveRes.content[0].text, /MAX_UINT256/);

  // 3. calldata_decode (Uniswap V2 swapExactTokensForTokens)
  const swapRes = messages[2].result;
  assert.equal(swapRes.isError, false);
  assert.equal(swapRes.structuredContent.selector, "0x38ed1739");
  assert.equal(swapRes.structuredContent.category, "Uniswap V2");
  assert.equal(swapRes.structuredContent.unlimitedApprovalRisk, false);
  assert.equal(swapRes.structuredContent.args[3].formatted, OFFICIAL_CHANNELS.usdtBep20);

  // 4. tokencost_estimate (multi-turn agent across Claude/GPT/Gemini/DeepSeek)
  const tokRes = messages[3].result;
  assert.equal(tokRes.isError, false);
  assert.equal(tokRes.structuredContent.assumptions.turns, 4);
  // 4 turns: 2000 + 2500 + 3000 + 3500 = 11000 input tokens; 4 * 500 = 2000 output tokens
  assert.equal(tokRes.structuredContent.assumptions.totalInputTokensPerRun, 11000);
  assert.equal(tokRes.structuredContent.assumptions.totalOutputTokensPerRun, 2000);
  const providers = new Set(tokRes.structuredContent.estimates.map((e) => e.provider));
  for (const p of ["OpenAI", "Anthropic", "Google", "DeepSeek"]) {
    assert.ok(providers.has(p), `Missing provider ${p} in tokencost_estimate`);
  }

  // 5. cryptobill_quote (exact math + live #inv= roundtrip + Pro Bundle CTA)
  const quoteRes = messages[4].result;
  assert.equal(quoteRes.isError, false);
  assert.equal(quoteRes.structuredContent.invoice.subtotal, 1500);
  assert.equal(quoteRes.structuredContent.invoice.discountAmount, 150);
  assert.equal(quoteRes.structuredContent.invoice.grandTotal, 1350);
  assert.equal(quoteRes.structuredContent.links.cryptobillApp, "https://youthmy11-ai.github.io/cryptobill.html");
  assert.equal(quoteRes.structuredContent.links.proBundlePriceUsd, 35);
  assert.match(quoteRes.content[0].text, /https:\/\/youthmy11-ai\.github\.io\/cryptobill\.html#inv=/);
  assert.match(quoteRes.content[0].text, /\$35/);

  const shareUrl = quoteRes.structuredContent.links.shareableInvoiceUrl;
  const hashPart = shareUrl.slice(shareUrl.indexOf("#inv="));
  const decoded = decodeInvoicePayload(hashPart);
  assert.equal(decoded.invoiceNumber, "INV-MCP-2026");
  assert.equal(decoded.clientName, "Protocol DAO");
  assert.equal(decoded.items.length, 2);
});

test("ForgeSuite MCP stdio server handles malformed JSON, unknown methods, unknown tools, and Content-Length framing", async () => {
  const clBody = JSON.stringify({ jsonrpc: "2.0", id: 99, method: "ping" });
  const clFramed = `Content-Length: ${Buffer.byteLength(clBody, "utf8")}\r\n\r\n${clBody}`;

  const writes = [
    "{broken-json\n",
    JSON.stringify({ jsonrpc: "2.0", id: 10, method: "unknown/method" }) + "\n",
    JSON.stringify({ jsonrpc: "2.0", id: 11, method: "tools/call", params: { name: "nonexistent_tool", arguments: {} } }) + "\n",
    JSON.stringify({ jsonrpc: "2.0", id: 12, method: "tools/call", params: { name: "calldata_decode", arguments: { calldata: "not-hex" } } }) + "\n",
    clFramed,
  ];

  const { code, messages } = await runMcpStdioSession(writes);
  assert.equal(code, 0);
  assert.equal(messages.length, 5);
  assert.equal(messages[0].error.code, -32700);
  assert.equal(messages[1].error.code, -32601);
  assert.equal(messages[2].error.code, -32602);
  assert.equal(messages[3].result.isError, true);
  assert.equal(messages[4].id, 99);
  assert.deepEqual(messages[4].result, {});
});

test(".nojekyll, A2A /.well-known/agent-card.json, and MCP /.well-known/mcp/server.json are valid and synced", () => {
  const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  assert.ok(fs.existsSync(path.join(rootDir, ".nojekyll")), ".nojekyll must exist so GitHub Pages serves /.well-known/*");
  const agentCard = JSON.parse(fs.readFileSync(path.join(rootDir, ".well-known", "agent-card.json"), "utf8"));
  assert.equal(agentCard.supportedInterfaces.length, 7);
  assert.equal(agentCard.supportedInterfaces[0].url, "https://forge-ai-agent.market.near.ai/a2a/v1");
  assert.equal(agentCard.supportedInterfaces[0].protocolBinding, "JSONRPC");
  for (const expectedUrl of [
    "https://wallet-activity-scanner.market.near.ai/a2a/v1",
    "https://short-video-clipper.market.near.ai/a2a/v1",
    "https://multi-lang-video-dubber.market.near.ai/a2a/v1",
  ]) {
    assert.ok(
      agentCard.supportedInterfaces.some((i) => i.url === expectedUrl),
      `agent-card.json missing A2A interface ${expectedUrl}`
    );
  }

  const mcpManifest = JSON.parse(fs.readFileSync(path.join(rootDir, ".well-known", "mcp", "server.json"), "utf8"));
  assert.equal(mcpManifest.name, "io.github.youthmy11-ai/forgesuite-mcp");
  assert.equal(mcpManifest.version, "1.4.0");
  assert.deepEqual(
    mcpManifest.tools.map((t) => t.name),
    [
      "envshield_scan",
      "calldata_decode",
      "tokencost_estimate",
      "cryptobill_quote",
      "evm_token_risk_scan",
      "solana_mint_risk_scan",
      "brand_domain_handle_scan",
      "multi_chain_wallet_scan",
      "subtitle_caption_audit",
    ]
  );
});

/* ============================================================================
 * 13. TokenGuard Engine (`assets/tokenaudit.js`) & MCP v1.1.0 Scan Tool Tests
 * ========================================================================== */

test("TokenGuard default RPC lists prioritize CORS-friendly PublicNode & Zan endpoints first", () => {
  assert.equal(TOKENGUARD_EVM_CHAINS.ethereum.rpcs[0], "https://ethereum-rpc.publicnode.com");
  assert.equal(TOKENGUARD_EVM_CHAINS.base.rpcs[0], "https://base-rpc.publicnode.com");
  assert.equal(TOKENGUARD_EVM_CHAINS.bsc.rpcs[0], "https://bsc-rpc.publicnode.com");
  assert.equal(TOKENGUARD_EVM_CHAINS.arbitrum.rpcs[0], "https://arbitrum-one-rpc.publicnode.com");
  assert.equal(TOKENGUARD_SOLANA_RPCS[0], "https://solana-rpc.publicnode.com");
  assert.equal(TOKENGUARD_SOLANA_RPCS[1], "https://api.zan.top/solana-mainnet");
});

test("analyzeEvmBytecodeHex performs PUSH-aware opcode disassembly, strips CBOR metadata, and detects EIP-1167 clones", () => {
  assert.equal(analyzeEvmBytecodeHex("0x").isContract, false);
  assert.equal(analyzeEvmBytecodeHex("").byteLength, 0);

  // PUSH32 containing 0xff, 0xf4, 0xf2, 0x32 data bytes + trailing IPFS CBOR metadata containing 0xff/0xf4
  // Must NOT trigger false-positive SELFDESTRUCT, DELEGATECALL, CALLCODE, or ORIGIN
  const push32Data = "ff" + "f4" + "f2" + "32" + "aa".repeat(28);
  const cborMeta = "a264697066735822" + "ff".repeat(34) + "64736f6c63430008140033"; // 51 bytes (0x0033)
  const safeBytecode = "0x6080604052" + "7f" + push32Data + "50" + "00" + cborMeta;
  const safeWalk = analyzeEvmBytecodeHex(safeBytecode);
  assert.equal(safeWalk.isContract, true);
  assert.equal(safeWalk.hasSelfDestruct, false);
  assert.equal(safeWalk.hasDelegateCall, false);
  assert.equal(safeWalk.hasCallCode, false);
  assert.equal(safeWalk.hasTxOrigin, false);

  // Real executable opcodes + PUSH4 risk selectors (mint, blacklist, pause, setSellTax)
  const riskyBytecode =
    "0x6080" +
    "6340c10f19" + // mint(address,uint256)
    "63f9f92be4" + // blacklist(address)
    "638456cb59" + // pause()
    "63cc1776d3" + // setSellTax(uint256)
    "32" + // ORIGIN
    "f4" + // DELEGATECALL
    "f2" + // CALLCODE
    "f5" + // CREATE2
    "ff"; // SELFDESTRUCT
  const riskyWalk = analyzeEvmBytecodeHex(riskyBytecode);
  assert.equal(riskyWalk.hasSelfDestruct, true);
  assert.equal(riskyWalk.hasDelegateCall, true);
  assert.equal(riskyWalk.hasCallCode, true);
  assert.equal(riskyWalk.hasCreate2, true);
  assert.equal(riskyWalk.hasTxOrigin, true);
  assert.deepEqual(riskyWalk.matchedSelectors.mint, ["mint(address,uint256)"]);
  assert.deepEqual(riskyWalk.matchedSelectors.blacklist, ["blacklist(address)"]);
  assert.deepEqual(riskyWalk.matchedSelectors.pause, ["pause()"]);
  assert.deepEqual(riskyWalk.matchedSelectors.taxAndLimits, ["setSellTax(uint256)"]);

  // EIP-1167 minimal proxy clone
  const implAddr = "2ce6311ddae708829bc0784c967b7d77d19fd779";
  const cloneHex = `0x363d3d373d3d3d363d73${implAddr}5af43d82803e903d91602b57fd5bf3`;
  const cloneWalk = analyzeEvmBytecodeHex(cloneHex);
  assert.equal(cloneWalk.eip1167Implementation, `0x${implAddr}`);
  assert.equal(cloneWalk.hasDelegateCall, true);
});

test("scoreEvmTokenRisk deterministically scores empty EOAs, clean renounced tokens, and honeypot/proxy contracts", () => {
  const emptyRes = scoreEvmTokenRisk({ isContract: false });
  assert.equal(emptyRes.riskScore, 85);
  assert.equal(emptyRes.riskLevel, "CRITICAL");
  assert.equal(emptyRes.flags[0].code, "NO_CONTRACT_BYTECODE");

  // Clean contract with renounced owner (0x0) and standard transfer selector only
  const cleanRes = scoreEvmTokenRisk({
    bytecode: "0x608060405263a9059cbb60005200",
    owner: "0x0000000000000000000000000000000000000000",
    paused: false,
  });
  assert.equal(cleanRes.riskScore, 0);
  assert.equal(cleanRes.riskLevel, "LOW");
  assert.equal(cleanRes.flags.length, 0);

  // High-risk upgradeable proxy with SELFDESTRUCT, mutable tax, paused transfers, and active owner
  const critRes = scoreEvmTokenRisk({
    bytecode: "0x6080f400",
    implementationBytecode: "0x6340c10f1963cc1776d3638456cb59ff",
    proxyType: "EIP-1967 Transparent/UUPS Proxy",
    implementationAddress: "0x2ce6311ddae708829bc0784c967b7d77d19fd779",
    adminAddress: "0x4fc7850364958d97b4d3f5a08f79db2493f8ca44",
    owner: "0x1111111111111111111111111111111111111111",
    paused: true,
  });
  assert.equal(critRes.riskScore, 100);
  assert.equal(critRes.riskLevel, "CRITICAL");
  const flagCodes = new Set(critRes.flags.map((f) => f.code));
  assert.ok(flagCodes.has("OPCODE_SELFDESTRUCT"));
  assert.ok(flagCodes.has("UPGRADEABLE_PROXY"));
  assert.ok(flagCodes.has("MINT_CAPABILITY_DETECTED"));
  assert.ok(flagCodes.has("MUTABLE_TAX_OR_TX_LIMITS"));
  assert.ok(flagCodes.has("PAUSABLE_TRANSFERS"));
  assert.ok(flagCodes.has("ACTIVE_OWNER_PRIVILEGE"));
});

test("scoreSolanaMintRisk deterministically scores clean revoked SPL mints vs Token-2022 permanentDelegate & whale concentration", () => {
  const cleanSpl = scoreSolanaMintRisk({
    decimals: 6,
    supply: "1000000000000", // 1,000,000 tokens
    mintAuthority: null,
    freezeAuthority: null,
    extensions: [],
    largestAccounts: [
      { address: "Holder1111111111111111111111111111111111111", amount: "50000000000" }, // 5%
      { address: "Holder2222222222222222222222222222222222222", amount: "40000000000" }, // 4%
    ],
  });
  assert.equal(cleanSpl.riskScore, 0);
  assert.equal(cleanSpl.riskLevel, "LOW");
  assert.equal(cleanSpl.flags.length, 0);
  assert.equal(cleanSpl.mintInfo.mintAuthorityRevoked, true);
  assert.equal(cleanSpl.mintInfo.freezeAuthorityRevoked, true);
  assert.equal(cleanSpl.holderConcentration.top1HolderPct, 5);
  assert.equal(cleanSpl.holderConcentration.top10HoldersPct, 9);

  const risky2022 = scoreSolanaMintRisk({
    decimals: 6,
    supply: "1000000000",
    mintAuthority: "MintAuth11111111111111111111111111111111111",
    freezeAuthority: "FreezeAuth111111111111111111111111111111111",
    extensions: [
      {
        extension: "permanentDelegate",
        state: { delegate: "PermDel111111111111111111111111111111111111" },
      },
      {
        extension: "transferFeeConfig",
        state: {
          newerTransferFee: { transferFeeBasisPoints: 600 },
          transferFeeConfigAuthority: "FeeAuth111111111111111111111111111111111111",
        },
      },
      {
        extension: "transferHook",
        state: { programId: "HookProg11111111111111111111111111111111111" },
      },
      {
        extension: "mintCloseAuthority",
        state: { closeAuthority: "CloseAuth1111111111111111111111111111111111" },
      },
      {
        extension: "tokenMetadata",
        state: { name: "Risky Token 2022", symbol: "RSK22" },
      },
    ],
    largestAccounts: [
      { address: "Whale11111111111111111111111111111111111111", amount: "450000000" }, // 45%
      { address: "Whale22222222222222222222222222222222222222", amount: "350000000" }, // 35% -> top10 = 80%
    ],
  });
  assert.equal(risky2022.riskScore, 100);
  assert.equal(risky2022.riskLevel, "CRITICAL");
  assert.equal(risky2022.mintInfo.embeddedMetadata.symbol, "RSK22");
  assert.equal(risky2022.extensions.transferFeeBps, 600);
  const solCodes = new Set(risky2022.flags.map((f) => f.code));
  assert.ok(solCodes.has("ACTIVE_MINT_AUTHORITY"));
  assert.ok(solCodes.has("ACTIVE_FREEZE_AUTHORITY"));
  assert.ok(solCodes.has("TOKEN2022_PERMANENT_DELEGATE"));
  assert.ok(solCodes.has("TOKEN2022_TRANSFER_FEE"));
  assert.ok(solCodes.has("TOKEN2022_TRANSFER_HOOK"));
  assert.ok(solCodes.has("TOKEN2022_MINT_CLOSE_AUTHORITY"));
  assert.ok(solCodes.has("EXTREME_TOP1_CONCENTRATION"));
  assert.ok(solCodes.has("EXTREME_TOP10_CONCENTRATION"));
});

function encodeAbiStringHex(str) {
  const hex = Buffer.from(str, "utf8").toString("hex");
  const lenHex = str.length.toString(16).padStart(64, "0");
  const paddedData = hex.padEnd(Math.ceil(Math.max(1, hex.length) / 64) * 64, "0");
  return "0x" + "20".padStart(64, "0") + lenHex + paddedData;
}

test("scanEvmTokenOnChain, scanSolanaMintOnChain, runBatchWatchlistScan, CSV dossier & CryptoBill handoff work end-to-end", async () => {
  const proxyAddr = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
  const implAddr = "0x2ce6311ddae708829bc0784c967b7d77d19fd779";
  const adminAddr = "0x4fc7850364958d97b4d3f5a08f79db2493f8ca44";
  const pyusdMint = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo";

  const mockRpcHandler = (body) => {
    const { method, params } = body;
    if (method === "eth_getCode") {
      if (params[0] === proxyAddr) return "0x6080604052f400";
      if (params[0] === implAddr) return "0x60806340c10f1963f9f92be4638456cb5900";
      return "0x";
    }
    if (method === "eth_getStorageAt") {
      if (params[1] === SLOT_ZEPPELINOS_IMPL) return "0x" + implAddr.slice(2).padStart(64, "0");
      if (params[1] === SLOT_ZEPPELINOS_ADMIN) return "0x" + adminAddr.slice(2).padStart(64, "0");
      return "0x" + "0".repeat(64);
    }
    if (method === "eth_call") {
      const data = params[0]?.data;
      if (data === "0x06fdde03") return encodeAbiStringHex("USD Coin");
      if (data === "0x95d89b41") return encodeAbiStringHex("USDC");
      if (data === "0x313ce567") return "0x" + (6).toString(16).padStart(64, "0");
      if (data === "0x18160ddd") return "0x" + (5000000000000n).toString(16).padStart(64, "0");
      if (data === "0x8da5cb5b") return "0x" + adminAddr.slice(2).padStart(64, "0");
      if (data === "0x5c975abb") return "0x" + "0".repeat(64);
    }
    if (method === "getAccountInfo") {
      return {
        value: {
          owner: TOKEN_2022_PROGRAM_ID,
          data: {
            parsed: {
              type: "mint",
              info: {
                decimals: 6,
                supply: "800000000000000",
                isInitialized: true,
                mintAuthority: "PyusdMintAuth111111111111111111111111111111",
                freezeAuthority: "PyusdFreezeAuth1111111111111111111111111111",
                extensions: [
                  {
                    extension: "permanentDelegate",
                    state: { delegate: "PyusdPermDel1111111111111111111111111111111" },
                  },
                  {
                    extension: "tokenMetadata",
                    state: { name: "PayPal USD", symbol: "PYUSD" },
                  },
                ],
              },
            },
          },
        },
      };
    }
    if (method === "getTokenLargestAccounts") {
      return {
        value: [
          { address: "SolVault11111111111111111111111111111111111", amount: "160000000000000" }, // 20%
        ],
      };
    }
    return null;
  };

  const mockFetch = async (_url, init) => {
    const body = JSON.parse(init.body);
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ jsonrpc: "2.0", id: body.id, result: mockRpcHandler(body) }),
    };
  };

  const evmReport = await scanEvmTokenOnChain(
    { chain: "base", address: proxyAddr },
    { fetchImpl: mockFetch }
  );
  assert.equal(evmReport.ok, true);
  assert.equal(evmReport.tokenMetadata.name, "USD Coin");
  assert.equal(evmReport.tokenMetadata.symbol, "USDC");
  assert.equal(evmReport.tokenMetadata.decimals, 6);
  assert.equal(evmReport.proxyAnalysis.isProxy, true);
  assert.equal(evmReport.proxyAnalysis.implementationAddress, implAddr);
  assert.match(evmReport.markdownSummary, /TokenGuard Risk Dossier/);

  const solReport = await scanSolanaMintOnChain(
    { mint: pyusdMint },
    { fetchImpl: mockFetch }
  );
  assert.equal(solReport.ok, true);
  assert.equal(solReport.tokenStandard, "Token-2022");
  assert.equal(solReport.riskLevel, "CRITICAL");
  assert.equal(solReport.holderConcentration.available, true);
  assert.equal(solReport.holderConcentration.top1HolderPct, 20);

  // Batch Watchlist + 25-address guard + CSV/Invoice handoff
  const parsedList = parseWatchlistEntries(`base:${proxyAddr}\nsolana:${pyusdMint}\n`);
  assert.equal(parsedList.length, 2);

  const batchReports = await runBatchWatchlistScan(parsedList, { fetchImpl: mockFetch });
  assert.equal(batchReports.length, 2);
  const csv = exportBatchReportsCsv(batchReports);
  assert.match(csv, /USDC/);
  assert.match(csv, /PYUSD/);

  const tooMany = Array.from({ length: 26 }, (_, i) => ({
    chain: "base",
    address: `0x${(i + 1).toString(16).padStart(40, "0")}`,
  }));
  await assert.rejects(() => runBatchWatchlistScan(tooMany, { fetchImpl: mockFetch }), /up to 25/i);

  const singleInv = buildAuditInvoicePayload(evmReport);
  const decodedInv = decodeInvoicePayload(encodeInvoicePayload(singleInv));
  assert.equal(decodedInv.items[0].unitPrice, 185);
});

test("ForgeSuite MCP v1.1.0 executes evm_token_risk_scan and solana_mint_risk_scan end-to-end over stdio", async () => {
  const tokenAddr = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
  const solMint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

  const mockRpcServer = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
    });
    req.on("end", () => {
      const body = JSON.parse(raw);
      let result = null;
      if (body.method === "eth_getCode") {
        result = "0x60806340c10f1900";
      } else if (body.method === "eth_getStorageAt") {
        result = "0x" + "0".repeat(64);
      } else if (body.method === "eth_call") {
        const sel = body.params[0]?.data;
        if (sel === "0x06fdde03") result = encodeAbiStringHex("Mock Base Token");
        else if (sel === "0x95d89b41") result = encodeAbiStringHex("MBT");
        else if (sel === "0x313ce567") result = "0x" + (18).toString(16).padStart(64, "0");
        else if (sel === "0x18160ddd") result = "0x" + (1000000000000000000000n).toString(16).padStart(64, "0");
        else result = "0x" + "0".repeat(64);
      } else if (body.method === "getAccountInfo") {
        result = {
          value: {
            owner: TOKEN_PROGRAM_ID,
            data: {
              parsed: {
                type: "mint",
                info: {
                  decimals: 6,
                  supply: "1000000000",
                  isInitialized: true,
                  mintAuthority: null,
                  freezeAuthority: null,
                },
              },
            },
          },
        };
      } else if (body.method === "getTokenLargestAccounts") {
        result = {
          value: [{ address: "HolderAcct111111111111111111111111111111111", amount: "100000000" }],
        };
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
    });
  });

  await new Promise((resolve) => mockRpcServer.listen(0, "127.0.0.1", resolve));
  const port = mockRpcServer.address().port;
  const localRpcUrl = `http://127.0.0.1:${port}`;

  try {
    const reqs = [
      {
        jsonrpc: "2.0",
        id: "evm-scan",
        method: "tools/call",
        params: {
          name: "evm_token_risk_scan",
          arguments: { chain: "base", address: tokenAddr, rpcUrl: localRpcUrl },
        },
      },
      {
        jsonrpc: "2.0",
        id: "sol-scan",
        method: "tools/call",
        params: {
          name: "solana_mint_risk_scan",
          arguments: { mint: solMint, rpcUrl: localRpcUrl },
        },
      },
      {
        jsonrpc: "2.0",
        id: "evm-bad",
        method: "tools/call",
        params: {
          name: "evm_token_risk_scan",
          arguments: { chain: "base", address: "not-an-address" },
        },
      },
    ];

    const { code, stderr, messages } = await runMcpStdioSession(
      reqs.map((r) => JSON.stringify(r) + "\n")
    );
    assert.equal(code, 0);
    assert.equal(stderr, "");
    assert.equal(messages.length, 3);

    assert.equal(messages[0].id, "evm-scan");
    assert.equal(messages[0].result.isError, false);
    assert.equal(messages[0].result.structuredContent.tokenMetadata.symbol, "MBT");
    assert.equal(messages[0].result.structuredContent.riskScore, 15);
    assert.match(messages[0].result.content[0].text, /MINT_CAPABILITY_DETECTED/);

    assert.equal(messages[1].id, "sol-scan");
    assert.equal(messages[1].result.isError, false);
    assert.equal(messages[1].result.structuredContent.tokenStandard, "SPL Token");
    assert.equal(messages[1].result.structuredContent.riskScore, 0);
    assert.equal(messages[1].result.structuredContent.holderConcentration.top1HolderPct, 10);

    assert.equal(messages[2].id, "evm-bad");
    assert.equal(messages[2].result.isError, true);
  } finally {
    await new Promise((resolve) => mockRpcServer.close(resolve));
  }
});

/* ============================================================================
 * 14. ForgeSuite MCP v1.2.0 Packaging, LF Line-Endings & Tool #7 Brand Scanner
 * ========================================================================== */

test("root package.json, .gitattributes, shebang LF line-endings, and v1.4.0 npx discovery docs are valid", () => {
  const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const pkgPath = path.join(rootDir, "package.json");
  const gitAttrPath = path.join(rootDir, ".gitattributes");
  const mcpBinPath = path.join(rootDir, "mcp", "forgesuite-mcp.mjs");

  assert.ok(fs.existsSync(pkgPath), "root package.json must exist for npx github:... execution");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  assert.equal(pkg.name, "forgesuite-mcp");
  assert.equal(pkg.version, "1.4.0");
  assert.equal(pkg.type, "module");
  assert.deepEqual(pkg.bin, { "forgesuite-mcp": "./mcp/forgesuite-mcp.mjs" });
  assert.equal(pkg.engines?.node, ">=20.0.0");
  assert.equal(pkg.dependencies, undefined, "root package.json must have zero dependencies");
  assert.equal(pkg.devDependencies, undefined, "root package.json must have zero devDependencies");

  assert.ok(fs.existsSync(gitAttrPath), ".gitattributes must exist");
  const gitAttr = fs.readFileSync(gitAttrPath, "utf8");
  assert.match(gitAttr, /\*\.mjs\s+text\s+eol=lf/);

  const rawMcpBytes = fs.readFileSync(mcpBinPath);
  const firstLineBytes = rawMcpBytes.subarray(0, 20).toString("ascii");
  assert.equal(
    firstLineBytes,
    "#!/usr/bin/env node\n",
    "mcp/forgesuite-mcp.mjs must start with exact LF shebang #!/usr/bin/env node\\n"
  );
  assert.equal(
    rawMcpBytes.includes(0x0d),
    false,
    "mcp/forgesuite-mcp.mjs must use strict LF (\\n) with zero CR (\\r) bytes"
  );

  // Check v1.4.0 and 1-command npx across discovery & storefront files
  const npxCmd = "npx --yes github:youthmy11-ai/youthmy11-ai.github.io";
  for (const rel of [
    ".well-known/mcp/server.json",
    ".well-known/agent-card.json",
    "mcp.html",
    "index.html",
    "llms.txt",
    "llms-full.txt",
    "README.md",
  ]) {
    const content = fs.readFileSync(path.join(rootDir, rel), "utf8");
    assert.ok(content.includes(npxCmd), `${rel} must showcase ${npxCmd}`);
    assert.ok(content.includes("brand_domain_handle_scan"), `${rel} must list brand_domain_handle_scan`);
    assert.ok(content.includes("multi_chain_wallet_scan"), `${rel} must list multi_chain_wallet_scan`);
    assert.ok(content.includes("subtitle_caption_audit"), `${rel} must list subtitle_caption_audit`);
    assert.ok(content.includes("1.4.0"), `${rel} must reference v1.4.0`);
  }
});

test("brand_domain_handle_scan (Tool #7) audits RDAP+DoH domains, npm/PyPI/GitHub, Bluesky/Reddit & iOS App Store", async () => {
  const norm = normalizeBrandCandidate("@ForgeSuite.io");
  assert.equal(norm.domainLabel, "forgesuite");
  assert.equal(norm.blueskyHandle, "forgesuite.bsky.social");
  assert.throws(() => normalizeBrandCandidate("x"), /at least 2 alphanumeric/i);

  const mockFetch = async (rawUrl) => {
    const u = String(rawUrl);
    const jsonResp = (status, obj) => ({
      ok: status >= 200 && status < 300,
      status,
      text: async () => (obj === null ? "" : JSON.stringify(obj)),
    });

    // Candidate 1 ("novaforgex") -> mostly available; Candidate 2 ("takenhub") -> mostly taken
    const isTakenBrand = u.toLowerCase().includes("takenhub");

    // Authoritative RDAP checks
    if (
      u.includes("rdap.verisign.com") ||
      u.includes("rdap.identitydigital.services") ||
      u.includes("pubapi.registry.google") ||
      u.includes("rdap.publicinterestregistry.org") ||
      u.includes("rdap.org/domain/")
    ) {
      if (isTakenBrand || u.endsWith("novaforgex.org")) {
        return jsonResp(200, {
          objectClassName: "domain",
          ldhName: isTakenBrand ? "TAKENHUB.COM" : "NOVAFORGEX.ORG",
          events: [{ eventAction: "expiration", eventDate: "2028-05-01T00:00:00Z" }],
        });
      }
      return jsonResp(404, { errorCode: 404, title: "Not Found" });
    }

    // Google DoH checks
    if (u.includes("dns.google/resolve")) {
      if (isTakenBrand || u.includes("name=novaforgex.org")) {
        return jsonResp(200, { Status: 0, Answer: [{ name: "example.", type: 2, data: "ns1.dns.com." }] });
      }
      return jsonResp(200, { Status: 3 });
    }

    // npm
    if (u.includes("registry.npmjs.org/")) {
      return isTakenBrand
        ? jsonResp(200, { name: "takenhub", "dist-tags": { latest: "4.2.0" } })
        : jsonResp(404, { error: "Not found" });
    }

    // PyPI
    if (u.includes("pypi.org/pypi/")) {
      return isTakenBrand
        ? jsonResp(200, { info: { version: "1.9.3" } })
        : jsonResp(404, { message: "Not Found" });
    }

    // GitHub API (test 403 fallback on novaforgex -> github.com web 404)
    if (u.includes("api.github.com/users/")) {
      if (isTakenBrand) return jsonResp(200, { login: "takenhub", type: "Organization" });
      return jsonResp(403, { message: "API rate limit exceeded" });
    }
    if (u.startsWith("https://github.com/")) {
      return isTakenBrand ? jsonResp(200, {}) : jsonResp(404, {});
    }

    // Bluesky
    if (u.includes("public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle")) {
      return isTakenBrand
        ? jsonResp(200, { did: "did:plc:takenhub12345" })
        : jsonResp(400, { error: "InvalidRequest", message: "Unable to resolve handle" });
    }

    // Reddit
    if (u.includes("reddit.com/api/username_available.json")) {
      return jsonResp(200, !isTakenBrand);
    }

    // Apple iOS App Store
    if (u.includes("itunes.apple.com/search")) {
      if (isTakenBrand) {
        return jsonResp(200, {
          resultCount: 2,
          results: [
            {
              trackName: "TakenHub: Team Chat",
              sellerName: "TakenHub Inc.",
              bundleId: "com.takenhub.ios",
              trackViewUrl: "https://apps.apple.com/us/app/takenhub/id123456",
            },
          ],
        });
      }
      return jsonResp(200, {
        resultCount: 1,
        results: [
          {
            trackName: "Unrelated Utility App",
            sellerName: "Other Studio",
            bundleId: "com.other.app",
            trackViewUrl: "https://apps.apple.com/us/app/other/id999999",
          },
        ],
      });
    }

    throw new Error(`Unexpected URL in brand scanner test: ${u}`);
  };

  const direct = await scanBrandDomainAndHandles(
    { name: "NovaForgeX, TakenHub" },
    { fetchImpl: mockFetch }
  );
  assert.equal(direct.ok, true);
  assert.equal(direct.candidateCount, 2);
  assert.equal(direct.recommendedCandidate, "NovaForgeX");
  assert.match(direct.checkedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  assert.deepEqual(direct.tldsChecked, ["com", "io", "ai", "dev", "app", "org"]);
  assert.equal(direct.upgradeLinks.proBundlePriceUsd, 35);
  assert.equal(direct.upgradeLinks.nearAgentFleet.length, 7);

  const nova = direct.results[0];
  assert.equal(nova.normalizedSlug, "novaforgex");
  assert.equal(nova.summary.comAvailable, true);
  assert.equal(nova.summary.allDeveloperRegistriesAvailable, true);
  assert.equal(nova.summary.verdict, "STRONG_GREENLIGHT");
  assert.ok(nova.summary.readinessScore >= 90);
  assert.equal(nova.domains.find((d) => d.tld === "com").available, true);
  assert.equal(nova.domains.find((d) => d.tld === "org").available, false);
  assert.equal(nova.registries.npm.available, true);
  assert.equal(nova.registries.pypi.available, true);
  assert.equal(nova.registries.github.available, true);
  assert.equal(nova.social.bluesky.available, true);
  assert.equal(nova.social.reddit.available, true);
  assert.equal(nova.iosAppStore.available, true);
  assert.equal(nova.iosAppStore.exactMatchFound, false);

  const taken = direct.results[1];
  assert.equal(taken.summary.readinessScore, 0);
  assert.equal(taken.summary.verdict, "HIGH_COLLISION");
  assert.equal(taken.registries.npm.latestVersion, "4.2.0");
  assert.equal(taken.registries.github.accountType, "Organization");
  assert.equal(taken.iosAppStore.available, false);
  assert.equal(taken.iosAppStore.exactMatchFound, true);

  // Full JSON-RPC tools/call dispatch test + stdio error validation
  const rpcResp = await handleJsonRpcMessage(
    {
      jsonrpc: "2.0",
      id: "brand-rpc-1",
      method: "tools/call",
      params: {
        name: "brand_domain_handle_scan",
        arguments: { name: "NovaForgeX" },
      },
    },
    { fetchImpl: mockFetch }
  );
  assert.equal(rpcResp.id, "brand-rpc-1");
  assert.equal(rpcResp.result.isError, false);
  assert.match(rpcResp.result.content[0].text, /STRONG_GREENLIGHT/);
  assert.match(rpcResp.result.content[0].text, /\$35/);
  assert.match(rpcResp.result.content[0].text, /market\.near\.ai\/a\/forge-ai-agent/);
  assert.equal(rpcResp.result.structuredContent.recommendedCandidate, "NovaForgeX");

  const stdioErr = await runMcpStdioSession([
    JSON.stringify({
      jsonrpc: "2.0",
      id: "brand-bad",
      method: "tools/call",
      params: { name: "brand_domain_handle_scan", arguments: { name: "   " } },
    }) + "\n",
  ]);
  assert.equal(stdioErr.code, 0);
  assert.equal(stdioErr.messages[0].result.isError, true);
});

/* ============================================================================
 * 15. BrandGuard Web App #8 (`assets/brandcheck.js` & `brandcheck.html`) Tests
 * ========================================================================== */

test("BrandGuard normalizes brand names, generates 6 smart variations, configures 8 CORS TLDs, and exposes Pro key validator", () => {
  assert.deepEqual(BRANDGUARD_DEFAULT_TLDS, [
    "com",
    "io",
    "ai",
    "dev",
    "app",
    "org",
    "net",
    "xyz",
  ]);
  for (const tld of BRANDGUARD_DEFAULT_TLDS) {
    assert.ok(CORS_RDAP_BY_TLD[tld]?.startsWith("https://"), `Missing CORS RDAP endpoint for .${tld}`);
  }

  const norm = normalizeBrandName("https://@Orbit-Ledger.xyz/docs");
  assert.equal(norm.domainLabel, "orbit-ledger");
  assert.equal(norm.packageSlug, "orbit-ledger");
  assert.equal(norm.githubHandle, "orbit-ledger");
  assert.equal(norm.blueskyHandle, "orbit-ledger.bsky.social");
  assert.equal(norm.compactKey, "orbitledger");
  assert.throws(() => normalizeBrandName("a"), /at least 2 alphanumeric/i);

  const vars = generateBrandVariations("NovaForge");
  assert.deepEqual(vars, [
    "getnovaforge",
    "usenovaforge",
    "novaforgehq",
    "novaforgelabs",
    "novaforgeai",
    "trynovaforge",
  ]);

  const sampleProKey = generateLicenseKey("BUNDLE", "brandguard-pro-test");
  assert.equal(brandGuardValidateKey(sampleProKey), true);
  assert.equal(brandGuardValidateKey("FS-PRO-BUNDLE-BADKEY00-0000"), false);
});

test("BrandGuard executes CORS-clean Simple GETs (no custom headers), handles RDAP CORS fallback to Google DoH, and scores 0-100 deterministically", async () => {
  const seenInits = [];
  const mockCorsFetch = async (rawUrl, init = {}) => {
    seenInits.push({ url: String(rawUrl), init });
    const u = String(rawUrl);
    const jsonResp = (status, obj) => ({
      ok: status >= 200 && status < 300,
      status,
      text: async () => (obj === null ? "" : JSON.stringify(obj)),
    });

    // Simulate non-CORS redirect failure on rdap.org + .xyz RDAP to verify clean DoH fallback
    if (u.includes("rdap.org/domain/") || u.includes("rdap.centralnic.com/xyz/")) {
      throw new TypeError("Failed to fetch (simulated non-CORS RDAP redirect)");
    }

    const isTaken = u.toLowerCase().includes("vercel");

    // Authoritative RDAP for remaining 7 TLDs
    if (
      u.includes("rdap.verisign.com") ||
      u.includes("pubapi.registry.google") ||
      u.includes("rdap.publicinterestregistry.org") ||
      u.includes("rdap.identitydigital.services")
    ) {
      if (isTaken) {
        return jsonResp(200, {
          objectClassName: "domain",
          events: [{ eventAction: "expiration", eventDate: "2029-10-15T00:00:00Z" }],
        });
      }
      return jsonResp(404, { errorCode: 404 });
    }

    // Google DoH NS + A
    if (u.includes("dns.google/resolve")) {
      if (isTaken) {
        return jsonResp(200, {
          Status: 0,
          Answer: [{ name: "vercel.", type: u.includes("type=A") ? 1 : 2, data: "76.76.21.21" }],
        });
      }
      return jsonResp(200, { Status: 3 }); // NXDOMAIN
    }

    if (u.includes("registry.npmjs.org/")) {
      return isTaken
        ? jsonResp(200, { "dist-tags": { latest: "39.1.0" } })
        : jsonResp(404, { error: "Not found" });
    }
    if (u.includes("pypi.org/pypi/")) {
      return isTaken
        ? jsonResp(200, { info: { version: "2.0.1" } })
        : jsonResp(404, { message: "Not Found" });
    }
    if (u.includes("api.github.com/users/")) {
      return isTaken
        ? jsonResp(200, { login: "vercel", type: "Organization" })
        : jsonResp(404, { message: "Not Found" });
    }
    if (u.includes("public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle")) {
      return isTaken
        ? jsonResp(200, { did: "did:plc:vercelofficial123" })
        : jsonResp(400, { error: "InvalidRequest", message: "Unable to resolve handle" });
    }
    if (u.includes("itunes.apple.com/search")) {
      return isTaken
        ? jsonResp(200, {
            resultCount: 1,
            results: [
              {
                trackName: "Vercel: Deploy & Preview",
                sellerName: "Vercel Inc.",
                bundleId: "com.vercel.mobile",
                trackViewUrl: "https://apps.apple.com/us/app/vercel/id111111",
              },
            ],
          })
        : jsonResp(200, {
            resultCount: 1,
            results: [{ trackName: "Unrelated Timer", sellerName: "Other LLC" }],
          });
    }

    throw new Error(`Unexpected BrandGuard fetch URL: ${u}`);
  };

  // Verify custom/non-CORS RDAP fallback directly on .xyz
  const xyzDomain = await checkDomainBrowserCors("novaforgex", "xyz", {
    fetchImpl: mockCorsFetch,
  });
  assert.equal(xyzDomain.available, true);
  assert.equal(xyzDomain.status, "likely_available");
  assert.equal(xyzDomain.statusLabel, "Likely Available (NXDOMAIN)");
  assert.equal(xyzDomain.rdapFallbackToDoh, true);
  assert.equal(xyzDomain.source, "doh");

  // Full greenlight scan across 8 TLDs + 5 registries
  const green = await scanSingleBrand("NovaForgeX", { fetchImpl: mockCorsFetch });
  assert.equal(green.ok, true);
  assert.equal(green.domains.length, 8);
  assert.equal(green.summary.readinessScore, 100);
  assert.equal(green.summary.verdict, "LAUNCH_READY");
  assert.equal(green.summary.availableCount, 13);
  assert.equal(green.summary.comAvailable, true);
  assert.equal(green.summary.allDevRegistriesClear, true);
  assert.match(green.checkedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  assert.match(green.markdownSummary, /BrandGuard Launch Readiness Dossier/);

  const comEntry = green.domains.find((d) => d.tld === "com");
  assert.equal(comEntry.statusLabel, "Likely Available (NXDOMAIN + RDAP 404)");

  // Full collision scan
  const red = await scanSingleBrand("Vercel", { fetchImpl: mockCorsFetch });
  assert.equal(red.summary.readinessScore, 0);
  assert.equal(red.summary.verdict, "HIGH_COLLISION");
  assert.equal(red.domains.find((d) => d.tld === "com").statusLabel, "Registered (Active DNS/RDAP)");
  assert.equal(red.registries.npm.latestVersion, "39.1.0");
  assert.equal(red.registries.github.accountType, "Organization");
  assert.equal(red.registries.iosAppStore.exactMatchFound, true);

  // Ensure zero custom headers were attached (so browsers send preflight-free Simple GETs)
  for (const call of seenInits) {
    assert.equal(call.init.headers, undefined, `Must not pass custom headers on ${call.url}`);
  }
});

test("BrandGuard supports Free 4-variation vs Pro 6-variation scans, 25-brand Batch Matrix, CSV formula guard, ScopeGuard/CryptoBill handoffs, and USPTO A2A CTA", async () => {
  const fastAvailableFetch = async (rawUrl) => {
    const u = String(rawUrl);
    const jsonResp = (status, obj) => ({
      ok: status >= 200 && status < 300,
      status,
      text: async () => JSON.stringify(obj),
    });
    if (u.includes("dns.google/resolve")) return jsonResp(200, { Status: 3 });
    if (u.includes("itunes.apple.com/search")) return jsonResp(200, { resultCount: 0, results: [] });
    if (u.includes("public.api.bsky.app")) {
      return jsonResp(400, { message: "Unable to resolve handle" });
    }
    return jsonResp(404, {});
  };

  const freeVars = await scanBrandVariations("Kestrel", {
    isPro: false,
    fetchImpl: fastAvailableFetch,
  });
  assert.equal(freeVars.scannedCount, FREE_VARIATION_LIMIT);
  assert.equal(freeVars.results.length, 4);
  assert.equal(freeVars.isProUnlocked, false);

  const proVars = await scanBrandVariations("Kestrel", {
    isPro: true,
    fetchImpl: fastAvailableFetch,
  });
  assert.equal(proVars.scannedCount, 6);
  assert.equal(proVars.results.length, 6);
  assert.equal(proVars.isProUnlocked, true);

  // Batch 25-Brand Agency Matrix + >25 enforcement
  const list = parseBatchBrandList("AlphaForge\nBetaForge, alphaforge\n=InjectedBrand");
  assert.deepEqual(list, ["AlphaForge", "BetaForge", "=InjectedBrand"]);

  const batchReports = await runBatchBrandScan(list, { fetchImpl: fastAvailableFetch });
  assert.equal(batchReports.length, 3);
  assert.equal(batchReports[0].ok, true);
  assert.equal(batchReports[2].ok, true);

  const csv = exportBrandMatrixCsv(batchReports);
  assert.match(csv, /candidate,slug,readiness_score,verdict,com,io,ai,dev,app,org,net,xyz/);
  assert.match(csv, /'=InjectedBrand/, "CSV export must neutralize spreadsheet formula injection");

  const overLimit = Array.from({ length: MAX_BATCH_BRANDS + 1 }, (_, i) => `BrandCandidate${i + 1}`);
  await assert.rejects(
    () => runBatchBrandScan(overLimit, { fetchImpl: fastAvailableFetch }),
    /up to 25/i
  );

  // CryptoBill & ScopeGuard SOW 1-click handoff roundtrips
  const singleInv = buildBrandAuditInvoicePayload(batchReports[0]);
  const decodedSingleInv = decodeInvoicePayload(encodeInvoicePayload(singleInv));
  assert.equal(decodedSingleInv.items[0].unitPrice, 145);

  const batchInv = buildBrandAuditInvoicePayload(batchReports);
  const decodedBatchInv = decodeInvoicePayload(encodeInvoicePayload(batchInv));
  assert.equal(decodedBatchInv.items[0].unitPrice, 195);

  const sowState = buildBrandSowState(batchReports);
  const sowToken = encodeSowHandoffPayload(sowState);
  const decodedSow = decodeSowHandoffPayload(`#sow=${sowToken}`);
  assert.equal(decodedSow.totalBudget, 650);
  assert.equal(computeSowTotals(decodedSow).isBalanced, true);

  // Verify brandcheck.html prominent $0.35 USDC NEAR AI A2A CTA & Pro license controls
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const brandHtml = fs.readFileSync(path.join(repoRoot, "brandcheck.html"), "utf8");
  assert.ok(brandHtml.includes(NEAR_BRAND_CHECKER_URL), "brandcheck.html must link to forge-brand-checker on NEAR AI Market");
  assert.match(brandHtml, /\$0\.35 USDC/);
  assert.match(brandHtml, /USPTO/);
  assert.match(brandHtml, /Google Play/);
  assert.match(brandHtml, /data-checkout-sku="BUNDLE"/);
  assert.match(brandHtml, /data-checkout-sku="CB"/);
});

test("root server.json, deterministic .mcpb packer, and GitHub OIDC MCP Registry workflow stay synced", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const serverJson = JSON.parse(fs.readFileSync(path.join(repoRoot, "server.json"), "utf8"));
  const pkgJson = JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8"));
  const { version, fileSha256, archiveBuffer } = createForgeSuiteMcpbBuffer(repoRoot);

  assert.equal(
    serverJson.$schema,
    "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
  );
  assert.equal(serverJson.name, "io.github.youthmy11-ai/forgesuite-mcp");
  assert.equal(serverJson.version, pkgJson.version);
  assert.ok(serverJson.description.length >= 1 && serverJson.description.length <= 100);
  assert.equal(serverJson.repository.url, "https://github.com/youthmy11-ai/youthmy11-ai.github.io");
  assert.equal(serverJson.repository.source, "github");

  const mcpbPkg = serverJson.packages[0];
  assert.equal(mcpbPkg.registryType, "mcpb");
  assert.equal(
    mcpbPkg.identifier,
    `https://github.com/youthmy11-ai/youthmy11-ai.github.io/releases/download/v${version}/forgesuite-mcp.mcpb`
  );
  assert.equal(mcpbPkg.version, version);
  assert.equal(mcpbPkg.fileSha256, fileSha256);
  assert.equal(mcpbPkg.transport.type, "stdio");
  assert.equal(mcpbPkg.registryBaseUrl, undefined);
  assert.equal(archiveBuffer.readUInt32LE(0), 0x04034b50, "MCPB bundle must start with PKZIP signature");

  const wf = fs.readFileSync(
    path.join(repoRoot, ".github", "workflows", "publish-mcp-registry.yml"),
    "utf8"
  );
  assert.match(wf, /id-token:\s*write/);
  assert.match(wf, /contents:\s*write/);
  assert.match(wf, /mcp-publisher login github-oidc/);
  assert.match(wf, /mcp-publisher publish/);
});

/* ============================================================================
 * 16. Funnel Upgrades: Query Deep-Links, MCP Registry IDE Buttons & SEO Pages
 * ========================================================================== */

test("parseTokenAuditQueryParams supports ?chain=solana&mint=..., EVM aliases, auto-detection, custom HTTPS RPCs, and autorun overrides", () => {
  const empty = parseTokenAuditQueryParams("");
  assert.equal(empty.hasTarget, false);
  assert.equal(empty.chain, "base");
  assert.equal(empty.autorun, false);

  const solMint = parseTokenAuditQueryParams(
    "?chain=solana&mint=2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
  );
  assert.equal(solMint.hasTarget, true);
  assert.equal(solMint.chain, "solana");
  assert.equal(solMint.address, "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo");
  assert.equal(solMint.autorun, true);

  // Base58 mint without chain param auto-switches to solana
  const autoSol = parseTokenAuditQueryParams(
    "address=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&autorun=0"
  );
  assert.equal(autoSol.hasTarget, true);
  assert.equal(autoSol.chain, "solana");
  assert.equal(autoSol.autorun, false);

  // EVM aliases + HTTPS RPC sanitization
  const arb = parseTokenAuditQueryParams(
    "?chain=arb&address=0xaf88d065e77c8cC2239327C5EDb3A432268e5831&rpc=https://arbitrum-one-rpc.publicnode.com"
  );
  assert.equal(arb.hasTarget, true);
  assert.equal(arb.chain, "arbitrum");
  assert.equal(arb.address, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831");
  assert.equal(arb.rpcUrl, "https://arbitrum-one-rpc.publicnode.com/");
  assert.equal(arb.autorun, true);

  // Reject unsafe non-HTTPS custom RPC gracefully without throwing
  const badRpc = parseTokenAuditQueryParams(
    "?chain=eth&address=0xdAC17F958D2ee523a2206206994597C13D831ec7&rpc=ftp://evil.example"
  );
  assert.equal(badRpc.chain, "ethereum");
  assert.equal(badRpc.rpcUrl, null);
});

test("mcp.html, index.html, and READMEs showcase Official MCP Registry Verified badge, 1-click VS Code deep-links, .mcpb bundle, and 7-agent A2A + x402 fleet", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const registryUrl = "https://registry.modelcontextprotocol.io/v0.1/servers?search=forgesuite";
  const vscodeLink =
    "vscode:mcp/install?%7B%22name%22%3A%22forgesuite%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22github%3Ayouthmy11-ai%2Fyouthmy11-ai.github.io%22%5D%7D";
  const vscodeInsidersLink =
    "vscode-insiders:mcp/install?%7B%22name%22%3A%22forgesuite%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22github%3Ayouthmy11-ai%2Fyouthmy11-ai.github.io%22%5D%7D";
  const mcpbAssetUrl =
    "https://github.com/youthmy11-ai/youthmy11-ai.github.io/releases/download/v1.4.0/forgesuite-mcp.mcpb";

  // Verify encoded VS Code deep-link payload decodes cleanly to valid JSON
  const decodedPayload = JSON.parse(decodeURIComponent(vscodeLink.split("?")[1]));
  assert.deepEqual(decodedPayload, {
    name: "forgesuite",
    command: "npx",
    args: ["-y", "github:youthmy11-ai/youthmy11-ai.github.io"],
  });

  const fleetAgents = [
    "https://market.near.ai/agents/wallet-activity-scanner",
    "https://market.near.ai/agents/forge-data-finops",
    "https://market.near.ai/agents/forge-token-guard",
    "https://market.near.ai/agents/forge-brand-checker",
    "https://market.near.ai/agents/short-video-clipper",
    "https://market.near.ai/agents/multi-lang-video-dubber",
    "https://market.near.ai/agents/forge-ai-agent",
  ];

  const mcpHtml = fs.readFileSync(path.join(repoRoot, "mcp.html"), "utf8");
  const indexHtml = fs.readFileSync(path.join(repoRoot, "index.html"), "utf8");
  const readmeMd = fs.readFileSync(path.join(repoRoot, "README.md"), "utf8");

  for (const [label, doc] of [
    ["mcp.html", mcpHtml],
    ["README.md", readmeMd],
  ]) {
    assert.ok(doc.includes(registryUrl), `${label} missing Official MCP Registry URL`);
    assert.ok(doc.includes("io.github.youthmy11-ai/forgesuite-mcp"), `${label} missing registry name`);
    assert.ok(doc.includes("v1.4.0 Active"), `${label} missing v1.4.0 Active badge`);
    assert.ok(doc.includes(vscodeLink), `${label} missing 1-click VS Code MCP install link`);
    assert.ok(doc.includes(vscodeInsidersLink), `${label} missing 1-click VS Code Insiders MCP install link`);
    assert.ok(doc.includes(mcpbAssetUrl), `${label} missing .mcpb release bundle download link`);
    for (const agentUrl of fleetAgents) {
      assert.ok(doc.includes(agentUrl), `${label} missing A2A fleet agent ${agentUrl}`);
    }
  }

  assert.ok(indexHtml.includes(registryUrl), "index.html missing Official MCP Registry URL");
  assert.ok(indexHtml.includes("v1.4.0 Active"), "index.html missing v1.4.0 Active badge");
  for (const agentUrl of fleetAgents) {
    assert.ok(indexHtml.includes(agentUrl), `index.html missing A2A fleet agent ${agentUrl}`);
  }

  const siblingProfileReadme = path.resolve(repoRoot, "..", "youthmy11-ai-profile", "README.md");
  if (fs.existsSync(siblingProfileReadme)) {
    const profileMd = fs.readFileSync(siblingProfileReadme, "utf8");
    assert.ok(profileMd.includes(registryUrl), "profile README missing Official MCP Registry URL");
    assert.ok(profileMd.includes(vscodeLink), "profile README missing VS Code install link");
    assert.ok(profileMd.includes(vscodeInsidersLink), "profile README missing VS Code Insiders install link");
    assert.ok(profileMd.includes(mcpbAssetUrl), "profile README missing .mcpb bundle link");
    assert.ok(profileMd.includes("srtlab.html"), "profile README missing ClipCaption Lab link");
    for (const agentUrl of fleetAgents) {
      assert.ok(profileMd.includes(agentUrl), `profile README missing ${agentUrl}`);
    }
  }
});

function extractAllJsonLdObjects(html) {
  const regex = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/g;
  const types = new Set();
  const parsedBlocks = [];
  let m;
  while ((m = regex.exec(html)) !== null) {
    const obj = JSON.parse(m[1]);
    parsedBlocks.push(obj);
    if (obj["@type"]) types.add(obj["@type"]);
    if (Array.isArray(obj["@graph"])) {
      for (const node of obj["@graph"]) {
        if (node["@type"]) types.add(node["@type"]);
      }
    }
  }
  return { types, parsedBlocks };
}

test("solana-token-2022-scanner.html ships valid SoftwareApplication + TechArticle + FAQPage JSON-LD, Token-2022 forensics, deep-links, MCP snippet, and Pro CTAs", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const html = fs.readFileSync(path.join(repoRoot, "solana-token-2022-scanner.html"), "utf8");

  const { types } = extractAllJsonLdObjects(html);
  assert.ok(types.has("SoftwareApplication"), "Missing SoftwareApplication JSON-LD");
  assert.ok(types.has("TechArticle"), "Missing TechArticle JSON-LD");
  assert.ok(types.has("FAQPage"), "Missing FAQPage JSON-LD");

  for (const term of [
    "PermanentDelegate",
    "TransferHook",
    "TransferFeeConfig",
    "100%",
    "FreezeAuthority",
    "solana_mint_risk_scan",
    "npx --yes github:youthmy11-ai/youthmy11-ai.github.io",
    "https://market.near.ai/agents/forge-token-guard",
    "$0.25",
    'data-checkout-sku="BUNDLE"',
  ]) {
    assert.ok(html.includes(term), `solana-token-2022-scanner.html missing "${term}"`);
  }

  const deepLinks = [...html.matchAll(/href="tokenaudit\.html\?([^"]+)"/g)].map((m) =>
    m[1].replace(/&amp;/g, "&")
  );
  assert.ok(deepLinks.length >= 4, "Expected at least 4 interactive Solana deep-links");
  for (const qs of deepLinks) {
    const parsed = parseTokenAuditQueryParams(qs);
    assert.equal(parsed.hasTarget, true);
    assert.equal(parsed.chain, "solana");
    assert.equal(parsed.autorun, true);
  }
});

test("evm-proxy-honeypot-scanner.html ships valid SoftwareApplication + TechArticle + FAQPage JSON-LD, proxy/opcode forensics, deep-links, MCP snippet, and Pro CTAs", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const html = fs.readFileSync(path.join(repoRoot, "evm-proxy-honeypot-scanner.html"), "utf8");

  const { types } = extractAllJsonLdObjects(html);
  assert.ok(types.has("SoftwareApplication"), "Missing SoftwareApplication JSON-LD");
  assert.ok(types.has("TechArticle"), "Missing TechArticle JSON-LD");
  assert.ok(types.has("FAQPage"), "Missing FAQPage JSON-LD");

  for (const term of [
    "EIP-1967",
    "EIP-1167",
    "DELEGATECALL",
    "SELFDESTRUCT",
    "blacklist",
    "setSellTax",
    "evm_token_risk_scan",
    "npx --yes github:youthmy11-ai/youthmy11-ai.github.io",
    "https://market.near.ai/agents/forge-token-guard",
    "$0.25",
    'data-checkout-sku="BUNDLE"',
  ]) {
    assert.ok(html.includes(term), `evm-proxy-honeypot-scanner.html missing "${term}"`);
  }

  const deepLinks = [...html.matchAll(/href="tokenaudit\.html\?([^"]+)"/g)].map((m) =>
    m[1].replace(/&amp;/g, "&")
  );
  assert.ok(deepLinks.length >= 4, "Expected at least 4 interactive EVM deep-links");
  const seenChains = new Set();
  for (const qs of deepLinks) {
    const parsed = parseTokenAuditQueryParams(qs);
    assert.equal(parsed.hasTarget, true);
    assert.match(parsed.address, /^0x[0-9a-fA-F]{40}$/);
    assert.equal(parsed.autorun, true);
    seenChains.add(parsed.chain);
  }
  assert.deepEqual(
    [...seenChains].sort(),
    ["arbitrum", "base", "bsc", "ethereum"],
    "EVM deep-links should cover Base, Ethereum, BSC, and Arbitrum"
  );
});


/* ============================================================================
 * 17. ForgeSuite MCP v1.3.0 Tool #8 (`multi_chain_wallet_scan`) & Web App #9 (`WalletLens`)
 * ========================================================================== */

test("WalletLens pure-JS SHA-256 + Ed25519 deriveSolanaAta, 32-byte Base58 validation, and CORS RPC endpoints match mainnet vectors", () => {
  const solWallet = "BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx";
  const usdcMint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
  const pyusdMint = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo";
  const tronAddress = "TGVUMYRwTqrCGzrPNW5V2bhrBNtsKgFcn7";

  assert.equal(walletLensValidSol(solWallet), true);
  assert.equal(walletLensValidSol(tronAddress), false, "25-byte TRON address must be rejected as Solana key");
  assert.equal(walletLensValidEvm("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"), true);
  assert.equal(walletLensValidEvm("0x1234"), false);

  const browserAta = deriveSolanaAta(solWallet, TOKEN_PROGRAM_ID, usdcMint);
  const nodeMcpAta = deriveSolanaAssociatedTokenAddress(solWallet, TOKEN_PROGRAM_ID, usdcMint);
  assert.equal(browserAta, "BNPJru7RVMw39jiGyCFcfBLhgoyhJ7DwycZ3m5PxqRE8");
  assert.equal(browserAta, nodeMcpAta);

  const pyusdAta = deriveSolanaAta(solWallet, TOKEN_2022_PROGRAM_ID, pyusdMint);
  assert.equal(pyusdAta, deriveSolanaAssociatedTokenAddress(solWallet, TOKEN_2022_PROGRAM_ID, pyusdMint));
  assert.equal(walletLensValidSol(pyusdAta), true);

  for (const ck of ["ethereum", "base", "arbitrum", "bsc", "polygon"]) {
    assert.match(WALLETLENS_EVM_CHAINS[ck].rpcs[0], /publicnode\.com/);
  }
  assert.equal(WALLETLENS_SOLANA_CONFIG.rpcs[0], "https://solana-rpc.publicnode.com");
});

test("parseWalletCheckQueryParams supports ?address=..., Etherscan/Solscan URLs, chain aliases, HTTPS RPC sanitization, and autorun", () => {
  const empty = parseWalletCheckQueryParams("");
  assert.equal(empty.hasTarget, false);
  assert.equal(empty.autorun, false);

  const evm = parseWalletCheckQueryParams(
    "?address=https://etherscan.io/address/0xfeB016d0D14AC0fa6d69199608B0776d007203B2&chains=eth,base,arb,pol&rpc=https://ethereum-rpc.publicnode.com"
  );
  assert.equal(evm.hasTarget, true);
  assert.equal(evm.address, "0xfeB016d0D14AC0fa6d69199608B0776d007203B2");
  assert.equal(evm.family, "evm");
  assert.deepEqual(evm.chains, ["ethereum", "base", "arbitrum", "polygon"]);
  assert.equal(evm.rpcUrl, "https://ethereum-rpc.publicnode.com/");
  assert.equal(evm.autorun, true);

  const sol = parseWalletCheckQueryParams(
    "?wallet=BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx&rpc=ftp://evil.example&autorun=0"
  );
  assert.equal(sol.hasTarget, true);
  assert.equal(sol.family, "solana");
  assert.equal(sol.rpcUrl, null);
  assert.equal(sol.autorun, false);
});

test("multi_chain_wallet_scan (Tool #8) inspects EVM EIP-7702, Gnosis Safe M-of-N, ERC-4337 & Solana SPL/Token-2022 over MCP JSON-RPC and stdio", async () => {
  const eip7702Addr = "0x874ebd03bee4ac1950796598d10f78be2ab3db3f";
  const delegateImpl = "0xae0fa4ff1b0e2fd4cd32fddc0f56b0e0c0bd1933";
  const safeAddr = "0xfeb016d0d14ac0fa6d69199608b0776d007203b2";
  const erc4337Addr = "0x3333333333333333333333333333333333333333";
  const entryPoint = "0x0000000071727de22e5e9d8baf0edac6f37da032";
  const solAddr = "BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx";

  assert.equal(classifyWalletEvmBytecode(`0xef0100${delegateImpl.slice(2)}`).accountType, "eip7702_delegated");
  assert.equal(walletLensClassifyCode(`0xef0100${delegateImpl.slice(2)}`).delegatedTo, delegateImpl);

  const ownerA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const ownerB = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const ownerC = "0xcccccccccccccccccccccccccccccccccccccccc";
  const abiOwners =
    "0x" +
    "20".padStart(64, "0") +
    "03".padStart(64, "0") +
    ownerA.slice(2).padStart(64, "0") +
    ownerB.slice(2).padStart(64, "0") +
    ownerC.slice(2).padStart(64, "0");

  const mockWalletFetch = async (rawUrl, init = {}) => {
    const u = String(rawUrl);
    const body = JSON.parse(init.body);
    const jsonResp = (obj) => ({
      ok: true,
      status: 200,
      json: async () => obj,
    });

    if (u.includes("solana")) {
      const req = Array.isArray(body) ? body[0] : body;
      if (req.method === "getAccountInfo") {
        return jsonResp({
          jsonrpc: "2.0",
          id: req.id,
          result: {
            context: { slot: 473305000 },
            value: { lamports: 2_500_000_000, owner: "11111111111111111111111111111111", executable: false },
          },
        });
      }
      if (req.method === "getTokenAccountsByOwner") {
        // Simulate HTTP 403 on indexed method to verify automatic O(1) ATA getMultipleAccounts fallback
        return { ok: false, status: 403, json: async () => ({ error: { message: "Indexed blocked" } }) };
      }
      if (req.method === "getMultipleAccounts") {
        const atas = req.params[0];
        const values = atas.map((_, idx) => {
          if (idx === 0) {
            return {
              data: {
                parsed: {
                  info: {
                    mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                    state: "initialized",
                    tokenAmount: { amount: "750500000", decimals: 6 }, // 750.50 USDC-SPL
                  },
                },
              },
            };
          }
          if (idx === 2) {
            return {
              data: {
                parsed: {
                  info: {
                    mint: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
                    state: "initialized",
                    tokenAmount: { amount: "120000000", decimals: 6 }, // 120.00 PYUSD (Token-2022)
                  },
                },
              },
            };
          }
          return null;
        });
        return jsonResp({ jsonrpc: "2.0", id: req.id, result: { context: { slot: 473305000 }, value: values } });
      }
      if (req.method === "getSignaturesForAddress") {
        return jsonResp({
          jsonrpc: "2.0",
          id: req.id,
          result: [
            {
              signature: "5h6xK9mN2pQ4rS7tU8vW1xY3zA5bC7dE9fG2hJ4kL6mN8pQ1rS3tU5vW7xY9zA1bC3dE5fG7hJ9kL2mN4pQ6rS8t",
              slot: 473304990,
              blockTime: 1763971200,
              err: null,
              memo: "ForgeSuite Pro Settlement",
              confirmationStatus: "confirmed",
            },
          ],
        });
      }
      return jsonResp({ jsonrpc: "2.0", id: req.id, result: null });
    }

    const reqs = Array.isArray(body) ? body : [body];
    const replies = reqs.map((r) => {
      const target = String(r.params?.[0]?.to || r.params?.[0] || "").toLowerCase();
      if (r.id === "block") {
        return { jsonrpc: "2.0", id: "block", result: { number: "0x1400000", timestamp: "0x67430000" } };
      }
      if (r.id === "balance") {
        return { jsonrpc: "2.0", id: "balance", result: "0xde0b6b3a7640000" }; // 1.0 native
      }
      if (r.id === "nonce") {
        return { jsonrpc: "2.0", id: "nonce", result: "0x19" }; // 25
      }
      if (r.id === "code") {
        if (target === eip7702Addr) return { jsonrpc: "2.0", id: "code", result: `0xef0100${delegateImpl.slice(2)}` };
        if (target === safeAddr || target === erc4337Addr) return { jsonrpc: "2.0", id: "code", result: "0x6080604052" };
        return { jsonrpc: "2.0", id: "code", result: "0x" };
      }
      if (r.id === "tok_0") {
        // USDC: 18dp on BSC, 6dp on Ethereum/Base/Arbitrum/Polygon
        const isBsc = u.includes("bsc");
        const amt = isBsc ? 500n * 10n ** 18n : 500n * 10n ** 6n;
        return { jsonrpc: "2.0", id: "tok_0", result: "0x" + amt.toString(16).padStart(64, "0") };
      }
      if (String(r.id).startsWith("tok_")) {
        return { jsonrpc: "2.0", id: r.id, result: "0x" + "0".repeat(64) };
      }
      if (r.id === "safe_threshold") {
        if (target === safeAddr) return { jsonrpc: "2.0", id: "safe_threshold", result: "0x" + "2".padStart(64, "0") };
        return { jsonrpc: "2.0", id: "safe_threshold", error: { code: -32000, message: "reverted" } };
      }
      if (r.id === "safe_owners") {
        if (target === safeAddr) return { jsonrpc: "2.0", id: "safe_owners", result: abiOwners };
        return { jsonrpc: "2.0", id: "safe_owners", error: { code: -32000, message: "reverted" } };
      }
      if (r.id === "erc4337_ep") {
        if (target === erc4337Addr) {
          return { jsonrpc: "2.0", id: "erc4337_ep", result: "0x" + entryPoint.slice(2).padStart(64, "0") };
        }
        return { jsonrpc: "2.0", id: "erc4337_ep", error: { code: -32000, message: "reverted" } };
      }
      return { jsonrpc: "2.0", id: r.id, result: "0x" };
    });
    return jsonResp(replies);
  };

  const scanRes = await scanMultiChainWallets(
    {
      wallets: [eip7702Addr, safeAddr, erc4337Addr, solAddr],
      chains: ["ethereum", "base", "solana"],
    },
    { fetchImpl: mockWalletFetch }
  );
  assert.equal(scanRes.ok, true);
  assert.equal(scanRes.walletCount, 4);
  assert.equal(scanRes.wallets[0].chains[0].account.accountType, "eip7702_delegated");
  assert.equal(scanRes.wallets[0].chains[0].account.delegatedTo, delegateImpl);
  assert.equal(scanRes.wallets[1].chains[0].account.accountType, "gnosis_safe");
  assert.equal(scanRes.wallets[1].chains[0].account.safeThreshold, 2);
  assert.equal(scanRes.wallets[1].chains[0].account.safeOwnersCount, 3);
  assert.equal(scanRes.wallets[2].chains[0].account.accountType, "erc4337");
  assert.equal(scanRes.wallets[2].chains[0].account.entryPoint, entryPoint);
  assert.equal(scanRes.wallets[3].family, "solana");
  assert.equal(scanRes.wallets[3].totalStablecoinUsd, 870.5); // 750.50 USDC + 120.00 PYUSD
  assert.equal(scanRes.upgradeLinks.proBundlePriceUsd, 35);
  assert.equal(scanRes.upgradeLinks.nearWalletScannerPriceUsdc, 0.15);

  const rpcMsg = await handleJsonRpcMessage(
    {
      jsonrpc: "2.0",
      id: "wallet-mcp-1",
      method: "tools/call",
      params: {
        name: "multi_chain_wallet_scan",
        arguments: { address: `${eip7702Addr}, ${solAddr}`, chains: ["ethereum", "solana"] },
      },
    },
    { fetchImpl: mockWalletFetch }
  );
  assert.equal(rpcMsg.id, "wallet-mcp-1");
  assert.equal(rpcMsg.result.isError, false);
  assert.match(rpcMsg.result.content[0].text, /EIP-7702 Delegated Account/);
  assert.match(rpcMsg.result.content[0].text, /walletcheck\.html/);
  assert.match(rpcMsg.result.content[0].text, /wallet-activity-scanner/);

  const badStdio = await runMcpStdioSession([
    JSON.stringify({
      jsonrpc: "2.0",
      id: "wallet-bad",
      method: "tools/call",
      params: { name: "multi_chain_wallet_scan", arguments: { address: "" } },
    }) + "\n",
  ]);
  assert.equal(badStdio.code, 0);
  assert.equal(badStdio.messages[0].result.isError, true);
});

test("WalletLens inspectSingleWallet, Pro 25-Wallet Watchlist, CSV formula guard, and CryptoBill/ScopeGuard handoffs work end-to-end", async () => {
  const safeAddr = "0xfeB016d0D14AC0fa6d69199608B0776d007203B2";
  const solAddr = "BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx";

  const mockBrowserFetch = async (rawUrl, init = {}) => {
    const u = String(rawUrl);
    const body = JSON.parse(init.body);
    if (u.includes("solana")) {
      if (body.method === "getAccountInfo") {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            jsonrpc: "2.0",
            id: body.id,
            result: {
              context: { slot: 473305100 },
              value: { lamports: 1_000_000_000, owner: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf", executable: false },
            },
          }),
        };
      }
      if (body.method === "getMultipleAccounts") {
        const vals = body.params[0].map((_, idx) =>
          idx === 0
            ? {
                data: {
                  parsed: {
                    info: {
                      mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                      tokenAmount: { amount: "250000000", decimals: 6 }, // 250 USDC
                    },
                  },
                },
              }
            : null
        );
        return {
          ok: true,
          status: 200,
          json: async () => ({ jsonrpc: "2.0", id: body.id, result: { context: { slot: 473305100 }, value: vals } }),
        };
      }
      return { ok: true, status: 200, json: async () => ({ jsonrpc: "2.0", id: body.id, result: [] }) };
    }

    const reqs = Array.isArray(body) ? body : [body];
    return {
      ok: true,
      status: 200,
      json: async () =>
        reqs.map((r) => {
          if (r.id === "block") return { jsonrpc: "2.0", id: "block", result: { number: "0x100", timestamp: "0x67430000" } };
          if (r.id === "balance") return { jsonrpc: "2.0", id: "balance", result: "0xde0b6b3a7640000" };
          if (r.id === "nonce") return { jsonrpc: "2.0", id: "nonce", result: "0x5" };
          if (r.id === "code") return { jsonrpc: "2.0", id: "code", result: "0x" };
          if (r.id === "tok_0") return { jsonrpc: "2.0", id: "tok_0", result: "0x" + (100n * 10n ** 6n).toString(16).padStart(64, "0") };
          return { jsonrpc: "2.0", id: r.id, result: "0x" + "0".repeat(64) };
        }),
    };
  };

  const entries = parseWalletWatchlistEntries(
    `=EvilFormulaLabel | ${safeAddr}\nSolana Squads Vault | https://solscan.io/account/${solAddr}`
  );
  assert.equal(entries.length, 2);
  assert.equal(entries[0].label, "=EvilFormulaLabel");
  assert.equal(entries[1].address, solAddr);

  const batch = await runBatchWalletWatchlist(entries, {
    chains: ["ethereum", "base", "solana"],
    fetchImpl: mockBrowserFetch,
  });
  assert.equal(batch.ok, true);
  assert.equal(batch.totalWallets, 2);
  assert.equal(batch.combinedStablecoinUsd, 450); // 100 ETH + 100 Base + 250 Solana
  assert.equal(batch.smartAccountsCount, 1); // Squads multisig

  const csv = exportWalletWatchlistCsv(batch);
  assert.match(csv, /label,address,family,primary_account_type,verdict/);
  assert.match(csv, /'=EvilFormulaLabel/, "CSV export must neutralize formula injection");
  assert.match(csv, /squads_multisig/);

  const tooMany = Array.from({ length: MAX_WATCHLIST_WALLETS + 1 }, (_, i) => ({
    label: `W${i}`,
    address: `0x${(i + 1).toString(16).padStart(40, "0")}`,
    family: "evm",
  }));
  await assert.rejects(
    () => runBatchWalletWatchlist(tooMany, { fetchImpl: mockBrowserFetch }),
    /up to 25/i
  );

  // CryptoBill & ScopeGuard SOW 1-click handoff roundtrips
  const singleReport = await inspectSingleWallet(safeAddr, {
    chains: ["ethereum"],
    fetchImpl: mockBrowserFetch,
  });
  const singleInv = buildWalletAuditInvoicePayload(singleReport);
  assert.equal(decodeInvoicePayload(encodeInvoicePayload(singleInv)).items[0].unitPrice, 165);

  const batchInv = buildWalletAuditInvoicePayload(batch);
  assert.equal(decodeInvoicePayload(encodeInvoicePayload(batchInv)).items[0].unitPrice, 245);

  const sow = buildWalletSowState(batch);
  const decodedSow = decodeSowHandoffPayload(`#sow=${encodeSowHandoffPayload(sow)}`);
  assert.equal(decodedSow.totalBudget, 750);
  assert.equal(computeSowTotals(decodedSow).isBalanced, true);
});

test("walletcheck.html and sitemap.xml ship valid SoftwareApplication + FAQPage JSON-LD, 1-click mainnet presets, Pro controls, and @wallet-activity-scanner $0.15 USDC CTA", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const html = fs.readFileSync(path.join(repoRoot, "walletcheck.html"), "utf8");
  const sitemap = fs.readFileSync(path.join(repoRoot, "sitemap.xml"), "utf8");

  assert.ok(sitemap.includes("https://youthmy11-ai.github.io/walletcheck.html"));

  const { types } = extractAllJsonLdObjects(html);
  assert.ok(types.has("SoftwareApplication"), "walletcheck.html missing SoftwareApplication JSON-LD");
  assert.ok(types.has("FAQPage"), "walletcheck.html missing FAQPage JSON-LD");

  for (const term of [
    NEAR_WALLET_SCANNER_URL,
    "$0.15 USDC",
    "EIP-7702",
    "0xef0100",
    "Gnosis Safe",
    "multi_chain_wallet_scan",
    'data-checkout-sku="BUNDLE"',
    'data-checkout-sku="CB"',
    'data-wl-sample="ens_safe"',
    'data-wl-sample="eip7702_eoa"',
    'data-wl-sample="vitalik_eoa"',
    'data-wl-sample="solana_treasury"',
  ]) {
    assert.ok(html.includes(term), `walletcheck.html missing "${term}"`);
  }
});

/* ============================================================================
 * 18. Task-Intent SEO Pages: EIP-7702 & Safe Checker + USPTO & Brand Checker
 * ========================================================================== */

function verifyInternalRelativeHtmlLinks(repoRoot, sourceFile, html) {
  const hrefs = [...html.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);
  for (const rawHref of hrefs) {
    if (
      rawHref.startsWith("http://") ||
      rawHref.startsWith("https://") ||
      rawHref.startsWith("mailto:") ||
      rawHref.startsWith("vscode:") ||
      rawHref.startsWith("vscode-insiders:") ||
      rawHref.startsWith("data:") ||
      rawHref.startsWith("#") ||
      rawHref === "./"
    ) {
      continue;
    }
    const cleanRel = rawHref.split("#")[0].split("?")[0];
    if (!cleanRel) continue;
    assert.ok(
      fs.existsSync(path.join(repoRoot, cleanRel)),
      `${sourceFile} contains broken internal link "${rawHref}"`
    );
  }
}

test("parseBrandCheckQueryParams supports ?brand=..., ?name=..., variations flag, autorun override, and invalid inputs", () => {
  const empty = parseBrandCheckQueryParams("");
  assert.equal(empty.hasTarget, false);
  assert.equal(empty.autorun, false);
  assert.equal(empty.runVariations, false);

  const clean = parseBrandCheckQueryParams("?brand=NovaForgeX&variations=1");
  assert.equal(clean.hasTarget, true);
  assert.equal(clean.brand, "NovaForgeX");
  assert.equal(clean.normalizedSlug, "novaforgex");
  assert.equal(clean.autorun, true);
  assert.equal(clean.runVariations, true);

  const urlInput = parseBrandCheckQueryParams("?name=https://@ForgeSuite.ai&autorun=0");
  assert.equal(urlInput.hasTarget, true);
  assert.equal(urlInput.normalizedSlug, "forgesuite");
  assert.equal(urlInput.autorun, false);

  const tooShort = parseBrandCheckQueryParams("?brand=a");
  assert.equal(tooShort.hasTarget, false);
});

test("eip-7702-delegation-gnosis-safe-checker.html ships valid SoftwareApplication + TechArticle + FAQPage JSON-LD, 1-click WalletLens deep-links, MCP v1.3.0, A2A & Pro CTAs", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const file = "eip-7702-delegation-gnosis-safe-checker.html";
  const canonicalUrl = `https://youthmy11-ai.github.io/${file}`;
  const html = fs.readFileSync(path.join(repoRoot, file), "utf8");
  const indexHtml = fs.readFileSync(path.join(repoRoot, "index.html"), "utf8");
  const walletHtml = fs.readFileSync(path.join(repoRoot, "walletcheck.html"), "utf8");

  assert.match(html, /<title>[^<]*EIP-7702[^<]*Gnosis Safe[^<]*<\/title>/);
  assert.match(html, /<meta name="description" content="[^"]{80,}"/);
  assert.ok(html.includes(`<link rel="canonical" href="${canonicalUrl}">`));
  assert.ok(indexHtml.includes(`href="${file}"`), "index.html must link to EIP-7702 & Safe guide");
  assert.ok(walletHtml.includes(`href="${file}"`), "walletcheck.html must link to EIP-7702 & Safe guide");

  const { types } = extractAllJsonLdObjects(html);
  assert.ok(types.has("SoftwareApplication"), "Missing SoftwareApplication JSON-LD");
  assert.ok(types.has("TechArticle"), "Missing TechArticle JSON-LD");
  assert.ok(types.has("FAQPage"), "Missing FAQPage JSON-LD");

  for (const term of [
    "EIP-7702",
    "0xef0100",
    "Pectra",
    "Prague",
    "Isthmus",
    "Gnosis Safe",
    "M-of-N",
    "walletcheck.html",
    "multi_chain_wallet_scan",
    "npx --yes github:youthmy11-ai/youthmy11-ai.github.io",
    "https://market.near.ai/agents/wallet-activity-scanner",
    "$0.15 USDC",
    'data-checkout-sku="CB"',
    'data-checkout-sku="BUNDLE"',
  ]) {
    assert.ok(html.includes(term), `${file} missing "${term}"`);
  }

  const deepLinks = [...html.matchAll(/href="walletcheck\.html\?([^"]+)"/g)].map((m) =>
    m[1].replace(/&amp;/g, "&")
  );
  assert.ok(deepLinks.length >= 4, "Expected at least 4 interactive WalletLens deep-links");
  const families = new Set();
  for (const qs of deepLinks) {
    const parsed = parseWalletCheckQueryParams(qs);
    assert.equal(parsed.hasTarget, true, `Invalid WalletLens deep-link query: ${qs}`);
    assert.equal(parsed.autorun, true);
    families.add(parsed.family);
  }
  assert.deepEqual([...families].sort(), ["evm", "solana"]);
  verifyInternalRelativeHtmlLinks(repoRoot, file, html);
});

test("uspto-trademark-domain-brand-checker.html ships valid SoftwareApplication + TechArticle + FAQPage JSON-LD, 1-click BrandGuard deep-links, MCP v1.3.0, A2A & Pro CTAs", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const file = "uspto-trademark-domain-brand-checker.html";
  const canonicalUrl = `https://youthmy11-ai.github.io/${file}`;
  const html = fs.readFileSync(path.join(repoRoot, file), "utf8");
  const indexHtml = fs.readFileSync(path.join(repoRoot, "index.html"), "utf8");
  const brandHtml = fs.readFileSync(path.join(repoRoot, "brandcheck.html"), "utf8");

  assert.match(html, /<title>[^<]*USPTO Trademark[^<]*Brand Checker[^<]*<\/title>/);
  assert.match(html, /<meta name="description" content="[^"]{80,}"/);
  assert.ok(html.includes(`<link rel="canonical" href="${canonicalUrl}">`));
  assert.ok(indexHtml.includes(`href="${file}"`), "index.html must link to USPTO & Brand guide");
  assert.ok(brandHtml.includes(`href="${file}"`), "brandcheck.html must link to USPTO & Brand guide");

  const { types } = extractAllJsonLdObjects(html);
  assert.ok(types.has("SoftwareApplication"), "Missing SoftwareApplication JSON-LD");
  assert.ok(types.has("TechArticle"), "Missing TechArticle JSON-LD");
  assert.ok(types.has("FAQPage"), "Missing FAQPage JSON-LD");

  for (const term of [
    "USPTO",
    ".com",
    ".ai",
    ".io",
    ".dev",
    ".app",
    ".org",
    ".net",
    ".xyz",
    "npm",
    "PyPI",
    "GitHub",
    "Apple",
    "Google Play",
    "brandcheck.html",
    "brand_domain_handle_scan",
    "npx --yes github:youthmy11-ai/youthmy11-ai.github.io",
    "https://market.near.ai/agents/forge-brand-checker",
    "$0.35 USDC",
    'data-checkout-sku="CB"',
    'data-checkout-sku="BUNDLE"',
  ]) {
    assert.ok(html.includes(term), `${file} missing "${term}"`);
  }

  const deepLinks = [...html.matchAll(/href="brandcheck\.html\?([^"]+)"/g)].map((m) =>
    m[1].replace(/&amp;/g, "&")
  );
  assert.ok(deepLinks.length >= 4, "Expected at least 4 interactive BrandGuard deep-links");
  for (const qs of deepLinks) {
    const parsed = parseBrandCheckQueryParams(qs);
    assert.equal(parsed.hasTarget, true, `Invalid BrandGuard deep-link query: ${qs}`);
    assert.equal(parsed.autorun, true);
  }
  verifyInternalRelativeHtmlLinks(repoRoot, file, html);
  verifyInternalRelativeHtmlLinks(repoRoot, "index.html", indexHtml);
});

/* ============================================================================
 * 19. Web App #10 (`ClipCaption Lab` — srtlab.html / assets/srtlab.js) &
 *     ForgeSuite MCP v1.4.0 Tool #9 (`subtitle_caption_audit`)
 * ========================================================================== */

test("ClipCaption Lab engine parses .srt/.vtt/.txt, shifts/scales timestamps, detects overlaps/CPS/9:16 overflows/mid-sentence cuts/brand terms, auto-fixes, and exports 1080x1920 .ASS", () => {
  assert.equal(parseTimestampMs("00:01:02,345"), 62345);
  assert.equal(parseTimestampMs("01:02.345"), 62345);
  assert.equal(formatSrtTimestamp(62345), "00:01:02,345");
  assert.equal(formatVttTimestamp(62345), "00:01:02.345");
  assert.equal(formatAssTimestamp(62345), "0:01:02.35");

  assert.equal(detectSubtitleFormat(SRTLAB_SAMPLES.creator_hook_issues), "srt");
  assert.equal(detectSubtitleFormat(SRTLAB_SAMPLES.clean_vertical_vtt), "vtt");
  assert.equal(detectSubtitleFormat("Plain spoken transcript sentence one. Sentence two!"), "txt");

  // Audit defective sample (overlap + CPS > 20 + 9:16 overflow + 3-line stack + mid-sentence cut)
  const rawAudit = auditSubtitles(SRTLAB_SAMPLES.creator_hook_issues, {
    maxCps: DEFAULT_MAX_CPS,
    maxLineLength: DEFAULT_MAX_LINE_CHARS,
    brandTerms: "ForgeSuite, MissingBrand, autoshorts studio",
    autoFix: false,
  });
  assert.equal(rawAudit.ok, true);
  assert.equal(rawAudit.detectedFormat, "srt");
  assert.equal(rawAudit.cueCount, 4);
  assert.ok(rawAudit.metrics.overlapCount >= 1, "Must detect overlapping cues");
  assert.ok(rawAudit.metrics.highCpsCount >= 1, "Must detect CPS > 20 reading speed");
  assert.ok(rawAudit.metrics.safeZoneOverflowCount >= 1, "Must detect >32 char 9:16 line overflow");
  assert.ok(rawAudit.metrics.multiLineOverflowCount >= 1, "Must detect >2 stacked lines");
  assert.ok(rawAudit.metrics.midSentenceCutCount >= 1, "Must detect mid-sentence cut at clip end");
  assert.ok(rawAudit.qualityScore < 75);
  assert.deepEqual(rawAudit.brandCheck.exactMatches, ["ForgeSuite"]);
  assert.deepEqual(rawAudit.brandCheck.caseMismatches, ["autoshorts studio"]);
  assert.deepEqual(rawAudit.brandCheck.missingTerms, ["MissingBrand"]);

  // Auto-fix eliminates overlaps and wraps lines cleanly inside 9:16 safe width
  const fixedAudit = auditSubtitles(SRTLAB_SAMPLES.creator_hook_issues, {
    maxCps: DEFAULT_MAX_CPS,
    maxLineLength: DEFAULT_MAX_LINE_CHARS,
    autoFix: true,
  });
  assert.equal(fixedAudit.metrics.overlapCount, 0);
  assert.equal(fixedAudit.metrics.safeZoneOverflowCount, 0);
  assert.ok(fixedAudit.qualityScore > rawAudit.qualityScore);

  // Bidirectional .SRT <-> .VTT <-> .TXT roundtrips + time-shift & tempo scale
  const vttParsed = parseSubtitles(SRTLAB_SAMPLES.clean_vertical_vtt);
  assert.equal(vttParsed.format, "vtt");
  assert.equal(vttParsed.cues.length, 3);
  const shifted = applyTimingTransform(vttParsed.cues, { shiftMs: 500, tempoScale: 1 });
  assert.equal(shifted[0].startMs, vttParsed.cues[0].startMs + 500);
  assert.match(serializeToSrt(shifted), /00:00:01,500 --> 00:00:04,700/);
  assert.match(serializeToVtt(shifted), /^WEBVTT\n\n1\n00:00:01\.500 --> 00:00:04\.700/);
  const txtWithTs = serializeToTranscriptTxt(shifted, { includeTimestamps: true });
  assert.equal(parseSubtitles(txtWithTs).cues.length, 3);

  // Pro 1080x1920 Animated .ASS export verification
  for (const presetKey of Object.keys(ASS_STYLE_PRESETS)) {
    const ass = serializeToVerticalAss(fixedAudit.cues, { preset: presetKey, animatePop: true });
    assert.match(ass, /PlayResX: 1080/);
    assert.match(ass, /PlayResY: 1920/);
    assert.match(ass, /\\fad\(70,60\)/);
    assert.match(ass, /Dialogue: 0,/);
  }
});

test("ClipCaption Lab Pro 25-File Batch Studio enforces <= 25 cap, guards CSV formula injection, parses URL params, and roundtrips CryptoBill/ScopeGuard handoffs", () => {
  const batchPack = runBatchSubtitleAudit([
    { name: "=InjectedHook.srt", content: SRTLAB_SAMPLES.creator_hook_issues },
    { name: "clean_reel.vtt", content: SRTLAB_SAMPLES.clean_vertical_vtt },
    { name: "dub_es.srt", content: SRTLAB_SAMPLES.multilang_dub_srt },
  ]);
  assert.equal(batchPack.ok, true);
  assert.equal(batchPack.totalFiles, 3);
  assert.equal(batchPack.okFiles, 3);
  assert.match(batchPack.reports[0].assOutput, /PlayResX: 1080/);

  const csv = exportBatchSubtitleCsv(batchPack);
  assert.match(csv, /file_name,detected_format,cue_count,duration_sec,quality_score/);
  assert.match(csv, /'=InjectedHook\.srt/, "CSV must guard leading = against formula injection");

  const overCap = Array.from({ length: MAX_BATCH_SUBTITLE_FILES + 1 }, (_, i) => ({
    name: `ep_${i + 1}.srt`,
    content: SRTLAB_SAMPLES.clean_vertical_vtt,
  }));
  assert.throws(() => runBatchSubtitleAudit(overCap), /up to 25/i);

  const qp = parseSrtLabQueryParams("?sample=clean_vertical_vtt&shift=-250&maxCps=18&maxLine=28&brands=ForgeSuite,NEAR");
  assert.equal(qp.sample, "clean_vertical_vtt");
  assert.equal(qp.shiftMs, -250);
  assert.equal(qp.maxCps, 18);
  assert.equal(qp.maxLineLength, 28);

  const inv = buildCaptionLocalizationInvoicePayload(batchPack);
  assert.equal(decodeInvoicePayload(encodeInvoicePayload(inv)).items.length, 2);

  const sow = buildCaptionSowState(batchPack);
  const decodedSow = decodeSowHandoffPayload(`#sow=${encodeSowHandoffPayload(sow)}`);
  assert.equal(computeSowTotals(decodedSow).isBalanced, true);
});

test("ForgeSuite MCP v1.4.0 Tool #9 (subtitle_caption_audit) audits .srt/.vtt over direct call, JSON-RPC, and stdio", async () => {
  const direct = auditSubtitleCaptions({
    content: SRTLAB_SAMPLES.creator_hook_issues,
    brandTerms: ["ForgeSuite", "autoshorts studio"],
    autoFix: true,
  });
  assert.equal(direct.ok, true);
  assert.equal(direct.cueCount, 4);
  assert.ok(direct.metrics.overlapCount >= 1);
  assert.equal(direct.postFixMetrics.overlapCount, 0);
  assert.equal(direct.postFixMetrics.safeZoneOverflowCount, 0);
  assert.ok(direct.qualityScore >= 0 && direct.qualityScore <= 100);
  assert.ok(direct.postFixQualityScore > direct.qualityScore);
  assert.deepEqual(direct.brandCheck.exactMatches, ["ForgeSuite"]);
  assert.deepEqual(direct.brandCheck.caseMismatches, ["autoshorts studio"]);
  assert.match(direct.normalizedSrt, /00:00:/);
  assert.match(direct.normalizedVtt, /^WEBVTT/);

  const rpc = await handleJsonRpcMessage({
    jsonrpc: "2.0",
    id: "sub-1",
    method: "tools/call",
    params: {
      name: "subtitle_caption_audit",
      arguments: {
        content: SRTLAB_SAMPLES.clean_vertical_vtt,
        shiftMs: 200,
        brandTerms: ["ForgeSuite"],
      },
    },
  });
  assert.equal(rpc.id, "sub-1");
  assert.equal(rpc.result.isError, false);
  assert.equal(rpc.result.structuredContent.qualityScore, 100);
  assert.match(rpc.result.content[0].text, /srtlab\.html/);
  assert.match(rpc.result.content[0].text, /short-video-clipper/);
  assert.match(rpc.result.content[0].text, /multi-lang-video-dubber/);

  const stdioRes = await runMcpStdioSession([
    JSON.stringify({
      jsonrpc: "2.0",
      id: "sub-stdio",
      method: "tools/call",
      params: {
        name: "subtitle_caption_audit",
        arguments: { content: SRTLAB_SAMPLES.creator_hook_issues, outputFormat: "srt" },
      },
    }) + "\n",
    JSON.stringify({
      jsonrpc: "2.0",
      id: "sub-empty",
      method: "tools/call",
      params: { name: "subtitle_caption_audit", arguments: { content: "" } },
    }) + "\n",
  ]);
  assert.equal(stdioRes.code, 0);
  assert.equal(stdioRes.messages[0].result.isError, false);
  assert.equal(stdioRes.messages[1].result.isError, true);
});

test("srtlab.html and all 10 core client-side web apps carry valid links, Pro controls, and cloud video agent handoffs", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const srtHtml = fs.readFileSync(path.join(repoRoot, "srtlab.html"), "utf8");
  const { types } = extractAllJsonLdObjects(srtHtml);
  assert.ok(types.has("SoftwareApplication"));
  assert.ok(types.has("FAQPage"));

  for (const term of [
    NEAR_VIDEO_CLIPPER_URL,
    NEAR_VIDEO_DUBBER_URL,
    "$0.50 USDC",
    "$0.65 USDC",
    "PlayResX: 1080",
    "PlayResY: 1920",
    "subtitle_caption_audit",
    'data-checkout-sku="BUNDLE"',
    'data-checkout-sku="AS"',
    'data-checkout-sku="CB"',
  ]) {
    assert.ok(srtHtml.includes(term), `srtlab.html missing "${term}"`);
  }
  verifyInternalRelativeHtmlLinks(repoRoot, "srtlab.html", srtHtml);

  const tenCoreWebApps = [
    "cryptobill.html",
    "tokencalc.html",
    "json2sheet.html",
    "sowbuilder.html",
    "txdecode.html",
    "envshield.html",
    "tokenaudit.html",
    "brandcheck.html",
    "walletcheck.html",
    "srtlab.html",
  ];
  const indexHtml = fs.readFileSync(path.join(repoRoot, "index.html"), "utf8");
  const sitemapXml = fs.readFileSync(path.join(repoRoot, "sitemap.xml"), "utf8");
  for (const appFile of tenCoreWebApps) {
    assert.ok(fs.existsSync(path.join(repoRoot, appFile)), `Missing core web app ${appFile}`);
    assert.ok(indexHtml.includes(`href="${appFile}"`), `index.html missing link to ${appFile}`);
    assert.ok(
      sitemapXml.includes(`<loc>https://youthmy11-ai.github.io/${appFile}</loc>`),
      `sitemap.xml missing ${appFile}`
    );
  }
});

/* ============================================================================
 * 20. Creator Video & AI Media Task-Intent SEO Pages (Iteration 9)
 * ========================================================================== */

test("tiktok-reels-9-16-subtitle-safe-zone-checker.html ships valid SoftwareApplication + TechArticle + FAQPage JSON-LD, 1-click srtlab.html presets, MCP v1.4.0 subtitle_caption_audit, cloud video agents & Pro CTAs", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const file = "tiktok-reels-9-16-subtitle-safe-zone-checker.html";
  const canonicalUrl = `https://youthmy11-ai.github.io/${file}`;
  const html = fs.readFileSync(path.join(repoRoot, file), "utf8");
  const srtHtml = fs.readFileSync(path.join(repoRoot, "srtlab.html"), "utf8");

  assert.match(html, /<title>[^<]*9:16 Subtitle Safe-Zone Checker[^<]*<\/title>/);
  assert.match(html, /<meta name="description" content="[^"]{90,}"/);
  assert.ok(html.includes(`<link rel="canonical" href="${canonicalUrl}">`));
  assert.ok(srtHtml.includes(`href="${file}"`), "srtlab.html must link bidirectionally to 9:16 safe-zone checker");

  const { types } = extractAllJsonLdObjects(html);
  assert.ok(types.has("SoftwareApplication"), "Missing SoftwareApplication JSON-LD");
  assert.ok(types.has("TechArticle"), "Missing TechArticle JSON-LD");
  assert.ok(types.has("FAQPage"), "Missing FAQPage JSON-LD");

  for (const term of [
    "9:16",
    "1080x1920",
    "TikTok",
    "Instagram Reels",
    "YouTube Shorts",
    "CPS",
    "20",
    ".ass",
    "PlayResX: 1080",
    "PlayResY: 1920",
    "srtlab.html",
    "subtitle_caption_audit",
    "v1.4.0",
    "npx --yes github:youthmy11-ai/youthmy11-ai.github.io",
    NEAR_VIDEO_CLIPPER_URL,
    NEAR_VIDEO_DUBBER_URL,
    "$0.50 USDC",
    "$0.65 USDC",
    "samples/video-clipping-sample.md",
    "samples/video-dubbing-sample.md",
    'data-checkout-sku="CB"',
    'data-checkout-sku="AS"',
    'data-checkout-sku="BUNDLE"',
  ]) {
    assert.ok(html.includes(term), `${file} missing "${term}"`);
  }

  const deepLinks = [...html.matchAll(/href="srtlab\.html\?([^"]+)"/g)].map((m) =>
    m[1].replace(/&amp;/g, "&")
  );
  assert.ok(deepLinks.length >= 4, "Expected at least 4 interactive srtlab.html deep-links");
  for (const qs of deepLinks) {
    const parsed = parseSrtLabQueryParams(qs);
    assert.ok(
      parsed.sample && Object.prototype.hasOwnProperty.call(SRTLAB_SAMPLES, parsed.sample),
      `Invalid srtlab.html sample query: ${qs}`
    );
  }
  const autoFixLink = deepLinks.find((q) => q.includes("autoFix=1"));
  assert.ok(autoFixLink, "Expected at least one autoFix=1 preset link");
  const parsedAutoFix = parseSrtLabQueryParams(autoFixLink);
  assert.equal(parsedAutoFix.autoFix, true);
  assert.equal(parsedAutoFix.outputTab, "ass");

  verifyInternalRelativeHtmlLinks(repoRoot, file, html);
});

test("youtube-most-replayed-clipper-ai-dubbing-guide.html ships valid SoftwareApplication + TechArticle + FAQPage JSON-LD, 1-click srtlab.html presets, MCP v1.4.0, stereo Mid/Side 26-lang dubbing & sample links", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const file = "youtube-most-replayed-clipper-ai-dubbing-guide.html";
  const canonicalUrl = `https://youthmy11-ai.github.io/${file}`;
  const html = fs.readFileSync(path.join(repoRoot, file), "utf8");
  const srtHtml = fs.readFileSync(path.join(repoRoot, "srtlab.html"), "utf8");

  assert.match(html, /<title>[^<]*YouTube Most Replayed Clipper[^<]*26-Language AI Video Dubbing[^<]*<\/title>/);
  assert.match(html, /<meta name="description" content="[^"]{90,}"/);
  assert.ok(html.includes(`<link rel="canonical" href="${canonicalUrl}">`));
  assert.ok(srtHtml.includes(`href="${file}"`), "srtlab.html must link bidirectionally to Most Replayed & AI Dubbing guide");

  const { types } = extractAllJsonLdObjects(html);
  assert.ok(types.has("SoftwareApplication"), "Missing SoftwareApplication JSON-LD");
  assert.ok(types.has("TechArticle"), "Missing TechArticle JSON-LD");
  assert.ok(types.has("FAQPage"), "Missing FAQPage JSON-LD");

  for (const term of [
    "Most Replayed",
    "26 languages",
    "Mid/Side",
    "-27.1 dBFS",
    "AutoShorts Studio Pro",
    "srtlab.html",
    "subtitle_caption_audit",
    "v1.4.0",
    "npx --yes github:youthmy11-ai/youthmy11-ai.github.io",
    NEAR_VIDEO_CLIPPER_URL,
    NEAR_VIDEO_DUBBER_URL,
    "$0.50 USDC",
    "$0.65 USDC",
    "samples/video-clipping-sample.md",
    "samples/video-dubbing-sample.md",
    'data-checkout-sku="CB"',
    'data-checkout-sku="AS"',
    'data-checkout-sku="BUNDLE"',
  ]) {
    assert.ok(html.includes(term), `${file} missing "${term}"`);
  }

  const deepLinks = [...html.matchAll(/href="srtlab\.html\?([^"]+)"/g)].map((m) =>
    m[1].replace(/&amp;/g, "&")
  );
  assert.ok(deepLinks.length >= 4, "Expected at least 4 interactive srtlab.html deep-links");
  for (const qs of deepLinks) {
    const parsed = parseSrtLabQueryParams(qs);
    assert.ok(
      parsed.sample && Object.prototype.hasOwnProperty.call(SRTLAB_SAMPLES, parsed.sample),
      `Invalid srtlab.html sample query: ${qs}`
    );
  }

  verifyInternalRelativeHtmlLinks(repoRoot, file, html);
});

test("index.html #technical-guides lists all 6 task-intent technical guides and preserves clean internal links across srtlab.html and index.html", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const indexHtml = fs.readFileSync(path.join(repoRoot, "index.html"), "utf8");
  const srtHtml = fs.readFileSync(path.join(repoRoot, "srtlab.html"), "utf8");

  const guidesSectionMatch = indexHtml.match(/<div class="cb-panel" id="technical-guides"[\s\S]*?<\/section>/);
  assert.ok(guidesSectionMatch, "index.html missing #technical-guides section");
  const guidesHtml = guidesSectionMatch[0];

  const expectedSixGuides = [
    "tiktok-reels-9-16-subtitle-safe-zone-checker.html",
    "youtube-most-replayed-clipper-ai-dubbing-guide.html",
    "eip-7702-delegation-gnosis-safe-checker.html",
    "uspto-trademark-domain-brand-checker.html",
    "solana-token-2022-scanner.html",
    "evm-proxy-honeypot-scanner.html",
  ];
  for (const guideFile of expectedSixGuides) {
    assert.ok(
      guidesHtml.includes(`href="${guideFile}"`),
      `index.html #technical-guides missing "${guideFile}"`
    );
  }
  const railCards = [...guidesHtml.matchAll(/class="fs-rail-box"/g)];
  assert.equal(railCards.length, 6, "index.html #technical-guides must display exactly 6 guide cards");

  verifyInternalRelativeHtmlLinks(repoRoot, "index.html", indexHtml);
  verifyInternalRelativeHtmlLinks(repoRoot, "srtlab.html", srtHtml);
});
