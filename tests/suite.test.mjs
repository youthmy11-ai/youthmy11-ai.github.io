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
  handleJsonRpcMessage,
  normalizeBrandCandidate,
  scanBrandDomainAndHandles,
} from "../mcp/forgesuite-mcp.mjs";
import { createForgeSuiteMcpbBuffer } from "../mcp/pack-mcpb.mjs";
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
  runBatchBrandScan,
  scanBrandVariations,
  scanSingleBrand,
  scoreBrandReadiness,
  validateLicenseKeyFormat as brandGuardValidateKey,
} from "../assets/brandcheck.js";

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
  assert.match(llmsFull, /ForgeSuite MCP Server/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/mcp\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/tokenaudit\.html/);
  assert.match(llmsTxt, /https:\/\/youthmy11-ai\.github\.io\/brandcheck\.html/);
  assert.match(llmsTxt, /https:\/\/market\.near\.ai\/agents\/forge-brand-checker/);
  assert.match(llmsTxt, /https:\/\/market\.near\.ai\/a\/forge-ai-agent/);
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
    { file: "brandcheck.html", url: "https://youthmy11-ai.github.io/brandcheck.html", category: "BusinessApplication" },
    { file: "tokencalc.html", url: "https://youthmy11-ai.github.io/tokencalc.html", category: "DeveloperApplication" },
    { file: "json2sheet.html", url: "https://youthmy11-ai.github.io/json2sheet.html", category: "DeveloperApplication" },
    { file: "sowbuilder.html", url: "https://youthmy11-ai.github.io/sowbuilder.html", category: "BusinessApplication" },
    { file: "txdecode.html", url: "https://youthmy11-ai.github.io/txdecode.html", category: "DeveloperApplication" },
    { file: "envshield.html", url: "https://youthmy11-ai.github.io/envshield.html", category: "SecurityApplication" },
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
  assert.equal(messages[0].result.serverInfo.version, "1.2.0");
  assert.equal(MCP_SERVER_INFO.version, "1.2.0");
  assert.ok(messages[0].result.capabilities.tools);

  assert.equal(messages[1].id, 2);
  assert.deepEqual(messages[1].result, {});

  assert.equal(messages[2].id, 3);
  assert.equal(messages[2].result.tools.length, 7);
  const toolNames = messages[2].result.tools.map((t) => t.name).sort();
  assert.deepEqual(toolNames, [
    "brand_domain_handle_scan",
    "calldata_decode",
    "cryptobill_quote",
    "envshield_scan",
    "evm_token_risk_scan",
    "solana_mint_risk_scan",
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
  assert.equal(agentCard.supportedInterfaces[0].url, "https://forge-ai-agent.market.near.ai/a2a/v1");
  assert.equal(agentCard.supportedInterfaces[0].protocolBinding, "JSONRPC");

  const mcpManifest = JSON.parse(fs.readFileSync(path.join(rootDir, ".well-known", "mcp", "server.json"), "utf8"));
  assert.equal(mcpManifest.name, "io.github.youthmy11-ai/forgesuite-mcp");
  assert.equal(mcpManifest.version, "1.2.0");
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

test("root package.json, .gitattributes, shebang LF line-endings, and v1.2.0 npx discovery docs are valid", () => {
  const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const pkgPath = path.join(rootDir, "package.json");
  const gitAttrPath = path.join(rootDir, ".gitattributes");
  const mcpBinPath = path.join(rootDir, "mcp", "forgesuite-mcp.mjs");

  assert.ok(fs.existsSync(pkgPath), "root package.json must exist for npx github:... execution");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  assert.equal(pkg.name, "forgesuite-mcp");
  assert.equal(pkg.version, "1.2.0");
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

  // Check v1.2.0 and 1-command npx across discovery & storefront files
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
    assert.ok(content.includes("1.2.0"), `${rel} must reference v1.2.0`);
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
  assert.equal(direct.upgradeLinks.nearAgentFleet.length, 3);

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
