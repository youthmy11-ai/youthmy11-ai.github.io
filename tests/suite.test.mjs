import test from "node:test";
import assert from "node:assert/strict";

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
