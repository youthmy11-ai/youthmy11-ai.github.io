import { renderQrSvg } from "./qr.js";

/**
 * Official Public Receiving Destinations & Storefront Catalog
 * Zero secrets, private keys, or internal host details.
 */
export const OFFICIAL_CHANNELS = Object.freeze({
  usdtBep20: "0x0a1e9c96755a7962306cf2ca9a80113a61559852",
  bscUsdtContract: "0x55d398326f99059fF775485246999027B3197955",
  bscChainId: 56,
  usdtDecimals: 18,
  solanaUsdc: "BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx",
  solanaUsdcMint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  usdtTrc20: "TGVUMYRwTqrCGzrPNW5V2bhrBNtsKgFcn7",
  binanceUid: "1179819899",
  binanceNickname: "vin9",
  paypalEmail: "min4444st@gmail.com",
  supportEmail: "youthmy11@gmail.com",
});

export const BSC_RPC_ENDPOINTS = Object.freeze([
  "https://bsc-dataseed.binance.org",
  "https://bsc-dataseed1.defibit.io",
]);

export const SOLANA_RPC_ENDPOINTS = Object.freeze([
  "https://api.mainnet-beta.solana.com",
]);

export const ERC20_TRANSFER_TOPIC0 =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

export const PRODUCTS = Object.freeze({
  CB: {
    sku: "CB",
    name: "CryptoBill Forge Pro",
    priceUsd: 15,
    billing: "Lifetime License",
    tagline: "Unlimited line items, white-label branding & batch invoice templates.",
    launchUrl: "cryptobill.html",
    repoUrl: "https://github.com/youthmy11-ai/youthmy11-ai.github.io",
    deliveryHint:
      "Unlocks instantly in this browser via License Key + backup JSON receipt.",
  },
  AS: {
    sku: "AS",
    name: "AutoShorts Studio Pro",
    priceUsd: 19,
    billing: "Lifetime License",
    tagline:
      "Automated 9:16/16:9/1:1 batch short-form video creator with SHA-256 deduplication & beat-milestone audio trimming.",
    launchUrl: "https://github.com/youthmy11-ai/autoshorts-studio",
    repoUrl: "https://github.com/youthmy11-ai/autoshorts-studio",
    deliveryHint:
      "Download Community Edition from GitHub and email your TxHash/License Key to youthmy11@gmail.com for Pro build access.",
  },
  WL: {
    sku: "WL",
    name: "WebLead & Table Extractor Pro",
    priceUsd: 15,
    billing: "Lifetime License",
    tagline:
      "Chrome MV3 Extension to extract web tables, emails & structured lists cleanly to CSV/JSON.",
    launchUrl: "https://github.com/youthmy11-ai/weblead-extractor",
    repoUrl: "https://github.com/youthmy11-ai/weblead-extractor",
    deliveryHint:
      "Install Lite Edition from GitHub and activate Pro exports with your License Key.",
  },
  BUNDLE: {
    sku: "BUNDLE",
    name: "All-Access Creator & Freelancer Bundle",
    priceUsd: 35,
    compareAtUsd: 49,
    savingsUsd: 14,
    billing: "Lifetime All-Access",
    tagline:
      "Includes CryptoBill Forge Pro + AutoShorts Studio Pro + WebLead & Table Extractor Pro.",
    launchUrl: "cryptobill.html",
    repoUrl: "https://github.com/youthmy11-ai",
    deliveryHint:
      "Instantly unlocks CryptoBill Forge Pro in-browser and covers all 3 Pro products.",
  },
});

const VALID_TIERS = new Set(["CB", "AS", "WL", "BUNDLE"]);
const LICENSE_KEY_REGEX =
  /^FS-PRO-(CB|AS|WL|BUNDLE)-([A-Z0-9]{8})(?:-([A-Z0-9]{4}))?$/;
const STORAGE_LICENSES_KEY = "forgesuite_licenses_v1";
const STORAGE_CB_PRO_KEY = "cryptobill_pro_license_v1";

function fnv1a32(str, seed = 0x811c9dc5) {
  let hash = seed >>> 0;
  for (let i = 0; i < str.length; i += 1) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function avalanche32(x) {
  let h = x >>> 0;
  h ^= h >>> 16;
  h = Math.imul(h, 0x7feb352d) >>> 0;
  h ^= h >>> 15;
  h = Math.imul(h, 0x846ca68b) >>> 0;
  h ^= h >>> 16;
  return h >>> 0;
}

function toBase36Padded(num, length) {
  const mod = 36 ** length;
  return (Math.abs(num) % mod).toString(36).toUpperCase().padStart(length, "0");
}

function computeChecksum2(prefixAndBody6) {
  const h = avalanche32(fnv1a32(`FS_CHK2|${prefixAndBody6}`, 0x9e3779b9));
  return toBase36Padded(h, 2);
}

/**
 * Shared 4-hex-digit FNV-1a 32-bit folded 16-bit checksum.
 * Matches AutoShorts Studio (Python) and WebLead Extractor (Chrome MV3) offline verifiers.
 */
function computeChecksum4(prefixAndCode8) {
  const h = fnv1a32(prefixAndCode8, 0x811c9dc5);
  const folded = ((h >>> 16) ^ (h & 0xffff)) & 0xffff;
  return folded.toString(16).toUpperCase().padStart(4, "0");
}

/**
 * Deterministically generates a checksummed Pro license key matching:
 * ^FS-PRO-(CB|AS|WL|BUNDLE)-[A-Z0-9]{8}(-[0-9A-F]{4})?$
 * @param {'CB'|'AS'|'WL'|'BUNDLE'} tier
 * @param {string} seed
 * @returns {string}
 */
export function generateLicenseKey(tier, seed) {
  const normalizedTier = VALID_TIERS.has(String(tier || "").toUpperCase())
    ? String(tier).toUpperCase()
    : "CB";
  const seedStr = String(seed || "default-seed");
  const h1 = avalanche32(fnv1a32(`${normalizedTier}|A|${seedStr}`, 0x811c9dc5));
  const h2 = avalanche32(fnv1a32(`${normalizedTier}|B|${seedStr}`, 0x13198a2e));
  const body6 = toBase36Padded(h1, 3) + toBase36Padded(h2, 3);
  const prefixBody6 = `FS-PRO-${normalizedTier}-${body6}`;
  const chk2 = computeChecksum2(prefixBody6);
  const code8 = `${body6}${chk2}`;
  const chk4 = computeChecksum4(`FS-PRO-${normalizedTier}-${code8}`);
  return `FS-PRO-${normalizedTier}-${code8}-${chk4}`;
}

/**
 * Validates format and deterministic embedded checksum of a ForgeSuite license key.
 * @param {string} key
 * @returns {boolean}
 */
export function validateLicenseKeyFormat(key) {
  if (typeof key !== "string") return false;
  const normalized = key.trim().toUpperCase();
  const match = normalized.match(LICENSE_KEY_REGEX);
  if (!match) return false;

  const [, tier, code8, chk4] = match;
  if (code8 === "00000000") return false;
  if (chk4 !== undefined) {
    if (!/^[0-9A-F]{4}$/.test(chk4)) return false;
    const expectedChk4 = computeChecksum4(`FS-PRO-${tier}-${code8}`);
    return chk4 === expectedChk4;
  }
  const expectedChk2 = computeChecksum2(`FS-PRO-${tier}-${code8.slice(0, 6)}`);
  return code8.slice(6, 8) === expectedChk2;
}

/**
 * Parses a validated license key and returns unlocked SKUs.
 * @param {string} key
 */
export function parseLicenseKey(key) {
  if (!validateLicenseKeyFormat(key)) {
    return { valid: false, tier: null, key: null, unlocks: [] };
  }
  const normalized = key.trim().toUpperCase();
  const match = normalized.match(LICENSE_KEY_REGEX);
  const tier = match[1];
  const unlocks = tier === "BUNDLE" ? ["CB", "AS", "WL", "BUNDLE"] : [tier];
  return { valid: true, tier, key: normalized, unlocks };
}

function usdToWei18(amountUsd) {
  const microUsd = BigInt(Math.round(Number(amountUsd) * 1_000_000));
  return microUsd * 10n ** 12n;
}

function wei18ToUsdFloat(weiBigInt) {
  const microUsd = weiBigInt / 10n ** 12n;
  return Number(microUsd) / 1_000_000;
}

function inferTierFromAmount(expectedAmountUsd, requestedTier) {
  if (requestedTier && VALID_TIERS.has(String(requestedTier).toUpperCase())) {
    return String(requestedTier).toUpperCase();
  }
  if (expectedAmountUsd >= 35) return "BUNDLE";
  if (expectedAmountUsd >= 19) return "AS";
  return "CB";
}

/**
 * Pure, deterministic verifier for BSC USDT (BEP20) transaction receipts.
 * Checks status === "0x1", BSC USDT contract, ERC-20 Transfer topic0,
 * padded recipient address in topics[2], and 18-decimal BigInt amount (0.5% tolerance).
 *
 * @param {object} receipt - JSON-RPC eth_getTransactionReceipt result object
 * @param {number} expectedAmountUsd - Expected payment amount in USD/USDT
 * @param {string} [expectedToAddress] - Expected receiving address (defaults to official BEP20 address)
 * @param {{ tier?: string, tolerancePct?: number, txHash?: string }} [options]
 */
export function verifyBscUsdtReceipt(
  receipt,
  expectedAmountUsd,
  expectedToAddress = OFFICIAL_CHANNELS.usdtBep20,
  options = {}
) {
  if (!receipt || typeof receipt !== "object") {
    return { verified: false, reason: "Transaction receipt is empty or invalid." };
  }

  const status = String(receipt.status || "").toLowerCase();
  if (status !== "0x1") {
    return {
      verified: false,
      reason: "Transaction failed or is not confirmed (status !== 0x1).",
    };
  }

  if (!Array.isArray(receipt.logs) || receipt.logs.length === 0) {
    return { verified: false, reason: "Transaction receipt contains no event logs." };
  }

  if (!Number.isFinite(Number(expectedAmountUsd)) || Number(expectedAmountUsd) <= 0) {
    return { verified: false, reason: "Expected payment amount must be greater than 0." };
  }

  const targetAddress = String(
    expectedToAddress || OFFICIAL_CHANNELS.usdtBep20
  ).toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(targetAddress)) {
    return { verified: false, reason: "Invalid expected recipient BEP20 address." };
  }

  const expectedContract = OFFICIAL_CHANNELS.bscUsdtContract.toLowerCase();
  const expectedWei = usdToWei18(expectedAmountUsd);
  const tolerancePct =
    typeof options.tolerancePct === "number" ? options.tolerancePct : 0.005;
  const bpsKeep = BigInt(Math.max(0, Math.round((1 - tolerancePct) * 10000)));
  const minRequiredWei = (expectedWei * bpsKeep) / 10000n;

  let sawUsdtTransfer = false;
  let sawOtherRecipient = false;
  let sawMalformedLog = false;
  let maxInsufficientWei = null;

  for (let i = 0; i < receipt.logs.length; i += 1) {
    const log = receipt.logs[i];
    if (!log || typeof log !== "object") continue;

    const logContract = String(log.address || "").toLowerCase();
    if (logContract !== expectedContract) continue;

    if (!Array.isArray(log.topics) || log.topics.length === 0) {
      sawMalformedLog = true;
      continue;
    }

    const topic0 = String(log.topics[0] || "").toLowerCase();
    if (topic0 !== ERC20_TRANSFER_TOPIC0) continue;

    sawUsdtTransfer = true;
    if (log.topics.length < 3) {
      sawMalformedLog = true;
      continue;
    }

    const topic2 = String(log.topics[2] || "");
    if (!/^0x0{24}[0-9a-fA-F]{40}$/.test(topic2)) {
      sawMalformedLog = true;
      continue;
    }

    const toAddress = `0x${topic2.slice(-40).toLowerCase()}`;
    if (toAddress !== targetAddress) {
      sawOtherRecipient = true;
      continue;
    }

    const rawData = String(log.data || "");
    if (!/^0x[0-9a-fA-F]{1,64}$/.test(rawData)) {
      sawMalformedLog = true;
      continue;
    }

    const amountWei = BigInt(rawData);
    if (amountWei < minRequiredWei) {
      if (maxInsufficientWei === null || amountWei > maxInsufficientWei) {
        maxInsufficientWei = amountWei;
      }
      continue;
    }

    const amountUsd = wei18ToUsdFloat(amountWei);
    const tier = inferTierFromAmount(Number(expectedAmountUsd), options.tier);
    const txHash = String(receipt.transactionHash || options.txHash || "");
    const seed = `${tier}|${txHash.toLowerCase()}|${i}|${amountWei.toString()}`;
    const licenseKey = generateLicenseKey(tier, seed);

    return {
      verified: true,
      amountUsd,
      amountWei: amountWei.toString(),
      txHash,
      to: toAddress,
      token: "USDT-BEP20",
      contract: OFFICIAL_CHANNELS.bscUsdtContract,
      tier,
      licenseKey,
    };
  }

  if (maxInsufficientWei !== null) {
    const received = wei18ToUsdFloat(maxInsufficientWei);
    return {
      verified: false,
      reason: `Insufficient USDT amount (${received} USDT received, expected $${Number(expectedAmountUsd).toFixed(2)}).`,
    };
  }

  if (sawMalformedLog) {
    return {
      verified: false,
      reason: "Malformed ERC-20 Transfer log detected in receipt.",
    };
  }

  if (sawOtherRecipient || sawUsdtTransfer) {
    return {
      verified: false,
      reason: `No USDT-BEP20 Transfer log to official address ${targetAddress} found.`,
    };
  }

  return {
    verified: false,
    reason: "No BSC USDT (BEP20) Transfer event found in this transaction.",
  };
}

/**
 * Fetches transaction receipt from BSC public JSON-RPC nodes with automatic fallback
 * and verifies USDT-BEP20 payment against official receiving address.
 *
 * @param {string} txHash
 * @param {number} expectedAmountUsd
 * @param {{ tier?: string, endpoints?: string[], fetchImpl?: typeof fetch, expectedToAddress?: string }} [options]
 */
export async function verifyBscUsdtTxOnChain(
  txHash,
  expectedAmountUsd,
  options = {}
) {
  const cleanHash = String(txHash || "").trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(cleanHash)) {
    return {
      verified: false,
      reason: "Invalid BSC transaction hash format (must start with 0x followed by 64 hex chars).",
    };
  }

  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    return {
      verified: false,
      reason: "Fetch API is unavailable in this environment.",
    };
  }

  const endpoints =
    Array.isArray(options.endpoints) && options.endpoints.length > 0
      ? options.endpoints
      : BSC_RPC_ENDPOINTS;

  let lastError = null;
  for (const endpoint of endpoints) {
    try {
      const response = await fetchImpl(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "eth_getTransactionReceipt",
          params: [cleanHash],
        }),
      });
      if (!response.ok) {
        lastError = `RPC HTTP ${response.status}`;
        continue;
      }
      const payload = await response.json();
      if (payload && payload.error) {
        lastError = payload.error.message || "RPC returned error";
        continue;
      }
      if (!payload || payload.result === null || payload.result === undefined) {
        return {
          verified: false,
          pending: true,
          reason:
            "Transaction is not indexed or still pending confirmation on BSC. Wait ~5–10 seconds and try again.",
        };
      }
      return verifyBscUsdtReceipt(
        payload.result,
        expectedAmountUsd,
        options.expectedToAddress || OFFICIAL_CHANNELS.usdtBep20,
        { ...options, txHash: cleanHash }
      );
    } catch (err) {
      lastError = err && err.message ? err.message : "Network error";
    }
  }

  return {
    verified: false,
    reason: `Unable to reach BSC RPC nodes (${lastError || "connection failed"}). Please retry or email your TxHash to ${OFFICIAL_CHANNELS.supportEmail}.`,
  };
}

/**
 * Pure, deterministic verifier for Solana SPL USDC transfers via `getTransaction` result.
 * Validates `meta.err === null`, USDC mint, official Solana wallet owner, and 6-decimal net credit.
 *
 * @param {object} txResult
 * @param {number} expectedAmountUsd
 * @param {string} [expectedOwner]
 * @param {{ tier?: string, tolerancePct?: number, signature?: string }} [options]
 */
export function verifySolanaUsdcTx(
  txResult,
  expectedAmountUsd,
  expectedOwner = OFFICIAL_CHANNELS.solanaUsdc,
  options = {}
) {
  if (!txResult || typeof txResult !== "object" || !txResult.meta) {
    return { verified: false, reason: "Solana transaction payload is empty or invalid." };
  }
  if (txResult.meta.err !== null && txResult.meta.err !== undefined) {
    return { verified: false, reason: "Solana transaction failed on-chain (meta.err !== null)." };
  }
  if (!Number.isFinite(Number(expectedAmountUsd)) || Number(expectedAmountUsd) <= 0) {
    return { verified: false, reason: "Expected payment amount must be greater than 0." };
  }

  const targetOwner = String(expectedOwner || OFFICIAL_CHANNELS.solanaUsdc).trim();
  const targetMint = OFFICIAL_CHANNELS.solanaUsdcMint;
  const preList = Array.isArray(txResult.meta.preTokenBalances)
    ? txResult.meta.preTokenBalances
    : [];
  const postList = Array.isArray(txResult.meta.postTokenBalances)
    ? txResult.meta.postTokenBalances
    : [];

  const preByIndex = new Map();
  for (const b of preList) {
    if (b && b.mint === targetMint && b.owner === targetOwner && b.uiTokenAmount?.amount != null) {
      preByIndex.set(b.accountIndex, BigInt(b.uiTokenAmount.amount));
    }
  }

  let totalCreditedMicro = 0n;
  for (const b of postList) {
    if (!b || b.mint !== targetMint || b.owner !== targetOwner || b.uiTokenAmount?.amount == null) {
      continue;
    }
    const postAmt = BigInt(b.uiTokenAmount.amount);
    const preAmt = preByIndex.get(b.accountIndex) ?? 0n;
    if (postAmt > preAmt) {
      totalCreditedMicro += postAmt - preAmt;
    }
  }

  if (totalCreditedMicro === 0n) {
    return {
      verified: false,
      reason: `No SPL USDC credit to official Solana wallet ${targetOwner} found in this transaction.`,
    };
  }

  const expectedMicro = BigInt(Math.round(Number(expectedAmountUsd) * 1_000_000));
  const tolerancePct = typeof options.tolerancePct === "number" ? options.tolerancePct : 0.005;
  const bpsKeep = BigInt(Math.max(0, Math.round((1 - tolerancePct) * 10000)));
  const minRequiredMicro = (expectedMicro * bpsKeep) / 10000n;

  if (totalCreditedMicro < minRequiredMicro) {
    const received = Number(totalCreditedMicro) / 1_000_000;
    return {
      verified: false,
      reason: `Insufficient USDC amount (${received.toFixed(2)} USDC received, expected $${Number(expectedAmountUsd).toFixed(2)}).`,
    };
  }

  const amountUsd = Number(totalCreditedMicro) / 1_000_000;
  const tier = inferTierFromAmount(Number(expectedAmountUsd), options.tier);
  const sig = String(
    options.signature || txResult.transaction?.signatures?.[0] || ""
  ).trim();
  const seed = `${tier}|SOL|${sig}|${totalCreditedMicro.toString()}`;
  const licenseKey = generateLicenseKey(tier, seed);

  return {
    verified: true,
    amountUsd,
    amountMicro: totalCreditedMicro.toString(),
    txHash: sig,
    to: targetOwner,
    token: "USDC-SOLANA",
    mint: targetMint,
    tier,
    licenseKey,
  };
}

/**
 * Fetches Solana transaction via JSON-RPC `getTransaction` and verifies SPL USDC payment.
 */
export async function verifySolanaUsdcTxOnChain(
  signature,
  expectedAmountUsd,
  options = {}
) {
  const cleanSig = String(signature || "").trim();
  if (!/^[1-9A-HJ-NP-Za-km-z]{64,92}$/.test(cleanSig)) {
    return {
      verified: false,
      reason: "Invalid Solana transaction signature format (base58 string expected).",
    };
  }

  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    return { verified: false, reason: "Fetch API is unavailable in this environment." };
  }

  const endpoints =
    Array.isArray(options.endpoints) && options.endpoints.length > 0
      ? options.endpoints
      : SOLANA_RPC_ENDPOINTS;

  let lastError = null;
  for (const endpoint of endpoints) {
    try {
      const response = await fetchImpl(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "getTransaction",
          params: [cleanSig, { encoding: "jsonParsed", maxSupportedTransactionVersion: 0 }],
        }),
      });
      if (!response.ok) {
        lastError = `Solana RPC HTTP ${response.status}`;
        continue;
      }
      const payload = await response.json();
      if (payload && payload.error) {
        lastError = payload.error.message || "Solana RPC error";
        continue;
      }
      if (!payload || payload.result === null || payload.result === undefined) {
        return {
          verified: false,
          pending: true,
          reason:
            "Transaction is not finalized yet on Solana mainnet. Wait a few seconds and retry.",
        };
      }
      return verifySolanaUsdcTx(
        payload.result,
        expectedAmountUsd,
        options.expectedToAddress || OFFICIAL_CHANNELS.solanaUsdc,
        { ...options, signature: cleanSig }
      );
    } catch (err) {
      lastError = err && err.message ? err.message : "Network error";
    }
  }

  return {
    verified: false,
    reason: `Unable to reach Solana RPC nodes (${lastError || "connection failed"}). Retry or email signature to ${OFFICIAL_CHANNELS.supportEmail}.`,
  };
}

/**
 * Builds the official PayPal.com checkout redirect URL targeting min4444st@gmail.com.
 * @param {{ itemName: string, amountUsd: number|string, sku?: string, businessEmail?: string, currencyCode?: string }} params
 * @returns {string}
 */
export function buildPaypalCheckoutUrl({
  itemName,
  amountUsd,
  sku,
  businessEmail = OFFICIAL_CHANNELS.paypalEmail,
  currencyCode = "USD",
}) {
  const numericAmount = Number(amountUsd);
  const formattedAmount =
    Number.isFinite(numericAmount) && numericAmount > 0
      ? numericAmount.toFixed(2)
      : "15.00";

  const params = new URLSearchParams({
    cmd: "_xclick",
    business: businessEmail,
    item_name: String(itemName || "ForgeSuite Pro License"),
    amount: formattedAmount,
    currency_code: String(currencyCode || "USD").toUpperCase(),
    no_shipping: "1",
  });
  if (sku) {
    params.set("item_number", String(sku));
  }
  return `https://www.paypal.com/cgi-bin/webscr?${params.toString()}`;
}

/**
 * Builds a pre-filled mailto: link for manual receipt verification via youthmy11@gmail.com.
 * @param {{ productName: string, sku?: string, amountUsd: number|string, paymentMethod: string, referenceId?: string, customerEmail?: string }} params
 * @returns {string}
 */
export function buildMailtoReceiptUrl({
  productName,
  sku = "",
  amountUsd,
  paymentMethod,
  referenceId = "",
  customerEmail = "",
}) {
  const formattedAmount = Number.isFinite(Number(amountUsd))
    ? `$${Number(amountUsd).toFixed(2)} USD`
    : String(amountUsd || "");
  const skuTag = sku ? ` [${sku}]` : "";
  const subject = `[ForgeSuite Receipt] ${productName}${skuTag} - ${paymentMethod}`;
  const bodyLines = [
    "Hello ForgeSuite Support,",
    "",
    "I completed payment and would like license verification / Pro delivery:",
    `- Product: ${productName}${skuTag}`,
    `- Amount: ${formattedAmount}`,
    `- Payment Method: ${paymentMethod}`,
    `- TxHash / Order ID: ${referenceId || "<paste TxHash or Order ID here>"}`,
    `- Delivery Email: ${customerEmail || "<your email address>"}`,
    "",
    "Thank you!",
  ];
  const query = new URLSearchParams({
    subject,
    body: bodyLines.join("\n"),
  });
  return `mailto:${OFFICIAL_CHANNELS.supportEmail}?${query.toString().replaceAll("+", "%20")}`;
}

/* ============================================================================
 * Browser Storage & License Persistence Helpers
 * ========================================================================== */

function getSafeStorage() {
  try {
    if (typeof globalThis !== "undefined" && globalThis.localStorage) {
      return globalThis.localStorage;
    }
  } catch {
    return null;
  }
  return null;
}

export function getStoredLicenses() {
  const storage = getSafeStorage();
  if (!storage) return [];
  try {
    const raw = storage.getItem(STORAGE_LICENSES_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed)
      ? parsed.filter((entry) => entry && validateLicenseKeyFormat(entry.key))
      : [];
  } catch {
    return [];
  }
}

export function saveVerifiedLicense(entry) {
  const parsed = parseLicenseKey(entry && entry.key);
  if (!parsed.valid) return false;

  const record = {
    key: parsed.key,
    tier: parsed.tier,
    unlocks: parsed.unlocks,
    txHash: entry.txHash || "",
    token: entry.token || "MANUAL",
    amountUsd: entry.amountUsd || 0,
    verifiedAt: entry.verifiedAt || new Date().toISOString(),
  };

  const storage = getSafeStorage();
  if (storage) {
    try {
      const existing = getStoredLicenses().filter((item) => item.key !== parsed.key);
      existing.unshift(record);
      storage.setItem(STORAGE_LICENSES_KEY, JSON.stringify(existing));
      if (parsed.unlocks.includes("CB")) {
        storage.setItem(STORAGE_CB_PRO_KEY, parsed.key);
      }
    } catch {
      // Ignore storage quota / private mode restrictions and still return record
    }
  }
  return record;
}

export function activateLicenseKey(rawKey) {
  const parsed = parseLicenseKey(rawKey);
  if (!parsed.valid) {
    return {
      ok: false,
      reason:
        "Invalid License Key format or checksum. Expected format: FS-PRO-(CB|AS|WL|BUNDLE)-XXXXXXXX-XXXX",
    };
  }
  const saved = saveVerifiedLicense({
    key: parsed.key,
    token: "LICENSE-KEY",
    amountUsd: PRODUCTS[parsed.tier]?.priceUsd || 15,
  });
  return { ok: true, tier: parsed.tier, unlocks: parsed.unlocks, key: parsed.key, saved };
}

export function hasUnlockedTier(tier) {
  const target = String(tier || "CB").toUpperCase();
  const licenses = getStoredLicenses();
  if (
    licenses.some(
      (item) =>
        Array.isArray(item.unlocks)
          ? item.unlocks.includes(target)
          : item.tier === "BUNDLE" || item.tier === target
    )
  ) {
    return true;
  }
  const storage = getSafeStorage();
  if (storage && target === "CB") {
    const legacy = storage.getItem(STORAGE_CB_PRO_KEY);
    if (legacy && validateLicenseKeyFormat(legacy)) {
      const parsed = parseLicenseKey(legacy);
      return parsed.unlocks.includes("CB");
    }
  }
  return false;
}

export function getActiveLicenseForTier(tier) {
  const target = String(tier || "CB").toUpperCase();
  const licenses = getStoredLicenses();
  const found = licenses.find((item) =>
    Array.isArray(item.unlocks)
      ? item.unlocks.includes(target)
      : item.tier === "BUNDLE" || item.tier === target
  );
  if (found) return found;

  const storage = getSafeStorage();
  if (storage && target === "CB") {
    const legacy = storage.getItem(STORAGE_CB_PRO_KEY);
    if (legacy && validateLicenseKeyFormat(legacy)) {
      const parsed = parseLicenseKey(legacy);
      if (parsed.unlocks.includes("CB")) {
        return { key: parsed.key, tier: parsed.tier, unlocks: parsed.unlocks };
      }
    }
  }
  return null;
}

/* ============================================================================
 * Interactive Checkout Modal Controller (Browser Only)
 * ========================================================================== */

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const input = document.createElement("textarea");
    input.value = text;
    input.style.position = "fixed";
    input.style.opacity = "0";
    document.body.appendChild(input);
    input.select();
    document.execCommand("copy");
    input.remove();
  }
  if (btn) {
    const orig = btn.textContent;
    btn.textContent = "Copied!";
    btn.classList.add("is-copied");
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove("is-copied");
    }, 1800);
  }
}

function ensureCheckoutModalElement() {
  let modal = document.getElementById("fsCheckoutModal");
  if (modal) return modal;

  modal = document.createElement("div");
  modal.id = "fsCheckoutModal";
  modal.className = "fs-modal-backdrop";
  modal.hidden = true;
  modal.setAttribute("role", "dialog");
  modal.setAttribute("aria-modal", "true");
  modal.setAttribute("aria-labelledby", "fsCheckoutTitle");

  modal.innerHTML = `
    <div class="fs-modal-panel">
      <div class="fs-modal-header">
        <div>
          <span class="fs-badge fs-badge-accent" id="fsCheckoutSkuBadge">PRO LICENSE</span>
          <h2 id="fsCheckoutTitle" class="fs-modal-title">Checkout</h2>
          <p id="fsCheckoutSubtitle" class="fs-modal-subtitle"></p>
        </div>
        <div class="fs-modal-price-wrap">
          <div class="fs-modal-price" id="fsCheckoutPrice">$15</div>
          <button type="button" class="fs-icon-btn" id="fsCheckoutClose" aria-label="Close checkout">✕</button>
        </div>
      </div>

      <div class="fs-tabs" role="tablist" aria-label="Payment Methods">
        <button type="button" class="fs-tab is-active" data-pay-tab="bep20">USDT (BEP20 Auto)</button>
        <button type="button" class="fs-tab" data-pay-tab="solana">USDC (Solana Auto)</button>
        <button type="button" class="fs-tab" data-pay-tab="trc20">USDT (TRC20)</button>
        <button type="button" class="fs-tab" data-pay-tab="binance">Binance Pay</button>
        <button type="button" class="fs-tab" data-pay-tab="paypal">PayPal</button>
        <button type="button" class="fs-tab" data-pay-tab="license">Have Key?</button>
      </div>

      <div class="fs-modal-body">
        <!-- BEP20 AUTO VERIFY -->
        <div class="fs-tab-panel is-active" data-pay-panel="bep20">
          <div class="fs-notice fs-notice-info">
            <strong>Instant On-Chain Auto-Verification:</strong> Send exact USDT on <strong>BNB Smart Chain (BEP20)</strong>, then paste your TxHash below to verify directly via BSC RPC and unlock immediately.
          </div>
          <div class="fs-pay-grid">
            <div class="fs-qr-box" id="fsQrBep20"></div>
            <div class="fs-pay-details">
              <div class="fs-field-label">Network &amp; Token</div>
              <div class="fs-mono-chip">BNB Smart Chain (BEP20 / Chain ID 56) · USDT</div>
              <div class="fs-field-label">Official Receiving Address</div>
              <div class="fs-copy-row">
                <code class="fs-code-val" id="fsBep20Addr">${OFFICIAL_CHANNELS.usdtBep20}</code>
                <button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-copy-val="${OFFICIAL_CHANNELS.usdtBep20}">Copy</button>
              </div>
              <div class="fs-field-label">Amount to Send</div>
              <div class="fs-mono-chip" id="fsBep20Amount">15.00 USDT</div>
            </div>
          </div>
          <div class="fs-verify-box">
            <label for="fsBscTxHash" class="fs-field-label">Paste BSC Transaction Hash (0x...)</label>
            <div class="fs-input-row">
              <input id="fsBscTxHash" type="text" class="fs-input" placeholder="0x... (64 hex characters)" spellcheck="false" autocomplete="off">
              <button type="button" class="fs-btn fs-btn-primary" id="fsVerifyBscBtn">Verify On-Chain &amp; Unlock</button>
            </div>
            <div id="fsVerifyStatus" class="fs-status-msg" aria-live="polite"></div>
          </div>
        </div>

        <!-- SOLANA USDC AUTO VERIFY -->
        <div class="fs-tab-panel" data-pay-panel="solana">
          <div class="fs-notice fs-notice-info">
            <strong>Instant Solana Auto-Verification:</strong> Send exact <strong>USDC (SPL)</strong> on <strong>Solana Mainnet</strong>, then paste your Transaction Signature below to verify via Solana RPC and unlock immediately.
          </div>
          <div class="fs-pay-grid">
            <div class="fs-qr-box" id="fsQrSolana"></div>
            <div class="fs-pay-details">
              <div class="fs-field-label">Network &amp; Token</div>
              <div class="fs-mono-chip">Solana Mainnet · SPL USDC (${OFFICIAL_CHANNELS.solanaUsdcMint.slice(0, 6)}...)</div>
              <div class="fs-field-label">Official Solana Address</div>
              <div class="fs-copy-row">
                <code class="fs-code-val" id="fsSolanaAddr">${OFFICIAL_CHANNELS.solanaUsdc}</code>
                <button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-copy-val="${OFFICIAL_CHANNELS.solanaUsdc}">Copy</button>
              </div>
              <div class="fs-field-label">Amount to Send</div>
              <div class="fs-mono-chip" id="fsSolanaAmount">15.00 USDC</div>
            </div>
          </div>
          <div class="fs-verify-box">
            <label for="fsSolTxSig" class="fs-field-label">Paste Solana Transaction Signature (Base58)</label>
            <div class="fs-input-row">
              <input id="fsSolTxSig" type="text" class="fs-input" placeholder="5x... (Solana tx signature)" spellcheck="false" autocomplete="off">
              <button type="button" class="fs-btn fs-btn-primary" id="fsVerifySolBtn">Verify Solana Tx &amp; Unlock</button>
            </div>
            <div id="fsVerifySolStatus" class="fs-status-msg" aria-live="polite"></div>
          </div>
        </div>

        <!-- TRC20 -->
        <div class="fs-tab-panel" data-pay-panel="trc20">
          <div class="fs-notice">
            Send exact USDT via <strong>TRON (TRC20)</strong> network, then submit your TxHash via email for manual key issuance (usually within minutes).
          </div>
          <div class="fs-pay-grid">
            <div class="fs-qr-box" id="fsQrTrc20"></div>
            <div class="fs-pay-details">
              <div class="fs-field-label">Network</div>
              <div class="fs-mono-chip">TRON (TRC20) · USDT</div>
              <div class="fs-field-label">Official TRC20 Address</div>
              <div class="fs-copy-row">
                <code class="fs-code-val" id="fsTrc20Addr">${OFFICIAL_CHANNELS.usdtTrc20}</code>
                <button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-copy-val="${OFFICIAL_CHANNELS.usdtTrc20}">Copy</button>
              </div>
              <div class="fs-field-label">Amount to Send</div>
              <div class="fs-mono-chip" id="fsTrc20Amount">15.00 USDT</div>
            </div>
          </div>
          <div class="fs-verify-box">
            <label for="fsTrc20TxInput" class="fs-field-label">TRON TxHash &amp; Your Delivery Email (optional)</label>
            <div class="fs-input-row">
              <input id="fsTrc20TxInput" type="text" class="fs-input" placeholder="Paste TRON TxHash">
              <input id="fsTrc20EmailInput" type="email" class="fs-input" placeholder="your@email.com">
            </div>
            <div class="fs-actions-end">
              <a id="fsTrc20Mailto" class="fs-btn fs-btn-primary" href="#">Email Receipt to ${OFFICIAL_CHANNELS.supportEmail}</a>
            </div>
          </div>
        </div>

        <!-- BINANCE PAY -->
        <div class="fs-tab-panel" data-pay-panel="binance">
          <div class="fs-notice">
            Zero-fee internal transfer via <strong>Binance Pay / Internal Transfer</strong>. Send USDT using our Binance UID below, then email your Order ID.
          </div>
          <div class="fs-pay-grid">
            <div class="fs-qr-box" id="fsQrBinance"></div>
            <div class="fs-pay-details">
              <div class="fs-field-label">Binance UID</div>
              <div class="fs-copy-row">
                <code class="fs-code-val">${OFFICIAL_CHANNELS.binanceUid}</code>
                <button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-copy-val="${OFFICIAL_CHANNELS.binanceUid}">Copy UID</button>
              </div>
              <div class="fs-field-label">Account Nickname</div>
              <div class="fs-mono-chip">${OFFICIAL_CHANNELS.binanceNickname}</div>
              <div class="fs-field-label">Amount to Send</div>
              <div class="fs-mono-chip" id="fsBinanceAmount">15.00 USDT</div>
            </div>
          </div>
          <div class="fs-verify-box">
            <label for="fsBinanceOrderInput" class="fs-field-label">Binance Order ID &amp; Delivery Email</label>
            <div class="fs-input-row">
              <input id="fsBinanceOrderInput" type="text" class="fs-input" placeholder="Paste Binance Pay Order ID">
              <input id="fsBinanceEmailInput" type="email" class="fs-input" placeholder="your@email.com">
            </div>
            <div class="fs-actions-end">
              <a id="fsBinanceMailto" class="fs-btn fs-btn-primary" href="#">Email Order ID to ${OFFICIAL_CHANNELS.supportEmail}</a>
            </div>
          </div>
        </div>

        <!-- PAYPAL DIRECT -->
        <div class="fs-tab-panel" data-pay-panel="paypal">
          <div class="fs-notice">
            Pay securely via official <strong>PayPal.com</strong> checkout to <code>${OFFICIAL_CHANNELS.paypalEmail}</code>. After paying, email your PayPal Transaction ID to receive your license key.
          </div>
          <div class="fs-paypal-card">
            <div>
              <div class="fs-field-label">PayPal Merchant Account</div>
              <div class="fs-mono-chip">${OFFICIAL_CHANNELS.paypalEmail}</div>
            </div>
            <a id="fsPaypalCheckoutBtn" class="fs-btn fs-btn-primary fs-btn-lg" href="#" target="_blank" rel="noopener noreferrer">
              Continue to PayPal Checkout
            </a>
          </div>
          <div class="fs-verify-box">
            <label for="fsPaypalTxInput" class="fs-field-label">After Paying: Send PayPal Transaction ID</label>
            <div class="fs-input-row">
              <input id="fsPaypalTxInput" type="text" class="fs-input" placeholder="PayPal Transaction / Receipt ID">
              <input id="fsPaypalEmailInput" type="email" class="fs-input" placeholder="your@email.com">
            </div>
            <div class="fs-actions-end">
              <a id="fsPaypalMailto" class="fs-btn fs-btn-secondary" href="#">Email Receipt to ${OFFICIAL_CHANNELS.supportEmail}</a>
            </div>
          </div>
        </div>

        <!-- LICENSE KEY ACTIVATION -->
        <div class="fs-tab-panel" data-pay-panel="license">
          <div class="fs-notice">
            Already received your <strong>ForgeSuite Pro License Key</strong>? Paste it below to unlock instantly in this browser.
          </div>
          <div class="fs-verify-box">
            <label for="fsManualKeyInput" class="fs-field-label">License Key</label>
            <div class="fs-input-row">
              <input id="fsManualKeyInput" type="text" class="fs-input" placeholder="FS-PRO-CB-XXXXXXXX-XXXX" spellcheck="false" autocomplete="off">
              <button type="button" class="fs-btn fs-btn-primary" id="fsActivateKeyBtn">Activate Key</button>
            </div>
            <div id="fsKeyStatus" class="fs-status-msg" aria-live="polite"></div>
          </div>
        </div>

        <!-- UNLOCKED CONFIRMATION BANNER -->
        <div id="fsUnlockSuccess" class="fs-unlock-banner" hidden>
          <div class="fs-unlock-head">
            <span class="fs-badge fs-badge-success">VERIFIED &amp; ACTIVATED</span>
            <h3 id="fsUnlockTitle">Pro License Unlocked!</h3>
          </div>
          <p id="fsUnlockDesc"></p>
          <div class="fs-copy-row">
            <code class="fs-code-val" id="fsUnlockedKeyDisplay"></code>
            <button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" id="fsCopyUnlockedKey">Copy Key</button>
          </div>
          <div class="fs-unlock-actions">
            <a id="fsLaunchUnlockedBtn" class="fs-btn fs-btn-primary" href="cryptobill.html">Open CryptoBill Forge Pro</a>
            <button type="button" class="fs-btn fs-btn-secondary" id="fsDownloadReceiptBtn">Save License Receipt (.json)</button>
            <a id="fsPostUnlockMailto" class="fs-btn fs-btn-ghost" href="#">Request Desktop/Extension Package</a>
          </div>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  return modal;
}

/**
 * Opens the interactive ForgeSuite checkout modal for a given SKU ('CB'|'AS'|'WL'|'BUNDLE').
 * @param {string} sku
 * @param {{ initialTab?: string, onUnlocked?: (record: object) => void }} [options]
 */
export function openCheckoutModal(sku = "CB", options = {}) {
  if (typeof document === "undefined") return;
  const product = PRODUCTS[String(sku || "CB").toUpperCase()] || PRODUCTS.CB;
  const modal = ensureCheckoutModalElement();

  // Populate product details
  modal.dataset.activeSku = product.sku;
  modal.querySelector("#fsCheckoutSkuBadge").textContent = `${product.sku} · ${product.billing.toUpperCase()}`;
  modal.querySelector("#fsCheckoutTitle").textContent = product.name;
  modal.querySelector("#fsCheckoutSubtitle").textContent = product.tagline;
  modal.querySelector("#fsCheckoutPrice").textContent = `$${product.priceUsd}`;
  modal.querySelector("#fsBep20Amount").textContent = `${product.priceUsd.toFixed(2)} USDT`;
  modal.querySelector("#fsSolanaAmount").textContent = `${product.priceUsd.toFixed(2)} USDC`;
  modal.querySelector("#fsTrc20Amount").textContent = `${product.priceUsd.toFixed(2)} USDT`;
  modal.querySelector("#fsBinanceAmount").textContent = `${product.priceUsd.toFixed(2)} USDT`;

  // Render offline QR codes
  modal.querySelector("#fsQrBep20").innerHTML = renderQrSvg(OFFICIAL_CHANNELS.usdtBep20, {
    size: 136,
    margin: 2,
    label: "USDT BEP20 Address QR",
  });
  modal.querySelector("#fsQrSolana").innerHTML = renderQrSvg(OFFICIAL_CHANNELS.solanaUsdc, {
    size: 136,
    margin: 2,
    label: "Solana USDC Address QR",
  });
  modal.querySelector("#fsQrTrc20").innerHTML = renderQrSvg(OFFICIAL_CHANNELS.usdtTrc20, {
    size: 136,
    margin: 2,
    label: "USDT TRC20 Address QR",
  });
  modal.querySelector("#fsQrBinance").innerHTML = renderQrSvg(
    `BinanceUID:${OFFICIAL_CHANNELS.binanceUid}`,
    { size: 136, margin: 2, label: "Binance Pay UID QR" }
  );

  // PayPal direct link
  const paypalBtn = modal.querySelector("#fsPaypalCheckoutBtn");
  paypalBtn.href = buildPaypalCheckoutUrl({
    itemName: `${product.name} (${product.billing})`,
    amountUsd: product.priceUsd,
    sku: product.sku,
  });
  paypalBtn.textContent = `Pay $${product.priceUsd.toFixed(2)} via Official PayPal`;

  // Reset status banners
  const verifyStatus = modal.querySelector("#fsVerifyStatus");
  const keyStatus = modal.querySelector("#fsKeyStatus");
  const unlockBox = modal.querySelector("#fsUnlockSuccess");
  verifyStatus.textContent = "";
  verifyStatus.className = "fs-status-msg";
  keyStatus.textContent = "";
  keyStatus.className = "fs-status-msg";
  unlockBox.hidden = true;

  // Dynamic mailto updaters
  const syncMailtos = () => {
    modal.querySelector("#fsTrc20Mailto").href = buildMailtoReceiptUrl({
      productName: product.name,
      sku: product.sku,
      amountUsd: product.priceUsd,
      paymentMethod: "USDT (TRC20)",
      referenceId: modal.querySelector("#fsTrc20TxInput").value.trim(),
      customerEmail: modal.querySelector("#fsTrc20EmailInput").value.trim(),
    });
    modal.querySelector("#fsBinanceMailto").href = buildMailtoReceiptUrl({
      productName: product.name,
      sku: product.sku,
      amountUsd: product.priceUsd,
      paymentMethod: `Binance Pay (UID ${OFFICIAL_CHANNELS.binanceUid})`,
      referenceId: modal.querySelector("#fsBinanceOrderInput").value.trim(),
      customerEmail: modal.querySelector("#fsBinanceEmailInput").value.trim(),
    });
    modal.querySelector("#fsPaypalMailto").href = buildMailtoReceiptUrl({
      productName: product.name,
      sku: product.sku,
      amountUsd: product.priceUsd,
      paymentMethod: `PayPal (${OFFICIAL_CHANNELS.paypalEmail})`,
      referenceId: modal.querySelector("#fsPaypalTxInput").value.trim(),
      customerEmail: modal.querySelector("#fsPaypalEmailInput").value.trim(),
    });
  };
  syncMailtos();

  const showUnlocked = (record) => {
    unlockBox.hidden = false;
    modal.querySelector("#fsUnlockTitle").textContent = `${product.name} Activated!`;
    modal.querySelector("#fsUnlockDesc").textContent = product.deliveryHint;
    modal.querySelector("#fsUnlockedKeyDisplay").textContent = record.key;
    modal.querySelector("#fsCopyUnlockedKey").onclick = (e) => copyText(record.key, e.currentTarget);

    const launchBtn = modal.querySelector("#fsLaunchUnlockedBtn");
    if (product.sku === "CB" || product.sku === "BUNDLE") {
      launchBtn.href = "cryptobill.html";
      launchBtn.textContent = "Launch CryptoBill Forge Pro →";
      launchBtn.removeAttribute("target");
    } else {
      launchBtn.href = product.repoUrl;
      launchBtn.textContent = `Open ${product.name} Repo →`;
      launchBtn.setAttribute("target", "_blank");
      launchBtn.setAttribute("rel", "noopener noreferrer");
    }

    modal.querySelector("#fsPostUnlockMailto").href = buildMailtoReceiptUrl({
      productName: product.name,
      sku: product.sku,
      amountUsd: product.priceUsd,
      paymentMethod: record.token || "USDT-BEP20",
      referenceId: `${record.txHash || record.key} | Key: ${record.key}`,
    });

    modal.querySelector("#fsDownloadReceiptBtn").onclick = () => {
      const receiptBlob = new Blob(
        [
          JSON.stringify(
            {
              suite: "ForgeSuite Studio",
              product: product.name,
              sku: product.sku,
              licenseKey: record.key,
              tier: record.tier,
              unlocks: record.unlocks,
              txHash: record.txHash || null,
              token: record.token || null,
              verifiedAt: record.verifiedAt || new Date().toISOString(),
              support: OFFICIAL_CHANNELS.supportEmail,
            },
            null,
            2
          ),
        ],
        { type: "application/json" }
      );
      const url = URL.createObjectURL(receiptBlob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `forgesuite-license-${record.tier.toLowerCase()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    };

    if (typeof options.onUnlocked === "function") {
      options.onUnlocked(record);
    }
    window.dispatchEvent(new CustomEvent("forgesuite:license-updated", { detail: record }));
  };

  // Switch tab helper
  const activateTab = (tabName) => {
    modal.querySelectorAll("[data-pay-tab]").forEach((btn) => {
      btn.classList.toggle("is-active", btn.dataset.payTab === tabName);
    });
    modal.querySelectorAll("[data-pay-panel]").forEach((panel) => {
      panel.classList.toggle("is-active", panel.dataset.payPanel === tabName);
    });
  };
  activateTab(options.initialTab || "bep20");

  // Bind one-time listeners on modal
  if (!modal.dataset.bound) {
    modal.dataset.bound = "1";

    modal.querySelector("#fsCheckoutClose").addEventListener("click", () => {
      modal.hidden = true;
    });
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.hidden = true;
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !modal.hidden) modal.hidden = true;
    });

    modal.querySelectorAll("[data-pay-tab]").forEach((btn) => {
      btn.addEventListener("click", () => activateTab(btn.dataset.payTab));
    });

    modal.querySelectorAll("[data-copy-val]").forEach((btn) => {
      btn.addEventListener("click", () => copyText(btn.dataset.copyVal, btn));
    });

    [
      "#fsTrc20TxInput",
      "#fsTrc20EmailInput",
      "#fsBinanceOrderInput",
      "#fsBinanceEmailInput",
      "#fsPaypalTxInput",
      "#fsPaypalEmailInput",
    ].forEach((sel) => {
      modal.querySelector(sel).addEventListener("input", () => {
        const currentSku = modal.dataset.activeSku || "CB";
        const activeProduct = PRODUCTS[currentSku] || PRODUCTS.CB;
        modal.querySelector("#fsTrc20Mailto").href = buildMailtoReceiptUrl({
          productName: activeProduct.name,
          sku: activeProduct.sku,
          amountUsd: activeProduct.priceUsd,
          paymentMethod: "USDT (TRC20)",
          referenceId: modal.querySelector("#fsTrc20TxInput").value.trim(),
          customerEmail: modal.querySelector("#fsTrc20EmailInput").value.trim(),
        });
        modal.querySelector("#fsBinanceMailto").href = buildMailtoReceiptUrl({
          productName: activeProduct.name,
          sku: activeProduct.sku,
          amountUsd: activeProduct.priceUsd,
          paymentMethod: `Binance Pay (UID ${OFFICIAL_CHANNELS.binanceUid})`,
          referenceId: modal.querySelector("#fsBinanceOrderInput").value.trim(),
          customerEmail: modal.querySelector("#fsBinanceEmailInput").value.trim(),
        });
        modal.querySelector("#fsPaypalMailto").href = buildMailtoReceiptUrl({
          productName: activeProduct.name,
          sku: activeProduct.sku,
          amountUsd: activeProduct.priceUsd,
          paymentMethod: `PayPal (${OFFICIAL_CHANNELS.paypalEmail})`,
          referenceId: modal.querySelector("#fsPaypalTxInput").value.trim(),
          customerEmail: modal.querySelector("#fsPaypalEmailInput").value.trim(),
        });
      });
    });

    modal.querySelector("#fsVerifyBscBtn").addEventListener("click", async () => {
      const currentSku = modal.dataset.activeSku || "CB";
      const activeProduct = PRODUCTS[currentSku] || PRODUCTS.CB;
      const txHash = modal.querySelector("#fsBscTxHash").value.trim();
      const statusEl = modal.querySelector("#fsVerifyStatus");
      const btn = modal.querySelector("#fsVerifyBscBtn");

      btn.disabled = true;
      btn.textContent = "Verifying on BSC...";
      statusEl.className = "fs-status-msg is-loading";
      statusEl.textContent = "Querying public BSC RPC nodes for Transfer receipt...";

      const result = await verifyBscUsdtTxOnChain(txHash, activeProduct.priceUsd, {
        tier: activeProduct.sku,
      });

      btn.disabled = false;
      btn.textContent = "Verify On-Chain & Unlock";

      if (result.verified) {
        statusEl.className = "fs-status-msg is-success";
        statusEl.textContent = `Confirmed ${result.amountUsd.toFixed(2)} USDT-BEP20! License issued.`;
        const saved = saveVerifiedLicense({
          key: result.licenseKey,
          txHash: result.txHash,
          token: result.token,
          amountUsd: result.amountUsd,
        });
        if (modal._onShowUnlocked) modal._onShowUnlocked(saved);
      } else {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = result.reason;
      }
    });

    modal.querySelector("#fsVerifySolBtn").addEventListener("click", async () => {
      const currentSku = modal.dataset.activeSku || "CB";
      const activeProduct = PRODUCTS[currentSku] || PRODUCTS.CB;
      const sig = modal.querySelector("#fsSolTxSig").value.trim();
      const statusEl = modal.querySelector("#fsVerifySolStatus");
      const btn = modal.querySelector("#fsVerifySolBtn");

      btn.disabled = true;
      btn.textContent = "Verifying on Solana...";
      statusEl.className = "fs-status-msg is-loading";
      statusEl.textContent = "Querying Solana RPC for SPL USDC transfer...";

      const result = await verifySolanaUsdcTxOnChain(sig, activeProduct.priceUsd, {
        tier: activeProduct.sku,
      });

      btn.disabled = false;
      btn.textContent = "Verify Solana Tx & Unlock";

      if (result.verified) {
        statusEl.className = "fs-status-msg is-success";
        statusEl.textContent = `Confirmed ${result.amountUsd.toFixed(2)} USDC-SOLANA! License issued.`;
        const saved = saveVerifiedLicense({
          key: result.licenseKey,
          txHash: result.txHash,
          token: result.token,
          amountUsd: result.amountUsd,
        });
        if (modal._onShowUnlocked) modal._onShowUnlocked(saved);
      } else {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = result.reason;
      }
    });

    modal.querySelector("#fsActivateKeyBtn").addEventListener("click", () => {
      const inputVal = modal.querySelector("#fsManualKeyInput").value;
      const statusEl = modal.querySelector("#fsKeyStatus");
      const res = activateLicenseKey(inputVal);
      if (res.ok) {
        statusEl.className = "fs-status-msg is-success";
        statusEl.textContent = `Activated ${res.tier} Pro license!`;
        if (modal._onShowUnlocked) modal._onShowUnlocked(res.saved);
      } else {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = res.reason;
      }
    });
  }

  modal._onShowUnlocked = showUnlocked;

  // If user already holds an active license for this SKU, show it conveniently
  const existing = getActiveLicenseForTier(product.sku);
  if (existing && options.initialTab === "license") {
    showUnlocked(existing);
  }

  modal.hidden = false;
}

/**
 * Binds click listeners to any elements carrying [data-checkout-sku].
 * @param {{ onUnlocked?: (record: object) => void }} [options]
 */
export function bindCheckoutTriggers(options = {}) {
  if (typeof document === "undefined") return;
  document.querySelectorAll("[data-checkout-sku]").forEach((el) => {
    if (el.dataset.checkoutBound) return;
    el.dataset.checkoutBound = "1";
    el.addEventListener("click", (e) => {
      e.preventDefault();
      const sku = el.dataset.checkoutSku || "CB";
      const tab = el.dataset.checkoutTab || "bep20";
      openCheckoutModal(sku, { initialTab: tab, onUnlocked: options.onUnlocked });
    });
  });
}
