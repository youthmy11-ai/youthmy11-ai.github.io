import {
  bindCheckoutTriggers,
  getStoredLicenses,
  hasUnlockedTier,
  openCheckoutModal,
} from "./checkout.js";
import { createDefaultInvoice, encodeInvoicePayload } from "./cryptobill.js";

/**
 * TokenGuard — Browser & Node 22+ EVM + Solana Token/Contract Risk Scanner Engine
 * Pure ES Module (zero npm dependencies, zero Buffer reliance, CORS-safe PublicNode primaries).
 */

export const EVM_CHAIN_CONFIG = Object.freeze({
  ethereum: {
    chain: "ethereum",
    caip2: "eip155:1",
    chainId: 1,
    name: "Ethereum Mainnet",
    explorerBase: "https://etherscan.io/address/",
    rpcs: Object.freeze([
      "https://ethereum-rpc.publicnode.com",
      "https://1rpc.io/eth",
      "https://eth.llamarpc.com",
    ]),
  },
  base: {
    chain: "base",
    caip2: "eip155:8453",
    chainId: 8453,
    name: "Base Mainnet",
    explorerBase: "https://basescan.org/address/",
    rpcs: Object.freeze([
      "https://base-rpc.publicnode.com",
      "https://mainnet.base.org",
      "https://base.llamarpc.com",
    ]),
  },
  bsc: {
    chain: "bsc",
    caip2: "eip155:56",
    chainId: 56,
    name: "BNB Smart Chain",
    explorerBase: "https://bscscan.com/address/",
    rpcs: Object.freeze([
      "https://bsc-rpc.publicnode.com",
      "https://bsc-dataseed.binance.org",
      "https://bsc-dataseed1.defibit.io",
    ]),
  },
  arbitrum: {
    chain: "arbitrum",
    caip2: "eip155:42161",
    chainId: 42161,
    name: "Arbitrum One",
    explorerBase: "https://arbiscan.io/address/",
    rpcs: Object.freeze([
      "https://arbitrum-one-rpc.publicnode.com",
      "https://arb1.arbitrum.io/rpc",
      "https://1rpc.io/arb",
    ]),
  },
});

export const SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
export const SOLANA_EXPLORER_BASE = "https://solscan.io/token/";

export const SOLANA_RPC_ENDPOINTS = Object.freeze([
  "https://solana-rpc.publicnode.com",
  "https://api.zan.top/solana-mainnet",
]);

export const SOLANA_INDEXED_RPC_ENDPOINTS = Object.freeze([
  "https://api.tatum.io/v3/blockchain/node/solana-mainnet",
  "https://solana.leorpc.com/?api_key=FREE",
]);

export const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

export const MAX_BATCH_WATCHLIST = 25;

// Standard EVM proxy storage slots
export const SLOT_EIP1967_IMPL =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
export const SLOT_EIP1967_ADMIN =
  "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
export const SLOT_EIP1967_BEACON =
  "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
export const SLOT_ZEPPELINOS_IMPL =
  "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3";
export const SLOT_ZEPPELINOS_ADMIN =
  "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b";

export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const BASE58_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: false });

export const RISK_SELECTORS = Object.freeze({
  mint: Object.freeze([
    { selector: "0x40c10f19", sig: "mint(address,uint256)" },
    { selector: "0xa0712d68", sig: "mint(uint256)" },
    { selector: "0x6a627842", sig: "mint(address)" },
    { selector: "0xcc872b66", sig: "issue(uint256)" },
  ]),
  blacklist: Object.freeze([
    { selector: "0xf9f92be4", sig: "blacklist(address)" },
    { selector: "0x4579268a", sig: "blacklistAddress(address)" },
    { selector: "0x16c02129", sig: "setBlacklist(address,bool)" },
    { selector: "0x0ecb93c0", sig: "addBlackList(address)" },
    { selector: "0xe724529c", sig: "freezeAccount(address,bool)" },
    { selector: "0xfe575a87", sig: "isBlacklisted(address)" },
  ]),
  pause: Object.freeze([
    { selector: "0x8456cb59", sig: "pause()" },
    { selector: "0x3f4ba83a", sig: "unpause()" },
    { selector: "0x5c975abb", sig: "paused()" },
  ]),
  taxAndLimits: Object.freeze([
    { selector: "0x061c82d0", sig: "setTaxFeePercent(uint256)" },
    { selector: "0x8ee88c53", sig: "setLiquidityFeePercent(uint256)" },
    { selector: "0x8cd4426d", sig: "setBuyTax(uint256)" },
    { selector: "0xcc1776d3", sig: "setSellTax(uint256)" },
    { selector: "0x0b78f9c0", sig: "setFees(uint256,uint256)" },
    { selector: "0x69fe0e2d", sig: "setFee(uint256)" },
    { selector: "0xd543dbeb", sig: "setMaxTxPercent(uint256)" },
    { selector: "0x74010ece", sig: "setMaxWalletSize(uint256)" },
    { selector: "0x8a8c523c", sig: "enableTrading()" },
    { selector: "0x437823ec", sig: "excludeFromFee(address)" },
  ]),
  upgrade: Object.freeze([
    { selector: "0x3659cfe6", sig: "upgradeTo(address)" },
    { selector: "0x4f1ef286", sig: "upgradeToAndCall(address,bytes)" },
    { selector: "0x52d1902d", sig: "proxiableUUID()" },
  ]),
});

export const TOKENGUARD_SAMPLES = Object.freeze({
  base_usdc: {
    chain: "base",
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    label: "Base USDC (FiatToken Proxy)",
  },
  sol_pyusd: {
    chain: "solana",
    address: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
    label: "Solana PYUSD (Token-2022)",
  },
  eth_usdt: {
    chain: "ethereum",
    address: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    label: "Ethereum USDT",
  },
  sol_bonk: {
    chain: "solana",
    address: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
    label: "Solana BONK (Revoked SPL)",
  },
});

export const DEFAULT_WATCHLIST_SAMPLE = [
  "base:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "solana:2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
  "bsc:0x55d398326f99059fF775485246999027B3197955",
  "solana:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
].join("\n");

/* ============================================================================
 * Pure Binary, ABI & Formatting Helpers (Browser + Node 22+ Safe)
 * ========================================================================== */

export function hexToBytes(rawHex) {
  const clean = String(rawHex || "")
    .trim()
    .toLowerCase()
    .replace(/^0x/, "");
  if (!clean || clean.length % 2 !== 0 || !/^[0-9a-f]+$/.test(clean)) {
    return new Uint8Array(0);
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

export function classifyRiskLevel(score) {
  const n = Number(score) || 0;
  if (n >= 70) return "CRITICAL";
  if (n >= 45) return "HIGH";
  if (n >= 20) return "MODERATE";
  return "LOW";
}

export function parseAddressFromSlot(slotHex) {
  if (!slotHex || typeof slotHex !== "string") return null;
  const clean = slotHex.toLowerCase().replace(/^0x/, "").padStart(64, "0");
  if (clean.length < 64 || !/^[0-9a-f]+$/.test(clean)) return null;
  const addrHex = clean.slice(-40);
  if (/^0+$/.test(addrHex)) return null;
  return `0x${addrHex}`;
}

export function decodeAbiStringOrBytes32(hexResult) {
  if (!hexResult || typeof hexResult !== "string" || hexResult === "0x") return null;
  const clean = hexResult.replace(/^0x/, "");
  if (clean.length < 64 || !/^[0-9a-fA-F]+$/.test(clean)) return null;
  try {
    if (clean.length >= 128) {
      const offsetBytes = Number(BigInt(`0x${clean.slice(0, 64)}`));
      if (offsetBytes === 32) {
        const strLen = Number(BigInt(`0x${clean.slice(64, 128)}`));
        if (strLen >= 0 && strLen <= 256 && clean.length >= 128 + strLen * 2) {
          const strBytes = hexToBytes(clean.slice(128, 128 + strLen * 2));
          return UTF8_DECODER.decode(strBytes).replace(/\0/g, "").trim() || null;
        }
      }
    }
    const raw32 = hexToBytes(clean.slice(0, 64));
    return UTF8_DECODER.decode(raw32).replace(/\0+$/g, "").trim() || null;
  } catch {
    return null;
  }
}

export function decodeAbiUint(hexResult) {
  if (!hexResult || typeof hexResult !== "string" || hexResult === "0x") return null;
  const clean = hexResult.replace(/^0x/, "");
  if (!clean || !/^[0-9a-fA-F]+$/.test(clean)) return null;
  try {
    return BigInt(`0x${clean.slice(0, 64)}`);
  } catch {
    return null;
  }
}

export function formatTokenUnits(rawBigInt, decimals = 18) {
  if (rawBigInt === null || rawBigInt === undefined) return null;
  const bigVal = typeof rawBigInt === "bigint" ? rawBigInt : BigInt(String(rawBigInt));
  const d = Math.max(0, Math.min(36, Number(decimals ?? 18)));
  if (d === 0) return bigVal.toString();
  const base = 10n ** BigInt(d);
  const whole = bigVal / base;
  const frac = (bigVal % base)
    .toString()
    .padStart(d, "0")
    .slice(0, 6)
    .replace(/0+$/, "");
  return frac ? `${whole.toString()}.${frac}` : whole.toString();
}

function matchSelectorCategories(selectorSet) {
  const matchList = (entries) =>
    entries.filter((entry) => selectorSet.has(entry.selector)).map((entry) => entry.sig);
  return {
    mint: matchList(RISK_SELECTORS.mint),
    blacklist: matchList(RISK_SELECTORS.blacklist),
    pause: matchList(RISK_SELECTORS.pause),
    taxAndLimits: matchList(RISK_SELECTORS.taxAndLimits),
    upgrade: matchList(RISK_SELECTORS.upgrade),
  };
}

function sanitizeCustomRpcUrl(rawUrl) {
  const trimmed = String(rawUrl || "").trim();
  if (!trimmed) return null;
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid custom RPC URL "${trimmed}".`);
  }
  const isLocal =
    parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLocal)) {
    throw new Error("Custom RPC URL must use https:// (or http://localhost for local testing).");
  }
  return parsed.toString();
}

/* ============================================================================
 * 1. Deterministic Pure EVM Bytecode Disassembler & Risk Scorer
 * ========================================================================== */

/**
 * PUSH-aware EVM bytecode disassembler.
 * Skips immediate PUSH1..PUSH32 data bytes and strips trailing Solidity CBOR metadata
 * so embedded constants are never misclassified as SELFDESTRUCT / DELEGATECALL opcodes.
 */
export function analyzeEvmBytecodeHex(rawBytecode) {
  const clean = String(rawBytecode || "")
    .trim()
    .toLowerCase()
    .replace(/^0x/, "");

  if (!clean || clean === "0" || clean.length % 2 !== 0 || !/^[0-9a-f]+$/.test(clean)) {
    const emptySet = new Set();
    return {
      isContract: false,
      byteLength: 0,
      hasSelfDestruct: false,
      hasDelegateCall: false,
      hasCallCode: false,
      hasCreate2: false,
      hasTxOrigin: false,
      push4Selectors: emptySet,
      selectors: [],
      matchedSelectors: matchSelectorCategories(emptySet),
      eip1167Implementation: null,
    };
  }

  let eip1167Implementation = null;
  const eip1167Match = clean.match(
    /^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$/
  );
  if (eip1167Match) {
    eip1167Implementation = `0x${eip1167Match[1]}`;
  }

  // Strip trailing Solidity CBOR metadata so IPFS/Swarm hash bytes aren't walked as opcodes
  let codeHex = clean;
  if (codeHex.length >= 12) {
    const metaLenBytes = Number.parseInt(codeHex.slice(-4), 16);
    const metaHexChars = metaLenBytes * 2 + 4;
    if (
      metaLenBytes >= 20 &&
      metaLenBytes <= 120 &&
      metaHexChars < codeHex.length &&
      (codeHex.slice(-metaHexChars).startsWith("a26469706673") ||
        codeHex.slice(-metaHexChars).startsWith("a265627a7a72") ||
        codeHex.slice(-metaHexChars).startsWith("a165627a7a72"))
    ) {
      codeHex = codeHex.slice(0, -metaHexChars);
    }
  }

  const bytes = hexToBytes(codeHex);
  let hasSelfDestruct = false;
  let hasDelegateCall = false;
  let hasCallCode = false;
  let hasCreate2 = false;
  let hasTxOrigin = false;
  const push4Selectors = new Set();

  for (let pc = 0; pc < bytes.length; pc += 1) {
    const op = bytes[pc];
    if (op >= 0x60 && op <= 0x7f) {
      const pushLen = op - 0x5f;
      if (op === 0x63 && pc + 4 < bytes.length) {
        const sel = bytesToHex(bytes.subarray(pc + 1, pc + 5));
        push4Selectors.add(`0x${sel}`);
      }
      pc += pushLen;
      continue;
    }
    if (op === 0xff) hasSelfDestruct = true;
    else if (op === 0xf4) hasDelegateCall = true;
    else if (op === 0xf2) hasCallCode = true;
    else if (op === 0xf5) hasCreate2 = true;
    else if (op === 0x32) hasTxOrigin = true;
  }

  return {
    isContract: true,
    byteLength: clean.length / 2,
    hasSelfDestruct,
    hasDelegateCall,
    hasCallCode,
    hasCreate2,
    hasTxOrigin,
    push4Selectors,
    selectors: Array.from(push4Selectors).sort(),
    matchedSelectors: matchSelectorCategories(push4Selectors),
    eip1167Implementation,
  };
}

/**
 * Deterministic pure EVM token/contract risk scorer.
 * Accepts raw hex bytecode or pre-disassembled `analyzeEvmBytecodeHex` results,
 * optional proxy slot findings, and optional ERC-20 metadata (`owner`, `paused`).
 */
export function scoreEvmTokenRisk(input = {}) {
  const outerWalk =
    input.outerWalk && input.outerWalk.push4Selectors instanceof Set
      ? input.outerWalk
      : input.push4Selectors instanceof Set
        ? input
        : input.bytecode !== undefined || input.rawBytecode !== undefined
          ? analyzeEvmBytecodeHex(input.bytecode ?? input.rawBytecode)
          : null;

  const explicitIsContract =
    typeof input.isContract === "boolean"
      ? input.isContract
      : outerWalk
        ? outerWalk.byteLength > 0
        : true;

  if (!explicitIsContract) {
    return {
      isContract: false,
      riskScore: 85,
      riskLevel: "CRITICAL",
      flags: [
        {
          code: "NO_CONTRACT_BYTECODE",
          severity: "CRITICAL",
          points: 85,
          evidence: "Target address has empty bytecode (EOA or self-destructed contract).",
        },
      ],
      proxyAnalysis: null,
      bytecodeAnalysis: null,
      recommendations: [
        "Do not send funds or approve tokens to an address with no deployed contract code.",
      ],
    };
  }

  const implWalk =
    input.implWalk && input.implWalk.push4Selectors instanceof Set
      ? input.implWalk
      : input.implementationBytecode
        ? analyzeEvmBytecodeHex(input.implementationBytecode)
        : null;

  const combinedSelectors = new Set(outerWalk?.push4Selectors || []);
  if (Array.isArray(input.selectors)) {
    for (const s of input.selectors) combinedSelectors.add(String(s).toLowerCase());
  }
  if (implWalk) {
    for (const s of implWalk.push4Selectors) combinedSelectors.add(s);
  }

  const hasSelfDestruct = Boolean(
    input.hasSelfDestruct || outerWalk?.hasSelfDestruct || implWalk?.hasSelfDestruct
  );
  const hasDelegateCall = Boolean(
    input.hasDelegateCall || outerWalk?.hasDelegateCall || implWalk?.hasDelegateCall
  );
  const hasCallCode = Boolean(
    input.hasCallCode || outerWalk?.hasCallCode || implWalk?.hasCallCode
  );
  const hasCreate2 = Boolean(
    input.hasCreate2 || outerWalk?.hasCreate2 || implWalk?.hasCreate2
  );
  const hasTxOrigin = Boolean(
    input.hasTxOrigin || outerWalk?.hasTxOrigin || implWalk?.hasTxOrigin
  );

  const eip1167Impl = outerWalk?.eip1167Implementation || null;
  const implementationAddress =
    input.implementationAddress || input.proxyAnalysis?.implementationAddress || eip1167Impl || null;
  const adminAddress = input.adminAddress || input.proxyAnalysis?.adminAddress || null;
  const beaconAddress = input.beaconAddress || input.proxyAnalysis?.beaconAddress || null;
  const proxyType =
    input.proxyType ||
    input.proxyAnalysis?.proxyType ||
    (eip1167Impl ? "EIP-1167 Minimal Clone Proxy" : null);

  const matched = matchSelectorCategories(combinedSelectors);
  const meta = input.tokenMetadata || {};
  const rawOwner = input.owner !== undefined ? input.owner : meta.owner ?? null;
  const ownerNormalized =
    typeof rawOwner === "string" && rawOwner.trim()
      ? rawOwner.trim().toLowerCase()
      : null;
  const hasActiveOwner = Boolean(
    ownerNormalized &&
      ownerNormalized !== ZERO_ADDRESS &&
      !/^0x0+$/.test(ownerNormalized)
  );
  const isPaused = Boolean(input.paused !== undefined ? input.paused : meta.paused);

  const flags = [];
  let score = 0;
  const addFlag = (code, severity, points, evidence) => {
    score += points;
    flags.push({ code, severity, points, evidence });
  };

  if (hasSelfDestruct) {
    addFlag(
      "OPCODE_SELFDESTRUCT",
      "CRITICAL",
      35,
      "Executable SELFDESTRUCT (0xff) opcode present in contract or implementation bytecode."
    );
  }
  if (hasCallCode) {
    addFlag(
      "OPCODE_CALLCODE",
      "HIGH",
      15,
      "Legacy CALLCODE (0xf2) opcode detected in executable bytecode."
    );
  }
  if (proxyType) {
    addFlag(
      "UPGRADEABLE_PROXY",
      "MEDIUM",
      15,
      `Contract is an upgradeable proxy (${proxyType})${implementationAddress ? ` pointing to ${implementationAddress}` : ""}.`
    );
  } else if (hasDelegateCall) {
    addFlag(
      "UNRECOGNIZED_DELEGATECALL",
      "HIGH",
      20,
      "Executable DELEGATECALL (0xf4) present without standard EIP-1967/ZeppelinOS/EIP-1167 proxy slots."
    );
  }
  if (matched.mint.length > 0) {
    addFlag(
      "MINT_CAPABILITY_DETECTED",
      "MEDIUM",
      15,
      `Supply-expansion selectors detected: ${matched.mint.join(", ")}.`
    );
  }
  if (matched.blacklist.length > 0) {
    addFlag(
      "BLACKLIST_OR_FREEZE_CAPABILITY",
      "MEDIUM",
      12,
      `Address-blocking selectors detected: ${matched.blacklist.join(", ")}.`
    );
  }
  if (matched.taxAndLimits.length > 0) {
    addFlag(
      "MUTABLE_TAX_OR_TX_LIMITS",
      "HIGH",
      25,
      `Fee/honeypot/limit selectors detected: ${matched.taxAndLimits.join(", ")}.`
    );
  }
  if (matched.pause.length > 0 || isPaused) {
    const pauseSigs = matched.pause.length > 0 ? matched.pause.join(", ") : "paused()";
    addFlag(
      "PAUSABLE_TRANSFERS",
      isPaused ? "CRITICAL" : "LOW",
      isPaused ? 35 : 8,
      isPaused
        ? `Token transfers are CURRENTLY PAUSED (${pauseSigs}).`
        : `Pausable selectors present (${pauseSigs}).`
    );
  }
  if (hasActiveOwner) {
    addFlag(
      "ACTIVE_OWNER_PRIVILEGE",
      "LOW",
      10,
      `Contract has non-zero owner ${ownerNormalized} (ownership not renounced).`
    );
  }
  if (hasTxOrigin) {
    addFlag(
      "OPCODE_TX_ORIGIN",
      "MEDIUM",
      10,
      "Executable ORIGIN (0x32) opcode detected; verify tx.origin is not used for auth/honeypot gating."
    );
  }

  const riskScore = Math.min(100, score);
  const riskLevel = classifyRiskLevel(riskScore);

  const recommendations = [];
  if (proxyType && adminAddress) {
    recommendations.push(
      `Verify whether proxy admin ${adminAddress} is governed by a multisig + timelock before holding large positions.`
    );
  }
  if (matched.taxAndLimits.length > 0) {
    recommendations.push(
      "Simulate both buy and sell swaps before trading; mutable tax/maxTx selectors are common in honeypot tokens."
    );
  }
  if (matched.blacklist.length > 0 || matched.pause.length > 0) {
    recommendations.push(
      "Centralized freeze/pause controls exist (standard for regulated stablecoins like USDC/USDT, high risk for meme tokens)."
    );
  }
  if (hasSelfDestruct) {
    recommendations.push(
      "CRITICAL: Inspect verified Solidity source immediately for reachable selfdestruct paths."
    );
  }
  if (recommendations.length === 0) {
    recommendations.push(
      "No high-risk proxy, mutable tax, blacklist, or self-destruct vectors detected in bytecode."
    );
  }

  return {
    isContract: true,
    riskScore,
    riskLevel,
    flags,
    proxyAnalysis: {
      isProxy: Boolean(proxyType),
      proxyType,
      implementationAddress,
      adminAddress,
      beaconAddress,
      implementationBytecodeBytes: implWalk ? implWalk.byteLength : null,
    },
    bytecodeAnalysis: {
      contractBytecodeBytes: outerWalk ? outerWalk.byteLength : 0,
      totalUniqueSelectors: combinedSelectors.size,
      opcodes: {
        selfDestruct: hasSelfDestruct,
        delegateCall: hasDelegateCall,
        callCode: hasCallCode,
        create2: hasCreate2,
        txOrigin: hasTxOrigin,
      },
      matchedSelectors: matched,
    },
    recommendations,
  };
}

/* ============================================================================
 * 2. Deterministic Pure Solana SPL & Token-2022 Mint Risk Scorer
 * ========================================================================== */

function normalizeSolanaExtensions(rawExtInput) {
  if (Array.isArray(rawExtInput)) {
    const extensionNames = rawExtInput.map((e) => e?.extension).filter(Boolean);
    let transferFeeBps = 0;
    let transferFeeAuthority = null;
    let permanentDelegate = null;
    let mintCloseAuthority = null;
    let transferHookProgramId = null;
    let defaultAccountState = null;
    let isNonTransferable = false;
    let embeddedMetadata = null;

    for (const ext of rawExtInput) {
      const name = ext?.extension;
      const state = ext?.state || {};
      if (name === "transferFeeConfig") {
        const newerBps = Number(state.newerTransferFee?.transferFeeBasisPoints ?? 0);
        const olderBps = Number(state.olderTransferFee?.transferFeeBasisPoints ?? 0);
        transferFeeBps = Math.max(newerBps, olderBps);
        transferFeeAuthority = state.transferFeeConfigAuthority || null;
      } else if (name === "permanentDelegate") {
        permanentDelegate = state.delegate || null;
      } else if (name === "mintCloseAuthority") {
        mintCloseAuthority = state.closeAuthority || null;
      } else if (name === "transferHook") {
        transferHookProgramId = state.programId || null;
      } else if (name === "defaultAccountState") {
        defaultAccountState = state.state || null;
      } else if (name === "nonTransferable") {
        isNonTransferable = true;
      } else if (name === "tokenMetadata") {
        embeddedMetadata = {
          name: state.name || null,
          symbol: state.symbol || null,
          uri: state.uri || null,
          updateAuthority: state.updateAuthority || null,
        };
      }
    }

    return {
      extensions: {
        count: extensionNames.length,
        names: extensionNames,
        transferFeeBps,
        transferFeeAuthority,
        permanentDelegate,
        mintCloseAuthority,
        transferHookProgramId,
        defaultAccountState,
        isNonTransferable,
      },
      embeddedMetadata,
    };
  }

  const obj = rawExtInput && typeof rawExtInput === "object" ? rawExtInput : {};
  const names = Array.isArray(obj.names) ? [...obj.names] : [];
  const transferFeeBps = Number(obj.transferFeeBps ?? 0) || 0;
  const transferFeeAuthority = obj.transferFeeAuthority || null;
  const permanentDelegate = obj.permanentDelegate || null;
  const mintCloseAuthority = obj.mintCloseAuthority || null;
  const transferHookProgramId = obj.transferHookProgramId || obj.transferHook || null;
  const defaultAccountState = obj.defaultAccountState || null;
  const isNonTransferable = Boolean(obj.isNonTransferable || obj.nonTransferable);

  if (permanentDelegate && !names.includes("permanentDelegate")) names.push("permanentDelegate");
  if ((transferFeeBps > 0 || transferFeeAuthority) && !names.includes("transferFeeConfig")) {
    names.push("transferFeeConfig");
  }
  if (mintCloseAuthority && !names.includes("mintCloseAuthority")) names.push("mintCloseAuthority");
  if (transferHookProgramId && !names.includes("transferHook")) names.push("transferHook");
  if (defaultAccountState && !names.includes("defaultAccountState")) names.push("defaultAccountState");
  if (isNonTransferable && !names.includes("nonTransferable")) names.push("nonTransferable");

  return {
    extensions: {
      count: names.length,
      names,
      transferFeeBps,
      transferFeeAuthority,
      permanentDelegate,
      mintCloseAuthority,
      transferHookProgramId,
      defaultAccountState,
      isNonTransferable,
    },
    embeddedMetadata: obj.embeddedMetadata || null,
  };
}

function computeHolderConcentrationFromList(largestAccounts, supplyBig, decimals, rpcUsed = null) {
  const list = Array.isArray(largestAccounts) ? largestAccounts : [];
  const top10 = list.slice(0, 10).map((item, idx) => {
    const amtBig = BigInt(String(item.amount ?? item.amountAtomic ?? "0"));
    const pct = supplyBig > 0n ? Number((amtBig * 10000n) / supplyBig) / 100 : 0;
    return {
      rank: idx + 1,
      tokenAccount: item.address || item.tokenAccount || `account_${idx + 1}`,
      amountAtomic: amtBig.toString(),
      uiAmountString: item.uiAmountString ?? formatTokenUnits(amtBig, decimals),
      pctOfSupply: pct,
    };
  });

  const top1Pct = top10[0]?.pctOfSupply ?? 0;
  const top10SumBig = list
    .slice(0, 10)
    .reduce((acc, item) => acc + BigInt(String(item.amount ?? item.amountAtomic ?? "0")), 0n);
  const top10Pct = supplyBig > 0n ? Number((top10SumBig * 10000n) / supplyBig) / 100 : 0;

  return {
    available: true,
    rpcUsed,
    top1HolderPct: top1Pct,
    top10HoldersPct: top10Pct,
    topHolders: top10,
  };
}

/**
 * Deterministic pure Solana SPL / Token-2022 mint authority, extension & holder concentration risk scorer.
 */
export function scoreSolanaMintRisk(input = {}) {
  const infoSrc = input.mintInfo || input.info || input;
  const decimals = Number(infoSrc.decimals ?? 0);
  const supplyAtomicStr = String(infoSrc.supplyAtomic ?? infoSrc.supply ?? "0");
  const supplyBig = BigInt(supplyAtomicStr);
  const mintAuthority = infoSrc.mintAuthority ?? null;
  const freezeAuthority = infoSrc.freezeAuthority ?? null;
  const isInitialized = infoSrc.isInitialized !== undefined ? Boolean(infoSrc.isInitialized) : true;

  const { extensions, embeddedMetadata } = normalizeSolanaExtensions(
    input.extensions ?? infoSrc.extensions
  );

  let holderConcentration;
  if (Array.isArray(input.largestAccounts)) {
    holderConcentration = computeHolderConcentrationFromList(
      input.largestAccounts,
      supplyBig,
      decimals,
      input.indexedRpcUsed || null
    );
  } else if (input.holderConcentration && typeof input.holderConcentration === "object") {
    const hc = input.holderConcentration;
    holderConcentration = {
      available: hc.available !== undefined ? Boolean(hc.available) : hc.top10HoldersPct !== null && hc.top10HoldersPct !== undefined,
      reason: hc.reason || null,
      rpcUsed: hc.rpcUsed || null,
      top1HolderPct: hc.top1HolderPct !== undefined && hc.top1HolderPct !== null ? Number(hc.top1HolderPct) : null,
      top10HoldersPct: hc.top10HoldersPct !== undefined && hc.top10HoldersPct !== null ? Number(hc.top10HoldersPct) : null,
      topHolders: Array.isArray(hc.topHolders) ? hc.topHolders : [],
    };
  } else {
    holderConcentration = {
      available: false,
      reason: "Holder concentration snapshot not provided.",
      top1HolderPct: null,
      top10HoldersPct: null,
      topHolders: [],
    };
  }

  const flags = [];
  let score = 0;
  const addFlag = (code, severity, points, evidence) => {
    score += points;
    flags.push({ code, severity, points, evidence });
  };

  if (mintAuthority) {
    addFlag(
      "ACTIVE_MINT_AUTHORITY",
      "HIGH",
      30,
      `Mint authority is NOT revoked (${mintAuthority}); issuer can mint unlimited supply.`
    );
  }
  if (freezeAuthority) {
    addFlag(
      "ACTIVE_FREEZE_AUTHORITY",
      "HIGH",
      25,
      `Freeze authority is NOT revoked (${freezeAuthority}); issuer can freeze holder token accounts.`
    );
  }
  if (extensions.permanentDelegate) {
    addFlag(
      "TOKEN2022_PERMANENT_DELEGATE",
      "CRITICAL",
      35,
      `Token-2022 permanentDelegate (${extensions.permanentDelegate}) can transfer or burn tokens from ANY wallet without owner approval.`
    );
  }
  if (extensions.transferFeeBps > 0 || extensions.transferFeeAuthority) {
    const highFee = extensions.transferFeeBps >= 500;
    addFlag(
      "TOKEN2022_TRANSFER_FEE",
      highFee ? "HIGH" : "MEDIUM",
      highFee ? 25 : 10,
      `Token-2022 transferFeeConfig active: ${extensions.transferFeeBps} bps (${(extensions.transferFeeBps / 100).toFixed(2)}%)${extensions.transferFeeAuthority ? `, mutable authority ${extensions.transferFeeAuthority}` : ""}.`
    );
  }
  if (extensions.transferHookProgramId) {
    addFlag(
      "TOKEN2022_TRANSFER_HOOK",
      "MEDIUM",
      15,
      `Token-2022 custom transferHook (${extensions.transferHookProgramId}) executes on every transfer and can enforce custom revert rules.`
    );
  }
  if (extensions.mintCloseAuthority) {
    addFlag(
      "TOKEN2022_MINT_CLOSE_AUTHORITY",
      "LOW",
      8,
      `Token-2022 mintCloseAuthority (${extensions.mintCloseAuthority}) is set.`
    );
  }
  if (extensions.defaultAccountState === "frozen") {
    addFlag(
      "DEFAULT_ACCOUNT_FROZEN",
      "CRITICAL",
      30,
      "New token accounts default to FROZEN state and cannot transfer without authority thaw."
    );
  }
  if (extensions.isNonTransferable) {
    addFlag(
      "NON_TRANSFERABLE_SOULBOUND",
      "CRITICAL",
      40,
      "Token-2022 nonTransferable extension enabled; tokens cannot be sold or transferred."
    );
  }

  if (holderConcentration.available) {
    const top1 = Number(holderConcentration.top1HolderPct ?? 0);
    const top10 = Number(holderConcentration.top10HoldersPct ?? 0);
    if (top1 >= 30) {
      addFlag(
        "EXTREME_TOP1_CONCENTRATION",
        "HIGH",
        20,
        `Top-1 token account holds ${top1.toFixed(2)}% of total supply.`
      );
    } else if (top1 >= 15) {
      addFlag(
        "ELEVATED_TOP1_CONCENTRATION",
        "MEDIUM",
        10,
        `Top-1 token account holds ${top1.toFixed(2)}% of total supply.`
      );
    }
    if (top10 >= 75) {
      addFlag(
        "EXTREME_TOP10_CONCENTRATION",
        "HIGH",
        20,
        `Top-10 token accounts control ${top10.toFixed(2)}% of total supply.`
      );
    } else if (top10 >= 50) {
      addFlag(
        "ELEVATED_TOP10_CONCENTRATION",
        "MEDIUM",
        10,
        `Top-10 token accounts control ${top10.toFixed(2)}% of total supply.`
      );
    }
  }

  const riskScore = Math.min(100, score);
  const riskLevel = classifyRiskLevel(riskScore);

  const recommendations = [];
  if (extensions.permanentDelegate) {
    recommendations.push(
      "CRITICAL: Avoid holding unverified tokens with permanentDelegate; only regulated institutional issuers (e.g. PYUSD) legitimately use this extension."
    );
  }
  if (mintAuthority || freezeAuthority) {
    recommendations.push(
      "For meme/community SPL tokens, require both mintAuthority === null and freezeAuthority === null before buying."
    );
  }
  if (holderConcentration.available && Number(holderConcentration.top10HoldersPct ?? 0) >= 50) {
    recommendations.push(
      "Verify whether top holder accounts belong to locked LP pools, staking vaults, or unlocked insider wallets."
    );
  }
  if (recommendations.length === 0) {
    recommendations.push(
      "Mint and freeze authorities are revoked and no dangerous Token-2022 extensions or holder concentration spikes were detected."
    );
  }

  return {
    isInitialized,
    riskScore,
    riskLevel,
    flags,
    mintInfo: {
      decimals,
      supplyAtomic: supplyAtomicStr,
      supplyFormatted: formatTokenUnits(supplyBig, decimals),
      mintAuthority,
      mintAuthorityRevoked: mintAuthority === null,
      freezeAuthority,
      freezeAuthorityRevoked: freezeAuthority === null,
      embeddedMetadata: embeddedMetadata || infoSrc.embeddedMetadata || null,
    },
    extensions,
    holderConcentration,
    recommendations,
  };
}

/* ============================================================================
 * 3. CORS-Safe Multi-RPC JSON-RPC Transport & Live Chain Scanners
 * ========================================================================== */

async function callJsonRpcWithFailover(urls, method, params, options = {}) {
  const timeoutMs = options.timeoutMs ?? 7500;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("Fetch API is unavailable in this runtime.");
  }

  const errors = [];
  for (const url of urls) {
    try {
      const init = {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method,
          params,
        }),
      };
      if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
        init.signal = AbortSignal.timeout(timeoutMs);
      }

      const res = await fetchImpl(url, init);
      const text = await res.text();
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        errors.push(`${url}: invalid JSON (${res.status})`);
        continue;
      }
      if (parsed && parsed.error) {
        errors.push(`${url}: RPC error ${parsed.error.code} (${parsed.error.message})`);
        continue;
      }
      if (!res.ok) {
        errors.push(`${url}: HTTP ${res.status}`);
        continue;
      }
      return { result: parsed.result, rpcUrl: url };
    } catch (err) {
      errors.push(`${url}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  throw new Error(`All RPC endpoints failed for ${method}: ${errors.join(" | ")}`);
}

export function formatAuditMarkdown(report) {
  if (!report || !report.ok) {
    return `# TokenGuard Risk Report\n\n- **Status:** Error — ${report?.error || "Scan failed"}`;
  }

  const isSolana = Boolean(report.mint);
  const titleTarget = isSolana
    ? `${report.mintInfo?.embeddedMetadata?.symbol || report.tokenStandard || "Solana Mint"} (${report.mint})`
    : `${report.tokenMetadata?.symbol || "EVM Contract"} (${report.address})`;

  const lines = [
    `# TokenGuard Risk Dossier — ${titleTarget}`,
    "",
    `- **Network:** ${isSolana ? `Solana Mainnet (${report.tokenStandard})` : `${report.chainName || report.chain} (${report.network})`}`,
    `- **Risk Score:** **${report.riskScore}/100 (${report.riskLevel})**`,
    `- **Audited At:** ${report.auditedAt}`,
  ];

  if (!isSolana) {
    if (report.tokenMetadata) {
      const m = report.tokenMetadata;
      lines.push(
        `- **Token:** ${m.name || "Unknown"} (${m.symbol || "N/A"}) · Decimals: ${m.decimals ?? "N/A"} · Supply: ${m.totalSupplyFormatted ?? "N/A"}`,
        `- **Owner:** \`${m.owner || "N/A / None"}\`${m.ownerRenounced ? " (Renounced)" : ""} · **Paused:** ${m.paused ? "YES" : "No"}`
      );
    }
    if (report.proxyAnalysis?.isProxy) {
      lines.push(
        `- **Proxy:** ${report.proxyAnalysis.proxyType} → Impl \`${report.proxyAnalysis.implementationAddress || "Beacon"}\`${report.proxyAnalysis.adminAddress ? ` (Admin \`${report.proxyAnalysis.adminAddress}\`)` : ""}`
      );
    }
  } else {
    const mi = report.mintInfo || {};
    lines.push(
      `- **Supply:** ${mi.supplyFormatted ?? "0"} (Decimals: ${mi.decimals ?? 0})`,
      `- **Mint Authority:** ${mi.mintAuthority ? `\`${mi.mintAuthority}\` (ACTIVE)` : "Revoked ✓"}`,
      `- **Freeze Authority:** ${mi.freezeAuthority ? `\`${mi.freezeAuthority}\` (ACTIVE)` : "Revoked ✓"}`
    );
    if (report.extensions?.count > 0) {
      lines.push(`- **Token-2022 Extensions (${report.extensions.count}):** ${report.extensions.names.join(", ")}`);
    }
    if (report.holderConcentration?.available) {
      lines.push(
        `- **Holder Concentration:** Top-1 = ${report.holderConcentration.top1HolderPct.toFixed(2)}% · Top-10 = ${report.holderConcentration.top10HoldersPct.toFixed(2)}%`
      );
    }
  }

  lines.push("", "## Risk Flags");
  if (!report.flags || report.flags.length === 0) {
    lines.push("- **CLEAN (0 flags):** No structural rug/freeze/honeypot flags triggered.");
  } else {
    for (const f of report.flags) {
      lines.push(`- **[${f.severity} · +${f.points}] \`${f.code}\`:** ${f.evidence}`);
    }
  }

  if (Array.isArray(report.recommendations) && report.recommendations.length > 0) {
    lines.push("", "## Security Recommendations");
    for (const r of report.recommendations) {
      lines.push(`- ${r}`);
    }
  }

  lines.push(
    "",
    "---",
    "- Scanned with **TokenGuard** (ForgeSuite Studio): https://youthmy11-ai.github.io/tokenaudit.html",
    "- Deep Solidity/Rust Source Audit ($5 USDC via A2A+x402): https://market.near.ai/a/forge-ai-agent"
  );
  return lines.join("\n");
}

/**
 * Live EVM Token & Smart Contract Scanner across Ethereum, Base, BSC, and Arbitrum.
 * Uses CORS-friendly PublicNode primaries by default.
 */
export async function scanEvmTokenOnChain(input = {}, options = {}) {
  const chainKey = String(input?.chain || "base")
    .trim()
    .toLowerCase();
  const addressRaw = String(input?.address || "").trim();

  if (!EVM_CHAIN_CONFIG[chainKey]) {
    throw new Error(
      `Unsupported EVM chain "${input?.chain}". Must be one of: ethereum, base, bsc, arbitrum.`
    );
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(addressRaw)) {
    throw new Error(
      `Invalid EVM contract address "${addressRaw}". Expected 0x-prefixed 20-byte hex address.`
    );
  }

  const chainCfg = EVM_CHAIN_CONFIG[chainKey];
  const customRpc = sanitizeCustomRpcUrl(input?.rpcUrl || options?.rpcUrl);
  const rpcs = customRpc
    ? [customRpc, ...chainCfg.rpcs]
    : Array.isArray(options.rpcs) && options.rpcs.length > 0
      ? options.rpcs
      : chainCfg.rpcs;

  const address = addressRaw.toLowerCase();

  const safeEthCall = async (target, data) => {
    try {
      const { result } = await callJsonRpcWithFailover(
        rpcs,
        "eth_call",
        [{ to: target, data }, "latest"],
        options
      );
      return result;
    } catch {
      return null;
    }
  };

  const safeGetStorage = async (slot) => {
    try {
      const { result } = await callJsonRpcWithFailover(
        rpcs,
        "eth_getStorageAt",
        [address, slot, "latest"],
        options
      );
      return result;
    } catch {
      return null;
    }
  };

  const codeResp = await callJsonRpcWithFailover(
    rpcs,
    "eth_getCode",
    [address, "latest"],
    options
  );
  const rawCode = codeResp.result || "0x";
  const outerWalk = analyzeEvmBytecodeHex(rawCode);

  if (!outerWalk.isContract) {
    const scoredEmpty = scoreEvmTokenRisk({ isContract: false });
    const emptyReport = {
      ok: true,
      ecosystem: "evm",
      auditedAt: new Date().toISOString(),
      chain: chainCfg.chain,
      chainName: chainCfg.name,
      network: chainCfg.caip2,
      rpcUsed: codeResp.rpcUrl,
      explorerUrl: `${chainCfg.explorerBase}${address}`,
      address,
      isContract: false,
      riskScore: scoredEmpty.riskScore,
      riskLevel: scoredEmpty.riskLevel,
      flags: scoredEmpty.flags,
      tokenMetadata: null,
      proxyAnalysis: null,
      bytecodeAnalysis: null,
      recommendations: scoredEmpty.recommendations,
    };
    emptyReport.markdownSummary = formatAuditMarkdown(emptyReport);
    return emptyReport;
  }

  const [
    eip1967ImplRaw,
    eip1967AdminRaw,
    eip1967BeaconRaw,
    zepImplRaw,
    zepAdminRaw,
    nameHex,
    symbolHex,
    decimalsHex,
    totalSupplyHex,
    ownerHex,
    pausedHex,
  ] = await Promise.all([
    safeGetStorage(SLOT_EIP1967_IMPL),
    safeGetStorage(SLOT_EIP1967_ADMIN),
    safeGetStorage(SLOT_EIP1967_BEACON),
    safeGetStorage(SLOT_ZEPPELINOS_IMPL),
    safeGetStorage(SLOT_ZEPPELINOS_ADMIN),
    safeEthCall(address, "0x06fdde03"),
    safeEthCall(address, "0x95d89b41"),
    safeEthCall(address, "0x313ce567"),
    safeEthCall(address, "0x18160ddd"),
    safeEthCall(address, "0x8da5cb5b"),
    safeEthCall(address, "0x5c975abb"),
  ]);

  const eip1967Impl = parseAddressFromSlot(eip1967ImplRaw);
  const eip1967Admin = parseAddressFromSlot(eip1967AdminRaw);
  const eip1967Beacon = parseAddressFromSlot(eip1967BeaconRaw);
  const zepImpl = parseAddressFromSlot(zepImplRaw);
  const zepAdmin = parseAddressFromSlot(zepAdminRaw);

  let beaconImpl = null;
  if (!eip1967Impl && eip1967Beacon) {
    const beaconImplHex = await safeEthCall(eip1967Beacon, "0x5c60da1b");
    beaconImpl = parseAddressFromSlot(beaconImplHex);
  }

  const implementationAddress =
    eip1967Impl || beaconImpl || zepImpl || outerWalk.eip1167Implementation || null;
  const adminAddress = eip1967Admin || zepAdmin || null;
  const proxyType = eip1967Impl
    ? "EIP-1967 Transparent/UUPS Proxy"
    : eip1967Beacon
      ? "EIP-1967 Beacon Proxy"
      : zepImpl
        ? "OpenZeppelin / FiatToken Upgradeable Proxy"
        : outerWalk.eip1167Implementation
          ? "EIP-1167 Minimal Clone Proxy"
          : null;

  let implWalk = null;
  if (implementationAddress) {
    try {
      const implCodeRes = await callJsonRpcWithFailover(
        rpcs,
        "eth_getCode",
        [implementationAddress, "latest"],
        options
      );
      if (implCodeRes.result && implCodeRes.result !== "0x") {
        implWalk = analyzeEvmBytecodeHex(implCodeRes.result);
      }
    } catch {
      implWalk = null;
    }
  }

  const decimalsBig = decodeAbiUint(decimalsHex);
  const decimals = decimalsBig !== null ? Number(decimalsBig) : null;
  const totalSupplyBig = decodeAbiUint(totalSupplyHex);
  const ownerParsed = parseAddressFromSlot(ownerHex);
  const ownerRenounced =
    ownerHex !== null &&
    ownerHex !== "0x" &&
    ownerHex.replace(/^0x/, "").length >= 64 &&
    ownerParsed === null;
  const pausedBig = decodeAbiUint(pausedHex);
  const isPaused = pausedBig !== null ? pausedBig !== 0n : false;

  const tokenMetadata = {
    name: decodeAbiStringOrBytes32(nameHex),
    symbol: decodeAbiStringOrBytes32(symbolHex),
    decimals,
    totalSupplyAtomic: totalSupplyBig !== null ? totalSupplyBig.toString() : null,
    totalSupplyFormatted:
      totalSupplyBig !== null ? formatTokenUnits(totalSupplyBig, decimals ?? 18) : null,
    owner: ownerRenounced ? ZERO_ADDRESS : ownerParsed,
    ownerRenounced,
    paused: isPaused,
  };

  const scored = scoreEvmTokenRisk({
    isContract: true,
    outerWalk,
    implWalk,
    proxyType,
    implementationAddress,
    adminAddress,
    beaconAddress: eip1967Beacon,
    tokenMetadata,
  });

  const report = {
    ok: true,
    ecosystem: "evm",
    auditedAt: new Date().toISOString(),
    chain: chainCfg.chain,
    chainName: chainCfg.name,
    network: chainCfg.caip2,
    rpcUsed: codeResp.rpcUrl,
    explorerUrl: `${chainCfg.explorerBase}${address}`,
    address,
    isContract: true,
    riskScore: scored.riskScore,
    riskLevel: scored.riskLevel,
    flags: scored.flags,
    tokenMetadata,
    proxyAnalysis: scored.proxyAnalysis,
    bytecodeAnalysis: scored.bytecodeAnalysis,
    recommendations: scored.recommendations,
  };
  report.markdownSummary = formatAuditMarkdown(report);
  return report;
}

/**
 * Live Solana SPL Token & Token-2022 Mint Scanner.
 * Uses CORS-friendly PublicNode + Zan primaries by default.
 */
export async function scanSolanaMintOnChain(input = {}, options = {}) {
  const mint = String(input?.mint || input?.address || "").trim();
  if (!BASE58_REGEX.test(mint)) {
    throw new Error(
      `Invalid Solana mint address "${mint}". Expected 32-44 char Base58 public key.`
    );
  }

  const customRpc = sanitizeCustomRpcUrl(input?.rpcUrl || options?.rpcUrl);
  const accountRpcs = customRpc
    ? [customRpc, ...SOLANA_RPC_ENDPOINTS]
    : Array.isArray(options.accountRpcs) && options.accountRpcs.length > 0
      ? options.accountRpcs
      : SOLANA_RPC_ENDPOINTS;

  const indexedRpcs = customRpc
    ? [customRpc, ...SOLANA_INDEXED_RPC_ENDPOINTS]
    : Array.isArray(options.indexedRpcs) && options.indexedRpcs.length > 0
      ? options.indexedRpcs
      : SOLANA_INDEXED_RPC_ENDPOINTS;

  const acctResp = await callJsonRpcWithFailover(
    accountRpcs,
    "getAccountInfo",
    [mint, { encoding: "jsonParsed", commitment: "confirmed" }],
    options
  );

  const acctVal = acctResp.result?.value;
  if (!acctVal) {
    throw new Error(`Solana account "${mint}" does not exist on Mainnet.`);
  }

  const programOwner = acctVal.owner;
  const tokenStandard =
    programOwner === TOKEN_PROGRAM_ID
      ? "SPL Token"
      : programOwner === TOKEN_2022_PROGRAM_ID
        ? "Token-2022"
        : null;

  const parsedData = acctVal.data?.parsed;
  if (!tokenStandard || parsedData?.type !== "mint") {
    throw new Error(
      `Account "${mint}" is owned by ${programOwner} (type: ${parsedData?.type || "raw"}), not an SPL Token or Token-2022 mint.`
    );
  }

  const info = parsedData.info || {};
  let largestAccounts = null;
  let indexedRpcUsed = null;
  let holderFailureReason = null;

  if (options.skipHolderScan !== true) {
    try {
      const largestResp = await callJsonRpcWithFailover(
        indexedRpcs,
        "getTokenLargestAccounts",
        [mint, { commitment: "confirmed" }],
        { ...options, timeoutMs: options.indexedTimeoutMs ?? 4500 }
      );
      if (Array.isArray(largestResp.result?.value)) {
        largestAccounts = largestResp.result.value;
        indexedRpcUsed = largestResp.rpcUrl;
      }
    } catch {
      holderFailureReason =
        "Mint exceeds public unauthenticated RPC indexed scan limits (typical for high-holder tokens); supply a custom indexed RPC URL if Top-10 holder percentages are required.";
    }
  }

  const scored = scoreSolanaMintRisk({
    info,
    extensions: info.extensions,
    ...(largestAccounts
      ? { largestAccounts, indexedRpcUsed }
      : {
          holderConcentration: {
            available: false,
            reason: holderFailureReason || "Holder scan skipped.",
            top1HolderPct: null,
            top10HoldersPct: null,
            topHolders: [],
          },
        }),
  });

  const report = {
    ok: true,
    ecosystem: "solana",
    auditedAt: new Date().toISOString(),
    chain: "solana",
    chainName: "Solana Mainnet",
    network: SOLANA_NETWORK,
    rpcUsed: acctResp.rpcUrl,
    explorerUrl: `${SOLANA_EXPLORER_BASE}${mint}`,
    mint,
    tokenStandard,
    programOwner,
    isInitialized: scored.isInitialized,
    riskScore: scored.riskScore,
    riskLevel: scored.riskLevel,
    flags: scored.flags,
    mintInfo: scored.mintInfo,
    extensions: scored.extensions,
    holderConcentration: scored.holderConcentration,
    recommendations: scored.recommendations,
  };
  report.markdownSummary = formatAuditMarkdown(report);
  return report;
}

/* ============================================================================
 * 4. Batch Watchlist Parser, Runner & CryptoBill Invoice Handoff
 * ========================================================================== */

export function parseWatchlistEntries(rawText, defaultChain = "base") {
  const lines = String(rawText || "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));

  const entries = [];
  const seen = new Set();

  for (const line of lines) {
    let chain = defaultChain;
    let target = line;
    const sepMatch = line.match(/^([a-zA-Z0-9_-]+)\s*[:,\s]\s*(\S+)$/);
    if (sepMatch) {
      const candidateChain = sepMatch[1].toLowerCase();
      if (candidateChain === "sol" || candidateChain === "solana") {
        chain = "solana";
        target = sepMatch[2];
      } else if (candidateChain === "eth" || candidateChain === "ethereum") {
        chain = "ethereum";
        target = sepMatch[2];
      } else if (EVM_CHAIN_CONFIG[candidateChain]) {
        chain = candidateChain;
        target = sepMatch[2];
      }
    } else if (BASE58_REGEX.test(target) && !target.startsWith("0x")) {
      chain = "solana";
    } else if (/^0x[0-9a-fA-F]{40}$/.test(target) && chain === "solana") {
      chain = "base";
    }

    const dedupKey = `${chain}:${chain === "solana" ? target : target.toLowerCase()}`;
    if (!seen.has(dedupKey)) {
      seen.add(dedupKey);
      entries.push({ chain, address: target });
    }
  }

  return entries;
}

export async function runBatchWatchlistScan(entries, options = {}) {
  const list = Array.isArray(entries) ? entries : [];
  if (list.length === 0) {
    throw new Error("Provide at least 1 token/contract address to scan.");
  }
  if (list.length > MAX_BATCH_WATCHLIST) {
    throw new Error(
      `Batch Watchlist supports up to ${MAX_BATCH_WATCHLIST} addresses at once (received ${list.length}).`
    );
  }

  const concurrency = Math.max(1, Math.min(6, Number(options.concurrency ?? 4)));
  const results = new Array(list.length);
  let cursor = 0;

  async function worker() {
    while (cursor < list.length) {
      const idx = cursor;
      cursor += 1;
      const item = list[idx];
      try {
        if (item.chain === "solana") {
          results[idx] = await scanSolanaMintOnChain(
            { mint: item.address, rpcUrl: options.solanaRpcUrl },
            options
          );
        } else {
          results[idx] = await scanEvmTokenOnChain(
            { chain: item.chain, address: item.address, rpcUrl: options.evmRpcUrl },
            options
          );
        }
      } catch (err) {
        results[idx] = {
          ok: false,
          chain: item.chain,
          address: item.address,
          mint: item.chain === "solana" ? item.address : undefined,
          riskScore: null,
          riskLevel: "ERROR",
          flags: [],
          error: err instanceof Error ? err.message : String(err),
        };
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, list.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

function csvCell(val) {
  const str = String(val ?? "");
  const safe = /^[=+\-@]/.test(str) ? `'${str}` : str;
  if (/[",\r\n]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

export function exportBatchReportsCsv(reports) {
  const headers = [
    "chain",
    "address_or_mint",
    "symbol",
    "name_or_standard",
    "risk_score",
    "risk_level",
    "flag_count",
    "top_flags",
    "proxy_or_authorities",
    "audited_at",
  ];
  const rows = (Array.isArray(reports) ? reports : []).map((r) => {
    if (!r || !r.ok) {
      return [
        r?.chain || "",
        r?.mint || r?.address || "",
        "",
        "ERROR",
        "",
        "ERROR",
        0,
        r?.error || "Scan error",
        "",
        new Date().toISOString(),
      ];
    }
    const isSol = r.ecosystem === "solana" || Boolean(r.mint);
    const addr = isSol ? r.mint : r.address;
    const symbol = isSol
      ? r.mintInfo?.embeddedMetadata?.symbol || r.tokenStandard || "SPL"
      : r.tokenMetadata?.symbol || "CONTRACT";
    const nameOrStd = isSol
      ? r.mintInfo?.embeddedMetadata?.name || r.tokenStandard
      : r.tokenMetadata?.name || (r.isContract ? "EVM Contract" : "EOA / Empty");
    const flagsSummary = (r.flags || []).map((f) => f.code).join("; ");
    const govSummary = isSol
      ? `mintAuth=${r.mintInfo?.mintAuthority ? "ACTIVE" : "revoked"}; freezeAuth=${r.mintInfo?.freezeAuthority ? "ACTIVE" : "revoked"}`
      : r.proxyAnalysis?.isProxy
        ? `${r.proxyAnalysis.proxyType} -> ${r.proxyAnalysis.implementationAddress || "beacon"}`
        : `owner=${r.tokenMetadata?.owner || "none"}`;

    return [
      r.chain,
      addr,
      symbol,
      nameOrStd,
      r.riskScore,
      r.riskLevel,
      (r.flags || []).length,
      flagsSummary,
      govSummary,
      r.auditedAt || "",
    ];
  });

  return [headers.join(","), ...rows.map((row) => row.map(csvCell).join(","))].join("\n");
}

export function buildAuditInvoicePayload(scanOrBatch) {
  const inv = createDefaultInvoice();
  inv.clientName = "Web3 Protocol / Treasury Risk Ops";
  inv.taxPercent = 0;
  inv.discountPercent = 0;

  if (Array.isArray(scanOrBatch) && scanOrBatch.length > 0) {
    const okCount = scanOrBatch.filter((r) => r && r.ok).length;
    inv.notes = `Multi-chain Watchlist Token Risk Audit (${okCount}/${scanOrBatch.length} contracts verified via ForgeSuite TokenGuard).`;
    inv.items = [
      {
        description: `Batch EVM & Solana Token Security Dossier (${scanOrBatch.length} Assets)`,
        qty: 1,
        unitPrice: Math.max(185, scanOrBatch.length * 35),
      },
    ];
    return inv;
  }

  const target = scanOrBatch?.mint || scanOrBatch?.address || "on-chain contract";
  const chainLabel = scanOrBatch?.chain ? scanOrBatch.chain.toUpperCase() : "MULTICHAIN";
  const scoreNote =
    scanOrBatch && typeof scanOrBatch.riskScore === "number"
      ? ` — Risk Score ${scanOrBatch.riskScore}/100 (${scanOrBatch.riskLevel})`
      : "";

  inv.notes = `On-chain bytecode, proxy & authority risk audit for ${chainLabel} ${target}${scoreNote} via ForgeSuite TokenGuard.`;
  inv.items = [
    {
      description: `Smart Contract & Token Risk Sign-Off Review (${chainLabel}: ${String(target).slice(0, 14)}...)`,
      qty: 1,
      unitPrice: 185,
    },
  ];
  return inv;
}

/* ============================================================================
 * 5. Browser UI Controller for tokenaudit.html
 * ========================================================================== */

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function badgeClassForRisk(level) {
  if (level === "CRITICAL" || level === "HIGH" || level === "ERROR") return "fs-badge-warn";
  if (level === "MODERATE") return "fs-badge-accent";
  if (level === "LOW") return "fs-badge-success";
  return "fs-badge-muted";
}

const CHAIN_QUERY_ALIASES = Object.freeze({
  ethereum: "ethereum",
  eth: "ethereum",
  mainnet: "ethereum",
  "1": "ethereum",
  base: "base",
  "8453": "base",
  bsc: "bsc",
  bnb: "bsc",
  "56": "bsc",
  arbitrum: "arbitrum",
  arb: "arbitrum",
  "42161": "arbitrum",
  solana: "solana",
  sol: "solana",
});

/**
 * Parses URL query parameters (`?chain=solana&mint=...` or `?chain=base&address=...`)
 * for deep-linking directly into TokenGuard from SEO guides, IDE docs, or dashboards.
 */
export function parseTokenAuditQueryParams(searchInput = "") {
  const raw = String(searchInput || "").trim();
  const params = new URLSearchParams(raw.startsWith("?") ? raw.slice(1) : raw);

  const rawChain = String(params.get("chain") || params.get("network") || "")
    .trim()
    .toLowerCase();
  const rawMint = String(params.get("mint") || "").trim();
  const rawAddress = String(
    rawMint ||
      params.get("address") ||
      params.get("token") ||
      params.get("contract") ||
      params.get("target") ||
      ""
  ).trim();

  let chain = CHAIN_QUERY_ALIASES[rawChain] || null;
  if (rawAddress) {
    if (/^0x[0-9a-fA-F]{40}$/.test(rawAddress)) {
      if (!chain || chain === "solana") chain = "base";
    } else if (BASE58_REGEX.test(rawAddress) && !rawAddress.startsWith("0x")) {
      chain = "solana";
    }
  }
  if (!chain && rawMint) {
    chain = "solana";
  }

  let rpcUrl = null;
  const rawRpc = params.get("rpc") || params.get("rpcUrl") || "";
  if (rawRpc.trim()) {
    try {
      rpcUrl = sanitizeCustomRpcUrl(rawRpc);
    } catch {
      rpcUrl = null;
    }
  }

  const rawAutorun = String(params.get("autorun") || params.get("scan") || "")
    .trim()
    .toLowerCase();
  const autorun =
    Boolean(rawAddress) &&
    rawAutorun !== "0" &&
    rawAutorun !== "false" &&
    rawAutorun !== "no";

  return {
    hasTarget: Boolean(rawAddress),
    chain: chain || "base",
    address: rawAddress,
    rpcUrl,
    autorun,
  };
}

function isTokenGuardProUnlocked() {
  return (
    hasUnlockedTier("BUNDLE") ||
    hasUnlockedTier("CB") ||
    getStoredLicenses().length > 0
  );
}

function downloadBlob(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function initTokenAuditApp() {
  if (typeof document === "undefined" || document.body?.dataset?.page !== "tokenaudit") return;

  const chainEl = document.getElementById("tgaChainSelect");
  const addrEl = document.getElementById("tgaAddressInput");
  const rpcEl = document.getElementById("tgaCustomRpcInput");
  const scanBtn = document.getElementById("tgaScanBtn");
  const statusEl = document.getElementById("tgaStatusMsg");

  const riskBadgeEl = document.getElementById("tgaRiskBadge");
  const scoreSummaryEl = document.getElementById("tgaScoreSummary");
  const metaGridEl = document.getElementById("tgaMetaGrid");
  const flagsBodyEl = document.getElementById("tgaFlagsBody");
  const recsListEl = document.getElementById("tgaRecsList");
  const copyMdBtn = document.getElementById("tgaCopyMdBtn");
  const invoiceBtn = document.getElementById("tgaSendInvoiceBtn");

  const proBadgeEl = document.getElementById("tgaProStatusBadge");
  const proLockBannerEl = document.getElementById("tgaProLockBanner");
  const batchInputEl = document.getElementById("tgaBatchInput");
  const batchRunBtn = document.getElementById("tgaBatchRunBtn");
  const batchExportJsonBtn = document.getElementById("tgaExportJsonBtn");
  const batchExportCsvBtn = document.getElementById("tgaExportCsvBtn");
  const batchStatusEl = document.getElementById("tgaBatchStatusMsg");
  const batchBodyEl = document.getElementById("tgaBatchBody");

  let lastSingleReport = null;
  let lastBatchReports = [];

  function syncProUi() {
    const unlocked = isTokenGuardProUnlocked();
    if (proBadgeEl) {
      proBadgeEl.textContent = unlocked
        ? "PRO ACTIVE · 25-TOKEN BATCH UNLOCKED ✓"
        : "PRO FEATURE · BUNDLE ($35)";
      proBadgeEl.className = `fs-badge ${unlocked ? "fs-badge-success" : "fs-badge-warn"}`;
    }
    if (proLockBannerEl) {
      proLockBannerEl.hidden = unlocked;
    }
    if (batchRunBtn) {
      batchRunBtn.textContent = unlocked
        ? "Run Batch Watchlist Audit (<= 25)"
        : "Unlock Batch Audit — Bundle ($35)";
    }
  }

  bindCheckoutTriggers({ onUnlocked: syncProUi });
  window.addEventListener("forgesuite:license-updated", syncProUi);

  const navBundleBtn = document.getElementById("tgaBundleBtn");
  if (navBundleBtn) {
    navBundleBtn.addEventListener("click", () =>
      openCheckoutModal("BUNDLE", { onUnlocked: syncProUi })
    );
  }
  const activateKeyBtn = document.getElementById("tgaActivateKeyBtn");
  if (activateKeyBtn) {
    activateKeyBtn.addEventListener("click", () =>
      openCheckoutModal("BUNDLE", { initialTab: "license", onUnlocked: syncProUi })
    );
  }

  const themeBtn = document.getElementById("themeToggleBtn");
  if (themeBtn) {
    const saved = window.localStorage.getItem("forgesuite_theme") || "dark";
    document.documentElement.dataset.theme = saved;
    themeBtn.textContent = saved === "light" ? "☀ Light" : "🌙 Dark";
    themeBtn.addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
      document.documentElement.dataset.theme = next;
      window.localStorage.setItem("forgesuite_theme", next);
      themeBtn.textContent = next === "light" ? "☀ Light" : "🌙 Dark";
    });
  }

  function renderReport(report) {
    lastSingleReport = report;
    if (!report || !report.ok) return;

    if (riskBadgeEl) {
      riskBadgeEl.textContent = `${report.riskScore}/100 · ${report.riskLevel}`;
      riskBadgeEl.className = `fs-badge ${badgeClassForRisk(report.riskLevel)}`;
    }

    const isSol = report.ecosystem === "solana" || Boolean(report.mint);
    const targetAddr = isSol ? report.mint : report.address;

    if (scoreSummaryEl) {
      scoreSummaryEl.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;">
          <div>
            <strong>${escapeHtml(report.chainName || report.chain)}</strong> ·
            <code>${escapeHtml(targetAddr)}</code>
          </div>
          <a href="${escapeHtml(report.explorerUrl || "#")}" target="_blank" rel="noopener noreferrer" class="fs-btn fs-btn-sm fs-btn-ghost">Explorer ↗</a>
        </div>
        <div class="inv-muted" style="margin-top:4px;">RPC Verified via <code>${escapeHtml(report.rpcUsed || "public-rpc")}</code></div>
      `;
    }

    if (metaGridEl) {
      if (!isSol) {
        const m = report.tokenMetadata || {};
        const p = report.proxyAnalysis || {};
        const b = report.bytecodeAnalysis || {};
        const opBadges = b.opcodes
          ? [
              b.opcodes.selfDestruct ? "SELFDESTRUCT!" : null,
              b.opcodes.delegateCall ? "DELEGATECALL" : null,
              b.opcodes.callCode ? "CALLCODE!" : null,
              b.opcodes.create2 ? "CREATE2" : null,
              b.opcodes.txOrigin ? "ORIGIN" : null,
            ]
              .filter(Boolean)
              .join(", ") || "None"
          : "Empty";

        metaGridEl.innerHTML = `
          <div class="fs-mono-chip"><strong>Token:</strong> ${escapeHtml(m.name || "Unlabeled Contract")} (${escapeHtml(m.symbol || "N/A")})</div>
          <div class="fs-mono-chip"><strong>Supply / Decimals:</strong> ${escapeHtml(m.totalSupplyFormatted ?? "N/A")} (dec: ${escapeHtml(m.decimals ?? "N/A")})</div>
          <div class="fs-mono-chip"><strong>Proxy Architecture:</strong> ${escapeHtml(p.isProxy ? p.proxyType : "Direct Contract (Non-Proxy)")}${p.implementationAddress ? `<br><small>Impl: ${escapeHtml(p.implementationAddress)}</small>` : ""}</div>
          <div class="fs-mono-chip"><strong>Owner / Bytecode:</strong> ${escapeHtml(m.ownerRenounced ? "Renounced (0x0)" : m.owner || "No owner()")} · ${escapeHtml(b.contractBytecodeBytes ?? 0)}B (${escapeHtml(opBadges)})</div>
        `;
      } else {
        const mi = report.mintInfo || {};
        const ext = report.extensions || {};
        const hc = report.holderConcentration || {};
        const metaTitle = mi.embeddedMetadata?.symbol
          ? `${mi.embeddedMetadata.name || ""} (${mi.embeddedMetadata.symbol})`
          : report.tokenStandard;

        metaGridEl.innerHTML = `
          <div class="fs-mono-chip"><strong>Standard / Label:</strong> ${escapeHtml(report.tokenStandard)} · ${escapeHtml(metaTitle)}</div>
          <div class="fs-mono-chip"><strong>Supply / Decimals:</strong> ${escapeHtml(mi.supplyFormatted ?? "0")} (dec: ${escapeHtml(mi.decimals ?? 0)})</div>
          <div class="fs-mono-chip"><strong>Authorities:</strong> Mint: ${escapeHtml(mi.mintAuthority ? "ACTIVE" : "Revoked ✓")} · Freeze: ${escapeHtml(mi.freezeAuthority ? "ACTIVE" : "Revoked ✓")}</div>
          <div class="fs-mono-chip"><strong>Extensions / Holders:</strong> ${escapeHtml(ext.count ? ext.names.join(", ") : "0 Extensions")} · ${hc.available ? `Top-10: ${hc.top10HoldersPct.toFixed(1)}%` : "Public RPC (No Index)"}</div>
        `;
      }
    }

    if (flagsBodyEl) {
      if (!report.flags || report.flags.length === 0) {
        flagsBodyEl.innerHTML =
          '<tr><td colspan="4" class="inv-muted">Zero rug/freeze/honeypot risk flags triggered in on-chain inspection.</td></tr>';
      } else {
        flagsBodyEl.innerHTML = report.flags
          .map(
            (f) => `<tr>
              <td><span class="fs-badge ${badgeClassForRisk(f.severity === "MEDIUM" ? "MODERATE" : f.severity)}">${escapeHtml(f.severity)}</span></td>
              <td><code>${escapeHtml(f.code)}</code></td>
              <td><strong>+${escapeHtml(f.points)}</strong></td>
              <td>${escapeHtml(f.evidence)}</td>
            </tr>`
          )
          .join("");
      }
    }

    if (recsListEl) {
      recsListEl.innerHTML = (report.recommendations || [])
        .map((r) => `<li>${escapeHtml(r)}</li>`)
        .join("");
    }
  }

  async function executeSingleScan() {
    const rawTarget = String(addrEl?.value || "").trim();
    if (!rawTarget) {
      if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = "Enter an EVM 0x contract address or Solana Base58 token mint.";
      }
      return;
    }

    // Auto-switch chain selector if user pastes Base58 into EVM mode or 0x into Solana mode
    let selectedChain = String(chainEl?.value || "base").toLowerCase();
    if (/^0x[0-9a-fA-F]{40}$/.test(rawTarget) && selectedChain === "solana") {
      selectedChain = "base";
      if (chainEl) chainEl.value = "base";
    } else if (BASE58_REGEX.test(rawTarget) && !rawTarget.startsWith("0x") && selectedChain !== "solana") {
      selectedChain = "solana";
      if (chainEl) chainEl.value = "solana";
    }

    const customRpc = String(rpcEl?.value || "").trim();
    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.textContent = "Scanning Live RPC...";
    }
    if (statusEl) {
      statusEl.className = "fs-status-msg is-loading";
      statusEl.textContent = `Querying CORS-safe ${selectedChain.toUpperCase()} JSON-RPC nodes...`;
    }

    try {
      const report =
        selectedChain === "solana"
          ? await scanSolanaMintOnChain({ mint: rawTarget, rpcUrl: customRpc || undefined })
          : await scanEvmTokenOnChain({
              chain: selectedChain,
              address: rawTarget,
              rpcUrl: customRpc || undefined,
            });

      renderReport(report);
      if (statusEl) {
        statusEl.className = "fs-status-msg is-success";
        statusEl.textContent = `Completed live ${report.chainName} scan — Risk Score ${report.riskScore}/100 (${report.riskLevel}).`;
      }
    } catch (err) {
      if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = err instanceof Error ? err.message : String(err);
      }
    } finally {
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.textContent = "Scan Token / Contract";
      }
    }
  }

  document.querySelectorAll("[data-tga-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.getAttribute("data-tga-sample");
      const sample = TOKENGUARD_SAMPLES[key];
      if (!sample) return;
      if (chainEl) chainEl.value = sample.chain;
      if (addrEl) addrEl.value = sample.address;
      executeSingleScan();
    });
  });

  if (scanBtn) scanBtn.addEventListener("click", executeSingleScan);
  if (addrEl) {
    addrEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        executeSingleScan();
      }
    });
  }

  if (copyMdBtn) {
    copyMdBtn.addEventListener("click", async () => {
      if (!lastSingleReport?.markdownSummary) return;
      const prev = copyMdBtn.textContent;
      try {
        await navigator.clipboard.writeText(lastSingleReport.markdownSummary);
        copyMdBtn.textContent = "Copied Markdown ✓";
        setTimeout(() => {
          copyMdBtn.textContent = prev;
        }, 1800);
      } catch {}
    });
  }

  if (invoiceBtn) {
    invoiceBtn.addEventListener("click", () => {
      const payload = buildAuditInvoicePayload(
        lastBatchReports.length > 0 ? lastBatchReports : lastSingleReport
      );
      const hash = encodeInvoicePayload(payload);
      window.location.href = `cryptobill.html#inv=${hash}`;
    });
  }

  if (batchInputEl && !batchInputEl.value.trim()) {
    batchInputEl.value = DEFAULT_WATCHLIST_SAMPLE;
  }

  if (batchRunBtn) {
    batchRunBtn.addEventListener("click", async () => {
      if (!isTokenGuardProUnlocked()) {
        openCheckoutModal("BUNDLE", { onUnlocked: syncProUi });
        return;
      }

      const defaultChain = String(chainEl?.value || "base").toLowerCase();
      const entries = parseWatchlistEntries(batchInputEl?.value || "", defaultChain);
      if (entries.length === 0) {
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-error";
          batchStatusEl.textContent = "Paste 1 to 25 addresses (one per line, e.g. base:0x... or solana:Mint...).";
        }
        return;
      }
      if (entries.length > MAX_BATCH_WATCHLIST) {
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-error";
          batchStatusEl.textContent = `Maximum ${MAX_BATCH_WATCHLIST} addresses per batch scan (found ${entries.length}).`;
        }
        return;
      }

      batchRunBtn.disabled = true;
      batchRunBtn.textContent = `Auditing ${entries.length} Assets...`;
      if (batchStatusEl) {
        batchStatusEl.className = "fs-status-msg is-loading";
        batchStatusEl.textContent = `Scanning ${entries.length} contracts across multi-chain RPCs...`;
      }

      try {
        const customRpc = String(rpcEl?.value || "").trim();
        const reports = await runBatchWatchlistScan(entries, {
          evmRpcUrl: customRpc && defaultChain !== "solana" ? customRpc : undefined,
          solanaRpcUrl: customRpc && defaultChain === "solana" ? customRpc : undefined,
        });
        lastBatchReports = reports;

        if (batchBodyEl) {
          batchBodyEl.innerHTML = reports
            .map((r, idx) => {
              if (!r.ok) {
                return `<tr>
                  <td>${escapeHtml(r.chain)}</td>
                  <td><code>${escapeHtml(r.address)}</code></td>
                  <td><span class="fs-badge fs-badge-warn">ERROR</span></td>
                  <td colspan="2" class="inv-muted">${escapeHtml(r.error)}</td>
                </tr>`;
              }
              const isSol = r.ecosystem === "solana";
              const target = isSol ? r.mint : r.address;
              const sym = isSol
                ? r.mintInfo?.embeddedMetadata?.symbol || r.tokenStandard
                : r.tokenMetadata?.symbol || "Contract";
              const flagText =
                r.flags.length === 0
                  ? "0 flags"
                  : r.flags.map((f) => f.code).slice(0, 3).join(", ");
              return `<tr>
                <td><strong>${escapeHtml(r.chain.toUpperCase())}</strong></td>
                <td><code>${escapeHtml(target.slice(0, 10))}...${escapeHtml(target.slice(-6))}</code><br><small class="inv-muted">${escapeHtml(sym)}</small></td>
                <td><span class="fs-badge ${badgeClassForRisk(r.riskLevel)}">${escapeHtml(r.riskScore)}/100 · ${escapeHtml(r.riskLevel)}</span></td>
                <td>${escapeHtml(flagText)}</td>
                <td><button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-batch-inspect="${idx}">Inspect</button></td>
              </tr>`;
            })
            .join("");

          batchBodyEl.querySelectorAll("[data-batch-inspect]").forEach((b) => {
            b.addEventListener("click", () => {
              const i = Number(b.getAttribute("data-batch-inspect"));
              if (lastBatchReports[i]?.ok) renderReport(lastBatchReports[i]);
            });
          });
        }

        if (batchExportJsonBtn) batchExportJsonBtn.disabled = false;
        if (batchExportCsvBtn) batchExportCsvBtn.disabled = false;
        if (batchStatusEl) {
          const okCount = reports.filter((x) => x.ok).length;
          batchStatusEl.className = "fs-status-msg is-success";
          batchStatusEl.textContent = `Batch audit complete: ${okCount}/${reports.length} succeeded. Ready for JSON/CSV Dossier export.`;
        }
      } catch (err) {
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-error";
          batchStatusEl.textContent = err instanceof Error ? err.message : String(err);
        }
      } finally {
        syncProUi();
        batchRunBtn.disabled = false;
      }
    });
  }

  if (batchExportJsonBtn) {
    batchExportJsonBtn.addEventListener("click", () => {
      if (!isTokenGuardProUnlocked()) {
        openCheckoutModal("BUNDLE", { onUnlocked: syncProUi });
        return;
      }
      if (lastBatchReports.length === 0) return;
      downloadBlob(
        "tokenguard-watchlist-dossier.json",
        JSON.stringify(
          {
            suite: "ForgeSuite TokenGuard Pro",
            generatedAt: new Date().toISOString(),
            totalAssets: lastBatchReports.length,
            reports: lastBatchReports,
          },
          null,
          2
        ),
        "application/json;charset=utf-8"
      );
    });
  }

  if (batchExportCsvBtn) {
    batchExportCsvBtn.addEventListener("click", () => {
      if (!isTokenGuardProUnlocked()) {
        openCheckoutModal("BUNDLE", { onUnlocked: syncProUi });
        return;
      }
      if (lastBatchReports.length === 0) return;
      downloadBlob(
        "tokenguard-watchlist-dossier.csv",
        exportBatchReportsCsv(lastBatchReports),
        "text/csv;charset=utf-8"
      );
    });
  }

  syncProUi();

  // Support URL query deep-links (?chain=solana&mint=... or ?chain=base&address=...)
  const queryTarget =
    typeof window !== "undefined"
      ? parseTokenAuditQueryParams(window.location.search)
      : { hasTarget: false, chain: "base", address: "", rpcUrl: null, autorun: false };

  if (addrEl && queryTarget.hasTarget) {
    if (chainEl) chainEl.value = queryTarget.chain;
    addrEl.value = queryTarget.address;
    if (rpcEl && queryTarget.rpcUrl) rpcEl.value = queryTarget.rpcUrl;
    if (queryTarget.autorun) {
      executeSingleScan();
    }
  } else if (addrEl && !addrEl.value.trim()) {
    // Populate initial sample address and run instant live demo scan
    if (chainEl) chainEl.value = TOKENGUARD_SAMPLES.base_usdc.chain;
    addrEl.value = TOKENGUARD_SAMPLES.base_usdc.address;
    executeSingleScan();
  }
}

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", initTokenAuditApp);
}
