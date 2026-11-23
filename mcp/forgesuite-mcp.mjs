#!/usr/bin/env node
/**
 * ForgeSuite MCP Server (v1.0.0)
 * Zero-dependency Node 22+ Model Context Protocol (MCP) stdio JSON-RPC 2.0 server.
 *
 * 100% Offline, Privacy-First Developer & Web3 Tools:
 *   1. envshield_scan     — Scan .env/configs/logs for leaked secrets & return redacted output
 *   2. calldata_decode    — Decode EVM calldata selectors & flag unlimited MaxUint256 approvals
 *   3. tokencost_estimate — Estimate LLM API & multi-turn AI agent run costs (Claude/GPT/Gemini/DeepSeek)
 *   4. cryptobill_quote   — Generate Markdown/JSON crypto invoices + live CryptoBill #inv= links
 *
 * Docs & Pro Bundle ($35 Lifetime): https://youthmy11-ai.github.io/mcp.html
 * License: MIT (youthmy11-ai)
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

export const SERVER_INFO = Object.freeze({
  name: "forgesuite-mcp",
  version: "1.0.0",
});

export const SUPPORTED_PROTOCOL_VERSIONS = Object.freeze([
  "2025-03-26",
  "2024-11-05",
]);

export const FORGESUITE_LINKS = Object.freeze({
  home: "https://youthmy11-ai.github.io/",
  mcp: "https://youthmy11-ai.github.io/mcp.html",
  envshield: "https://youthmy11-ai.github.io/envshield.html",
  txdecode: "https://youthmy11-ai.github.io/txdecode.html",
  tokencalc: "https://youthmy11-ai.github.io/tokencalc.html",
  cryptobill: "https://youthmy11-ai.github.io/cryptobill.html",
  pricing: "https://youthmy11-ai.github.io/#pricing",
});

/* ============================================================================
 * 1. EnvShield Secret Scanner (100% Offline)
 * ========================================================================== */

export const SECRET_RULES = Object.freeze([
  {
    id: "PRIVATE_KEY_PEM",
    label: "PEM Private Key Block",
    severity: "CRITICAL",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
  },
  {
    id: "EVM_PRIVATE_KEY",
    label: "EVM / Hex Private Key (64-hex)",
    severity: "CRITICAL",
    regex: /(?:(?:PRIV(?:ATE)?_?KEY|SIGNER_?KEY|WALLET_?KEY|DEPLOYER_?KEY|MNEMONIC|SECRET)\s*[:=]\s*["']?)(0x[a-fA-F0-9]{64}|[a-fA-F0-9]{64})\b/gi,
    captureGroup: 1,
  },
  {
    id: "MNEMONIC_PHRASE",
    label: "Seed / Mnemonic Phrase Assignment",
    severity: "CRITICAL",
    regex: /(?:(?:MNEMONIC|SEED_?PHRASE|RECOVERY_?PHRASE)\s*[:=]\s*["']?)([a-z]{3,10}(?:\s+[a-z]{3,10}){11,23})["']?/gi,
    captureGroup: 1,
  },
  {
    id: "ANTHROPIC_KEY",
    label: "Anthropic API Key",
    severity: "CRITICAL",
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "OPENAI_KEY",
    label: "OpenAI API Key",
    severity: "CRITICAL",
    regex: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "GITHUB_TOKEN",
    label: "GitHub Personal Access Token",
    severity: "CRITICAL",
    regex: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
  },
  {
    id: "AWS_ACCESS_KEY",
    label: "AWS Access Key ID",
    severity: "HIGH",
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: "GOOGLE_API_KEY",
    label: "Google / Gemini / Firebase API Key",
    severity: "HIGH",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    id: "STRIPE_LIVE_KEY",
    label: "Stripe Live Secret / Restricted Key",
    severity: "CRITICAL",
    regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/g,
  },
  {
    id: "TELEGRAM_BOT_TOKEN",
    label: "Telegram Bot API Token",
    severity: "HIGH",
    regex: /\b\d{8,11}:[A-Za-z0-9_-]{33,45}\b/g,
  },
  {
    id: "SLACK_TOKEN",
    label: "Slack Bot / User OAuth Token",
    severity: "HIGH",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
  },
  {
    id: "DB_URI_CREDENTIALS",
    label: "Database URI Embedded Password",
    severity: "HIGH",
    regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^:\s/@]+:([^@\s/]+)@/gi,
    captureGroup: 1,
  },
  {
    id: "JWT_TOKEN",
    label: "Signed JWT Bearer Token",
    severity: "MEDIUM",
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
]);

function shannonEntropy(input) {
  const s = String(input || "");
  if (!s.length) return 0;
  const counts = new Map();
  for (let i = 0; i < s.length; i += 1) {
    counts.set(s[i], (counts.get(s[i]) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function maskSecretValue(secret) {
  const s = String(secret || "");
  if (s.length <= 8) return "****";
  return `${s.slice(0, 4)}...${s.slice(-4)}`;
}

function computeLineNumber(text, index) {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function addSpanIfUnique(spans, candidate) {
  const overlaps = spans.some(
    (s) => candidate.start < s.end && candidate.end > s.start
  );
  if (!overlaps) spans.push(candidate);
}

export function scanSecrets(rawInput) {
  const text = String(rawInput ?? "");
  if (!text.trim()) {
    return {
      totalFindings: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      findings: [],
      redactedText: "",
    };
  }

  const spans = [];

  for (const rule of SECRET_RULES) {
    const rx = new RegExp(rule.regex.source, rule.regex.flags);
    let m;
    while ((m = rx.exec(text)) !== null) {
      let secretStr = m[0];
      let start = m.index;
      if (rule.captureGroup && m[rule.captureGroup]) {
        secretStr = m[rule.captureGroup];
        const rel = m[0].indexOf(secretStr);
        start = m.index + (rel >= 0 ? rel : 0);
      }
      const end = start + secretStr.length;
      if (secretStr.length > 0) {
        addSpanIfUnique(spans, {
          start,
          end,
          ruleId: rule.id,
          label: rule.label,
          severity: rule.severity,
          secretStr,
        });
      }
      if (m.index === rx.lastIndex) rx.lastIndex += 1;
    }
  }

  const envRx = /(?:^|\n)\s*([A-Z0-9_]*(?:SECRET|TOKEN|PASS(?:WORD)?|API_?KEY|PRIVATE)[A-Z0-9_]*)\s*=\s*["']?([^\s"'#]{16,})["']?/g;
  let em;
  while ((em = envRx.exec(text)) !== null) {
    const val = em[2];
    if (val.startsWith("<REDACTED:") || /^0x[0-9a-fA-F]{40}$/.test(val)) continue;
    if (shannonEntropy(val) >= 3.5) {
      const rel = em[0].lastIndexOf(val);
      const start = em.index + rel;
      addSpanIfUnique(spans, {
        start,
        end: start + val.length,
        ruleId: "HIGH_ENTROPY_SECRET",
        label: `High-Entropy Env Secret (${em[1]})`,
        severity: "HIGH",
        secretStr: val,
      });
    }
  }

  spans.sort((a, b) => a.start - b.start);

  let cursor = 0;
  const outChunks = [];
  const findings = spans.map((sp, idx) => {
    outChunks.push(text.slice(cursor, sp.start));
    outChunks.push(`<REDACTED:${sp.ruleId}>`);
    cursor = sp.end;
    return {
      index: idx + 1,
      line: computeLineNumber(text, sp.start),
      ruleId: sp.ruleId,
      label: sp.label,
      severity: sp.severity,
      previewMasked: maskSecretValue(sp.secretStr),
      length: sp.secretStr.length,
    };
  });
  outChunks.push(text.slice(cursor));

  return {
    totalFindings: findings.length,
    criticalCount: findings.filter((f) => f.severity === "CRITICAL").length,
    highCount: findings.filter((f) => f.severity === "HIGH").length,
    mediumCount: findings.filter((f) => f.severity === "MEDIUM").length,
    findings,
    redactedText: outChunks.join(""),
  };
}

/* ============================================================================
 * 2. Calldata Lens EVM ABI & Approval Risk Decoder (100% Offline)
 * ========================================================================== */

const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_UINT160 = (1n << 160n) - 1n;

export const KNOWN_SELECTORS = Object.freeze({
  "0xa9059cbb": {
    sig: "transfer(address to, uint256 value)",
    category: "ERC-20",
    risk: "ASSET_OUT",
    params: [
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
    ],
  },
  "0x23b872dd": {
    sig: "transferFrom(address from, address to, uint256 value)",
    category: "ERC-20",
    risk: "ASSET_OUT",
    params: [
      { name: "from", type: "address" },
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
    ],
  },
  "0x095ea7b3": {
    sig: "approve(address spender, uint256 value)",
    category: "ERC-20",
    risk: "ALLOWANCE",
    params: [
      { name: "spender", type: "address" },
      { name: "value", type: "uint256" },
    ],
  },
  "0x39509351": {
    sig: "increaseAllowance(address spender, uint256 addedValue)",
    category: "ERC-20",
    risk: "ALLOWANCE",
    params: [
      { name: "spender", type: "address" },
      { name: "addedValue", type: "uint256" },
    ],
  },
  "0xa457c2d7": {
    sig: "decreaseAllowance(address spender, uint256 subtractedValue)",
    category: "ERC-20",
    risk: "ALLOWANCE_REDUCE",
    params: [
      { name: "spender", type: "address" },
      { name: "subtractedValue", type: "uint256" },
    ],
  },
  "0xd505accf": {
    sig: "permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)",
    category: "EIP-2612",
    risk: "ALLOWANCE",
    params: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
      { name: "value", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "v", type: "uint8" },
      { name: "r", type: "bytes32" },
      { name: "s", type: "bytes32" },
    ],
  },
  "0x87517c45": {
    sig: "approve(address token, address spender, uint160 amount, uint48 expiration)",
    category: "Permit2",
    risk: "ALLOWANCE",
    params: [
      { name: "token", type: "address" },
      { name: "spender", type: "address" },
      { name: "amount", type: "uint160" },
      { name: "expiration", type: "uint48" },
    ],
  },
  "0xa22cb465": {
    sig: "setApprovalForAll(address operator, bool approved)",
    category: "ERC-721/1155",
    risk: "HIGH_ALLOWANCE",
    params: [
      { name: "operator", type: "address" },
      { name: "approved", type: "bool" },
    ],
  },
  "0x38ed1739": {
    sig: "swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)",
    category: "Uniswap V2",
    risk: "DEX_SWAP",
    params: [
      { name: "amountIn", type: "uint256" },
      { name: "amountOutMin", type: "uint256" },
      { name: "pathOffset", type: "uint256" },
      { name: "to", type: "address" },
      { name: "deadline", type: "uint256" },
    ],
  },
  "0x7ff36ab5": {
    sig: "swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)",
    category: "Uniswap V2",
    risk: "DEX_SWAP",
    params: [
      { name: "amountOutMin", type: "uint256" },
      { name: "pathOffset", type: "uint256" },
      { name: "to", type: "address" },
      { name: "deadline", type: "uint256" },
    ],
  },
  "0x18cbafe5": {
    sig: "swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)",
    category: "Uniswap V2",
    risk: "DEX_SWAP",
    params: [
      { name: "amountIn", type: "uint256" },
      { name: "amountOutMin", type: "uint256" },
      { name: "pathOffset", type: "uint256" },
      { name: "to", type: "address" },
      { name: "deadline", type: "uint256" },
    ],
  },
  "0x414bf389": {
    sig: "exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96))",
    category: "Uniswap V3",
    risk: "DEX_SWAP",
    params: [
      { name: "tokenIn", type: "address" },
      { name: "tokenOut", type: "address" },
      { name: "fee", type: "uint256" },
      { name: "recipient", type: "address" },
      { name: "deadline", type: "uint256" },
      { name: "amountIn", type: "uint256" },
      { name: "amountOutMinimum", type: "uint256" },
      { name: "sqrtPriceLimitX96", type: "uint160" },
    ],
  },
  "0x04e45aaf": {
    sig: "exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96))",
    category: "Uniswap V3 Router02",
    risk: "DEX_SWAP",
    params: [
      { name: "tokenIn", type: "address" },
      { name: "tokenOut", type: "address" },
      { name: "fee", type: "uint256" },
      { name: "recipient", type: "address" },
      { name: "amountIn", type: "uint256" },
      { name: "amountOutMinimum", type: "uint256" },
      { name: "sqrtPriceLimitX96", type: "uint160" },
    ],
  },
  "0x3593564c": {
    sig: "execute(bytes commands, bytes[] inputs, uint256 deadline)",
    category: "Uniswap Universal Router",
    risk: "BATCH_SWAP",
    params: [
      { name: "commandsOffset", type: "uint256" },
      { name: "inputsOffset", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  },
  "0x5ae401dc": {
    sig: "multicall(uint256 deadline, bytes[] data)",
    category: "Uniswap Router",
    risk: "BATCH_CALL",
    params: [
      { name: "deadline", type: "uint256" },
      { name: "dataOffset", type: "uint256" },
    ],
  },
  "0xac9650d8": {
    sig: "multicall(bytes[] data)",
    category: "Router",
    risk: "BATCH_CALL",
    params: [{ name: "dataOffset", type: "uint256" }],
  },
  "0xd0e30db0": {
    sig: "deposit()",
    category: "WETH9",
    risk: "WRAP_NATIVE",
    params: [],
  },
  "0x2e1a7d4d": {
    sig: "withdraw(uint256 wad)",
    category: "WETH9",
    risk: "UNWRAP_NATIVE",
    params: [{ name: "wad", type: "uint256" }],
  },
  "0x6e553f65": {
    sig: "deposit(uint256 assets, address receiver)",
    category: "ERC-4626",
    risk: "ASSET_OUT",
    params: [
      { name: "assets", type: "uint256" },
      { name: "receiver", type: "address" },
    ],
  },
  "0xba087652": {
    sig: "redeem(uint256 shares, address receiver, address owner)",
    category: "ERC-4626",
    risk: "ASSET_MOVE",
    params: [
      { name: "shares", type: "uint256" },
      { name: "receiver", type: "address" },
      { name: "owner", type: "address" },
    ],
  },
  "0xb460af94": {
    sig: "withdraw(uint256 assets, address receiver, address owner)",
    category: "ERC-4626",
    risk: "ASSET_MOVE",
    params: [
      { name: "assets", type: "uint256" },
      { name: "receiver", type: "address" },
      { name: "owner", type: "address" },
    ],
  },
  "0x6a761202": {
    sig: "execTransaction(address to, uint256 value, bytes data, uint8 operation, ...)",
    category: "Safe Multisig",
    risk: "ADMIN_EXEC",
    params: [
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
      { name: "dataOffset", type: "uint256" },
      { name: "operation", type: "uint8" },
    ],
  },
  "0xf2fde38b": {
    sig: "transferOwnership(address newOwner)",
    category: "AccessControl",
    risk: "HIGH_ADMIN",
    params: [{ name: "newOwner", type: "address" }],
  },
  "0x2f2ff15d": {
    sig: "grantRole(bytes32 role, address account)",
    category: "AccessControl",
    risk: "HIGH_ADMIN",
    params: [
      { name: "role", type: "bytes32" },
      { name: "account", type: "address" },
    ],
  },
});

function formatScaledUnits(bigVal, decimals) {
  const factor = 10n ** BigInt(decimals);
  const whole = bigVal / factor;
  const frac = (bigVal % factor)
    .toString()
    .padStart(decimals, "0")
    .slice(0, 6)
    .replace(/0+$/, "");
  return frac
    ? `${whole.toLocaleString("en-US")}.${frac}`
    : whole.toLocaleString("en-US");
}

function decodeWordAs(wordHex, type) {
  const normalized = wordHex.padStart(64, "0");
  if (type === "address") {
    return {
      raw: `0x${normalized}`,
      formatted: `0x${normalized.slice(24)}`,
      note:
        normalized.slice(0, 24) === "000000000000000000000000"
          ? "valid 20-byte EVM address"
          : "non-zero upper padding!",
      isUnlimited: false,
    };
  }
  const bigVal = BigInt(`0x${normalized}`);
  if (type === "bool") {
    return {
      raw: `0x${normalized}`,
      formatted: bigVal === 0n ? "false" : "true",
      note: bigVal === 0n ? "boolean false" : "boolean true",
      isUnlimited: false,
    };
  }
  if (type === "uint8" || type === "uint48") {
    return {
      raw: `0x${normalized}`,
      formatted: bigVal.toString(),
      note: type,
      isUnlimited: false,
    };
  }
  if (type === "uint160") {
    const isMax = bigVal >= MAX_UINT160;
    return {
      raw: `0x${normalized}`,
      formatted: isMax ? "MAX_UINT160 (Unlimited Permit2)" : bigVal.toString(),
      note: isMax
        ? "UNLIMITED / INFINITE PERMIT2 APPROVAL RISK"
        : `18dp: ${formatScaledUnits(bigVal, 18)} | 6dp: ${formatScaledUnits(bigVal, 6)}`,
      isUnlimited: isMax,
    };
  }
  if (type === "uint256") {
    const isMax = bigVal === MAX_UINT256;
    return {
      raw: `0x${normalized}`,
      formatted: isMax ? "MAX_UINT256 (Unlimited)" : bigVal.toString(),
      note: isMax
        ? "UNLIMITED / INFINITE APPROVAL RISK"
        : `18dp: ${formatScaledUnits(bigVal, 18)} | 6dp: ${formatScaledUnits(bigVal, 6)}`,
      isUnlimited: isMax,
    };
  }
  return {
    raw: `0x${normalized}`,
    formatted: `0x${normalized}`,
    note: "bytes32 word",
    isUnlimited: false,
  };
}

export function decodeCalldata(rawInput) {
  const cleaned = String(rawInput ?? "").trim().replace(/\s+/g, "").toLowerCase();
  const hex = cleaned.startsWith("0x") ? cleaned.slice(2) : cleaned;

  if (!hex || !/^[0-9a-f]+$/.test(hex) || hex.length < 8 || hex.length % 2 !== 0) {
    return {
      ok: false,
      error: "Invalid hex calldata (need >= 4 bytes / 8 hex chars, even length).",
    };
  }

  const selector = `0x${hex.slice(0, 8)}`;
  const body = hex.slice(8);
  const words = [];
  for (let i = 0; i < body.length; i += 64) {
    words.push(body.slice(i, i + 64));
  }

  const match = KNOWN_SELECTORS[selector] || null;
  const warnings = [];
  let unlimitedApprovalRisk = false;

  const decodedArgs = words.map((w, idx) => {
    const spec = match?.params?.[idx];
    const type =
      spec?.type ||
      (w.length === 64 &&
      w.startsWith("000000000000000000000000") &&
      w.slice(24) !== "0".repeat(40)
        ? "address"
        : "uint256");
    const parsed =
      w.length === 64
        ? decodeWordAs(w, type)
        : {
            raw: `0x${w}`,
            formatted: `0x${w}`,
            note: "partial trailing bytes",
            isUnlimited: false,
          };
    if (parsed.isUnlimited) {
      unlimitedApprovalRisk = true;
      warnings.push(
        `CRITICAL: Slot #${idx} (${spec?.name || `arg${idx}`}) grants UNLIMITED (${parsed.formatted}) allowance!`
      );
    }
    return {
      slot: idx,
      name: spec?.name || `arg${idx}`,
      type: spec?.type || `inferred:${type}`,
      raw: parsed.raw,
      formatted: parsed.formatted,
      note: parsed.note,
    };
  });

  if (selector === "0xa22cb465" && decodedArgs[1]?.formatted === "true") {
    unlimitedApprovalRisk = true;
    warnings.push(
      `CRITICAL: setApprovalForAll grants operator ${decodedArgs[0]?.formatted} full control over ALL NFTs in collection!`
    );
  }
  if (match?.risk === "HIGH_ADMIN") {
    warnings.push(`HIGH_ADMIN: ${match.sig} changes privileged contract ownership or access roles.`);
  }

  return {
    ok: true,
    selector,
    known: Boolean(match),
    signature: match?.sig || "Unknown 4-byte selector (raw ABI slot inspection)",
    category: match?.category || "Custom Contract",
    risk: unlimitedApprovalRisk ? "UNLIMITED_APPROVAL_RISK" : match?.risk || "UNKNOWN",
    unlimitedApprovalRisk,
    warnings,
    byteLength: hex.length / 2,
    wordCount: words.length,
    args: decodedArgs,
  };
}

/* ============================================================================
 * 3. TokenCost Lab Estimator (100% Offline, Single & Multi-Turn Agent Runs)
 * ========================================================================== */

export const MODEL_PRICING = Object.freeze([
  {
    id: "gpt-5",
    provider: "OpenAI",
    name: "GPT-5 Flagship",
    contextWindow: 400_000,
    inputPer1M: 1.25,
    cachedInputPer1M: 0.125,
    outputPer1M: 10.0,
  },
  {
    id: "gpt-5-mini",
    provider: "OpenAI",
    name: "GPT-5 Mini",
    contextWindow: 400_000,
    inputPer1M: 0.25,
    cachedInputPer1M: 0.025,
    outputPer1M: 2.0,
  },
  {
    id: "claude-opus-4.5",
    provider: "Anthropic",
    name: "Claude Opus 4.5",
    contextWindow: 200_000,
    inputPer1M: 5.0,
    cachedInputPer1M: 0.5,
    outputPer1M: 25.0,
  },
  {
    id: "claude-sonnet-4.5",
    provider: "Anthropic",
    name: "Claude Sonnet 4.5",
    contextWindow: 200_000,
    inputPer1M: 3.0,
    cachedInputPer1M: 0.3,
    outputPer1M: 15.0,
  },
  {
    id: "claude-haiku-4.5",
    provider: "Anthropic",
    name: "Claude Haiku 4.5",
    contextWindow: 200_000,
    inputPer1M: 0.8,
    cachedInputPer1M: 0.08,
    outputPer1M: 4.0,
  },
  {
    id: "gemini-2.5-pro",
    provider: "Google",
    name: "Gemini 2.5 Pro",
    contextWindow: 1_000_000,
    inputPer1M: 1.25,
    cachedInputPer1M: 0.31,
    outputPer1M: 10.0,
  },
  {
    id: "gemini-2.5-flash",
    provider: "Google",
    name: "Gemini 2.5 Flash",
    contextWindow: 1_000_000,
    inputPer1M: 0.3,
    cachedInputPer1M: 0.075,
    outputPer1M: 2.5,
  },
  {
    id: "deepseek-v3",
    provider: "DeepSeek",
    name: "DeepSeek V3 / Chat",
    contextWindow: 128_000,
    inputPer1M: 0.27,
    cachedInputPer1M: 0.07,
    outputPer1M: 1.1,
  },
]);

export function estimateTokenCount(text) {
  const src = String(text ?? "");
  const chars = src.length;
  if (chars === 0) {
    return { tokens: 0, chars: 0, words: 0, lines: 0, bytesUtf8: 0 };
  }

  let nonAscii = 0;
  let symbols = 0;
  let inWord = false;
  let words = 0;
  let lines = 1;

  for (let i = 0; i < chars; i += 1) {
    const c = src.charCodeAt(i);
    if (c === 10) lines += 1;
    if (c > 127) {
      nonAscii += 1;
      inWord = false;
      continue;
    }
    const isWs = c === 32 || c === 9 || c === 10 || c === 13;
    if (isWs) {
      inWord = false;
      continue;
    }
    if (!inWord) {
      words += 1;
      inWord = true;
    }
    const isAlnum =
      (c >= 48 && c <= 57) ||
      (c >= 65 && c <= 90) ||
      (c >= 97 && c <= 122);
    if (!isAlnum) symbols += 1;
  }

  const asciiChars = chars - nonAscii;
  const asciiScore = asciiChars / 3.9 + symbols * 0.22;
  const unicodeScore = nonAscii * 0.65;
  const tokens = Math.max(1, Math.ceil(asciiScore + unicodeScore));
  const bytesUtf8 = new TextEncoder().encode(src).length;

  return { tokens, chars, words, lines, bytesUtf8 };
}

export function estimateTokenCost(params = {}) {
  const promptStats =
    typeof params.prompt === "string" && params.prompt.length > 0
      ? estimateTokenCount(params.prompt)
      : null;

  const baseInputTokens =
    params.inputTokens !== undefined && params.inputTokens !== null
      ? Math.max(0, Number(params.inputTokens) || 0)
      : promptStats
        ? promptStats.tokens
        : 2000;
  const outputTokensPerTurn = Math.max(0, Number(params.outputTokens ?? 600) || 0);
  const turns = Math.max(1, Math.min(100, Math.floor(Number(params.turns ?? 1) || 1)));
  const toolTokensPerTurn = Math.max(0, Number(params.toolTokensPerTurn ?? 0) || 0);
  const cachedRatioPct = Math.min(100, Math.max(0, Number(params.cachedRatioPct ?? 0) || 0));
  const requestsPerDay = Math.max(0, Number(params.requestsPerDay ?? 100) || 0);
  const daysPerMonth = Math.max(1, Number(params.daysPerMonth ?? 30) || 30);
  const marginMultiplier = Math.max(1, Number(params.marginMultiplier ?? 1) || 1);

  // Multi-turn agent context accumulation: turn k re-sends baseInput + (k-1)*(output + toolTokens)
  let totalInputTokensPerRun = 0;
  let peakContextTokens = 0;
  const growthPerTurn = outputTokensPerTurn + toolTokensPerTurn;
  for (let t = 0; t < turns; t += 1) {
    const turnIn = baseInputTokens + t * growthPerTurn;
    totalInputTokensPerRun += turnIn;
    peakContextTokens = Math.max(peakContextTokens, turnIn + outputTokensPerTurn);
  }
  const totalOutputTokensPerRun = outputTokensPerTurn * turns;
  const cacheShare = cachedRatioPct / 100;

  let models = MODEL_PRICING;
  if (params.model) {
    const query = String(params.model).trim().toLowerCase();
    const filtered = MODEL_PRICING.filter(
      (m) =>
        m.id.toLowerCase().includes(query) ||
        m.name.toLowerCase().includes(query) ||
        m.provider.toLowerCase().includes(query)
    );
    if (filtered.length > 0) models = filtered;
  }

  const estimates = models
    .map((m) => {
      const cachedIn = totalInputTokensPerRun * cacheShare;
      const uncachedIn = totalInputTokensPerRun - cachedIn;
      const runInputCost =
        (uncachedIn / 1_000_000) * m.inputPer1M +
        (cachedIn / 1_000_000) * m.cachedInputPer1M;
      const runOutputCost = (totalOutputTokensPerRun / 1_000_000) * m.outputPer1M;
      const costPerRunUsd = runInputCost + runOutputCost;
      const dailyCostUsd = costPerRunUsd * requestsPerDay;
      const monthlyRawCostUsd = dailyCostUsd * daysPerMonth;
      const monthlyClientQuoteUsd = monthlyRawCostUsd * marginMultiplier;
      const contextFillPct = Number(
        Math.min(999, (peakContextTokens / m.contextWindow) * 100).toFixed(2)
      );

      return {
        modelId: m.id,
        provider: m.provider,
        modelName: m.name,
        contextWindow: m.contextWindow,
        contextFillPct,
        exceedsContextWindow: peakContextTokens > m.contextWindow,
        costPerRunUsd: Number(costPerRunUsd.toFixed(6)),
        dailyCostUsd: Number(dailyCostUsd.toFixed(4)),
        monthlyRawCostUsd: Number(monthlyRawCostUsd.toFixed(2)),
        monthlyClientQuoteUsd: Number(monthlyClientQuoteUsd.toFixed(2)),
      };
    })
    .sort((a, b) => a.costPerRunUsd - b.costPerRunUsd);

  return {
    assumptions: {
      baseInputTokens,
      outputTokensPerTurn,
      toolTokensPerTurn,
      turns,
      totalInputTokensPerRun,
      totalOutputTokensPerRun,
      peakContextTokens,
      cachedRatioPct,
      requestsPerDay,
      daysPerMonth,
      monthlyRuns: requestsPerDay * daysPerMonth,
      marginMultiplier,
    },
    promptStats,
    cheapestModel: estimates[0]?.modelId || null,
    estimates,
  };
}

/* ============================================================================
 * 4. CryptoBill Forge Invoice & Payment Quote Generator (100% Offline)
 * ========================================================================== */

const SUPPORTED_CURRENCIES = Object.freeze({
  USD: { code: "USD", symbol: "$", position: "prefix" },
  EUR: { code: "EUR", symbol: "€", position: "prefix" },
  USDT: { code: "USDT", symbol: "USDT", position: "suffix" },
});

function round2(num) {
  return Math.round((Number(num) + Number.EPSILON) * 100) / 100;
}

function clamp(num, min, max) {
  if (!Number.isFinite(num)) return min;
  return Math.min(max, Math.max(min, num));
}

function formatMoney(amount, currency = "USDT") {
  const num = Number.isFinite(Number(amount)) ? Number(amount) : 0;
  const formatted = num.toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
  const spec = SUPPORTED_CURRENCIES[currency] || SUPPORTED_CURRENCIES.USDT;
  return spec.position === "suffix"
    ? `${formatted} ${spec.symbol}`
    : `${spec.symbol}${formatted}`;
}

function encodeBase64UrlUtf8(jsonStr) {
  return Buffer.from(jsonStr, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function getIsoDate(offsetDays = 0) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

export function generateCryptoBillQuote(params = {}) {
  const rawItems = Array.isArray(params.items) ? params.items : [];
  if (rawItems.length === 0) {
    return {
      ok: false,
      error: "At least one line item with description and unitPrice is required.",
    };
  }

  const currency = SUPPORTED_CURRENCIES[String(params.currency || "USDT").toUpperCase()]
    ? String(params.currency || "USDT").toUpperCase()
    : "USDT";
  const taxPercent = clamp(Number(params.taxPercent ?? 0) || 0, 0, 100);
  const discountPercent = clamp(Number(params.discountPercent ?? 0) || 0, 0, 100);
  const dueDays = clamp(Math.floor(Number(params.dueDays ?? 7) || 7), 0, 365);

  const items = rawItems.map((it, idx) => {
    const qty = Math.max(0, Number(it?.qty ?? 1) || 0);
    const unitPrice = Math.max(0, Number(it?.unitPrice ?? 0) || 0);
    return {
      description: String(it?.description || `Deliverable #${idx + 1}`).trim(),
      qty,
      unitPrice: round2(unitPrice),
      lineTotal: round2(qty * unitPrice),
    };
  });

  const subtotal = round2(items.reduce((acc, it) => acc + it.lineTotal, 0));
  const discountAmount = round2(subtotal * (discountPercent / 100));
  const taxableAmount = round2(Math.max(0, subtotal - discountAmount));
  const taxAmount = round2(taxableAmount * (taxPercent / 100));
  const grandTotal = round2(taxableAmount + taxAmount);

  const issueDate = String(params.issueDate || getIsoDate(0));
  const dueDate = String(params.dueDate || getIsoDate(dueDays));
  const invoiceNumber = String(params.invoiceNumber || `INV-${issueDate.replace(/-/g, "")}-01`).trim();
  const businessName = String(params.businessName || "ForgeSuite Contractor").trim();
  const businessEmail = String(params.businessEmail || "").trim();
  const clientName = String(params.clientName || "Client").trim();
  const clientEmail = String(params.clientEmail || "").trim();
  const notes = String(
    params.notes ||
      `Please include invoice reference ${invoiceNumber} with your payment transfer.`
  ).trim();

  const pm = params.paymentMethods && typeof params.paymentMethods === "object"
    ? params.paymentMethods
    : {};
  const paymentMethods = {
    bep20: String(pm.bep20 || "").trim(),
    trc20: String(pm.trc20 || "").trim(),
    paypalEmail: String(pm.paypalEmail || "").trim(),
    binancePayId: String(pm.binancePayId || "").trim(),
  };
  const solanaUsdc = String(pm.solanaUsdc || "").trim();

  // Payload compatible with assets/cryptobill.js decodeInvoicePayload(#inv=...)
  const sharePayload = {
    businessName,
    businessEmail,
    clientName,
    clientEmail,
    invoiceNumber,
    issueDate,
    dueDate,
    currency,
    taxPercent,
    discountPercent,
    notes: solanaUsdc ? `${notes}\nSolana USDC Wallet: ${solanaUsdc}` : notes,
    paymentMethods,
    qrMethod: "auto",
    branding: {
      accentColor: "#2563eb",
      logoText: businessName.slice(0, 2).toUpperCase() || "FS",
      hideFooterBadge: false,
    },
    items: items.map(({ description, qty, unitPrice }) => ({
      description,
      qty,
      unitPrice,
    })),
  };

  const invHash = encodeBase64UrlUtf8(JSON.stringify(sharePayload));
  const shareUrl = `${FORGESUITE_LINKS.cryptobill}#inv=${invHash}`;

  const railLines = [];
  if (paymentMethods.bep20) railLines.push(`- **USDT (BEP20 / BSC):** \`${paymentMethods.bep20}\``);
  if (solanaUsdc) railLines.push(`- **USDC (Solana SPL):** \`${solanaUsdc}\``);
  if (paymentMethods.trc20) railLines.push(`- **USDT (TRC20 / TRON):** \`${paymentMethods.trc20}\``);
  if (paymentMethods.binancePayId) railLines.push(`- **Binance Pay UID:** \`${paymentMethods.binancePayId}\``);
  if (paymentMethods.paypalEmail) railLines.push(`- **PayPal:** \`${paymentMethods.paypalEmail}\``);
  if (railLines.length === 0) {
    railLines.push(`- Configure your receiving BEP20 / TRC20 / Solana / PayPal address in [CryptoBill Forge](${shareUrl}).`);
  }

  const itemRows = items
    .map(
      (it) =>
        `| ${it.description.replace(/\|/g, "\\|")} | ${it.qty} | ${formatMoney(it.unitPrice, currency)} | ${formatMoney(it.lineTotal, currency)} |`
    )
    .join("\n");

  const markdown = [
    `# Invoice ${invoiceNumber}`,
    "",
    `- **From:** ${businessName}${businessEmail ? ` (${businessEmail})` : ""}`,
    `- **Bill To:** ${clientName}${clientEmail ? ` (${clientEmail})` : ""}`,
    `- **Issue Date:** ${issueDate} | **Due Date:** ${dueDate}`,
    `- **Currency:** ${currency}`,
    "",
    "| Deliverable | Qty | Unit Price | Line Total |",
    "| :--- | :---: | :---: | :---: |",
    itemRows,
    "",
    `- **Subtotal:** ${formatMoney(subtotal, currency)}`,
    ...(discountPercent > 0
      ? [`- **Discount (${discountPercent}%):** -${formatMoney(discountAmount, currency)}`]
      : []),
    ...(taxPercent > 0
      ? [`- **Tax (${taxPercent}%):** +${formatMoney(taxAmount, currency)}`]
      : []),
    `- **Total Due:** **${formatMoney(grandTotal, currency)}**`,
    "",
    "## Payment Instructions",
    ...railLines,
    "",
    `> ${notes}`,
    "",
    "---",
    `- Open A4 PDF & Offline QR Payment View: ${shareUrl}`,
    `- Interactive CryptoBill Forge (Free & $15 Pro): ${FORGESUITE_LINKS.cryptobill}`,
    `- Unlock All-Access ForgeSuite Pro Bundle ($35 Lifetime, Save $14): ${FORGESUITE_LINKS.pricing}`,
  ].join("\n");

  return {
    ok: true,
    invoice: {
      invoiceNumber,
      businessName,
      businessEmail,
      clientName,
      clientEmail,
      issueDate,
      dueDate,
      currency,
      items,
      subtotal,
      discountPercent,
      discountAmount,
      taxPercent,
      taxAmount,
      grandTotal,
      formattedTotal: formatMoney(grandTotal, currency),
      paymentMethods: { ...paymentMethods, solanaUsdc },
      notes,
    },
    links: {
      shareableInvoiceUrl: shareUrl,
      cryptobillApp: FORGESUITE_LINKS.cryptobill,
      proBundleUrl: FORGESUITE_LINKS.pricing,
      proBundlePriceUsd: 35,
    },
    markdown,
  };
}

/* ============================================================================
 * 5. MCP Tool Definitions & Dispatch
 * ========================================================================== */

export const TOOLS = Object.freeze([
  {
    name: "envshield_scan",
    description:
      "Scan .env files, JSON configs, shell logs, or transcripts 100% offline for leaked API keys (OpenAI, Anthropic, GitHub, AWS, Google, Stripe, Telegram, Slack), 64-hex EVM private keys, seed mnemonics, JWTs, database URI passwords, and high-entropy secrets. Returns structured findings and safely redacted text.",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "Raw .env, config, JSON, diff, or log text to scan locally.",
        },
        includeRedacted: {
          type: "boolean",
          description: "Include the safely redacted text in the output (default: true).",
          default: true,
        },
      },
      required: ["text"],
    },
  },
  {
    name: "calldata_decode",
    description:
      "Decode Ethereum / BSC / EVM 0x hex calldata 100% offline. Recognizes ERC-20 (transfer, approve, transferFrom, increaseAllowance), EIP-2612 permit, Permit2 approve, ERC-721/1155 setApprovalForAll, Uniswap V2/V3/Universal Router swaps, WETH9, ERC-4626 vaults, and Safe/AccessControl calls, and explicitly flags unlimited MaxUint256 / MaxUint160 approval risks.",
    inputSchema: {
      type: "object",
      properties: {
        calldata: {
          type: "string",
          description: "Hex-encoded EVM transaction calldata (with or without 0x prefix).",
        },
      },
      required: ["calldata"],
    },
  },
  {
    name: "tokencost_estimate",
    description:
      "Estimate LLM API and multi-turn AI agent run costs offline across major frontier models (Claude Opus/Sonnet/Haiku 4.5, GPT-5/Mini, Gemini 2.5 Pro/Flash, DeepSeek V3), including prompt caching, multi-turn context growth, daily/monthly projections, and client retainer quotes.",
    inputSchema: {
      type: "object",
      properties: {
        prompt: {
          type: "string",
          description: "Optional sample prompt text to auto-estimate input token count offline.",
        },
        inputTokens: {
          type: "number",
          description: "Explicit input token count per initial turn (overrides prompt estimate).",
        },
        outputTokens: {
          type: "number",
          description: "Expected output tokens generated per turn (default: 600).",
          default: 600,
        },
        turns: {
          type: "number",
          description: "Number of agent turns per run with context accumulation (default: 1).",
          default: 1,
        },
        toolTokensPerTurn: {
          type: "number",
          description: "Extra tool-response tokens appended to context after each turn (default: 0).",
          default: 0,
        },
        cachedRatioPct: {
          type: "number",
          description: "Percentage of input tokens served from prompt cache (0-100, default: 0).",
          default: 0,
        },
        requestsPerDay: {
          type: "number",
          description: "Number of runs per day for daily/monthly cost projection (default: 100).",
          default: 100,
        },
        daysPerMonth: {
          type: "number",
          description: "Active billing days per month (default: 30).",
          default: 30,
        },
        marginMultiplier: {
          type: "number",
          description: "Optional agency/SaaS quote multiplier (e.g. 1.5 for 50% markup, default: 1).",
          default: 1,
        },
        model: {
          type: "string",
          description: "Optional model/provider filter (e.g. 'claude', 'gpt-5', 'gemini', 'deepseek'). Omit to compare all models.",
        },
      },
    },
  },
  {
    name: "cryptobill_quote",
    description:
      "Generate a clean Markdown and/or JSON freelance crypto invoice & payment block with exact subtotal/discount/tax math plus a live serverless CryptoBill Forge #inv= share URL (A4 PDF & offline QR) and Pro Bundle ($35) reference.",
    inputSchema: {
      type: "object",
      properties: {
        businessName: { type: "string", description: "Sender / contractor business name." },
        businessEmail: { type: "string", description: "Optional sender contact email." },
        clientName: { type: "string", description: "Client or organization name being billed." },
        clientEmail: { type: "string", description: "Optional client billing email." },
        invoiceNumber: { type: "string", description: "Invoice reference number (e.g. INV-2026-042)." },
        currency: {
          type: "string",
          enum: ["USDT", "USD", "EUR"],
          description: "Invoice currency (default: USDT).",
          default: "USDT",
        },
        items: {
          type: "array",
          description: "Line items to bill.",
          items: {
            type: "object",
            properties: {
              description: { type: "string" },
              qty: { type: "number", default: 1 },
              unitPrice: { type: "number" },
            },
            required: ["description", "unitPrice"],
          },
        },
        taxPercent: { type: "number", description: "Tax percentage (0-100, default: 0).", default: 0 },
        discountPercent: { type: "number", description: "Discount percentage (0-100, default: 0).", default: 0 },
        dueDays: { type: "number", description: "Days until invoice due date (default: 7).", default: 7 },
        notes: { type: "string", description: "Optional invoice footer note or payment reference instruction." },
        paymentMethods: {
          type: "object",
          description: "Optional receiving addresses/IDs (bep20, trc20, solanaUsdc, paypalEmail, binancePayId).",
          properties: {
            bep20: { type: "string" },
            trc20: { type: "string" },
            solanaUsdc: { type: "string" },
            paypalEmail: { type: "string" },
            binancePayId: { type: "string" },
          },
        },
        format: {
          type: "string",
          enum: ["markdown", "json", "both"],
          description: "Response text formatting preference (default: both).",
          default: "both",
        },
      },
      required: ["clientName", "items"],
    },
  },
]);

function executeTool(name, args = {}) {
  const safeArgs = args && typeof args === "object" && !Array.isArray(args) ? args : {};

  switch (name) {
    case "envshield_scan": {
      if (typeof safeArgs.text !== "string") {
        return {
          isError: true,
          content: [{ type: "text", text: "Invalid argument: 'text' must be a string." }],
        };
      }
      const res = scanSecrets(safeArgs.text);
      const includeRedacted = safeArgs.includeRedacted !== false;
      const summaryLines = [
        res.totalFindings === 0
          ? "EnvShield Scan: CLEAN (0 exposed secret signatures detected)."
          : `EnvShield Scan: ${res.totalFindings} exposed secret(s) detected (${res.criticalCount} Critical, ${res.highCount} High, ${res.mediumCount} Medium).`,
      ];
      if (res.findings.length > 0) {
        summaryLines.push("", "Findings:");
        for (const f of res.findings) {
          summaryLines.push(
            `- L${f.line} [${f.severity}] ${f.label} (${f.ruleId}): ${f.previewMasked} (${f.length} chars)`
          );
        }
      }
      if (includeRedacted) {
        summaryLines.push("", "Redacted Output:", "```", res.redactedText, "```");
      }
      summaryLines.push("", `Web UI (100% offline): ${FORGESUITE_LINKS.envshield}`);
      return {
        isError: false,
        content: [{ type: "text", text: summaryLines.join("\n") }],
        structuredContent: includeRedacted
          ? res
          : { ...res, redactedText: undefined },
      };
    }

    case "calldata_decode": {
      if (typeof safeArgs.calldata !== "string") {
        return {
          isError: true,
          content: [{ type: "text", text: "Invalid argument: 'calldata' must be a hex string." }],
        };
      }
      const res = decodeCalldata(safeArgs.calldata);
      if (!res.ok) {
        return {
          isError: true,
          content: [{ type: "text", text: `Calldata Decode Error: ${res.error}` }],
          structuredContent: res,
        };
      }
      const lines = [
        `Selector: ${res.selector}`,
        `Signature: ${res.signature}`,
        `Category: ${res.category} | Risk: ${res.risk}`,
        `Size: ${res.byteLength} bytes (${res.wordCount} ABI words)`,
      ];
      if (res.warnings.length > 0) {
        lines.push("", "Security Warnings:");
        for (const w of res.warnings) lines.push(`- ${w}`);
      }
      if (res.args.length > 0) {
        lines.push("", "Decoded Parameters:");
        for (const a of res.args) {
          lines.push(`- [${a.slot}] ${a.name} (${a.type}): ${a.formatted} — ${a.note}`);
        }
      }
      lines.push("", `Web UI (100% offline): ${FORGESUITE_LINKS.txdecode}`);
      return {
        isError: false,
        content: [{ type: "text", text: lines.join("\n") }],
        structuredContent: res,
      };
    }

    case "tokencost_estimate": {
      const res = estimateTokenCost(safeArgs);
      const a = res.assumptions;
      const header = [
        `TokenCost Estimate (${a.turns} turn(s), ${a.totalInputTokensPerRun.toLocaleString("en-US")} total in / ${a.totalOutputTokensPerRun.toLocaleString("en-US")} total out tokens per run, ${a.cachedRatioPct}% cached, ${a.requestsPerDay}/day × ${a.daysPerMonth}d):`,
        "",
        "| Provider | Model | Cost / Run | Daily | Monthly Raw | Client Quote | Context Fill |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: |",
      ];
      const rows = res.estimates.map(
        (e) =>
          `| ${e.provider} | ${e.modelName} | $${e.costPerRunUsd.toFixed(5)} | $${e.dailyCostUsd.toFixed(2)} | $${e.monthlyRawCostUsd.toFixed(2)} | $${e.monthlyClientQuoteUsd.toFixed(2)} | ${e.contextFillPct}%${e.exceedsContextWindow ? " (OVER!)" : ""} |`
      );
      const footer = [
        "",
        `Cheapest option: ${res.cheapestModel || "n/a"}`,
        `Interactive TokenCost Lab: ${FORGESUITE_LINKS.tokencalc}`,
      ];
      return {
        isError: false,
        content: [{ type: "text", text: [...header, ...rows, ...footer].join("\n") }],
        structuredContent: res,
      };
    }

    case "cryptobill_quote": {
      const res = generateCryptoBillQuote(safeArgs);
      if (!res.ok) {
        return {
          isError: true,
          content: [{ type: "text", text: `CryptoBill Quote Error: ${res.error}` }],
          structuredContent: res,
        };
      }
      const fmt = String(safeArgs.format || "both").toLowerCase();
      let text;
      if (fmt === "json") {
        text = JSON.stringify({ invoice: res.invoice, links: res.links }, null, 2);
      } else if (fmt === "markdown") {
        text = res.markdown;
      } else {
        text = `${res.markdown}\n\n\`\`\`json\n${JSON.stringify({ invoice: res.invoice, links: res.links }, null, 2)}\n\`\`\``;
      }
      return {
        isError: false,
        content: [{ type: "text", text }],
        structuredContent: { invoice: res.invoice, links: res.links },
      };
    }

    default:
      return null;
  }
}

/* ============================================================================
 * 6. JSON-RPC 2.0 MCP Protocol Router
 * ========================================================================== */

function rpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function rpcError(id, code, message, data) {
  const err = { code, message };
  if (data !== undefined) err.data = data;
  return { jsonrpc: "2.0", id: id ?? null, error: err };
}

/**
 * Process one parsed JSON-RPC 2.0 message.
 * Returns a response object, or `null` for notifications (no response permitted).
 */
export function handleJsonRpcMessage(msg) {
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
    return rpcError(null, -32600, "Invalid Request: expected JSON-RPC object.");
  }

  const hasId = Object.prototype.hasOwnProperty.call(msg, "id") && msg.id !== undefined;
  const id = hasId ? msg.id : null;

  if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    return hasId ? rpcError(id, -32600, "Invalid Request: missing jsonrpc '2.0' or method.") : null;
  }

  // Notifications must never receive a response per JSON-RPC 2.0 & MCP spec
  if (!hasId) {
    return null;
  }

  const params = msg.params && typeof msg.params === "object" ? msg.params : {};

  switch (msg.method) {
    case "initialize": {
      const requested = typeof params.protocolVersion === "string" ? params.protocolVersion : "";
      const negotiated = SUPPORTED_PROTOCOL_VERSIONS.includes(requested)
        ? requested
        : SUPPORTED_PROTOCOL_VERSIONS[0];
      return rpcResult(id, {
        protocolVersion: negotiated,
        capabilities: {
          tools: { listChanged: false },
        },
        serverInfo: SERVER_INFO,
        instructions:
          "ForgeSuite MCP Server provides 4 zero-dependency, 100% offline tools: envshield_scan (.env/secret leak redactor), calldata_decode (EVM ABI & unlimited approval risk detector), tokencost_estimate (LLM & multi-turn agent cost estimator), and cryptobill_quote (Markdown/JSON crypto invoice & live CryptoBill #inv= generator). Docs: https://youthmy11-ai.github.io/mcp.html",
      });
    }

    case "ping":
      return rpcResult(id, {});

    case "tools/list":
      return rpcResult(id, { tools: TOOLS });

    case "tools/call": {
      const toolName = params.name;
      if (typeof toolName !== "string" || !toolName) {
        return rpcError(id, -32602, "Invalid params: missing tool 'name'.");
      }
      const result = executeTool(toolName, params.arguments);
      if (result === null) {
        return rpcError(id, -32602, `Unknown tool: ${toolName}`);
      }
      return rpcResult(id, result);
    }

    default:
      return rpcError(id, -32601, `Method not found: ${msg.method}`);
  }
}

/* ============================================================================
 * 7. Stdio Transport (Newline-Delimited JSON-RPC + Content-Length Fallback)
 * ========================================================================== */

function startStdioServer() {
  let buffer = Buffer.alloc(0);

  function send(payload) {
    if (!payload) return;
    process.stdout.write(`${JSON.stringify(payload)}\n`);
  }

  function dispatchRawJson(rawText) {
    const trimmed = rawText.trim();
    if (!trimmed) return;
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (err) {
      send(rpcError(null, -32700, "Parse error: invalid JSON.", err instanceof Error ? err.message : String(err)));
      return;
    }
    if (Array.isArray(parsed)) {
      if (parsed.length === 0) {
        send(rpcError(null, -32600, "Invalid Request: empty batch."));
        return;
      }
      const responses = parsed.map((item) => handleJsonRpcMessage(item)).filter(Boolean);
      if (responses.length > 0) send(responses);
      return;
    }
    const response = handleJsonRpcMessage(parsed);
    if (response) send(response);
  }

  function drainBuffer() {
    while (buffer.length > 0) {
      // Trim leading CR/LF whitespace between messages
      let offset = 0;
      while (offset < buffer.length && (buffer[offset] === 0x0a || buffer[offset] === 0x0d)) {
        offset += 1;
      }
      if (offset > 0) {
        buffer = buffer.subarray(offset);
        if (buffer.length === 0) return;
      }

      // Optional LSP-style Content-Length framing support
      const headPreview = buffer.subarray(0, Math.min(buffer.length, 32)).toString("ascii");
      if (/^Content-Length:/i.test(headPreview)) {
        const headerEnd = buffer.indexOf("\r\n\r\n");
        const altEnd = headerEnd === -1 ? buffer.indexOf("\n\n") : -1;
        const sepIdx = headerEnd !== -1 ? headerEnd : altEnd;
        const sepLen = headerEnd !== -1 ? 4 : 2;
        if (sepIdx === -1) return; // wait for complete headers

        const headerStr = buffer.subarray(0, sepIdx).toString("ascii");
        const lenMatch = headerStr.match(/Content-Length:\s*(\d+)/i);
        if (!lenMatch) {
          buffer = buffer.subarray(sepIdx + sepLen);
          continue;
        }
        const contentLen = Number.parseInt(lenMatch[1], 10);
        const bodyStart = sepIdx + sepLen;
        if (buffer.length < bodyStart + contentLen) return; // wait for full body

        const rawJson = buffer.subarray(bodyStart, bodyStart + contentLen).toString("utf8");
        buffer = buffer.subarray(bodyStart + contentLen);
        dispatchRawJson(rawJson);
        continue;
      }

      // Standard MCP stdio newline-delimited JSON-RPC
      const nlIdx = buffer.indexOf(0x0a);
      if (nlIdx === -1) return; // wait for newline
      const line = buffer.subarray(0, nlIdx).toString("utf8");
      buffer = buffer.subarray(nlIdx + 1);
      dispatchRawJson(line);
    }
  }

  process.stdin.on("data", (chunk) => {
    const piece = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
    buffer = Buffer.concat([buffer, piece]);
    drainBuffer();
  });

  process.stdin.on("end", () => {
    if (buffer.length > 0) {
      const tail = buffer.toString("utf8").trim();
      buffer = Buffer.alloc(0);
      if (tail) dispatchRawJson(tail);
    }
  });

  process.stdin.resume();
}

const isMainModule = (() => {
  if (!process.argv[1]) return false;
  try {
    return path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1]);
  } catch {
    return false;
  }
})();

if (isMainModule) {
  startStdioServer();
}
