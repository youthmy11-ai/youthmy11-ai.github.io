#!/usr/bin/env node
/**
 * ForgeSuite MCP Server (v1.2.0)
 * Zero-dependency Node 20+ Model Context Protocol (MCP) stdio JSON-RPC 2.0 server.
 *
 * 1-Command Global Run:
 *   npx --yes github:youthmy11-ai/youthmy11-ai.github.io
 *
 * 7 Developer, FinOps, Brand Launch & Web3 Security Tools:
 *   1. envshield_scan           — Scan .env/configs/logs offline for leaked secrets & return redacted output
 *   2. calldata_decode          — Decode EVM calldata selectors offline & flag unlimited MaxUint256 approvals
 *   3. tokencost_estimate       — Estimate LLM API & multi-turn AI agent run costs (Claude/GPT/Gemini/DeepSeek)
 *   4. cryptobill_quote         — Generate Markdown/JSON crypto invoices + live CryptoBill #inv= links
 *   5. evm_token_risk_scan      — Live EVM token/proxy/opcode risk audit across Base/Ethereum/BSC/Arbitrum
 *   6. solana_mint_risk_scan    — Live Solana SPL / Token-2022 authority, extension & holder concentration audit
 *   7. brand_domain_handle_scan — Live RDAP + DoH domain (.com/.io/.ai/.dev/.app/.org), npm/PyPI/GitHub, Bluesky/Reddit & iOS App Store availability audit
 *
 * Docs & Pro Bundle ($35 Lifetime): https://youthmy11-ai.github.io/mcp.html
 * License: MIT (youthmy11-ai)
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const SERVER_INFO = Object.freeze({
  name: "forgesuite-mcp",
  version: "1.2.0",
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
  tokenaudit: "https://youthmy11-ai.github.io/tokenaudit.html",
  tokencalc: "https://youthmy11-ai.github.io/tokencalc.html",
  cryptobill: "https://youthmy11-ai.github.io/cryptobill.html",
  pricing: "https://youthmy11-ai.github.io/#pricing",
  forgeAgent: "https://market.near.ai/a/forge-ai-agent",
  forgeTokenGuard: "https://market.near.ai/a/forge-token-guard",
  forgeDataFinops: "https://market.near.ai/a/forge-data-finops",
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
 * 5. TokenGuard Live EVM & Solana Token/Contract Risk Scanner (v1.1.0)
 * ========================================================================== */

export const EVM_CHAIN_CONFIG = Object.freeze({
  ethereum: {
    chain: "ethereum",
    caip2: "eip155:1",
    chainId: 1,
    name: "Ethereum Mainnet",
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
    rpcs: Object.freeze([
      "https://arbitrum-one-rpc.publicnode.com",
      "https://arb1.arbitrum.io/rpc",
      "https://1rpc.io/arb",
    ]),
  },
});

export const SOLANA_RPC_ENDPOINTS = Object.freeze([
  "https://solana-rpc.publicnode.com",
  "https://api.zan.top/solana-mainnet",
  "https://api.mainnet-beta.solana.com",
]);

export const SOLANA_INDEXED_RPC_ENDPOINTS = Object.freeze([
  "https://api.tatum.io/v3/blockchain/node/solana-mainnet",
  "https://solana.leorpc.com/?api_key=FREE",
  "https://api.mainnet-beta.solana.com",
]);

const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const BASE58_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

const SLOT_EIP1967_IMPL =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const SLOT_EIP1967_ADMIN =
  "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const SLOT_EIP1967_BEACON =
  "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
const SLOT_ZEPPELINOS_IMPL =
  "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3";
const SLOT_ZEPPELINOS_ADMIN =
  "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b";

export const RISK_SELECTORS = Object.freeze({
  mint: [
    { selector: "0x40c10f19", sig: "mint(address,uint256)" },
    { selector: "0xa0712d68", sig: "mint(uint256)" },
    { selector: "0x6a627842", sig: "mint(address)" },
    { selector: "0xcc872b66", sig: "issue(uint256)" },
  ],
  blacklist: [
    { selector: "0xf9f92be4", sig: "blacklist(address)" },
    { selector: "0x4579268a", sig: "blacklistAddress(address)" },
    { selector: "0x16c02129", sig: "setBlacklist(address,bool)" },
    { selector: "0x0ecb93c0", sig: "addBlackList(address)" },
    { selector: "0xe724529c", sig: "freezeAccount(address,bool)" },
    { selector: "0xfe575a87", sig: "isBlacklisted(address)" },
  ],
  pause: [
    { selector: "0x8456cb59", sig: "pause()" },
    { selector: "0x3f4ba83a", sig: "unpause()" },
    { selector: "0x5c975abb", sig: "paused()" },
  ],
  taxAndLimits: [
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
  ],
  upgrade: [
    { selector: "0x3659cfe6", sig: "upgradeTo(address)" },
    { selector: "0x4f1ef286", sig: "upgradeToAndCall(address,bytes)" },
    { selector: "0x52d1902d", sig: "proxiableUUID()" },
  ],
});

function classifyRiskLevel(score) {
  if (score >= 70) return "CRITICAL";
  if (score >= 45) return "HIGH";
  if (score >= 20) return "MODERATE";
  return "LOW";
}

function matchSelectorCategories(selectorSet) {
  const matchList = (entries) =>
    entries.filter((e) => selectorSet.has(e.selector)).map((e) => e.sig);
  return {
    mint: matchList(RISK_SELECTORS.mint),
    blacklist: matchList(RISK_SELECTORS.blacklist),
    pause: matchList(RISK_SELECTORS.pause),
    taxAndLimits: matchList(RISK_SELECTORS.taxAndLimits),
    upgrade: matchList(RISK_SELECTORS.upgrade),
  };
}

function parseAddressFromSlot(slotHex) {
  if (!slotHex || typeof slotHex !== "string") return null;
  const clean = slotHex.toLowerCase().replace(/^0x/, "").padStart(64, "0");
  if (clean.length < 64 || !/^[0-9a-f]+$/.test(clean)) return null;
  const addrHex = clean.slice(-40);
  if (/^0+$/.test(addrHex)) return null;
  return `0x${addrHex}`;
}

function decodeAbiStringOrBytes32(hexResult) {
  if (!hexResult || typeof hexResult !== "string" || hexResult === "0x") return null;
  const clean = hexResult.replace(/^0x/, "");
  if (clean.length < 64 || !/^[0-9a-fA-F]+$/.test(clean)) return null;
  try {
    if (clean.length >= 128) {
      const offsetBytes = Number(BigInt(`0x${clean.slice(0, 64)}`));
      if (offsetBytes === 32) {
        const strLen = Number(BigInt(`0x${clean.slice(64, 128)}`));
        if (strLen >= 0 && strLen <= 256 && clean.length >= 128 + strLen * 2) {
          return Buffer.from(clean.slice(128, 128 + strLen * 2), "hex")
            .toString("utf8")
            .replace(/\0/g, "")
            .trim() || null;
        }
      }
    }
    return Buffer.from(clean.slice(0, 64), "hex")
      .toString("utf8")
      .replace(/\0+$/g, "")
      .trim() || null;
  } catch {
    return null;
  }
}

function decodeAbiUint(hexResult) {
  if (!hexResult || typeof hexResult !== "string" || hexResult === "0x") return null;
  const clean = hexResult.replace(/^0x/, "");
  if (!clean || !/^[0-9a-fA-F]+$/.test(clean)) return null;
  try {
    return BigInt(`0x${clean.slice(0, 64)}`);
  } catch {
    return null;
  }
}

function formatTokenUnits(rawBigInt, decimals = 18) {
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

function sanitizeCustomRpcUrl(rawUrl) {
  const trimmed = String(rawUrl || "").trim();
  if (!trimmed) return null;
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid custom RPC URL "${trimmed}".`);
  }
  const isLocal = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLocal)) {
    throw new Error("Custom RPC URL must use https:// (or http://localhost).");
  }
  return parsed.toString();
}

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

  const bytes = Buffer.from(codeHex, "hex");
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
        push4Selectors.add(`0x${bytes.subarray(pc + 1, pc + 5).toString("hex")}`);
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
    typeof rawOwner === "string" && rawOwner.trim() ? rawOwner.trim().toLowerCase() : null;
  const hasActiveOwner = Boolean(
    ownerNormalized && ownerNormalized !== ZERO_ADDRESS && !/^0x0+$/.test(ownerNormalized)
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

export function scoreSolanaMintRisk(input = {}) {
  const infoSrc = input.mintInfo || input.info || input;
  const decimals = Number(infoSrc.decimals ?? 0);
  const supplyAtomicStr = String(infoSrc.supplyAtomic ?? infoSrc.supply ?? "0");
  const supplyBig = BigInt(supplyAtomicStr);
  const mintAuthority = infoSrc.mintAuthority ?? null;
  const freezeAuthority = infoSrc.freezeAuthority ?? null;
  const isInitialized = infoSrc.isInitialized !== undefined ? Boolean(infoSrc.isInitialized) : true;

  const rawExts = input.extensions ?? infoSrc.extensions;
  let extensionNames = [];
  let transferFeeBps = 0;
  let transferFeeAuthority = null;
  let permanentDelegate = null;
  let mintCloseAuthority = null;
  let transferHookProgramId = null;
  let defaultAccountState = null;
  let isNonTransferable = false;
  let embeddedMetadata = null;

  if (Array.isArray(rawExts)) {
    extensionNames = rawExts.map((e) => e?.extension).filter(Boolean);
    for (const ext of rawExts) {
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
  } else if (rawExts && typeof rawExts === "object") {
    extensionNames = Array.isArray(rawExts.names) ? [...rawExts.names] : [];
    transferFeeBps = Number(rawExts.transferFeeBps ?? 0) || 0;
    transferFeeAuthority = rawExts.transferFeeAuthority || null;
    permanentDelegate = rawExts.permanentDelegate || null;
    mintCloseAuthority = rawExts.mintCloseAuthority || null;
    transferHookProgramId = rawExts.transferHookProgramId || rawExts.transferHook || null;
    defaultAccountState = rawExts.defaultAccountState || null;
    isNonTransferable = Boolean(rawExts.isNonTransferable || rawExts.nonTransferable);
    embeddedMetadata = rawExts.embeddedMetadata || null;
  }

  let holderConcentration;
  if (Array.isArray(input.largestAccounts)) {
    const list = input.largestAccounts;
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
    const top10SumBig = list
      .slice(0, 10)
      .reduce((acc, item) => acc + BigInt(String(item.amount ?? item.amountAtomic ?? "0")), 0n);
    holderConcentration = {
      available: true,
      rpcUsed: input.indexedRpcUsed || null,
      top1HolderPct: top10[0]?.pctOfSupply ?? 0,
      top10HoldersPct: supplyBig > 0n ? Number((top10SumBig * 10000n) / supplyBig) / 100 : 0,
      topHolders: top10,
    };
  } else if (input.holderConcentration && typeof input.holderConcentration === "object") {
    holderConcentration = { ...input.holderConcentration };
  } else {
    holderConcentration = {
      available: false,
      reason: "Holder concentration snapshot not available.",
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
  if (permanentDelegate) {
    addFlag(
      "TOKEN2022_PERMANENT_DELEGATE",
      "CRITICAL",
      35,
      `Token-2022 permanentDelegate (${permanentDelegate}) can transfer or burn tokens from ANY wallet without owner approval.`
    );
  }
  if (transferFeeBps > 0 || transferFeeAuthority) {
    const highFee = transferFeeBps >= 500;
    addFlag(
      "TOKEN2022_TRANSFER_FEE",
      highFee ? "HIGH" : "MEDIUM",
      highFee ? 25 : 10,
      `Token-2022 transferFeeConfig active: ${transferFeeBps} bps (${(transferFeeBps / 100).toFixed(2)}%)${transferFeeAuthority ? `, mutable authority ${transferFeeAuthority}` : ""}.`
    );
  }
  if (transferHookProgramId) {
    addFlag(
      "TOKEN2022_TRANSFER_HOOK",
      "MEDIUM",
      15,
      `Token-2022 custom transferHook (${transferHookProgramId}) executes on every transfer.`
    );
  }
  if (mintCloseAuthority) {
    addFlag(
      "TOKEN2022_MINT_CLOSE_AUTHORITY",
      "LOW",
      8,
      `Token-2022 mintCloseAuthority (${mintCloseAuthority}) is set.`
    );
  }
  if (defaultAccountState === "frozen") {
    addFlag(
      "DEFAULT_ACCOUNT_FROZEN",
      "CRITICAL",
      30,
      "New token accounts default to FROZEN state."
    );
  }
  if (isNonTransferable) {
    addFlag(
      "NON_TRANSFERABLE_SOULBOUND",
      "CRITICAL",
      40,
      "Token-2022 nonTransferable extension enabled; tokens cannot be transferred."
    );
  }

  if (holderConcentration.available) {
    const top1 = Number(holderConcentration.top1HolderPct ?? 0);
    const top10 = Number(holderConcentration.top10HoldersPct ?? 0);
    if (top1 >= 30) {
      addFlag("EXTREME_TOP1_CONCENTRATION", "HIGH", 20, `Top-1 account holds ${top1.toFixed(2)}% of supply.`);
    } else if (top1 >= 15) {
      addFlag("ELEVATED_TOP1_CONCENTRATION", "MEDIUM", 10, `Top-1 account holds ${top1.toFixed(2)}% of supply.`);
    }
    if (top10 >= 75) {
      addFlag("EXTREME_TOP10_CONCENTRATION", "HIGH", 20, `Top-10 accounts control ${top10.toFixed(2)}% of supply.`);
    } else if (top10 >= 50) {
      addFlag("ELEVATED_TOP10_CONCENTRATION", "MEDIUM", 10, `Top-10 accounts control ${top10.toFixed(2)}% of supply.`);
    }
  }

  const riskScore = Math.min(100, score);
  const riskLevel = classifyRiskLevel(riskScore);

  const recommendations = [];
  if (permanentDelegate) {
    recommendations.push(
      "CRITICAL: Avoid holding unverified tokens with permanentDelegate; only regulated issuers (e.g. PYUSD) legitimately use it."
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
      "Mint and freeze authorities are revoked and holder concentration is within normal bounds."
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
    holderConcentration,
    recommendations,
  };
}

async function callJsonRpcWithFailover(urls, method, params, options = {}) {
  const timeoutMs = options.timeoutMs ?? 7500;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const errors = [];

  for (const url of urls) {
    try {
      const res = await fetchImpl(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method,
          params,
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
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

export async function scanEvmTokenOnChain(input = {}, options = {}) {
  const chainKey = String(input?.chain || "base").trim().toLowerCase();
  const addressRaw = String(input?.address || "").trim();

  if (!EVM_CHAIN_CONFIG[chainKey]) {
    throw new Error(
      `Unsupported EVM chain "${input?.chain}". Must be one of: base, ethereum, bsc, arbitrum.`
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

  const codeResp = await callJsonRpcWithFailover(rpcs, "eth_getCode", [address, "latest"], options);
  const outerWalk = analyzeEvmBytecodeHex(codeResp.result || "0x");

  if (!outerWalk.isContract) {
    const scoredEmpty = scoreEvmTokenRisk({ isContract: false });
    return {
      ok: true,
      auditedAt: new Date().toISOString(),
      chain: chainCfg.chain,
      network: chainCfg.caip2,
      rpcUsed: codeResp.rpcUrl,
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
    beaconImpl = parseAddressFromSlot(await safeEthCall(eip1967Beacon, "0x5c60da1b"));
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

  return {
    ok: true,
    auditedAt: new Date().toISOString(),
    chain: chainCfg.chain,
    network: chainCfg.caip2,
    rpcUsed: codeResp.rpcUrl,
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
}

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
      "Mint exceeds public RPC indexed account scan threshold; pass custom rpcUrl for Top-10 holder concentration.";
  }

  const scored = scoreSolanaMintRisk({
    info,
    extensions: info.extensions,
    ...(largestAccounts
      ? { largestAccounts, indexedRpcUsed }
      : {
          holderConcentration: {
            available: false,
            reason: holderFailureReason,
            top1HolderPct: null,
            top10HoldersPct: null,
            topHolders: [],
          },
        }),
  });

  return {
    ok: true,
    auditedAt: new Date().toISOString(),
    network: SOLANA_NETWORK,
    rpcUsed: acctResp.rpcUrl,
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
}

/* ============================================================================
 * 6. Brand, Domain & Handle Availability Scanner (v1.2.0)
 * ========================================================================== */

export const BRAND_SCAN_DEFAULT_TLDS = Object.freeze([
  "com",
  "io",
  "ai",
  "dev",
  "app",
  "org",
]);

export const RDAP_ENDPOINTS_BY_TLD = Object.freeze({
  com: "https://rdap.verisign.com/com/v1/domain/",
  net: "https://rdap.verisign.com/net/v1/domain/",
  org: "https://rdap.publicinterestregistry.org/rdap/domain/",
  dev: "https://pubapi.registry.google/rdap/domain/",
  app: "https://pubapi.registry.google/rdap/domain/",
  io: "https://rdap.identitydigital.services/rdap/domain/",
  ai: "https://rdap.identitydigital.services/rdap/domain/",
});

export const NEAR_AGENT_FLEET = Object.freeze([
  {
    id: "forge-ai-agent",
    name: "Forge AI Agent — Deep Smart Contract Audits & Full-Stack Engineering ($5.00 USDC/call)",
    marketUrl: FORGESUITE_LINKS.forgeAgent,
    a2aEndpoint: "https://forge-ai-agent.market.near.ai/a2a/v1",
  },
  {
    id: "forge-token-guard",
    name: "Forge TokenGuard — Instant <15s EVM & Solana Rug/Proxy Scanner ($0.25 USDC/call)",
    marketUrl: FORGESUITE_LINKS.forgeTokenGuard,
    a2aEndpoint: "https://forge-token-guard.market.near.ai/a2a/v1",
  },
  {
    id: "forge-data-finops",
    name: "Forge Data & FinOps — Instant <500ms JSON/CSV PII Redactor, LLM Budget & Crypto SOW ($0.15 USDC/call)",
    marketUrl: FORGESUITE_LINKS.forgeDataFinops,
    a2aEndpoint: "https://forge-data-finops.market.near.ai/a2a/v1",
  },
]);

export function normalizeBrandCandidate(rawName) {
  const display = String(rawName ?? "")
    .trim()
    .replace(/^@+/, "")
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "");

  // Strip known trailing TLD if caller passed e.g. "forgesuite.io"
  const basePart = display.replace(/\.(?:com|io|ai|dev|app|org|net|xyz|co)$/i, "").trim();
  const domainLabel = basePart
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);

  const compactKey = domainLabel.replace(/-/g, "");
  if (!domainLabel || domainLabel.length < 2 || !compactKey) {
    throw new Error(
      `Invalid brand candidate "${rawName}". Provide at least 2 alphanumeric characters.`
    );
  }

  return {
    displayName: basePart || domainLabel,
    domainLabel,
    packageSlug: domainLabel,
    githubHandle: domainLabel.slice(0, 39).replace(/-+$/g, ""),
    blueskyHandle: `${domainLabel.slice(0, 50).replace(/-+$/g, "")}.bsky.social`,
    redditHandle: basePart
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "_")
      .replace(/_{2,}/g, "_")
      .replace(/^[-_]+|[-_]+$/g, "")
      .slice(0, 20) || compactKey.slice(0, 20),
    compactKey,
  };
}

function mapDnsRcode(rcode) {
  if (rcode === 0) return "NOERROR";
  if (rcode === 2) return "SERVFAIL";
  if (rcode === 3) return "NXDOMAIN";
  return typeof rcode === "number" ? `RCODE_${rcode}` : null;
}

async function safeJsonFetch(url, options = {}) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 6500;
  const headers = {
    "User-Agent": "ForgeSuite-MCP/1.2.0 (+https://youthmy11-ai.github.io)",
    Accept: options.accept || "application/json",
    ...(options.headers || {}),
  };
  const res = await fetchImpl(url, {
    method: options.method || "GET",
    headers,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { ok: res.ok, status: res.status, text, json };
}

async function checkSingleDomainAvailability(domainLabel, rawTld, options = {}) {
  const tld = String(rawTld || "")
    .trim()
    .toLowerCase()
    .replace(/^\.+/, "");
  const domain = `${domainLabel}.${tld}`;
  const rdapPrimary = RDAP_ENDPOINTS_BY_TLD[tld]
    ? `${RDAP_ENDPOINTS_BY_TLD[tld]}${encodeURIComponent(domain)}`
    : `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  const dohUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=NS`;

  const [rdapOutcome, dohOutcome] = await Promise.allSettled([
    safeJsonFetch(rdapPrimary, {
      ...options,
      accept: "application/rdap+json, application/json",
    }),
    safeJsonFetch(dohUrl, options),
  ]);

  let rdapRes = rdapOutcome.status === "fulfilled" ? rdapOutcome.value : null;
  if (
    (!rdapRes || (rdapRes.status !== 200 && rdapRes.status !== 404)) &&
    RDAP_ENDPOINTS_BY_TLD[tld]
  ) {
    try {
      rdapRes = await safeJsonFetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
        ...options,
        accept: "application/rdap+json, application/json",
      });
    } catch {
      // keep existing rdapRes
    }
  }

  const dohRes = dohOutcome.status === "fulfilled" ? dohOutcome.value : null;
  const checkedAt = new Date().toISOString();

  const rdapStatus = rdapRes ? rdapRes.status : null;
  const dnsRcode = dohRes?.json && typeof dohRes.json.Status === "number" ? dohRes.json.Status : null;
  const dnsStatus = mapDnsRcode(dnsRcode);
  const hasDnsDelegation = Boolean(
    dnsRcode === 0 && Array.isArray(dohRes?.json?.Answer) && dohRes.json.Answer.length > 0
  );

  let expirationDate = null;
  if (rdapStatus === 200 && Array.isArray(rdapRes?.json?.events)) {
    const expEvt = rdapRes.json.events.find((e) => e?.eventAction === "expiration");
    if (expEvt?.eventDate) expirationDate = String(expEvt.eventDate);
  }

  let available = null;
  let status = "unknown";
  let source = "unverified";

  if (rdapStatus === 200) {
    available = false;
    status = "taken";
    source = dohRes?.ok ? "rdap+doh" : "rdap";
  } else if (hasDnsDelegation) {
    available = false;
    status = "taken";
    source = rdapStatus ? "rdap+doh" : "doh";
  } else if (rdapStatus === 404) {
    available = true;
    status = "available";
    source = dohRes?.ok ? "rdap+doh" : "rdap";
  } else if (dnsRcode === 3) {
    available = true;
    status = "likely_available";
    source = "doh";
  }

  return {
    domain,
    tld,
    available,
    status,
    rdapStatus,
    dnsStatus,
    hasDnsDelegation,
    expirationDate,
    source,
    checkedAt,
  };
}

async function checkNpmPackageAvailability(packageSlug, options = {}) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(packageSlug)}`;
  const publicUrl = `https://www.npmjs.com/package/${packageSlug}`;
  try {
    const res = await safeJsonFetch(url, options);
    const checkedAt = new Date().toISOString();
    if (res.status === 404) {
      return {
        registry: "npm",
        name: packageSlug,
        available: true,
        status: "available",
        latestVersion: null,
        url: publicUrl,
        checkedAt,
      };
    }
    if (res.status === 200) {
      return {
        registry: "npm",
        name: packageSlug,
        available: false,
        status: "taken",
        latestVersion: res.json?.["dist-tags"]?.latest || null,
        url: publicUrl,
        checkedAt,
      };
    }
    return {
      registry: "npm",
      name: packageSlug,
      available: null,
      status: `http_${res.status}`,
      latestVersion: null,
      url: publicUrl,
      checkedAt,
    };
  } catch (err) {
    return {
      registry: "npm",
      name: packageSlug,
      available: null,
      status: "error",
      error: err instanceof Error ? err.message : String(err),
      url: publicUrl,
      checkedAt: new Date().toISOString(),
    };
  }
}

async function checkPypiPackageAvailability(packageSlug, options = {}) {
  const url = `https://pypi.org/pypi/${encodeURIComponent(packageSlug)}/json`;
  const publicUrl = `https://pypi.org/project/${packageSlug}/`;
  try {
    const res = await safeJsonFetch(url, options);
    const checkedAt = new Date().toISOString();
    if (res.status === 404) {
      return {
        registry: "pypi",
        name: packageSlug,
        available: true,
        status: "available",
        latestVersion: null,
        url: publicUrl,
        checkedAt,
      };
    }
    if (res.status === 200) {
      return {
        registry: "pypi",
        name: packageSlug,
        available: false,
        status: "taken",
        latestVersion: res.json?.info?.version || null,
        url: publicUrl,
        checkedAt,
      };
    }
    return {
      registry: "pypi",
      name: packageSlug,
      available: null,
      status: `http_${res.status}`,
      latestVersion: null,
      url: publicUrl,
      checkedAt,
    };
  } catch (err) {
    return {
      registry: "pypi",
      name: packageSlug,
      available: null,
      status: "error",
      error: err instanceof Error ? err.message : String(err),
      url: publicUrl,
      checkedAt: new Date().toISOString(),
    };
  }
}

async function checkGithubNamespaceAvailability(githubHandle, options = {}) {
  const apiUrl = `https://api.github.com/users/${encodeURIComponent(githubHandle)}`;
  const profileUrl = `https://github.com/${githubHandle}`;
  try {
    const res = await safeJsonFetch(apiUrl, {
      ...options,
      accept: "application/vnd.github+json",
    });
    const checkedAt = new Date().toISOString();
    if (res.status === 404) {
      return {
        registry: "github",
        handle: githubHandle,
        available: true,
        status: "available",
        accountType: null,
        url: profileUrl,
        checkedAt,
      };
    }
    if (res.status === 200) {
      return {
        registry: "github",
        handle: githubHandle,
        available: false,
        status: "taken",
        accountType: res.json?.type || "Account",
        url: profileUrl,
        checkedAt,
      };
    }
    if (res.status === 403 || res.status === 429) {
      const webRes = await safeJsonFetch(profileUrl, {
        ...options,
        accept: "text/html",
      });
      const fallbackAt = new Date().toISOString();
      if (webRes.status === 404) {
        return {
          registry: "github",
          handle: githubHandle,
          available: true,
          status: "available",
          accountType: null,
          url: profileUrl,
          checkedAt: fallbackAt,
        };
      }
      if (webRes.status === 200) {
        return {
          registry: "github",
          handle: githubHandle,
          available: false,
          status: "taken",
          accountType: "WebProfile",
          url: profileUrl,
          checkedAt: fallbackAt,
        };
      }
    }
    return {
      registry: "github",
      handle: githubHandle,
      available: null,
      status: `http_${res.status}`,
      accountType: null,
      url: profileUrl,
      checkedAt,
    };
  } catch (err) {
    return {
      registry: "github",
      handle: githubHandle,
      available: null,
      status: "error",
      error: err instanceof Error ? err.message : String(err),
      url: profileUrl,
      checkedAt: new Date().toISOString(),
    };
  }
}

async function checkBlueskyHandleAvailability(blueskyHandle, options = {}) {
  const apiUrl = `https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(blueskyHandle)}`;
  const profileUrl = `https://bsky.app/profile/${blueskyHandle}`;
  try {
    const res = await safeJsonFetch(apiUrl, options);
    const checkedAt = new Date().toISOString();
    if (res.status === 200 && res.json?.did) {
      return {
        platform: "bluesky",
        handle: blueskyHandle,
        available: false,
        status: "taken",
        did: res.json.did,
        url: profileUrl,
        checkedAt,
      };
    }
    if (
      res.status === 404 ||
      (res.status === 400 && /unable to resolve handle/i.test(String(res.json?.message || res.text)))
    ) {
      return {
        platform: "bluesky",
        handle: blueskyHandle,
        available: true,
        status: "available",
        did: null,
        url: profileUrl,
        checkedAt,
      };
    }
    return {
      platform: "bluesky",
      handle: blueskyHandle,
      available: null,
      status: `http_${res.status}`,
      did: null,
      url: profileUrl,
      checkedAt,
    };
  } catch (err) {
    return {
      platform: "bluesky",
      handle: blueskyHandle,
      available: null,
      status: "error",
      error: err instanceof Error ? err.message : String(err),
      url: profileUrl,
      checkedAt: new Date().toISOString(),
    };
  }
}

async function checkRedditHandleAvailability(redditHandle, options = {}) {
  const availUrl = `https://www.reddit.com/api/username_available.json?user=${encodeURIComponent(redditHandle)}`;
  const profileUrl = `https://www.reddit.com/user/${redditHandle}/`;
  try {
    const res = await safeJsonFetch(availUrl, options);
    const checkedAt = new Date().toISOString();
    if (res.status === 200 && typeof res.json === "boolean") {
      return {
        platform: "reddit",
        handle: redditHandle,
        available: res.json,
        status: res.json ? "available" : "taken",
        url: profileUrl,
        checkedAt,
      };
    }
    if (res.status === 404) {
      return {
        platform: "reddit",
        handle: redditHandle,
        available: true,
        status: "available",
        url: profileUrl,
        checkedAt,
      };
    }
    return {
      platform: "reddit",
      handle: redditHandle,
      available: null,
      status: res.status === 403 || res.status === 429 ? "restricted" : `http_${res.status}`,
      httpStatus: res.status,
      url: profileUrl,
      checkedAt,
    };
  } catch (err) {
    return {
      platform: "reddit",
      handle: redditHandle,
      available: null,
      status: "error",
      error: err instanceof Error ? err.message : String(err),
      url: profileUrl,
      checkedAt: new Date().toISOString(),
    };
  }
}

async function checkIosAppStoreCollision(candidateSpec, options = {}) {
  const searchUrl = `https://itunes.apple.com/search?term=${encodeURIComponent(candidateSpec.displayName)}&entity=software&country=us&limit=5`;
  try {
    const res = await safeJsonFetch(searchUrl, options);
    const checkedAt = new Date().toISOString();
    if (!res.ok || !res.json || !Array.isArray(res.json.results)) {
      return {
        store: "apple_ios_app_store",
        query: candidateSpec.displayName,
        available: null,
        status: `http_${res.status}`,
        exactMatchFound: false,
        totalSearchHits: 0,
        topMatches: [],
        checkedAt,
      };
    }

    const results = res.json.results;
    const targetLower = candidateSpec.displayName.toLowerCase();
    const exactMatchFound = results.some((item) => {
      const trackName = String(item?.trackName || "").trim();
      if (!trackName) return false;
      const trackLower = trackName.toLowerCase();
      const trackCompact = trackLower.replace(/[^a-z0-9]+/g, "");
      const leadingBrand = trackLower.split(/[:\-–—|]/)[0].trim().replace(/[^a-z0-9]+/g, "");
      return (
        trackLower === targetLower ||
        trackCompact === candidateSpec.compactKey ||
        leadingBrand === candidateSpec.compactKey
      );
    });

    return {
      store: "apple_ios_app_store",
      query: candidateSpec.displayName,
      available: !exactMatchFound,
      status: exactMatchFound ? "collision_detected" : "clear",
      exactMatchFound,
      totalSearchHits: Number(res.json.resultCount ?? results.length) || 0,
      topMatches: results.slice(0, 3).map((r) => ({
        trackName: r.trackName || null,
        sellerName: r.sellerName || null,
        bundleId: r.bundleId || null,
        trackViewUrl: r.trackViewUrl || null,
      })),
      checkedAt,
    };
  } catch (err) {
    return {
      store: "apple_ios_app_store",
      query: candidateSpec.displayName,
      available: null,
      status: "error",
      exactMatchFound: false,
      totalSearchHits: 0,
      topMatches: [],
      error: err instanceof Error ? err.message : String(err),
      checkedAt: new Date().toISOString(),
    };
  }
}

function scoreBrandCandidateReadiness(domains, registries, social, appStore) {
  let earned = 0;
  let possible = 0;
  const addWeight = (avail, weight) => {
    if (typeof avail !== "boolean") return;
    possible += weight;
    if (avail) earned += weight;
  };

  const domainMap = new Map(domains.map((d) => [d.tld, d.available]));
  addWeight(domainMap.get("com") ?? null, 25);
  addWeight(domainMap.get("ai") ?? null, 10);
  addWeight(domainMap.get("io") ?? null, 10);
  addWeight(domainMap.get("dev") ?? null, 8);
  addWeight(domainMap.get("app") ?? null, 6);
  addWeight(domainMap.get("org") ?? null, 6);

  // Include any extra custom TLDs
  for (const d of domains) {
    if (!["com", "ai", "io", "dev", "app", "org"].includes(d.tld)) {
      addWeight(d.available, 5);
    }
  }

  addWeight(registries.npm.available, 10);
  addWeight(registries.pypi.available, 8);
  addWeight(registries.github.available, 12);
  addWeight(social.bluesky.available, 6);
  addWeight(social.reddit.available, 4);
  addWeight(appStore.available, 10);

  const readinessScore = possible > 0 ? Math.round((earned / possible) * 100) : 0;
  const allChecks = [
    ...domains.map((d) => d.available),
    registries.npm.available,
    registries.pypi.available,
    registries.github.available,
    social.bluesky.available,
    social.reddit.available,
    appStore.available,
  ];

  return {
    readinessScore,
    verdict:
      readinessScore >= 80
        ? "STRONG_GREENLIGHT"
        : readinessScore >= 55
          ? "VIABLE_WITH_TRADEOFFS"
          : "HIGH_COLLISION",
    availableCount: allChecks.filter((v) => v === true).length,
    takenCount: allChecks.filter((v) => v === false).length,
    unknownCount: allChecks.filter((v) => v === null).length,
    comAvailable: domainMap.get("com") ?? null,
    allDeveloperRegistriesAvailable:
      registries.npm.available === true &&
      registries.pypi.available === true &&
      registries.github.available === true,
  };
}

export async function scanBrandDomainAndHandles(input = {}, options = {}) {
  const rawCandidates = [];
  if (Array.isArray(input?.candidates)) {
    for (const item of input.candidates) {
      if (typeof item === "string" && item.trim()) rawCandidates.push(item.trim());
    }
  }
  if (typeof input?.name === "string" && input.name.trim()) {
    for (const part of input.name.split(",")) {
      if (part.trim()) rawCandidates.push(part.trim());
    }
  }

  const dedupedRaw = Array.from(new Set(rawCandidates)).slice(0, 5);
  if (dedupedRaw.length === 0) {
    throw new Error(
      "Missing brand name: provide 'name' (e.g. 'forgesuite') or 'candidates' (up to 5 names)."
    );
  }

  const requestedTlds =
    Array.isArray(input?.tlds) && input.tlds.length > 0
      ? Array.from(
          new Set(
            input.tlds
              .map((t) =>
                String(t || "")
                  .trim()
                  .toLowerCase()
                  .replace(/^\.+/, "")
              )
              .filter((t) => /^[a-z0-9-]{2,24}$/.test(t))
          )
        ).slice(0, 10)
      : [...BRAND_SCAN_DEFAULT_TLDS];

  if (requestedTlds.length === 0) {
    throw new Error("At least one valid TLD is required.");
  }

  const normalizedCandidates = dedupedRaw.map((c) => normalizeBrandCandidate(c));

  const results = await Promise.all(
    normalizedCandidates.map(async (spec) => {
      const [domains, npmRes, pypiRes, githubRes, blueskyRes, redditRes, appStoreRes] =
        await Promise.all([
          Promise.all(
            requestedTlds.map((tld) =>
              checkSingleDomainAvailability(spec.domainLabel, tld, options)
            )
          ),
          checkNpmPackageAvailability(spec.packageSlug, options),
          checkPypiPackageAvailability(spec.packageSlug, options),
          checkGithubNamespaceAvailability(spec.githubHandle, options),
          checkBlueskyHandleAvailability(spec.blueskyHandle, options),
          checkRedditHandleAvailability(spec.redditHandle, options),
          checkIosAppStoreCollision(spec, options),
        ]);

      const registries = {
        npm: npmRes,
        pypi: pypiRes,
        github: githubRes,
      };
      const social = {
        bluesky: blueskyRes,
        reddit: redditRes,
      };
      const summary = scoreBrandCandidateReadiness(domains, registries, social, appStoreRes);

      return {
        candidate: spec.displayName,
        normalizedSlug: spec.domainLabel,
        checkedAt: new Date().toISOString(),
        summary,
        domains,
        registries,
        social,
        iosAppStore: appStoreRes,
      };
    })
  );

  const ranked = [...results].sort(
    (a, b) => b.summary.readinessScore - a.summary.readinessScore
  );

  return {
    ok: true,
    checkedAt: new Date().toISOString(),
    tldsChecked: requestedTlds,
    candidateCount: results.length,
    recommendedCandidate: ranked[0]?.candidate || null,
    results,
    upgradeLinks: {
      proBundleUrl: FORGESUITE_LINKS.pricing,
      proBundlePriceUsd: 35,
      proBundleOffer:
        "Unlock ForgeSuite All-Access Lifetime Pro Bundle ($35, save $14 — CryptoBill Pro, TokenGuard 25-Token Batch Watchlist, AutoShorts Pro & WebLead Pro)",
      mcpDocsUrl: FORGESUITE_LINKS.mcp,
      nearAgentFleet: NEAR_AGENT_FLEET,
    },
  };
}

/* ============================================================================
 * 7. MCP Tool Definitions & Dispatch (7 Tools)
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
  {
    name: "evm_token_risk_scan",
    description:
      "Run a live EVM token and smart contract rug, proxy, and bytecode risk audit across Base, Ethereum, BSC, or Arbitrum via CORS-safe public JSON-RPC. Inspects EIP-1967 / ZeppelinOS / Beacon / EIP-1167 proxy slots, implementation opcodes (SELFDESTRUCT, DELEGATECALL, CALLCODE, ORIGIN), ERC-20 metadata, ownership status, and mint/blacklist/pause/tax selectors.",
    inputSchema: {
      type: "object",
      properties: {
        chain: {
          type: "string",
          enum: ["base", "ethereum", "bsc", "arbitrum"],
          description: "Target EVM chain (default: base).",
          default: "base",
        },
        address: {
          type: "string",
          description: "0x-prefixed 20-byte EVM contract or token address.",
        },
        rpcUrl: {
          type: "string",
          description: "Optional custom HTTPS EVM JSON-RPC endpoint.",
        },
      },
      required: ["address"],
    },
  },
  {
    name: "solana_mint_risk_scan",
    description:
      "Run a live Solana Mainnet SPL Token and Token-2022 mint risk audit via JSON-RPC. Evaluates active mintAuthority and freezeAuthority, Token-2022 extensions (permanentDelegate, transferFeeConfig, mintCloseAuthority, transferHook, defaultAccountState, nonTransferable), supply, and Top-10 holder concentration.",
    inputSchema: {
      type: "object",
      properties: {
        mint: {
          type: "string",
          description: "32-44 character Base58 Solana SPL or Token-2022 mint address.",
        },
        rpcUrl: {
          type: "string",
          description: "Optional custom HTTPS Solana JSON-RPC endpoint.",
        },
      },
      required: ["mint"],
    },
  },
  {
    name: "brand_domain_handle_scan",
    description:
      "Check candidate brand or project names live across authoritative RDAP + Google DoH domains (.com, .io, .ai, .dev, .app, .org), developer registries (npm, PyPI, GitHub), social handles (Bluesky, Reddit), and the Apple iOS App Store (itunes.apple.com). Returns structured availability, launch readiness score, and UTC check timestamps.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description:
            "Candidate brand/project name (e.g. 'forgesuite' or comma-separated list of up to 5 candidates).",
        },
        candidates: {
          type: "array",
          items: { type: "string" },
          description: "Optional array of up to 5 candidate brand names to compare in parallel.",
        },
        tlds: {
          type: "array",
          items: { type: "string" },
          description:
            "Optional list of domain TLDs to verify (default: ['com', 'io', 'ai', 'dev', 'app', 'org']).",
        },
      },
      required: ["name"],
    },
  },
]);

function executeTool(name, args = {}, options = {}) {
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

    case "evm_token_risk_scan": {
      if (typeof safeArgs.address !== "string" || !safeArgs.address.trim()) {
        return {
          isError: true,
          content: [{ type: "text", text: "Invalid argument: 'address' must be a 0x EVM address string." }],
        };
      }
      return scanEvmTokenOnChain(safeArgs, options)
        .then((res) => {
          const lines = [
            `TokenGuard EVM Risk Scan — ${res.chain.toUpperCase()} (${res.address})`,
            `Risk Score: ${res.riskScore}/100 (${res.riskLevel}) | Contract: ${res.isContract ? "YES" : "NO"}`,
          ];
          if (res.tokenMetadata) {
            lines.push(
              `Token: ${res.tokenMetadata.name || "Unknown"} (${res.tokenMetadata.symbol || "N/A"}) | Decimals: ${res.tokenMetadata.decimals ?? "N/A"} | Supply: ${res.tokenMetadata.totalSupplyFormatted ?? "N/A"}`
            );
          }
          if (res.proxyAnalysis?.isProxy) {
            lines.push(
              `Proxy: ${res.proxyAnalysis.proxyType} -> Implementation ${res.proxyAnalysis.implementationAddress || "Beacon"}`
            );
          }
          if (res.flags.length > 0) {
            lines.push("", "Risk Flags:");
            for (const f of res.flags) {
              lines.push(`- [${f.severity} +${f.points}] ${f.code}: ${f.evidence}`);
            }
          } else {
            lines.push("", "Risk Flags: CLEAN (0 structural flags triggered).");
          }
          lines.push(
            "",
            `Interactive Browser Scanner & Pro 25-Token Batch Watchlist: ${FORGESUITE_LINKS.tokenaudit}`,
            `Deep Solidity/Rust Source Audit ($5 USDC via A2A+x402): ${FORGESUITE_LINKS.forgeAgent}`
          );
          return {
            isError: false,
            content: [{ type: "text", text: lines.join("\n") }],
            structuredContent: res,
          };
        })
        .catch((err) => ({
          isError: true,
          content: [
            {
              type: "text",
              text: `EVM Token Risk Scan Error: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
        }));
    }

    case "solana_mint_risk_scan": {
      if (typeof safeArgs.mint !== "string" || !safeArgs.mint.trim()) {
        return {
          isError: true,
          content: [{ type: "text", text: "Invalid argument: 'mint' must be a Base58 Solana mint string." }],
        };
      }
      return scanSolanaMintOnChain(safeArgs, options)
        .then((res) => {
          const lines = [
            `TokenGuard Solana Mint Scan — ${res.tokenStandard} (${res.mint})`,
            `Risk Score: ${res.riskScore}/100 (${res.riskLevel})`,
            `Supply: ${res.mintInfo.supplyFormatted} (Decimals: ${res.mintInfo.decimals})`,
            `Mint Authority: ${res.mintInfo.mintAuthority || "Revoked ✓"} | Freeze Authority: ${res.mintInfo.freezeAuthority || "Revoked ✓"}`,
          ];
          if (res.extensions.count > 0) {
            lines.push(`Extensions (${res.extensions.count}): ${res.extensions.names.join(", ")}`);
          }
          if (res.holderConcentration.available) {
            lines.push(
              `Holder Concentration: Top-1 = ${res.holderConcentration.top1HolderPct.toFixed(2)}% | Top-10 = ${res.holderConcentration.top10HoldersPct.toFixed(2)}%`
            );
          }
          if (res.flags.length > 0) {
            lines.push("", "Risk Flags:");
            for (const f of res.flags) {
              lines.push(`- [${f.severity} +${f.points}] ${f.code}: ${f.evidence}`);
            }
          } else {
            lines.push("", "Risk Flags: CLEAN (0 authority/extension/concentration flags triggered).");
          }
          lines.push(
            "",
            `Interactive Browser Scanner & Pro 25-Token Batch Watchlist: ${FORGESUITE_LINKS.tokenaudit}`,
            `Deep Rust/Anchor Source Audit ($5 USDC via A2A+x402): ${FORGESUITE_LINKS.forgeAgent}`
          );
          return {
            isError: false,
            content: [{ type: "text", text: lines.join("\n") }],
            structuredContent: res,
          };
        })
        .catch((err) => ({
          isError: true,
          content: [
            {
              type: "text",
              text: `Solana Mint Risk Scan Error: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
        }));
    }

    case "brand_domain_handle_scan": {
      const hasName = typeof safeArgs.name === "string" && safeArgs.name.trim().length > 0;
      const hasCandidates =
        Array.isArray(safeArgs.candidates) && safeArgs.candidates.some((c) => typeof c === "string" && c.trim());
      if (!hasName && !hasCandidates) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: "Invalid argument: provide 'name' (string) or 'candidates' (non-empty string array).",
            },
          ],
        };
      }
      return scanBrandDomainAndHandles(safeArgs, options)
        .then((res) => {
          const fmtStatus = (avail, labelStatus) => {
            if (avail === true) return `AVAILABLE (${labelStatus || "available"})`;
            if (avail === false) return `TAKEN (${labelStatus || "taken"})`;
            return `UNVERIFIED (${labelStatus || "unknown"})`;
          };
          const lines = [
            `Brand, Domain & Handle Scan (Checked UTC: ${res.checkedAt})`,
            `Recommended Candidate: ${res.recommendedCandidate || "n/a"}`,
          ];
          for (const item of res.results) {
            lines.push(
              "",
              `## ${item.candidate} (slug: \`${item.normalizedSlug}\` — Readiness: ${item.summary.readinessScore}/100 · ${item.summary.verdict})`,
              `- Domains: ${item.domains.map((d) => `\`${d.domain}\`=${d.available === true ? "FREE" : d.available === false ? "TAKEN" : "?"}`).join(", ")}`,
              `- Registries: npm=${fmtStatus(item.registries.npm.available, item.registries.npm.status)} | PyPI=${fmtStatus(item.registries.pypi.available, item.registries.pypi.status)} | GitHub=${fmtStatus(item.registries.github.available, item.registries.github.status)}`,
              `- Social: Bluesky (\`${item.social.bluesky.handle}\`)=${fmtStatus(item.social.bluesky.available, item.social.bluesky.status)} | Reddit (\`u/${item.social.reddit.handle}\`)=${fmtStatus(item.social.reddit.available, item.social.reddit.status)}`,
              `- Apple iOS App Store: ${item.iosAppStore.available === true ? "CLEAR (no exact title collision)" : item.iosAppStore.available === false ? "COLLISION DETECTED" : "UNVERIFIED"} (${item.iosAppStore.totalSearchHits} search hits)`
            );
          }
          lines.push(
            "",
            `Upgrade to ForgeSuite All-Access Pro Bundle ($35 Lifetime, Save $14): ${FORGESUITE_LINKS.pricing}`,
            `NEAR AI Agent Market Fleet (A2A + x402):`,
            `- Forge AI Agent ($5.00 USDC/call): ${FORGESUITE_LINKS.forgeAgent}`,
            `- Forge TokenGuard ($0.25 USDC/call): ${FORGESUITE_LINKS.forgeTokenGuard}`,
            `- Forge Data & FinOps ($0.15 USDC/call): ${FORGESUITE_LINKS.forgeDataFinops}`
          );
          return {
            isError: false,
            content: [{ type: "text", text: lines.join("\n") }],
            structuredContent: res,
          };
        })
        .catch((err) => ({
          isError: true,
          content: [
            {
              type: "text",
              text: `Brand Domain & Handle Scan Error: ${err instanceof Error ? err.message : String(err)}`,
            },
          ],
        }));
    }

    default:
      return null;
  }
}

/* ============================================================================
 * 8. JSON-RPC 2.0 MCP Protocol Router
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
 * Returns a response object synchronously for offline calls, a Promise for live RPC tools,
 * or `null` for notifications (no response permitted).
 */
export function handleJsonRpcMessage(msg, options = {}) {
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
          "ForgeSuite MCP Server (v1.2.0) provides 7 zero-dependency developer, FinOps, brand launch & Web3 security tools: envshield_scan (.env/secret leak redactor), calldata_decode (EVM ABI & unlimited approval risk detector), tokencost_estimate (LLM & multi-turn agent cost estimator), cryptobill_quote (Markdown/JSON crypto invoice & live CryptoBill #inv= generator), evm_token_risk_scan (live EVM contract bytecode/proxy/rug scanner), solana_mint_risk_scan (live Solana SPL/Token-2022 mint & authority risk scanner), and brand_domain_handle_scan (authoritative RDAP + Google DoH .com/.io/.ai/.dev/.app/.org domains, npm/PyPI/GitHub, Bluesky/Reddit & iOS App Store availability scanner). Global run: npx --yes github:youthmy11-ai/youthmy11-ai.github.io | Docs: https://youthmy11-ai.github.io/mcp.html",
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
      const result = executeTool(toolName, params.arguments, options);
      if (result === null) {
        return rpcError(id, -32602, `Unknown tool: ${toolName}`);
      }
      if (result && typeof result.then === "function") {
        return result.then((resolved) => rpcResult(id, resolved));
      }
      return rpcResult(id, result);
    }

    default:
      return rpcError(id, -32601, `Method not found: ${msg.method}`);
  }
}

/* ============================================================================
 * 8. Stdio Transport (FIFO Async Queue + Content-Length Fallback)
 * ========================================================================== */

function startStdioServer() {
  let buffer = Buffer.alloc(0);
  let dispatchChain = Promise.resolve();

  function send(payload) {
    if (!payload) return;
    process.stdout.write(`${JSON.stringify(payload)}\n`);
  }

  async function processRawJsonAsync(rawText) {
    const trimmed = rawText.trim();
    if (!trimmed) return;
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (err) {
      send(
        rpcError(
          null,
          -32700,
          "Parse error: invalid JSON.",
          err instanceof Error ? err.message : String(err)
        )
      );
      return;
    }
    if (Array.isArray(parsed)) {
      if (parsed.length === 0) {
        send(rpcError(null, -32600, "Invalid Request: empty batch."));
        return;
      }
      const responses = (await Promise.all(parsed.map((item) => handleJsonRpcMessage(item)))).filter(
        Boolean
      );
      if (responses.length > 0) send(responses);
      return;
    }
    const response = await handleJsonRpcMessage(parsed);
    if (response) send(response);
  }

  function enqueueRawJson(rawText) {
    dispatchChain = dispatchChain
      .then(() => processRawJsonAsync(rawText))
      .catch((err) => {
        send(
          rpcError(
            null,
            -32603,
            "Internal error.",
            err instanceof Error ? err.message : String(err)
          )
        );
      });
  }

  function drainBuffer() {
    while (buffer.length > 0) {
      let offset = 0;
      while (offset < buffer.length && (buffer[offset] === 0x0a || buffer[offset] === 0x0d)) {
        offset += 1;
      }
      if (offset > 0) {
        buffer = buffer.subarray(offset);
        if (buffer.length === 0) return;
      }

      const headPreview = buffer.subarray(0, Math.min(buffer.length, 32)).toString("ascii");
      if (/^Content-Length:/i.test(headPreview)) {
        const headerEnd = buffer.indexOf("\r\n\r\n");
        const altEnd = headerEnd === -1 ? buffer.indexOf("\n\n") : -1;
        const sepIdx = headerEnd !== -1 ? headerEnd : altEnd;
        const sepLen = headerEnd !== -1 ? 4 : 2;
        if (sepIdx === -1) return;

        const headerStr = buffer.subarray(0, sepIdx).toString("ascii");
        const lenMatch = headerStr.match(/Content-Length:\s*(\d+)/i);
        if (!lenMatch) {
          buffer = buffer.subarray(sepIdx + sepLen);
          continue;
        }
        const contentLen = Number.parseInt(lenMatch[1], 10);
        const bodyStart = sepIdx + sepLen;
        if (buffer.length < bodyStart + contentLen) return;

        const rawJson = buffer.subarray(bodyStart, bodyStart + contentLen).toString("utf8");
        buffer = buffer.subarray(bodyStart + contentLen);
        enqueueRawJson(rawJson);
        continue;
      }

      const nlIdx = buffer.indexOf(0x0a);
      if (nlIdx === -1) return;
      const line = buffer.subarray(0, nlIdx).toString("utf8");
      buffer = buffer.subarray(nlIdx + 1);
      enqueueRawJson(line);
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
      if (tail) enqueueRawJson(tail);
    }
  });

  process.stdin.resume();
}

const isMainModule = (() => {
  if (!process.argv[1]) return false;
  try {
    const selfReal = fs.realpathSync(fileURLToPath(import.meta.url));
    const entryReal = fs.realpathSync(path.resolve(process.argv[1]));
    return selfReal === entryReal;
  } catch {
    try {
      return path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1]);
    } catch {
      return false;
    }
  }
})();

if (isMainModule) {
  startStdioServer();
}
