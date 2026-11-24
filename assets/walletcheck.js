import {
  bindCheckoutTriggers,
  getStoredLicenses,
  hasUnlockedTier,
  openCheckoutModal,
  validateLicenseKeyFormat,
} from "./checkout.js";
import { createDefaultInvoice, encodeInvoicePayload } from "./cryptobill.js";

export { validateLicenseKeyFormat };

/**
 * WalletLens — 100% Client-Side CORS-Clean Multi-Chain Wallet Portfolio,
 * EIP-7702 Delegation, Gnosis Safe M-of-N Multisig & Solana SPL/Token-2022 Inspector.
 * Compatible with Browser ES Modules and Node.js 20+ (0 npm dependencies).
 */

export const MAX_WATCHLIST_WALLETS = 25;
export const DEFAULT_SOLANA_SIG_LIMIT = 10;
export const DEFAULT_RPC_TIMEOUT_MS = 4500;

export const NEAR_WALLET_SCANNER_URL =
  "https://market.near.ai/agents/wallet-activity-scanner";
export const NEAR_WALLET_SCANNER_PROFILE_URL =
  "https://market.near.ai/a/wallet-activity-scanner";
export const NEAR_WALLET_SCANNER_A2A_URL =
  "https://wallet-activity-scanner.market.near.ai/a2a/v1";

export const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
export const ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
export const SOLANA_SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";

export const WALLETLENS_ALL_CHAINS = Object.freeze([
  "ethereum",
  "base",
  "arbitrum",
  "bsc",
  "polygon",
  "solana",
]);

export const WALLETLENS_EVM_CHAINS = Object.freeze({
  ethereum: {
    key: "ethereum",
    name: "Ethereum",
    chainId: 1,
    nativeSymbol: "ETH",
    nativeDecimals: 18,
    explorerUrl: "https://etherscan.io",
    rpcs: Object.freeze([
      "https://ethereum-rpc.publicnode.com",
      "https://1rpc.io/eth",
      "https://eth.llamarpc.com",
    ]),
    tokens: Object.freeze([
      { symbol: "USDC", address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", decimals: 6, isStablecoin: true },
      { symbol: "USDT", address: "0xdAC17F958D2ee523a2206206994597C13D831ec7", decimals: 6, isStablecoin: true },
      { symbol: "DAI", address: "0x6B175474E89094C44Da98b954EedeAC495271d0F", decimals: 18, isStablecoin: true },
      { symbol: "WETH", address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", decimals: 18, isStablecoin: false },
    ]),
  },
  base: {
    key: "base",
    name: "Base",
    chainId: 8453,
    nativeSymbol: "ETH",
    nativeDecimals: 18,
    explorerUrl: "https://basescan.org",
    rpcs: Object.freeze([
      "https://base-rpc.publicnode.com",
      "https://mainnet.base.org",
      "https://1rpc.io/base",
    ]),
    tokens: Object.freeze([
      { symbol: "USDC", address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", decimals: 6, isStablecoin: true },
      { symbol: "USDT", address: "0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2", decimals: 6, isStablecoin: true },
      { symbol: "DAI", address: "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb", decimals: 18, isStablecoin: true },
      { symbol: "WETH", address: "0x4200000000000000000000000000000000000006", decimals: 18, isStablecoin: false },
    ]),
  },
  arbitrum: {
    key: "arbitrum",
    name: "Arbitrum",
    chainId: 42161,
    nativeSymbol: "ETH",
    nativeDecimals: 18,
    explorerUrl: "https://arbiscan.io",
    rpcs: Object.freeze([
      "https://arbitrum-one-rpc.publicnode.com",
      "https://arb1.arbitrum.io/rpc",
      "https://1rpc.io/arb",
    ]),
    tokens: Object.freeze([
      { symbol: "USDC", address: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", decimals: 6, isStablecoin: true },
      { symbol: "USDT", address: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", decimals: 6, isStablecoin: true },
      { symbol: "DAI", address: "0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1", decimals: 18, isStablecoin: true },
      { symbol: "WETH", address: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", decimals: 18, isStablecoin: false },
    ]),
  },
  bsc: {
    key: "bsc",
    name: "BSC",
    chainId: 56,
    nativeSymbol: "BNB",
    nativeDecimals: 18,
    explorerUrl: "https://bscscan.com",
    rpcs: Object.freeze([
      "https://bsc-rpc.publicnode.com",
      "https://bsc-dataseed.binance.org",
      "https://1rpc.io/bnb",
    ]),
    tokens: Object.freeze([
      { symbol: "USDC", address: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", decimals: 18, isStablecoin: true },
      { symbol: "USDT", address: "0x55d398326f99059fF775485246999027B3197955", decimals: 18, isStablecoin: true },
      { symbol: "DAI", address: "0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3", decimals: 18, isStablecoin: true },
      { symbol: "WETH", address: "0x2170Ed0880ac9A755fd29B2688956BD959F933F8", decimals: 18, isStablecoin: false },
    ]),
  },
  polygon: {
    key: "polygon",
    name: "Polygon",
    chainId: 137,
    nativeSymbol: "POL",
    nativeDecimals: 18,
    explorerUrl: "https://polygonscan.com",
    rpcs: Object.freeze([
      "https://polygon-bor-rpc.publicnode.com",
      "https://polygon-rpc.com",
      "https://1rpc.io/matic",
    ]),
    tokens: Object.freeze([
      { symbol: "USDC", address: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", decimals: 6, isStablecoin: true },
      { symbol: "USDC.e", address: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", decimals: 6, isStablecoin: true },
      { symbol: "USDT", address: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", decimals: 6, isStablecoin: true },
      { symbol: "DAI", address: "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063", decimals: 18, isStablecoin: true },
      { symbol: "WETH", address: "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619", decimals: 18, isStablecoin: false },
    ]),
  },
});

export const WALLETLENS_SOLANA_CONFIG = Object.freeze({
  key: "solana",
  name: "Solana Mainnet",
  nativeSymbol: "SOL",
  nativeDecimals: 9,
  explorerUrl: "https://solscan.io",
  rpcs: Object.freeze([
    "https://solana-rpc.publicnode.com",
    "https://api.zan.top/solana-mainnet",
  ]),
  knownMints: Object.freeze({
    EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: {
      symbol: "USDC-SPL",
      decimals: 6,
      isStablecoin: true,
      programId: TOKEN_PROGRAM_ID,
    },
    Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: {
      symbol: "USDT-SPL",
      decimals: 6,
      isStablecoin: true,
      programId: TOKEN_PROGRAM_ID,
    },
    "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo": {
      symbol: "PYUSD",
      decimals: 6,
      isStablecoin: true,
      programId: TOKEN_2022_PROGRAM_ID,
    },
    USDSwr9ApdHk5bvJKMjzff41FfuX8bSxdKcR81vTwcA: {
      symbol: "USDS",
      decimals: 6,
      isStablecoin: true,
      programId: TOKEN_PROGRAM_ID,
    },
    So11111111111111111111111111111111111111112: {
      symbol: "wSOL",
      decimals: 9,
      isStablecoin: false,
      programId: TOKEN_PROGRAM_ID,
    },
    JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN: {
      symbol: "JUP",
      decimals: 6,
      isStablecoin: false,
      programId: TOKEN_PROGRAM_ID,
    },
    mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So: {
      symbol: "mSOL",
      decimals: 9,
      isStablecoin: false,
      programId: TOKEN_PROGRAM_ID,
    },
    J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn: {
      symbol: "jitoSOL",
      decimals: 9,
      isStablecoin: false,
      programId: TOKEN_PROGRAM_ID,
    },
    DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263: {
      symbol: "BONK",
      decimals: 5,
      isStablecoin: false,
      programId: TOKEN_PROGRAM_ID,
    },
    "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R": {
      symbol: "RAY",
      decimals: 6,
      isStablecoin: false,
      programId: TOKEN_PROGRAM_ID,
    },
  }),
});

export const WALLETLENS_SAMPLES = Object.freeze({
  vitalik_eoa: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  ens_safe: "0xfeB016d0D14AC0fa6d69199608B0776d007203B2",
  eip7702_eoa: "0x874ebd03bee4ac1950796598d10f78be2ab3db3f",
  solana_treasury: "BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx",
});

export const DEFAULT_WATCHLIST_SAMPLE = [
  "ENS DAO Treasury Safe | 0xfeB016d0D14AC0fa6d69199608B0776d007203B2",
  "Vitalik Multi-Chain EOA | 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "EIP-7702 Delegated Signer | 0x874ebd03bee4ac1950796598d10f78be2ab3db3f",
  "Solana USDC Treasury | BSdWMAHHsygetguA1ioynXQcgYMYeJHstEqAk7fNpJSx",
].join("\n");

const CHAIN_ALIASES = Object.freeze({
  eth: "ethereum",
  ethereum: "ethereum",
  mainnet: "ethereum",
  "1": "ethereum",
  "eip155:1": "ethereum",
  base: "base",
  "8453": "base",
  "eip155:8453": "base",
  arb: "arbitrum",
  arbitrum: "arbitrum",
  "arbitrum-one": "arbitrum",
  "42161": "arbitrum",
  "eip155:42161": "arbitrum",
  bsc: "bsc",
  bnb: "bsc",
  "bnb-chain": "bsc",
  binance: "bsc",
  "56": "bsc",
  "eip155:56": "bsc",
  pol: "polygon",
  polygon: "polygon",
  matic: "polygon",
  "137": "polygon",
  "eip155:137": "polygon",
  sol: "solana",
  solana: "solana",
  "solana-mainnet": "solana",
});

/* ============================================================================
 * 1. Pure-JS SHA-256, Base58 & Ed25519 Off-Curve Solana ATA Derivation
 * ========================================================================== */

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr32(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

export function sha256Bytes(msgBytes) {
  const len = msgBytes.length;
  const bitLenHi = Math.floor((len * 8) / 0x100000000);
  const bitLenLo = (len * 8) >>> 0;
  const padLen = ((len + 9 + 63) & ~63);
  const buf = new Uint8Array(padLen);
  buf.set(msgBytes, 0);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, bitLenHi, false);
  dv.setUint32(padLen - 4, bitLenLo, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i += 1) {
      w[i] = dv.getUint32(off + i * 4, false);
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i += 1) {
      const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outDv = new DataView(out.buffer);
  outDv.setUint32(0, h0, false);
  outDv.setUint32(4, h1, false);
  outDv.setUint32(8, h2, false);
  outDv.setUint32(12, h3, false);
  outDv.setUint32(16, h4, false);
  outDv.setUint32(20, h5, false);
  outDv.setUint32(24, h6, false);
  outDv.setUint32(28, h7, false);
  return out;
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_MAP = new Map([...BASE58_ALPHABET].map((ch, idx) => [ch, idx]));
const ED25519_P = (1n << 255n) - 19n;
const ED25519_D =
  37095705934669439343138083508754565189542113879843219016388785533085940283555n;

function decodeBase58(str) {
  const s = String(str || "").trim();
  if (!s) return null;
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros += 1;
  const rev = [];
  for (let i = 0; i < s.length; i += 1) {
    const val = BASE58_MAP.get(s[i]);
    if (val === undefined) return null;
    let carry = val;
    for (let j = 0; j < rev.length; j += 1) {
      carry += rev[j] * 58;
      rev[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      rev.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const out = new Uint8Array(zeros + rev.length);
  for (let i = 0; i < rev.length; i += 1) {
    out[out.length - 1 - i] = rev[i];
  }
  return out;
}

function encodeBase58(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  const digits = [];
  for (let i = zeros; i < bytes.length; i += 1) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j += 1) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  return "1".repeat(zeros) + digits.reverse().map((d) => BASE58_ALPHABET[d]).join("");
}

function modPow(base, exp, mod) {
  let r = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return r;
}

function isOnEd25519Curve(bytes32) {
  if (!bytes32 || bytes32.length !== 32) return false;
  let y = 0n;
  for (let i = 0; i < 32; i += 1) {
    y |= BigInt(bytes32[i]) << BigInt(8 * i);
  }
  const sign = Number((y >> 255n) & 1n);
  y &= (1n << 255n) - 1n;
  if (y >= ED25519_P) return false;
  const y2 = (y * y) % ED25519_P;
  const u = (y2 - 1n + ED25519_P) % ED25519_P;
  const v = (ED25519_D * y2 + 1n) % ED25519_P;
  const v3 = (((v * v) % ED25519_P) * v) % ED25519_P;
  const v7 = (((v3 * v3) % ED25519_P) * v) % ED25519_P;
  const uv7 = (u * v7) % ED25519_P;
  let x = (((u * v3) % ED25519_P) * modPow(uv7, (ED25519_P - 5n) / 8n, ED25519_P)) % ED25519_P;
  const vx2 = (v * ((x * x) % ED25519_P)) % ED25519_P;
  if (vx2 !== u) {
    const negU = (ED25519_P - u) % ED25519_P;
    if (vx2 === negU) {
      const sqrtM1 = modPow(2n, (ED25519_P - 1n) / 4n, ED25519_P);
      x = (x * sqrtM1) % ED25519_P;
    } else {
      return false;
    }
  }
  if (x === 0n && sign === 1) return false;
  return true;
}

export function deriveSolanaAta(ownerB58, tokenProgramB58, mintB58) {
  const owner = decodeBase58(ownerB58);
  const prog = decodeBase58(tokenProgramB58);
  const mint = decodeBase58(mintB58);
  const ataProg = decodeBase58(ASSOCIATED_TOKEN_PROGRAM_ID);
  if (
    !owner ||
    owner.length !== 32 ||
    !prog ||
    prog.length !== 32 ||
    !mint ||
    mint.length !== 32 ||
    !ataProg
  ) {
    return null;
  }
  const marker = new TextEncoder().encode("ProgramDerivedAddress");
  const seedBuf = new Uint8Array(32 + 32 + 32 + 1 + 32 + marker.length);
  seedBuf.set(owner, 0);
  seedBuf.set(prog, 32);
  seedBuf.set(mint, 64);
  seedBuf.set(ataProg, 97);
  seedBuf.set(marker, 129);

  for (let bump = 255; bump >= 0; bump -= 1) {
    seedBuf[96] = bump;
    const digest = sha256Bytes(seedBuf);
    if (!isOnEd25519Curve(digest)) {
      return encodeBase58(digest);
    }
  }
  return null;
}

export function isValidSolanaAddress(candidate) {
  const s = String(candidate || "").trim();
  if (s.length < 32 || s.length > 44) return false;
  const decoded = decodeBase58(s);
  return Boolean(decoded && decoded.length === 32);
}

export function isValidEvmAddress(candidate) {
  return /^0x[a-fA-F0-9]{40}$/.test(String(candidate || "").trim());
}

export function formatUnitsExact(rawBigInt, decimals, maxFractionDigits = 6) {
  const neg = rawBigInt < 0n;
  const v = neg ? -rawBigInt : rawBigInt;
  const base = 10n ** BigInt(decimals);
  const whole = v / base;
  const fracRaw = (v % base).toString().padStart(decimals, "0");
  const trimmedFull = fracRaw.replace(/0+$/, "");
  const exactStr = trimmedFull
    ? `${neg ? "-" : ""}${whole.toString()}.${trimmedFull}`
    : `${neg ? "-" : ""}${whole.toString()}`;

  const displayFrac = fracRaw.slice(0, maxFractionDigits).replace(/0+$/, "");
  const displayStr = displayFrac
    ? `${neg ? "-" : ""}${whole.toLocaleString("en-US")}.${displayFrac}`
    : `${neg ? "-" : ""}${whole.toLocaleString("en-US")}`;

  return {
    atomic: (neg ? -v : v).toString(),
    exact: exactStr,
    display: displayStr,
    numeric: Number(exactStr),
  };
}

/* ============================================================================
 * 2. URL Query Deep-Link Parser & Input Sanitizers
 * ========================================================================== */

export function sanitizeHttpsRpcUrl(rawUrl) {
  const trimmed = String(rawUrl || "").trim();
  if (!trimmed) return null;
  try {
    const u = new URL(trimmed);
    const isLocal = u.hostname === "localhost" || u.hostname === "127.0.0.1";
    if (u.protocol !== "https:" && !(u.protocol === "http:" && isLocal)) {
      return null;
    }
    return u.toString();
  } catch {
    return null;
  }
}

export function normalizeChainSelection(rawChains) {
  if (!rawChains) return null;
  const parts = Array.isArray(rawChains)
    ? rawChains
    : String(rawChains)
        .split(/[\s,|/]+/)
        .filter(Boolean);
  const out = [];
  for (const p of parts) {
    const mapped = CHAIN_ALIASES[String(p).trim().toLowerCase()];
    if (mapped && !out.includes(mapped)) out.push(mapped);
  }
  return out.length > 0 ? out : null;
}

export function extractSingleWalletAddress(rawText) {
  const s = String(rawText || "").trim();
  if (!s) return null;
  if (isValidEvmAddress(s)) return { address: s, family: "evm" };
  if (isValidSolanaAddress(s)) return { address: s, family: "solana" };

  const urlExtracted = s.replace(
    /https?:\/\/[^\s)"'`<>]+\/(?:address|account|tx|token)\/([A-Za-z0-9]+)/gi,
    " $1 "
  );
  const evmMatch = urlExtracted.match(/(?<![0-9a-fA-F])(0x[a-fA-F0-9]{40})(?![0-9a-fA-F])/);
  if (evmMatch) return { address: evmMatch[1], family: "evm" };

  const tokens = urlExtracted.split(/[\s,;:()[\]{}"'`<>!?|\\/]+/).filter(Boolean);
  for (const tok of tokens) {
    if (tok.startsWith("0x")) continue;
    if (isValidSolanaAddress(tok)) {
      return { address: tok, family: "solana" };
    }
  }
  return null;
}

export function parseWalletCheckQueryParams(searchStr = "") {
  const clean = String(searchStr || "").replace(/^\?/, "");
  const params = new URLSearchParams(clean);
  const rawTarget = (
    params.get("address") ||
    params.get("wallet") ||
    params.get("q") ||
    ""
  ).trim();

  const target = extractSingleWalletAddress(rawTarget);
  const chains = normalizeChainSelection(params.get("chains") || params.get("chain"));
  const rpcUrl = sanitizeHttpsRpcUrl(params.get("rpc") || params.get("rpcUrl") || "");
  const autorunParam = params.get("autorun");
  const autorun = target
    ? autorunParam === null
      ? true
      : !["0", "false", "no"].includes(autorunParam.trim().toLowerCase())
    : false;

  return {
    hasTarget: Boolean(target),
    address: target?.address || "",
    family: target?.family || null,
    chains,
    rpcUrl,
    autorun,
  };
}

/* ============================================================================
 * 3. EVM & Solana Multi-Chain JSON-RPC Inspection Engine (CORS-Clean)
 * ========================================================================== */

function decodeUint256Hex(hex) {
  if (typeof hex !== "string" || !hex.startsWith("0x") || hex.length < 3) return null;
  try {
    return BigInt(hex);
  } catch {
    return null;
  }
}

function decodeAbiAddressArray(hex) {
  if (typeof hex !== "string" || !hex.startsWith("0x")) return null;
  const clean = hex.slice(2);
  if (clean.length < 128 || clean.length % 64 !== 0) return null;
  try {
    const offset = Number(BigInt("0x" + clean.slice(0, 64)));
    const lenWordStart = offset * 2;
    if (lenWordStart + 64 > clean.length) return null;
    const count = Number(BigInt("0x" + clean.slice(lenWordStart, lenWordStart + 64)));
    if (!Number.isInteger(count) || count < 1 || count > 50) return null;
    if (lenWordStart + 64 + count * 64 > clean.length) return null;
    const owners = [];
    for (let i = 0; i < count; i += 1) {
      const word = clean.slice(lenWordStart + 64 + i * 64, lenWordStart + 128 + i * 64);
      owners.push("0x" + word.slice(24));
    }
    return owners;
  } catch {
    return null;
  }
}

export function classifyEvmCodeStatic(rawCode) {
  const code = String(rawCode || "0x").trim();
  const lower = code.toLowerCase();

  if (!lower || lower === "0x" || lower === "0x0") {
    return {
      accountType: "eoa",
      label: "EOA (Externally Owned Account)",
      isContract: false,
      codeBytes: 0,
      delegatedTo: null,
      implementation: null,
    };
  }

  const hexBody = lower.startsWith("0x") ? lower.slice(2) : lower;
  const codeBytes = Math.floor(hexBody.length / 2);

  if (hexBody.startsWith("ef0100") && hexBody.length >= 46) {
    return {
      accountType: "eip7702_delegated",
      label: "EIP-7702 Delegated Account",
      isContract: true,
      codeBytes,
      delegatedTo: "0x" + hexBody.slice(6, 46),
      implementation: null,
    };
  }

  if (hexBody.startsWith("363d3d373d3d3d363d73") && hexBody.length >= 60) {
    return {
      accountType: "eip1167_proxy",
      label: "EIP-1167 Minimal Proxy / Smart Account",
      isContract: true,
      codeBytes,
      delegatedTo: null,
      implementation: "0x" + hexBody.slice(20, 60),
    };
  }

  return {
    accountType: "contract",
    label: "Smart Contract",
    isContract: true,
    codeBytes,
    delegatedTo: null,
    implementation: null,
  };
}

async function rpcBatchWithFailover(
  rpcUrls,
  batchRequests,
  { fetchImpl = globalThis.fetch, timeoutMs = DEFAULT_RPC_TIMEOUT_MS } = {}
) {
  let lastErr = "All RPC endpoints failed";
  for (const rpcUrl of rpcUrls) {
    try {
      const res = await fetchImpl(rpcUrl, {
        method: "POST",
        signal: AbortSignal.timeout(timeoutMs),
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(batchRequests),
      });
      if (!res.ok) {
        lastErr = `HTTP ${res.status} from ${rpcUrl}`;
        continue;
      }
      const parsed = await res.json();
      if (Array.isArray(parsed) && parsed.length > 0) {
        const byId = new Map(parsed.map((item) => [item.id, item]));
        const allErrored = batchRequests.every((req) => byId.get(req.id)?.error);
        if (allErrored) {
          lastErr = byId.get(batchRequests[0].id)?.error?.message || "RPC batch error";
          continue;
        }
        return { ok: true, rpcUrl, byId };
      }

      const singles = await Promise.all(
        batchRequests.map(async (req) => {
          const sr = await fetchImpl(rpcUrl, {
            method: "POST",
            signal: AbortSignal.timeout(timeoutMs),
            headers: { "Content-Type": "application/json", Accept: "application/json" },
            body: JSON.stringify(req),
          });
          return sr.ok ? sr.json() : { id: req.id, error: { message: `HTTP ${sr.status}` } };
        })
      );
      const byId = new Map(singles.map((item, idx) => [item?.id ?? batchRequests[idx].id, item]));
      const allFailed = batchRequests.every((req) => byId.get(req.id)?.error);
      if (!allFailed) return { ok: true, rpcUrl, byId };
      lastErr = byId.get(batchRequests[0].id)?.error?.message || "RPC single-fallback error";
    } catch (err) {
      lastErr =
        err?.name === "TimeoutError"
          ? `Timeout (${timeoutMs}ms) at ${rpcUrl}`
          : err instanceof Error
            ? err.message
            : String(err);
    }
  }
  return { ok: false, error: lastErr, byId: new Map() };
}

export async function inspectEvmWalletOnChain(
  address,
  chainCfg,
  { fetchImpl = globalThis.fetch, timeoutMs = DEFAULT_RPC_TIMEOUT_MS, customRpcUrl = null } = {}
) {
  const rpcList = customRpcUrl ? [customRpcUrl, ...chainCfg.rpcs] : chainCfg.rpcs;
  const paddedAddr = address.slice(2).toLowerCase().padStart(64, "0");
  const balanceCallData = `0x70a08231${paddedAddr}`;

  const batch = [
    { jsonrpc: "2.0", id: "block", method: "eth_getBlockByNumber", params: ["latest", false] },
    { jsonrpc: "2.0", id: "balance", method: "eth_getBalance", params: [address, "latest"] },
    { jsonrpc: "2.0", id: "nonce", method: "eth_getTransactionCount", params: [address, "latest"] },
    { jsonrpc: "2.0", id: "code", method: "eth_getCode", params: [address, "latest"] },
    ...chainCfg.tokens.map((tok, idx) => ({
      jsonrpc: "2.0",
      id: `tok_${idx}`,
      method: "eth_call",
      params: [{ to: tok.address, data: balanceCallData }, "latest"],
    })),
  ];

  const batchRes = await rpcBatchWithFailover(rpcList, batch, { fetchImpl, timeoutMs });
  if (!batchRes.ok) {
    return {
      ok: false,
      chain: chainCfg.key,
      chainName: chainCfg.name,
      chainId: chainCfg.chainId,
      error: batchRes.error,
    };
  }

  const blockObj = batchRes.byId.get("block")?.result || null;
  const blockNumber = blockObj?.number ? Number.parseInt(blockObj.number, 16) : null;
  const blockTimestampSec = blockObj?.timestamp ? Number.parseInt(blockObj.timestamp, 16) : null;
  const blockTimeUtc =
    Number.isFinite(blockTimestampSec) && blockTimestampSec > 0
      ? new Date(blockTimestampSec * 1000).toISOString()
      : null;

  const rawBalBig = decodeUint256Hex(batchRes.byId.get("balance")?.result) ?? 0n;
  const nativeBalance = formatUnitsExact(rawBalBig, chainCfg.nativeDecimals, 6);

  const rawNonceBig = decodeUint256Hex(batchRes.byId.get("nonce")?.result) ?? 0n;
  const nonce = Number(rawNonceBig);

  const codeHex = batchRes.byId.get("code")?.result || "0x";
  let accountClassification = classifyEvmCodeStatic(codeHex);

  if (
    accountClassification.isContract &&
    accountClassification.accountType !== "eip7702_delegated"
  ) {
    const smartWalletProbe = [
      {
        jsonrpc: "2.0",
        id: "safe_threshold",
        method: "eth_call",
        params: [{ to: address, data: "0xe75235b8" }, "latest"],
      },
      {
        jsonrpc: "2.0",
        id: "safe_owners",
        method: "eth_call",
        params: [{ to: address, data: "0xa0e67e2b" }, "latest"],
      },
      {
        jsonrpc: "2.0",
        id: "erc4337_ep",
        method: "eth_call",
        params: [{ to: address, data: "0xb0d691fe" }, "latest"],
      },
    ];
    const probeRes = await rpcBatchWithFailover(
      [batchRes.rpcUrl, ...rpcList.filter((u) => u !== batchRes.rpcUrl)],
      smartWalletProbe,
      { fetchImpl, timeoutMs: Math.min(2400, timeoutMs) }
    );
    if (probeRes.ok) {
      const threshBig = decodeUint256Hex(probeRes.byId.get("safe_threshold")?.result);
      const owners = decodeAbiAddressArray(probeRes.byId.get("safe_owners")?.result);
      if (
        threshBig !== null &&
        threshBig >= 1n &&
        threshBig <= 50n &&
        Array.isArray(owners) &&
        owners.length >= Number(threshBig)
      ) {
        const threshold = Number(threshBig);
        accountClassification = {
          ...accountClassification,
          accountType: "gnosis_safe",
          label: `Gnosis Safe (${threshold}-of-${owners.length} Multisig)`,
          safeThreshold: threshold,
          safeOwnersCount: owners.length,
          safeOwners: owners,
        };
      } else {
        const epHex = probeRes.byId.get("erc4337_ep")?.result;
        if (typeof epHex === "string" && epHex.length === 66 && !/^0x0+$/.test(epHex)) {
          accountClassification = {
            ...accountClassification,
            accountType: "erc4337",
            label: "ERC-4337 Smart Wallet",
            entryPoint: "0x" + epHex.slice(26),
          };
        }
      }
    }
  }

  const tokens = chainCfg.tokens.map((tok, idx) => {
    const rawHex = batchRes.byId.get(`tok_${idx}`)?.result;
    const rawBig = decodeUint256Hex(rawHex) ?? 0n;
    const formatted = formatUnitsExact(rawBig, tok.decimals, tok.decimals === 6 ? 2 : 4);
    return {
      symbol: tok.symbol,
      contract: tok.address,
      decimals: tok.decimals,
      isStablecoin: tok.isStablecoin,
      atomic: formatted.atomic,
      balance: formatted.exact,
      display: formatted.display,
      numeric: formatted.numeric,
    };
  });

  const nonZeroTokens = tokens.filter((t) => BigInt(t.atomic) > 0n);
  const stablecoinUsdTotal = Number(
    nonZeroTokens
      .filter((t) => t.isStablecoin)
      .reduce((acc, t) => acc + t.numeric, 0)
      .toFixed(2)
  );

  const hasActivity =
    nonce > 0 || rawBalBig > 0n || nonZeroTokens.length > 0 || accountClassification.isContract;

  return {
    ok: true,
    chain: chainCfg.key,
    chainName: chainCfg.name,
    chainId: chainCfg.chainId,
    rpcUsed: batchRes.rpcUrl,
    explorerAddressUrl: `${chainCfg.explorerUrl}/address/${address}`,
    blockNumber,
    blockTimeUtc,
    account: accountClassification,
    nonce,
    hasActivity,
    native: {
      symbol: chainCfg.nativeSymbol,
      decimals: chainCfg.nativeDecimals,
      atomic: nativeBalance.atomic,
      balance: nativeBalance.exact,
      display: nativeBalance.display,
      numeric: nativeBalance.numeric,
    },
    stablecoinUsdTotal,
    tokens,
    nonZeroTokens,
  };
}

function classifySolanaOwnerProgram(accountVal) {
  if (!accountVal) {
    return {
      accountType: "unfunded_system_wallet",
      label: "System Wallet (0 SOL / Uninitialized)",
      executable: false,
      ownerProgram: SOLANA_SYSTEM_PROGRAM_ID,
    };
  }
  const owner = accountVal.owner || SOLANA_SYSTEM_PROGRAM_ID;
  const executable = Boolean(accountVal.executable);
  if (executable) {
    return {
      accountType: "program",
      label: "Executable Solana Program",
      executable: true,
      ownerProgram: owner,
    };
  }
  if (owner === SOLANA_SYSTEM_PROGRAM_ID) {
    return {
      accountType: "system_wallet",
      label: "System Wallet (EOA)",
      executable: false,
      ownerProgram: owner,
    };
  }
  if (owner === TOKEN_PROGRAM_ID || owner === TOKEN_2022_PROGRAM_ID) {
    return {
      accountType: "token_account_or_mint",
      label:
        owner === TOKEN_2022_PROGRAM_ID
          ? "Token-2022 Mint / Account"
          : "SPL Token Mint / Account",
      executable: false,
      ownerProgram: owner,
    };
  }
  if (
    owner === "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf" ||
    owner === "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu"
  ) {
    return {
      accountType: "squads_multisig",
      label: "Squads Smart Wallet / Multisig",
      executable: false,
      ownerProgram: owner,
    };
  }
  return {
    accountType: "pda_or_program_account",
    label: `Program-Owned Account (${owner.slice(0, 6)}…${owner.slice(-4)})`,
    executable: false,
    ownerProgram: owner,
  };
}

async function solanaSingleRpcWithFailover(
  rpcUrls,
  reqObj,
  { fetchImpl = globalThis.fetch, timeoutMs = DEFAULT_RPC_TIMEOUT_MS } = {}
) {
  let lastErr = "All Solana RPC endpoints failed";
  for (const rpcUrl of rpcUrls) {
    try {
      const res = await fetchImpl(rpcUrl, {
        method: "POST",
        signal: AbortSignal.timeout(timeoutMs),
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(reqObj),
      });
      if (!res.ok) {
        lastErr = `HTTP ${res.status} from ${rpcUrl}`;
        continue;
      }
      const parsed = await res.json();
      const item = Array.isArray(parsed)
        ? parsed.find((x) => x.id === reqObj.id) || parsed[0]
        : parsed;
      if (item?.error) {
        lastErr = item.error.message || JSON.stringify(item.error);
        continue;
      }
      return { ok: true, rpcUrl, item };
    } catch (err) {
      lastErr =
        err?.name === "TimeoutError"
          ? `Timeout (${timeoutMs}ms) at ${rpcUrl}`
          : err instanceof Error
            ? err.message
            : String(err);
    }
  }
  return { ok: false, error: lastErr, item: null };
}

export async function inspectSolanaWalletOnChain(
  address,
  {
    signatureLimit = DEFAULT_SOLANA_SIG_LIMIT,
    fetchImpl = globalThis.fetch,
    timeoutMs = DEFAULT_RPC_TIMEOUT_MS,
    customRpcUrl = null,
  } = {}
) {
  const solRpcs = customRpcUrl
    ? [customRpcUrl, ...WALLETLENS_SOLANA_CONFIG.rpcs]
    : WALLETLENS_SOLANA_CONFIG.rpcs;

  const knownEntries = Object.entries(WALLETLENS_SOLANA_CONFIG.knownMints);
  const derivedAtas = knownEntries
    .map(([mint, meta]) => ({
      mint,
      meta,
      ata: deriveSolanaAta(address, meta.programId, mint),
    }))
    .filter((x) => Boolean(x.ata));

  // Browser CORS RPCs (PublicNode / Zan) support O(1) getAccountInfo, getMultipleAccounts, and getSignaturesForAddress
  // with Access-Control-Allow-Origin: * while blocking indexed getTokenAccountsByOwner on free tiers.
  // If a custom RPC is supplied, we ALSO query getTokenAccountsByOwner to capture arbitrary SPL/Token-2022 mints.
  const customOwnerCalls = customRpcUrl
    ? Promise.all([
        solanaSingleRpcWithFailover(
          [customRpcUrl],
          {
            jsonrpc: "2.0",
            id: "spl",
            method: "getTokenAccountsByOwner",
            params: [
              address,
              { programId: TOKEN_PROGRAM_ID },
              { encoding: "jsonParsed", commitment: "confirmed" },
            ],
          },
          { fetchImpl, timeoutMs }
        ),
        solanaSingleRpcWithFailover(
          [customRpcUrl],
          {
            jsonrpc: "2.0",
            id: "tok22",
            method: "getTokenAccountsByOwner",
            params: [
              address,
              { programId: TOKEN_2022_PROGRAM_ID },
              { encoding: "jsonParsed", commitment: "confirmed" },
            ],
          },
          { fetchImpl, timeoutMs }
        ),
      ])
    : Promise.resolve([
        { ok: false, item: null },
        { ok: false, item: null },
      ]);

  const [acctCall, ataMultiCall, sigsCall, [splCall, tok22Call]] = await Promise.all([
    solanaSingleRpcWithFailover(
      solRpcs,
      {
        jsonrpc: "2.0",
        id: "acct",
        method: "getAccountInfo",
        params: [address, { encoding: "base64", commitment: "confirmed" }],
      },
      { fetchImpl, timeoutMs }
    ),
    solanaSingleRpcWithFailover(
      solRpcs,
      {
        jsonrpc: "2.0",
        id: "atas",
        method: "getMultipleAccounts",
        params: [derivedAtas.map((x) => x.ata), { encoding: "jsonParsed", commitment: "confirmed" }],
      },
      { fetchImpl, timeoutMs }
    ),
    solanaSingleRpcWithFailover(
      solRpcs,
      {
        jsonrpc: "2.0",
        id: "sigs",
        method: "getSignaturesForAddress",
        params: [address, { limit: signatureLimit, commitment: "confirmed" }],
      },
      { fetchImpl, timeoutMs }
    ),
    customOwnerCalls,
  ]);

  if (!acctCall.ok && !sigsCall.ok && !ataMultiCall.ok) {
    return {
      ok: false,
      chain: "solana",
      chainName: WALLETLENS_SOLANA_CONFIG.name,
      error: acctCall.error || sigsCall.error,
    };
  }

  const rpcUsed = acctCall.rpcUrl || ataMultiCall.rpcUrl || sigsCall.rpcUrl || solRpcs[0];
  const acctResult = acctCall.item?.result;
  const slot =
    acctResult?.context?.slot ??
    ataMultiCall.item?.result?.context?.slot ??
    null;
  const lamportsBig = BigInt(acctResult?.value?.lamports ?? 0);
  const nativeSol = formatUnitsExact(lamportsBig, 9, 6);
  const accountClassification = classifySolanaOwnerProgram(acctResult?.value || null);

  const byMint = new Map();
  let splAccountCount = 0;
  let token2022AccountCount = 0;

  const ingestAccountInfo = (info, programLabel, pubkey = null) => {
    const tokAmt = info?.tokenAmount;
    const mint = info?.mint;
    if (!mint || !tokAmt) return;
    const rawBig = BigInt(tokAmt.amount || "0");
    const decimals = Number(tokAmt.decimals ?? 0);
    const prev = byMint.get(mint);
    if (prev) {
      if (pubkey && prev.seenPubkeys.has(pubkey)) return;
      if (pubkey) prev.seenPubkeys.add(pubkey);
      prev.atomicBig += rawBig;
      prev.accountCount += 1;
    } else {
      const known = WALLETLENS_SOLANA_CONFIG.knownMints[mint];
      byMint.set(mint, {
        mint,
        symbol: known?.symbol || `SPL:${mint.slice(0, 4)}…${mint.slice(-4)}`,
        isKnown: Boolean(known),
        isStablecoin: Boolean(known?.isStablecoin),
        program: programLabel,
        decimals,
        atomicBig: rawBig,
        accountCount: 1,
        seenPubkeys: new Set(pubkey ? [pubkey] : []),
      });
    }
    if (programLabel === "token-2022") token2022AccountCount += 1;
    else splAccountCount += 1;
  };

  const splRaw = Array.isArray(splCall.item?.result?.value) ? splCall.item.result.value : [];
  const tok22Raw = Array.isArray(tok22Call.item?.result?.value) ? tok22Call.item.result.value : [];
  for (const r of splRaw) {
    ingestAccountInfo(r?.account?.data?.parsed?.info, "spl-token", r?.pubkey || null);
  }
  for (const r of tok22Raw) {
    ingestAccountInfo(r?.account?.data?.parsed?.info, "token-2022", r?.pubkey || null);
  }

  const ataValues = Array.isArray(ataMultiCall.item?.result?.value)
    ? ataMultiCall.item.result.value
    : [];
  ataValues.forEach((acctVal, idx) => {
    if (!acctVal) return;
    const entry = derivedAtas[idx];
    if (!entry || byMint.has(entry.mint)) return;
    const info = acctVal?.data?.parsed?.info;
    const progLabel = entry.meta.programId === TOKEN_2022_PROGRAM_ID ? "token-2022" : "spl-token";
    ingestAccountInfo(info, progLabel, entry.ata);
  });

  const totalTokenAccounts = splAccountCount + token2022AccountCount;

  for (const [mint, meta] of [
    ["EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", WALLETLENS_SOLANA_CONFIG.knownMints.EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v],
    ["Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", WALLETLENS_SOLANA_CONFIG.knownMints.Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB],
  ]) {
    if (!byMint.has(mint)) {
      byMint.set(mint, {
        mint,
        symbol: meta.symbol,
        isKnown: true,
        isStablecoin: true,
        program: "spl-token",
        decimals: meta.decimals,
        atomicBig: 0n,
        accountCount: 0,
      });
    }
  }

  const allTokens = [...byMint.values()]
    .map((entry) => {
      const fmt = formatUnitsExact(entry.atomicBig, entry.decimals, entry.decimals === 6 ? 2 : 4);
      return {
        symbol: entry.symbol,
        mint: entry.mint,
        program: entry.program,
        decimals: entry.decimals,
        isKnown: entry.isKnown,
        isStablecoin: entry.isStablecoin,
        accountCount: entry.accountCount,
        atomic: fmt.atomic,
        balance: fmt.exact,
        display: fmt.display,
        numeric: fmt.numeric,
      };
    })
    .sort((a, b) => {
      if (a.isStablecoin !== b.isStablecoin) return a.isStablecoin ? -1 : 1;
      if (a.isKnown !== b.isKnown) return a.isKnown ? -1 : 1;
      return b.numeric - a.numeric;
    });

  const nonZeroTokens = allTokens.filter((t) => BigInt(t.atomic) > 0n);
  const stablecoinUsdTotal = Number(
    nonZeroTokens
      .filter((t) => t.isStablecoin)
      .reduce((acc, t) => acc + t.numeric, 0)
      .toFixed(2)
  );

  const rawSigs = Array.isArray(sigsCall.item?.result) ? sigsCall.item.result : [];
  const signatures = rawSigs.map((s) => ({
    signature: s.signature,
    slot: s.slot ?? null,
    blockTimeUtc:
      typeof s.blockTime === "number" && s.blockTime > 0
        ? new Date(s.blockTime * 1000).toISOString()
        : null,
    status: s.err ? "FAILED" : "SUCCESS",
    confirmationStatus: s.confirmationStatus || "confirmed",
    error: s.err ? JSON.stringify(s.err) : null,
    memo: s.memo || null,
    explorerTxUrl: `${WALLETLENS_SOLANA_CONFIG.explorerUrl}/tx/${s.signature}`,
  }));

  const slotTimeUtc = signatures[0]?.blockTimeUtc || new Date().toISOString();
  const hasActivity = lamportsBig > 0n || totalTokenAccounts > 0 || signatures.length > 0;

  return {
    ok: true,
    chain: "solana",
    chainName: WALLETLENS_SOLANA_CONFIG.name,
    rpcUsed,
    explorerAddressUrl: `${WALLETLENS_SOLANA_CONFIG.explorerUrl}/account/${address}`,
    slot,
    slotTimeUtc,
    account: accountClassification,
    totalTokenAccounts,
    splAccountCount,
    token2022AccountCount,
    recentSignatureCount: signatures.length,
    hasActivity,
    native: {
      symbol: "SOL",
      decimals: 9,
      atomic: nativeSol.atomic,
      balance: nativeSol.exact,
      display: nativeSol.display,
      numeric: nativeSol.numeric,
    },
    stablecoinUsdTotal,
    tokens: allTokens,
    nonZeroTokens,
    recentSignatures: signatures,
  };
}

/* ============================================================================
 * 4. Single Wallet Scan, Markdown Formatter, Pro 25-Wallet Watchlist & Exports
 * ========================================================================== */

export function formatWalletMarkdownReport(report) {
  if (!report || !report.ok) return "";
  const lines = [
    `# WalletLens Multi-Chain Portfolio & Smart Account Dossier`,
    `- **Address:** \`${report.address}\`${report.label ? ` (${report.label})` : ""}`,
    `- **Network Family:** ${report.family.toUpperCase()}`,
    `- **Verdict:** **${report.verdict}**`,
    `- **Combined Stablecoins:** **$${report.totalStablecoinUsd.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}**`,
    `- **Active Chains:** ${report.activeChainsCount} · **Activity Count:** ${report.totalActivityCount}`,
    `- **Inspected At (UTC):** \`${report.inspectedAtUtc}\` (${report.executionMs} ms)`,
    "",
  ];

  if (report.family === "evm") {
    lines.push(
      "## 1. Multi-Chain EVM Portfolio & Nonce Matrix",
      "| Chain | Block | Account Classification | Tx Nonce | Native Balance | Stablecoins & WETH |",
      "| :--- | :---: | :--- | :---: | :---: | :--- |"
    );
    for (const c of report.chains) {
      if (!c.ok) {
        lines.push(`| ${c.chainName} | — | RPC Error | — | — | ${c.error || "Unreachable"} |`);
        continue;
      }
      const acctDesc = c.account.delegatedTo
        ? `${c.account.label} (\`${c.account.delegatedTo}\`)`
        : c.account.label;
      const tokText =
        c.nonZeroTokens.length > 0
          ? c.nonZeroTokens.map((t) => `${t.display} ${t.symbol}`).join(", ")
          : "$0.00";
      lines.push(
        `| [${c.chainName}](${c.explorerAddressUrl}) | \`#${c.blockNumber ?? "—"}\` | ${acctDesc} | \`${c.nonce}\` | **${c.native.display} ${c.native.symbol}** | ${tokText} |`
      );
    }

    if (report.smartAccountHighlights.length > 0) {
      lines.push("", "## 2. Smart Account & Delegation Intelligence");
      for (const h of report.smartAccountHighlights) {
        lines.push(`- **${h.chainName}:** ${h.summary}`);
      }
    }
  } else {
    const sol = report.chains[0];
    if (sol?.ok) {
      lines.push(
        "## 1. Solana Mainnet Overview",
        `- **Account Type:** ${sol.account.label} (Owner: \`${sol.account.ownerProgram}\`)`,
        `- **Slot:** \`#${sol.slot ?? "—"}\` (\`${sol.slotTimeUtc}\`)`,
        `- **Native Balance:** **${sol.native.display} SOL**`,
        `- **Stablecoins Held:** **$${sol.stablecoinUsdTotal.toFixed(2)}**`,
        ""
      );
      if (sol.nonZeroTokens.length > 0) {
        lines.push(
          "## 2. Non-Zero SPL & Token-2022 Holdings",
          "| Symbol | Program | Balance | Mint |",
          "| :--- | :---: | :---: | :--- |",
          ...sol.nonZeroTokens.map(
            (t) => `| **${t.symbol}** | \`${t.program}\` | **${t.display}** | \`${t.mint}\` |`
          ),
          ""
        );
      }
      if (sol.recentSignatures.length > 0) {
        lines.push(
          `## 3. Latest Solana Signatures (${sol.recentSignatures.length})`,
          "| # | UTC Timestamp | Status | Signature | Memo / Error |",
          "| :---: | :--- | :---: | :--- | :--- |",
          ...sol.recentSignatures.map(
            (s, i) =>
              `| ${i + 1} | \`${s.blockTimeUtc || "—"}\` | ${s.status} | \`${s.signature.slice(0, 10)}…${s.signature.slice(-6)}\` | ${(s.error || s.memo || "—").replace(/\|/g, "\\|")} |`
          ),
          ""
        );
      }
    }
  }

  lines.push(
    `- Autonomous Cloud A2A Agent (\`$0.15 USDC/call\`): ${NEAR_WALLET_SCANNER_URL}`,
    `- Interactive Browser WalletLens: https://youthmy11-ai.github.io/walletcheck.html?address=${encodeURIComponent(report.address)}`
  );
  return lines.join("\n");
}

export async function inspectSingleWallet(rawInput, options = {}) {
  const t0 = globalThis.performance.now();
  const target = extractSingleWalletAddress(rawInput);
  if (!target) {
    throw new Error(
      "Enter a valid EVM ('0x...' 40-hex) or Solana (Base58 32-byte) wallet address."
    );
  }

  const label = options.label ? String(options.label).trim() : "";
  const customRpcUrl = sanitizeHttpsRpcUrl(options.rpcUrl || "");
  const selectedChains = normalizeChainSelection(options.chains);
  const warnings = [];

  let chains = [];
  let verdict = "";
  let primaryAccountType = "eoa";
  let activeChainsCount = 0;
  let totalActivityCount = 0;
  let totalStablecoinUsd = 0;
  const smartAccountHighlights = [];

  if (target.family === "evm") {
    const requestedEvm = selectedChains
      ? selectedChains.filter((c) => c in WALLETLENS_EVM_CHAINS)
      : Object.keys(WALLETLENS_EVM_CHAINS);
    const evmKeys =
      requestedEvm.length > 0 ? requestedEvm : Object.keys(WALLETLENS_EVM_CHAINS);

    chains = await Promise.all(
      evmKeys.map((ck) =>
        inspectEvmWalletOnChain(target.address, WALLETLENS_EVM_CHAINS[ck], {
          fetchImpl: options.fetchImpl,
          timeoutMs: options.timeoutMs ?? DEFAULT_RPC_TIMEOUT_MS,
          customRpcUrl: evmKeys.length === 1 ? customRpcUrl : null,
        })
      )
    );

    for (const c of chains) {
      if (!c.ok) {
        warnings.push(`${c.chainName}: ${c.error}`);
        continue;
      }
      if (c.account.accountType === "eip7702_delegated") {
        smartAccountHighlights.push({
          chain: c.chain,
          chainName: c.chainName,
          accountType: "eip7702_delegated",
          targetAddress: c.account.delegatedTo,
          summary: `EIP-7702 Delegated EOA (0xef0100...) pointing to implementation ${c.account.delegatedTo}`,
        });
      } else if (c.account.accountType === "gnosis_safe") {
        smartAccountHighlights.push({
          chain: c.chain,
          chainName: c.chainName,
          accountType: "gnosis_safe",
          threshold: c.account.safeThreshold,
          ownersCount: c.account.safeOwnersCount,
          owners: c.account.safeOwners,
          summary: `Gnosis Safe Multisig (${c.account.safeThreshold}-of-${c.account.safeOwnersCount} threshold) — Owners: ${c.account.safeOwners.join(", ")}`,
        });
      } else if (c.account.accountType === "erc4337") {
        smartAccountHighlights.push({
          chain: c.chain,
          chainName: c.chainName,
          accountType: "erc4337",
          targetAddress: c.account.entryPoint,
          summary: `ERC-4337 Smart Wallet governed by EntryPoint ${c.account.entryPoint}`,
        });
      } else if (c.account.accountType === "eip1167_proxy") {
        smartAccountHighlights.push({
          chain: c.chain,
          chainName: c.chainName,
          accountType: "eip1167_proxy",
          targetAddress: c.account.implementation,
          summary: `EIP-1167 Minimal Clone Proxy delegating to ${c.account.implementation}`,
        });
      }
    }

    const okChains = chains.filter((c) => c.ok);
    if (okChains.length === 0) {
      throw new Error(warnings[0] || "All EVM RPC endpoints failed.");
    }
    const activeChains = okChains.filter((c) => c.hasActivity);
    activeChainsCount = activeChains.length;
    totalActivityCount = okChains.reduce((acc, c) => acc + c.nonce, 0);
    totalStablecoinUsd = Number(
      okChains.reduce((acc, c) => acc + c.stablecoinUsdTotal, 0).toFixed(2)
    );

    if (okChains.some((c) => c.account.accountType === "gnosis_safe")) {
      primaryAccountType = "gnosis_safe";
      verdict = `Gnosis Safe Multisig (Active on ${activeChainsCount}/${okChains.length} chains)`;
    } else if (okChains.some((c) => c.account.accountType === "eip7702_delegated")) {
      primaryAccountType = "eip7702_delegated";
      verdict = `EIP-7702 Delegated Smart EOA (${totalActivityCount} outgoing txs across ${activeChainsCount} active chain(s))`;
    } else if (okChains.some((c) => c.account.accountType === "erc4337")) {
      primaryAccountType = "erc4337";
      verdict = `ERC-4337 Smart Wallet (Active on ${activeChainsCount}/${okChains.length} chains)`;
    } else if (okChains.some((c) => c.account.isContract)) {
      primaryAccountType = "contract";
      verdict = `Smart Contract / Proxy Account (Active on ${activeChainsCount}/${okChains.length} chains)`;
    } else if (activeChainsCount >= 2) {
      primaryAccountType = "eoa";
      verdict = `Active Multi-Chain EOA (${activeChainsCount} active chains · ${totalActivityCount} outgoing txs)`;
    } else if (activeChainsCount === 1) {
      primaryAccountType = "eoa";
      verdict = `Active Single-Chain EOA on ${activeChains[0].chainName} (${totalActivityCount} outgoing txs)`;
    } else {
      primaryAccountType = "eoa";
      verdict = "Fresh / Dormant EVM Address (0 on-chain activity)";
    }
  } else {
    const solRes = await inspectSolanaWalletOnChain(target.address, {
      signatureLimit: options.signatureLimit ?? DEFAULT_SOLANA_SIG_LIMIT,
      fetchImpl: options.fetchImpl,
      timeoutMs: options.timeoutMs ?? DEFAULT_RPC_TIMEOUT_MS,
      customRpcUrl,
    });
    if (!solRes.ok) {
      throw new Error(solRes.error || "Solana RPC inspection failed.");
    }
    chains = [solRes];
    primaryAccountType = solRes.account.accountType;
    activeChainsCount = solRes.hasActivity ? 1 : 0;
    totalActivityCount = solRes.recentSignatureCount;
    totalStablecoinUsd = solRes.stablecoinUsdTotal;

    if (solRes.account.accountType === "squads_multisig") {
      smartAccountHighlights.push({
        chain: "solana",
        chainName: "Solana Mainnet",
        accountType: "squads_multisig",
        targetAddress: solRes.account.ownerProgram,
        summary: `Squads Smart Wallet / Multisig owned by program ${solRes.account.ownerProgram}`,
      });
      verdict = "Squads Multisig Smart Wallet on Solana";
    } else if (solRes.account.executable) {
      verdict = "Executable Solana On-Chain Program";
    } else if (solRes.hasActivity) {
      verdict = `Active Solana Wallet (${solRes.native.display} SOL · ${solRes.nonZeroTokens.length} non-zero token(s) · ${solRes.recentSignatureCount} recent tx(s))`;
    } else {
      verdict = "Unfunded / Dormant Solana Address";
    }
  }

  const executionMs = Math.max(1, Math.round(globalThis.performance.now() - t0));
  const inspectedAtUtc = new Date().toISOString();

  const report = {
    ok: true,
    address: target.address,
    label,
    family: target.family,
    inspectedAtUtc,
    executionMs,
    verdict,
    primaryAccountType,
    activeChainsCount,
    totalActivityCount,
    totalStablecoinUsd,
    chains,
    smartAccountHighlights,
    warnings,
    markdownSummary: "",
  };
  report.markdownSummary = formatWalletMarkdownReport(report);
  return report;
}

export function parseWalletWatchlistEntries(rawInput) {
  const lines = Array.isArray(rawInput)
    ? rawInput.map((x) => String(x ?? "").trim()).filter(Boolean)
    : String(rawInput ?? "")
        .split(/[\r\n]+/)
        .map((s) => s.trim())
        .filter(Boolean);

  const entries = [];
  const seen = new Set();

  for (const line of lines) {
    // Support "Label | 0x..." or comma-separated raw addresses on a single line
    if (line.includes("|")) {
      const pipeIdx = line.indexOf("|");
      const labelPart = line.slice(0, pipeIdx).trim();
      const addrPart = line.slice(pipeIdx + 1).trim();
      const extracted = extractSingleWalletAddress(addrPart);
      if (extracted) {
        const key = extracted.family === "evm" ? extracted.address.toLowerCase() : extracted.address;
        if (!seen.has(key)) {
          seen.add(key);
          entries.push({
            label: labelPart,
            address: extracted.address,
            family: extracted.family,
          });
        }
      }
      continue;
    }

    const segments = line.split(",").map((s) => s.trim()).filter(Boolean);
    for (const seg of segments) {
      const extracted = extractSingleWalletAddress(seg);
      if (!extracted) continue;
      const key = extracted.family === "evm" ? extracted.address.toLowerCase() : extracted.address;
      if (seen.has(key)) continue;
      seen.add(key);
      entries.push({
        label: "",
        address: extracted.address,
        family: extracted.family,
      });
    }
  }

  return entries;
}

export async function runBatchWalletWatchlist(rawInput, options = {}) {
  const entries =
    Array.isArray(rawInput) && rawInput.every((x) => x && typeof x === "object" && "address" in x)
      ? rawInput
      : parseWalletWatchlistEntries(rawInput);

  if (entries.length === 0) {
    throw new Error(
      "Provide 1 to 25 valid EVM ('0x...') or Solana (Base58) wallet addresses."
    );
  }
  if (entries.length > MAX_WATCHLIST_WALLETS) {
    throw new Error(
      `Pro Treasury Watchlist supports up to ${MAX_WATCHLIST_WALLETS} wallets per batch (received ${entries.length}).`
    );
  }

  const concurrency = Math.max(1, Math.min(5, Number(options.concurrency ?? 4)));
  const reports = new Array(entries.length);
  let cursor = 0;

  async function worker() {
    while (cursor < entries.length) {
      const idx = cursor;
      cursor += 1;
      const item = entries[idx];
      try {
        reports[idx] = await inspectSingleWallet(item.address, {
          ...options,
          label: item.label || "",
        });
      } catch (err) {
        reports[idx] = {
          ok: false,
          address: item.address,
          label: item.label || "",
          family: item.family || "unknown",
          error: err instanceof Error ? err.message : String(err),
          inspectedAtUtc: new Date().toISOString(),
        };
      }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, entries.length) }, () => worker())
  );

  const okReports = reports.filter((r) => r && r.ok);
  const combinedStablecoinUsd = Number(
    okReports.reduce((acc, r) => acc + r.totalStablecoinUsd, 0).toFixed(2)
  );
  const totalActiveChains = okReports.reduce((acc, r) => acc + r.activeChainsCount, 0);
  const smartAccountsCount = okReports.filter((r) =>
    ["gnosis_safe", "eip7702_delegated", "erc4337", "eip1167_proxy", "squads_multisig"].includes(
      r.primaryAccountType
    )
  ).length;

  return {
    ok: okReports.length > 0,
    inspectedAtUtc: new Date().toISOString(),
    totalWallets: reports.length,
    okCount: okReports.length,
    combinedStablecoinUsd,
    totalActiveChains,
    smartAccountsCount,
    reports,
  };
}

function csvSafeCell(value) {
  let str = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@]/.test(str)) {
    str = `'${str}`;
  }
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export function exportWalletWatchlistCsv(batchOrReports = []) {
  const reports = Array.isArray(batchOrReports)
    ? batchOrReports
    : Array.isArray(batchOrReports?.reports)
      ? batchOrReports.reports
      : [];

  const headers = [
    "label",
    "address",
    "family",
    "primary_account_type",
    "verdict",
    "active_chains",
    "tx_activity_count",
    "total_stablecoin_usd",
    "ethereum_native",
    "base_native",
    "arbitrum_native",
    "bsc_native",
    "polygon_native",
    "solana_native",
    "smart_account_detail",
    "inspected_at_utc",
  ];

  const rows = reports.map((r) => {
    if (!r || !r.ok) {
      return [
        r?.label || "",
        r?.address || "",
        r?.family || "",
        "ERROR",
        r?.error || "Scan failed",
        0,
        0,
        "0.00",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        r?.inspectedAtUtc || "",
      ];
    }

    const byChain = new Map((r.chains || []).filter((c) => c.ok).map((c) => [c.chain, c]));
    const fmtNat = (k) => {
      const c = byChain.get(k);
      return c ? `${c.native.balance} ${c.native.symbol}` : "";
    };
    const smartNote = (r.smartAccountHighlights || []).map((h) => h.summary).join(" | ");

    return [
      r.label || "",
      r.address,
      r.family,
      r.primaryAccountType,
      r.verdict,
      r.activeChainsCount,
      r.totalActivityCount,
      r.totalStablecoinUsd.toFixed(2),
      fmtNat("ethereum"),
      fmtNat("base"),
      fmtNat("arbitrum"),
      fmtNat("bsc"),
      fmtNat("polygon"),
      fmtNat("solana"),
      smartNote,
      r.inspectedAtUtc || "",
    ];
  });

  return [
    headers.join(","),
    ...rows.map((row) => row.map(csvSafeCell).join(",")),
  ].join("\n");
}

/* ============================================================================
 * 5. CryptoBill Invoice & ScopeGuard SOW 1-Click Handoff Builders
 * ========================================================================== */

export function buildWalletAuditInvoicePayload(scanOrBatch) {
  const inv = createDefaultInvoice();
  inv.clientName = "DAO Treasury / Web3 Operations Team";
  inv.taxPercent = 0;
  inv.discountPercent = 0;

  const batchList = Array.isArray(scanOrBatch)
    ? scanOrBatch
    : Array.isArray(scanOrBatch?.reports)
      ? scanOrBatch.reports
      : null;

  if (batchList && batchList.length > 0) {
    const okList = batchList.filter((r) => r && r.ok);
    const totalUsd = okList.reduce((acc, r) => acc + (r.totalStablecoinUsd || 0), 0);
    inv.notes = `Multi-Chain Treasury, EIP-7702 Delegation & Gnosis Safe Multisig Watchlist Audit (${okList.length}/${batchList.length} wallets inspected across Ethereum, Base, Arbitrum, BSC, Polygon & Solana via ForgeSuite WalletLens; $${totalUsd.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} stablecoins verified).`;
    inv.items = [
      {
        description: `Multi-Chain Treasury & Counterparty Wallet Audit (${batchList.length} Wallets)`,
        qty: 1,
        unitPrice: Math.max(245, batchList.length * 25),
      },
    ];
    return inv;
  }

  const addr = scanOrBatch?.address || "0x... / Solana Treasury";
  const shortAddr =
    addr.length > 16 ? `${addr.slice(0, 8)}...${addr.slice(-6)}` : addr;
  inv.notes = `Multi-chain wallet portfolio, EIP-7702 delegation, Gnosis Safe signer threshold & counterparty due-diligence dossier for ${addr}${scanOrBatch?.verdict ? ` (${scanOrBatch.verdict})` : ""} via ForgeSuite WalletLens.`;
  inv.items = [
    {
      description: `Multi-Chain Wallet & Smart Account Due-Diligence Report (${shortAddr})`,
      qty: 1,
      unitPrice: 165,
    },
  ];
  return inv;
}

export function encodeSowHandoffPayload(sowState) {
  const json = JSON.stringify(sowState);
  const bytes = new TextEncoder().encode(json);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 =
    typeof btoa === "function"
      ? btoa(binary)
      : globalThis.Buffer.from(json, "utf8").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function buildWalletSowState(scanOrBatch) {
  const batchList = Array.isArray(scanOrBatch)
    ? scanOrBatch
    : Array.isArray(scanOrBatch?.reports)
      ? scanOrBatch.reports
      : null;
  const isBatch = Boolean(batchList && batchList.length > 0);
  const targetLabel = isBatch
    ? `${batchList.length}-Wallet Treasury & Counterparty Cohort`
    : scanOrBatch?.address
      ? `${scanOrBatch.address.slice(0, 8)}…${scanOrBatch.address.slice(-6)}`
      : "Multi-Chain Treasury";
  const totalBudget = isBatch ? Math.max(750, batchList.length * 45) : 550;

  return {
    projectTitle: `Multi-Chain Treasury, EIP-7702 & Safe Multisig Review — ${targetLabel}`,
    providerName: "ForgeSuite Web3 Risk & Treasury Ops",
    clientName: "DAO / Protocol Treasury Council",
    totalBudget,
    revisionsIncluded: 2,
    noticeDays: 3,
    settlementRail: "sol-usdc",
    deliverables: [
      `- 6-chain native & stablecoin liquidity snapshot (Ethereum, Base, Arbitrum, BSC, Polygon, Solana) for ${targetLabel}`,
      "- EIP-7702 delegation (0xef0100...), Gnosis Safe M-of-N signer threshold, and ERC-4337 EntryPoint verification",
      "- CSV/JSON treasury reconciliation matrix & counterparty risk recommendations",
    ].join("\n"),
    milestones: [
      { title: "M1: On-Chain Portfolio, Nonce & Delegation Snapshot", percent: 50, due: "On kickoff" },
      { title: "M2: Multisig Governance Review & CSV/JSON Treasury Dossier", percent: 50, due: "Day 3" },
    ],
  };
}

/* ============================================================================
 * 6. Browser UI Controller for walletcheck.html
 * ========================================================================== */

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function badgeClassForAccountType(accountType) {
  if (accountType === "gnosis_safe" || accountType === "squads_multisig") return "fs-badge-success";
  if (accountType === "eip7702_delegated" || accountType === "erc4337" || accountType === "eip1167_proxy") {
    return "fs-badge-warn";
  }
  if (accountType === "eoa" || accountType === "system_wallet") return "fs-badge-accent";
  return "fs-badge-muted";
}

function isWalletLensProUnlocked() {
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

function initWalletLensApp() {
  if (typeof document === "undefined" || document.body?.dataset?.page !== "walletcheck") {
    return;
  }

  const addressInputEl = document.getElementById("wlAddressInput");
  const customRpcInputEl = document.getElementById("wlCustomRpcInput");
  const scanBtn = document.getElementById("wlScanBtn");
  const statusEl = document.getElementById("wlStatusMsg");
  const chainCheckboxes = Array.from(document.querySelectorAll("[data-wl-chain]"));

  const verdictBadgeEl = document.getElementById("wlVerdictBadge");
  const summaryHeaderEl = document.getElementById("wlSummaryHeader");
  const metaGridEl = document.getElementById("wlMetaGrid");
  const smartBoxEl = document.getElementById("wlSmartAccountBox");
  const smartListEl = document.getElementById("wlSmartAccountList");
  const chainsTitleEl = document.getElementById("wlChainsSectionTitle");
  const chainsBodyEl = document.getElementById("wlChainsBody");
  const solanaExtraWrapEl = document.getElementById("wlSolanaExtraWrap");
  const solTokensBodyEl = document.getElementById("wlSolTokensBody");
  const solSigsBodyEl = document.getElementById("wlSolSigsBody");
  const copyMdBtn = document.getElementById("wlCopyMdBtn");

  const proBadgeEl = document.getElementById("wlProStatusBadge");
  const proLockBannerEl = document.getElementById("wlProLockBanner");
  const batchInputEl = document.getElementById("wlBatchInput");
  const batchRunBtn = document.getElementById("wlBatchRunBtn");
  const exportCsvBtn = document.getElementById("wlExportCsvBtn");
  const exportJsonBtn = document.getElementById("wlExportJsonBtn");
  const batchStatusEl = document.getElementById("wlBatchStatusMsg");
  const batchBodyEl = document.getElementById("wlBatchBody");

  const invoiceBtn = document.getElementById("wlSendInvoiceBtn");
  const sowBtn = document.getElementById("wlSendSowBtn");

  let lastSingleReport = null;
  let lastBatchPack = null;

  function syncProUi() {
    const unlocked = isWalletLensProUnlocked();
    if (proBadgeEl) {
      proBadgeEl.textContent = unlocked
        ? "PRO ACTIVE · 25-WALLET WATCHLIST UNLOCKED ✓"
        : "PRO FEATURE · $15 PRO / $35 BUNDLE";
      proBadgeEl.className = `fs-badge ${unlocked ? "fs-badge-success" : "fs-badge-warn"}`;
    }
    if (proLockBannerEl) {
      proLockBannerEl.hidden = unlocked;
    }
    if (batchRunBtn) {
      batchRunBtn.textContent = unlocked
        ? "Run 25-Wallet Treasury Watchlist"
        : "Unlock 25-Wallet Watchlist — Bundle ($35)";
    }
  }

  bindCheckoutTriggers({ onUnlocked: syncProUi });
  window.addEventListener("forgesuite:license-updated", syncProUi);

  const navBundleBtn = document.getElementById("wlBundleBtn");
  if (navBundleBtn) {
    navBundleBtn.addEventListener("click", () =>
      openCheckoutModal("BUNDLE", { onUnlocked: syncProUi })
    );
  }
  const activateKeyBtn = document.getElementById("wlActivateKeyBtn");
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

  function getSelectedChainsFromUi() {
    if (chainCheckboxes.length === 0) return null;
    const checked = chainCheckboxes
      .filter((cb) => cb.checked)
      .map((cb) => cb.getAttribute("data-wl-chain"))
      .filter(Boolean);
    return checked.length > 0 ? checked : null;
  }

  function renderSingleReport(report) {
    lastSingleReport = report;
    if (!report || !report.ok) return;

    if (verdictBadgeEl) {
      const badgeLabel =
        report.primaryAccountType === "gnosis_safe"
          ? "GNOSIS SAFE MULTISIG"
          : report.primaryAccountType === "eip7702_delegated"
            ? "EIP-7702 DELEGATED"
            : report.primaryAccountType === "erc4337"
              ? "ERC-4337 SMART WALLET"
              : report.family === "solana"
                ? "SOLANA MAINNET"
                : `${report.activeChainsCount} ACTIVE CHAIN(S)`;
      verdictBadgeEl.textContent = badgeLabel;
      verdictBadgeEl.className = `fs-badge ${badgeClassForAccountType(report.primaryAccountType)}`;
    }

    if (summaryHeaderEl) {
      summaryHeaderEl.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;">
          <div>
            <code>${escapeHtml(report.address)}</code>
            ${report.label ? `<span class="inv-muted">· ${escapeHtml(report.label)}</span>` : ""}
          </div>
          <span class="inv-muted" style="font-size:0.82rem;">UTC: <code>${escapeHtml(report.inspectedAtUtc)}</code> (${escapeHtml(report.executionMs)} ms)</span>
        </div>
        <div style="margin-top:6px;font-weight:600;">${escapeHtml(report.verdict)}</div>
      `;
    }

    if (metaGridEl) {
      metaGridEl.innerHTML = `
        <div class="fs-mono-chip"><strong>Combined Stablecoins:</strong> $${escapeHtml(report.totalStablecoinUsd.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }))}</div>
        <div class="fs-mono-chip"><strong>Active Chains:</strong> ${escapeHtml(report.activeChainsCount)} / ${escapeHtml(report.chains.length)}</div>
        <div class="fs-mono-chip"><strong>${report.family === "solana" ? "Recent Signatures" : "Total Outgoing Nonces"}:</strong> ${escapeHtml(report.totalActivityCount.toLocaleString("en-US"))}</div>
        <div class="fs-mono-chip"><strong>Account Class:</strong> ${escapeHtml(report.primaryAccountType.toUpperCase())}</div>
      `;
    }

    if (smartBoxEl && smartListEl) {
      if (report.smartAccountHighlights.length > 0) {
        smartBoxEl.hidden = false;
        smartListEl.innerHTML = report.smartAccountHighlights
          .map((h) => {
            const auditLink =
              h.targetAddress && h.chain !== "solana" && ["ethereum", "base", "bsc", "arbitrum"].includes(h.chain)
                ? ` · <a href="tokenaudit.html?chain=${encodeURIComponent(h.chain)}&amp;address=${encodeURIComponent(h.targetAddress)}" style="text-decoration:underline;font-weight:600;">Audit Implementation in TokenGuard →</a>`
                : "";
            return `<li><strong>${escapeHtml(h.chainName)}:</strong> ${escapeHtml(h.summary)}${auditLink}</li>`;
          })
          .join("");
      } else {
        smartBoxEl.hidden = true;
        smartListEl.innerHTML = "";
      }
    }

    if (report.family === "evm") {
      if (chainsTitleEl) {
        chainsTitleEl.textContent = "Multi-Chain EVM Balance, Nonce & Smart Account Matrix";
      }
      if (solanaExtraWrapEl) solanaExtraWrapEl.hidden = true;
      if (chainsBodyEl) {
        chainsBodyEl.innerHTML = report.chains
          .map((c) => {
            if (!c.ok) {
              return `<tr>
                <td><strong>${escapeHtml(c.chainName)}</strong></td>
                <td><span class="fs-badge fs-badge-warn">RPC ERROR</span></td>
                <td>—</td>
                <td>—</td>
                <td class="inv-muted">${escapeHtml(c.error || "Unreachable")}</td>
              </tr>`;
            }
            const subNote = c.account.delegatedTo
              ? `<div style="font-size:0.76rem;" class="inv-muted">→ <code>${escapeHtml(c.account.delegatedTo.slice(0, 10))}…${escapeHtml(c.account.delegatedTo.slice(-6))}</code></div>`
              : c.account.accountType === "gnosis_safe"
                ? `<div style="font-size:0.76rem;" class="inv-muted">${escapeHtml(c.account.safeThreshold)}/${escapeHtml(c.account.safeOwnersCount)} signers</div>`
                : "";
            const tokStr =
              c.nonZeroTokens.length > 0
                ? c.nonZeroTokens
                    .map((t) => `<strong>${escapeHtml(t.display)} ${escapeHtml(t.symbol)}</strong>`)
                    .join(" · ")
                : `<span class="inv-muted">$0.00</span>`;
            return `<tr>
              <td>
                <a href="${escapeHtml(c.explorerAddressUrl)}" target="_blank" rel="noopener noreferrer" style="font-weight:700;text-decoration:underline;">${escapeHtml(c.chainName)} ↗</a>
                <div style="font-size:0.75rem;" class="inv-muted">Blk #${escapeHtml(c.blockNumber ?? "—")}</div>
              </td>
              <td>
                <span class="fs-badge ${badgeClassForAccountType(c.account.accountType)}">${escapeHtml(c.account.label)}</span>
                ${subNote}
              </td>
              <td><code>${escapeHtml(c.nonce.toLocaleString("en-US"))}</code></td>
              <td><strong>${escapeHtml(c.native.display)} ${escapeHtml(c.native.symbol)}</strong></td>
              <td>${tokStr}</td>
            </tr>`;
          })
          .join("");
      }
    } else {
      const sol = report.chains[0];
      if (chainsTitleEl) {
        chainsTitleEl.textContent = "Solana Mainnet Account & Native SOL Overview";
      }
      if (chainsBodyEl && sol) {
        chainsBodyEl.innerHTML = `<tr>
          <td>
            <a href="${escapeHtml(sol.explorerAddressUrl)}" target="_blank" rel="noopener noreferrer" style="font-weight:700;text-decoration:underline;">Solana Mainnet ↗</a>
            <div style="font-size:0.75rem;" class="inv-muted">Slot #${escapeHtml(sol.slot ?? "—")}</div>
          </td>
          <td>
            <span class="fs-badge ${badgeClassForAccountType(sol.account.accountType)}">${escapeHtml(sol.account.label)}</span>
            <div style="font-size:0.75rem;" class="inv-muted">Owner: <code>${escapeHtml(sol.account.ownerProgram.slice(0, 8))}…</code></div>
          </td>
          <td><code>${escapeHtml(sol.recentSignatureCount)} recent</code></td>
          <td><strong>${escapeHtml(sol.native.display)} SOL</strong></td>
          <td><strong>$${escapeHtml(sol.stablecoinUsdTotal.toFixed(2))}</strong> (${escapeHtml(sol.nonZeroTokens.length)} non-zero token(s))</td>
        </tr>`;
      }

      if (solanaExtraWrapEl && sol) {
        solanaExtraWrapEl.hidden = false;
        if (solTokensBodyEl) {
          if (sol.nonZeroTokens.length === 0) {
            solTokensBodyEl.innerHTML = `<tr><td colspan="4" class="inv-muted">No non-zero canonical SPL / Token-2022 balances detected on this address.</td></tr>`;
          } else {
            solTokensBodyEl.innerHTML = sol.nonZeroTokens
              .map(
                (t) => `<tr>
                  <td><strong>${escapeHtml(t.symbol)}</strong></td>
                  <td><code>${escapeHtml(t.program)}</code></td>
                  <td><strong>${escapeHtml(t.display)}</strong></td>
                  <td>
                    <code>${escapeHtml(t.mint.slice(0, 8))}…${escapeHtml(t.mint.slice(-6))}</code>
                    · <a href="tokenaudit.html?chain=solana&amp;mint=${encodeURIComponent(t.mint)}" style="text-decoration:underline;">Audit Mint →</a>
                  </td>
                </tr>`
              )
              .join("");
          }
        }

        if (solSigsBodyEl) {
          if (sol.recentSignatures.length === 0) {
            solSigsBodyEl.innerHTML = `<tr><td colspan="4" class="inv-muted">No recent confirmed Solana transactions found.</td></tr>`;
          } else {
            solSigsBodyEl.innerHTML = sol.recentSignatures
              .map(
                (s) => `<tr>
                  <td><code>${escapeHtml(s.blockTimeUtc ? s.blockTimeUtc.replace("T", " ").replace(/\.\d+Z$/, " UTC") : "—")}</code></td>
                  <td><span class="fs-badge ${s.status === "SUCCESS" ? "fs-badge-success" : "fs-badge-warn"}">${escapeHtml(s.status)}</span></td>
                  <td><a href="${escapeHtml(s.explorerTxUrl)}" target="_blank" rel="noopener noreferrer" style="text-decoration:underline;"><code>${escapeHtml(s.signature.slice(0, 10))}…${escapeHtml(s.signature.slice(-6))}</code> ↗</a></td>
                  <td><small>${escapeHtml(s.error || s.memo || "—")}</small></td>
                </tr>`
              )
              .join("");
          }
        }
      }
    }
  }

  async function executeSingleScan() {
    const raw = String(addressInputEl?.value || "").trim();
    if (!raw) {
      if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = "Enter an EVM ('0x...' 40-hex) or Solana (Base58) wallet address.";
      }
      return;
    }

    const chains = getSelectedChainsFromUi();
    const rpcUrl = String(customRpcInputEl?.value || "").trim();

    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.textContent = "Scanning Live RPCs...";
    }
    if (statusEl) {
      statusEl.className = "fs-status-msg is-loading";
      statusEl.textContent =
        "Querying CORS-clean PublicNode EVM & Solana JSON-RPC endpoints in parallel...";
    }

    try {
      const report = await inspectSingleWallet(raw, { chains, rpcUrl });
      renderSingleReport(report);
      if (typeof window !== "undefined" && window.history?.replaceState) {
        const nextUrl = new URL(window.location.href);
        nextUrl.searchParams.set("address", report.address);
        window.history.replaceState({}, "", nextUrl.toString());
      }
      if (statusEl) {
        statusEl.className = "fs-status-msg is-success";
        statusEl.textContent = `Inspected ${report.address.slice(0, 10)}… in ${report.executionMs} ms — ${report.verdict}.`;
      }
    } catch (err) {
      if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = err instanceof Error ? err.message : String(err);
      }
    } finally {
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.textContent = "Inspect Wallet";
      }
    }
  }

  document.querySelectorAll("[data-wl-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.getAttribute("data-wl-sample");
      const addr = WALLETLENS_SAMPLES[key] || key;
      if (!addr) return;
      if (addressInputEl) addressInputEl.value = addr;
      executeSingleScan();
    });
  });

  if (scanBtn) scanBtn.addEventListener("click", executeSingleScan);
  if (addressInputEl) {
    addressInputEl.addEventListener("keydown", (e) => {
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
      const payload = buildWalletAuditInvoicePayload(lastBatchPack || lastSingleReport);
      const hash = encodeInvoicePayload(payload);
      window.location.href = `cryptobill.html#inv=${hash}`;
    });
  }

  if (sowBtn) {
    sowBtn.addEventListener("click", () => {
      const sowState = buildWalletSowState(lastBatchPack || lastSingleReport);
      const hash = encodeSowHandoffPayload(sowState);
      window.location.href = `sowbuilder.html#sow=${hash}`;
    });
  }

  if (batchInputEl && !batchInputEl.value.trim()) {
    batchInputEl.value = DEFAULT_WATCHLIST_SAMPLE;
  }

  if (batchRunBtn) {
    batchRunBtn.addEventListener("click", async () => {
      if (!isWalletLensProUnlocked()) {
        openCheckoutModal("BUNDLE", { onUnlocked: syncProUi });
        return;
      }

      const entries = parseWalletWatchlistEntries(batchInputEl?.value || "");
      if (entries.length === 0) {
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-error";
          batchStatusEl.textContent =
            "Enter 1 to 25 EVM ('0x...') or Solana (Base58) wallet addresses.";
        }
        return;
      }
      if (entries.length > MAX_WATCHLIST_WALLETS) {
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-error";
          batchStatusEl.textContent = `Maximum ${MAX_WATCHLIST_WALLETS} wallets per watchlist run (found ${entries.length}).`;
        }
        return;
      }

      batchRunBtn.disabled = true;
      batchRunBtn.textContent = `Scanning ${entries.length} Wallets...`;
      if (batchStatusEl) {
        batchStatusEl.className = "fs-status-msg is-loading";
        batchStatusEl.textContent = `Inspecting ${entries.length} multi-chain treasury/counterparty wallets in parallel...`;
      }

      try {
        const pack = await runBatchWalletWatchlist(entries, {
          chains: getSelectedChainsFromUi(),
        });
        lastBatchPack = pack;

        if (batchBodyEl) {
          batchBodyEl.innerHTML = pack.reports
            .map((r, idx) => {
              if (!r.ok) {
                return `<tr>
                  <td><code>${escapeHtml(r.address.slice(0, 10))}…</code></td>
                  <td><span class="fs-badge fs-badge-warn">ERROR</span></td>
                  <td colspan="3" class="inv-muted">${escapeHtml(r.error)}</td>
                </tr>`;
              }
              return `<tr>
                <td>
                  <strong><code>${escapeHtml(r.address.slice(0, 8))}…${escapeHtml(r.address.slice(-6))}</code></strong>
                  ${r.label ? `<div style="font-size:0.75rem;" class="inv-muted">${escapeHtml(r.label)}</div>` : ""}
                </td>
                <td><span class="fs-badge ${badgeClassForAccountType(r.primaryAccountType)}">${escapeHtml(r.primaryAccountType.toUpperCase())}</span></td>
                <td><strong>$${escapeHtml(r.totalStablecoinUsd.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }))}</strong></td>
                <td><small>${escapeHtml(r.activeChainsCount)} chain(s) · ${escapeHtml(r.totalActivityCount)} txs</small></td>
                <td><button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-wl-batch-idx="${idx}">Inspect</button></td>
              </tr>`;
            })
            .join("");

          batchBodyEl.querySelectorAll("[data-wl-batch-idx]").forEach((b) => {
            b.addEventListener("click", () => {
              const i = Number(b.getAttribute("data-wl-batch-idx"));
              if (lastBatchPack?.reports?.[i]?.ok) {
                if (addressInputEl) addressInputEl.value = lastBatchPack.reports[i].address;
                renderSingleReport(lastBatchPack.reports[i]);
              }
            });
          });
        }

        if (exportCsvBtn) exportCsvBtn.disabled = false;
        if (exportJsonBtn) exportJsonBtn.disabled = false;
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-success";
          batchStatusEl.textContent = `Watchlist complete: ${pack.okCount}/${pack.totalWallets} wallets · $${pack.combinedStablecoinUsd.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} total stablecoins · ${pack.smartAccountsCount} smart account(s).`;
        }
      } catch (err) {
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-error";
          batchStatusEl.textContent = err instanceof Error ? err.message : String(err);
        }
      } finally {
        batchRunBtn.disabled = false;
        syncProUi();
      }
    });
  }

  if (exportCsvBtn) {
    exportCsvBtn.addEventListener("click", () => {
      if (!isWalletLensProUnlocked()) {
        openCheckoutModal("BUNDLE", { onUnlocked: syncProUi });
        return;
      }
      if (!lastBatchPack) return;
      downloadBlob(
        "walletlens-treasury-watchlist.csv",
        exportWalletWatchlistCsv(lastBatchPack),
        "text/csv;charset=utf-8"
      );
    });
  }

  if (exportJsonBtn) {
    exportJsonBtn.addEventListener("click", () => {
      if (!isWalletLensProUnlocked()) {
        openCheckoutModal("BUNDLE", { onUnlocked: syncProUi });
        return;
      }
      if (!lastBatchPack) return;
      downloadBlob(
        "walletlens-treasury-watchlist.json",
        JSON.stringify(
          {
            suite: "ForgeSuite WalletLens Pro",
            ...lastBatchPack,
          },
          null,
          2
        ),
        "application/json;charset=utf-8"
      );
    });
  }

  syncProUi();

  const qp = parseWalletCheckQueryParams(window.location.search);
  if (qp.chains && chainCheckboxes.length > 0) {
    chainCheckboxes.forEach((cb) => {
      const k = cb.getAttribute("data-wl-chain");
      cb.checked = qp.chains.includes(k);
    });
  }
  if (qp.rpcUrl && customRpcInputEl) {
    customRpcInputEl.value = qp.rpcUrl;
  }
  if (qp.hasTarget && addressInputEl) {
    addressInputEl.value = qp.address;
    if (qp.autorun) executeSingleScan();
  } else if (addressInputEl && !addressInputEl.value.trim()) {
    addressInputEl.value = WALLETLENS_SAMPLES.ens_safe;
    executeSingleScan();
  }
}

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", initWalletLensApp);
}
