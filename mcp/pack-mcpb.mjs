#!/usr/bin/env node
/**
 * Deterministic zero-dependency MCPB (.mcpb ZIP archive) builder for ForgeSuite MCP.
 * Produces a bit-for-bit reproducible PKZIP (STORE) bundle across Windows/Linux/macOS
 * and prints the JSON metadata + SHA-256 digest.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

export function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Builds a deterministic PKZIP archive (method 0 STORE, fixed timestamp 2026-01-01 00:00:00)
 * from an array of { name: string, data: Buffer, mode?: number }.
 */
export function buildDeterministicZip(entries) {
  // Fixed DOS date/time: 2026-01-01 00:00:00 -> date = ((2026-1980)<<9)|(1<<5)|1 = 0x5c21, time = 0x0000
  const DOS_TIME = 0x0000;
  const DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1;

  const localChunks = [];
  const centralChunks = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name.replace(/\\/g, "/"), "utf8");
    const dataBuf = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data);
    const sum = crc32(dataBuf);
    const size = dataBuf.length;
    const unixMode = entry.mode ?? 0o100644;

    // Local file header (30 bytes + filename)
    const localHdr = Buffer.alloc(30);
    localHdr.writeUInt32LE(0x04034b50, 0); // signature
    localHdr.writeUInt16LE(20, 4); // version needed (2.0)
    localHdr.writeUInt16LE(0x0800, 6); // UTF-8 filename flag
    localHdr.writeUInt16LE(0, 8); // compression method: 0 (STORE)
    localHdr.writeUInt16LE(DOS_TIME, 10);
    localHdr.writeUInt16LE(DOS_DATE, 12);
    localHdr.writeUInt32LE(sum, 14);
    localHdr.writeUInt32LE(size, 18);
    localHdr.writeUInt32LE(size, 22);
    localHdr.writeUInt16LE(nameBuf.length, 26);
    localHdr.writeUInt16LE(0, 28); // extra length

    localChunks.push(localHdr, nameBuf, dataBuf);

    // Central directory header (46 bytes + filename)
    const centralHdr = Buffer.alloc(46);
    centralHdr.writeUInt32LE(0x02014b50, 0); // signature
    centralHdr.writeUInt16LE(0x0314, 4); // version made by: Unix (3) + 2.0 (20)
    centralHdr.writeUInt16LE(20, 6); // version needed
    centralHdr.writeUInt16LE(0x0800, 8); // UTF-8 flag
    centralHdr.writeUInt16LE(0, 10); // method: STORE
    centralHdr.writeUInt16LE(DOS_TIME, 12);
    centralHdr.writeUInt16LE(DOS_DATE, 14);
    centralHdr.writeUInt32LE(sum, 16);
    centralHdr.writeUInt32LE(size, 20);
    centralHdr.writeUInt32LE(size, 24);
    centralHdr.writeUInt16LE(nameBuf.length, 28);
    centralHdr.writeUInt16LE(0, 30); // extra length
    centralHdr.writeUInt16LE(0, 32); // comment length
    centralHdr.writeUInt16LE(0, 34); // disk number
    centralHdr.writeUInt16LE(0, 36); // internal attrs
    centralHdr.writeUInt32LE((unixMode << 16) >>> 0, 38); // external attrs (Unix permissions)
    centralHdr.writeUInt32LE(offset, 42); // relative offset of local header

    centralChunks.push(centralHdr, nameBuf);
    offset += 30 + nameBuf.length + size;
  }

  const centralDirBuf = Buffer.concat(centralChunks);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // EOCD signature
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // central dir start disk
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localChunks, centralDirBuf, eocd]);
}

export function buildMcpbManifest(version) {
  return {
    manifest_version: "0.3",
    name: "forgesuite-mcp",
    display_name: "ForgeSuite Web3, FinOps, Brand & Media MCP",
    version,
    description:
      "Zero-dependency Node 20+ MCP server with 9 tools for multi-chain EVM/Solana wallet & portfolio inspection, token risk scanning, calldata decoding, .env secret redaction, SRT/VTT 9:16 caption auditing, LLM cost estimation, crypto invoicing, and brand availability.",
    author: {
      name: "ForgeSuite Studio (youthmy11-ai)",
      email: "youthmy11@gmail.com",
      url: "https://youthmy11-ai.github.io",
    },
    repository: {
      type: "git",
      url: "https://github.com/youthmy11-ai/youthmy11-ai.github.io.git",
    },
    homepage: "https://youthmy11-ai.github.io/mcp.html",
    documentation: "https://youthmy11-ai.github.io/llms-full.txt",
    license: "MIT",
    server: {
      type: "node",
      entry_point: "mcp/forgesuite-mcp.mjs",
      mcp_config: {
        command: "node",
        args: ["${__dirname}/mcp/forgesuite-mcp.mjs"],
      },
    },
    tools: [
      {
        name: "envshield_scan",
        description: "Scan .env/configs/logs offline for leaked secrets and return redacted output.",
      },
      {
        name: "calldata_decode",
        description: "Decode EVM 0x hex calldata offline and flag MaxUint256 unlimited approvals.",
      },
      {
        name: "tokencost_estimate",
        description: "Estimate multi-turn LLM API budgets across GPT-5, Claude 4.5, Gemini 2.5, and DeepSeek.",
      },
      {
        name: "cryptobill_quote",
        description: "Generate freelance crypto invoices and serverless CryptoBill #inv= payment links.",
      },
      {
        name: "evm_token_risk_scan",
        description: "Audit live EVM token/contract bytecode opcodes, proxies, and honeypot selectors.",
      },
      {
        name: "solana_mint_risk_scan",
        description: "Audit live Solana SPL & Token-2022 authorities, extensions, and top holders.",
      },
      {
        name: "brand_domain_handle_scan",
        description: "Check live domain RDAP/DoH, npm, PyPI, GitHub, Bluesky, and iOS App Store availability.",
      },
      {
        name: "multi_chain_wallet_scan",
        description: "Inspect 1-5 EVM & Solana wallets across 6 chains for balances, EIP-7702, Gnosis Safe, SPL/Token-2022 & tx activity.",
      },
      {
        name: "subtitle_caption_audit",
        description: "Audit .srt/.vtt captions offline for overlaps, CPS > 20, 9:16 safe zones & brand terms and return normalized .srt/.vtt.",
      },
    ],
  };
}

export function createForgeSuiteMcpbBuffer(repoRoot = REPO_ROOT) {
  const pkgJson = JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8"));
  const version = pkgJson.version;
  const manifestJson = JSON.stringify(buildMcpbManifest(version), null, 2) + "\n";
  const bundlePkgJson =
    JSON.stringify(
      {
        name: pkgJson.name,
        version,
        description: pkgJson.description,
        type: "module",
        main: "./mcp/forgesuite-mcp.mjs",
        bin: pkgJson.bin,
        engines: pkgJson.engines,
        license: pkgJson.license,
      },
      null,
      2
    ) + "\n";

  const normalizeLf = (rawBuf) => Buffer.from(rawBuf.toString("utf8").replace(/\r\n/g, "\n"), "utf8");

  const mcpSourceBuf = normalizeLf(
    fs.readFileSync(path.join(repoRoot, "mcp", "forgesuite-mcp.mjs"))
  );
  const licenseBuf = normalizeLf(fs.readFileSync(path.join(repoRoot, "LICENSE")));

  const archiveBuffer = buildDeterministicZip([
    { name: "manifest.json", data: Buffer.from(manifestJson, "utf8"), mode: 0o100644 },
    { name: "package.json", data: Buffer.from(bundlePkgJson, "utf8"), mode: 0o100644 },
    { name: "mcp/forgesuite-mcp.mjs", data: mcpSourceBuf, mode: 0o100755 },
    { name: "LICENSE", data: licenseBuf, mode: 0o100644 },
  ]);

  const fileSha256 = crypto.createHash("sha256").update(archiveBuffer).digest("hex");
  return { version, archiveBuffer, fileSha256, byteLength: archiveBuffer.length };
}

const isDirectRun =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectRun) {
  const outArg = process.argv[2];
  const updateServerJson = process.argv.includes("--sync-server-json");
  const { version, archiveBuffer, fileSha256, byteLength } = createForgeSuiteMcpbBuffer(REPO_ROOT);

  if (outArg && !outArg.startsWith("--")) {
    const outPath = path.resolve(process.cwd(), outArg);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, archiveBuffer);
  }

  if (updateServerJson) {
    const serverJsonPath = path.join(REPO_ROOT, "server.json");
    if (fs.existsSync(serverJsonPath)) {
      const serverObj = JSON.parse(fs.readFileSync(serverJsonPath, "utf8"));
      serverObj.version = version;
      if (Array.isArray(serverObj.packages) && serverObj.packages[0]) {
        serverObj.packages[0].version = version;
        serverObj.packages[0].identifier = `https://github.com/youthmy11-ai/youthmy11-ai.github.io/releases/download/v${version}/forgesuite-mcp.mcpb`;
        serverObj.packages[0].fileSha256 = fileSha256;
      }
      fs.writeFileSync(serverJsonPath, JSON.stringify(serverObj, null, 2) + "\n", "utf8");
    }
  }

  process.stdout.write(
    JSON.stringify({ version, fileSha256, byteLength }, null, 2) + "\n"
  );
}
