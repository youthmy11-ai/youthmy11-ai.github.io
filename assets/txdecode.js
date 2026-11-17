import { bindCheckoutTriggers, openCheckoutModal } from "./checkout.js";
import { createDefaultInvoice, encodeInvoicePayload } from "./cryptobill.js";

/**
 * Curated dictionary of common EVM / DeFi / ERC-20 / Vault / Permit2 / Safe 4-byte selectors.
 */
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
  "0xac9650d8": {
    sig: "multicall(bytes[] data)",
    category: "Router",
    risk: "BATCH_CALL",
    params: [{ name: "offsetOrRaw", type: "bytes32" }],
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

export const CALLDATA_SAMPLES = Object.freeze({
  usdt_transfer:
    "0xa9059cbb" +
    "0000000000000000000000000a1e9c96755a7962306cf2ca9a80113a61559852" +
    "000000000000000000000000000000000000000000000001e5b8fa8fe2ac0000",
  max_approve:
    "0x095ea7b3" +
    "000000000000000000000000111111125421ca6dc452d289314280a0f8842a65" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  vault_deposit:
    "0x6e553f65" +
    "00000000000000000000000000000000000000000000003635c9adc5dea00000" +
    "000000000000000000000000742d35cc6634c0532925a3b844bc454e4438f44e",
});

function formatScaledUnits(bigVal, decimals) {
  const factor = 10n ** BigInt(decimals);
  const whole = bigVal / factor;
  const frac = (bigVal % factor).toString().padStart(decimals, "0").slice(0, 6).replace(/0+$/, "");
  return frac ? `${whole.toLocaleString("en-US")}.${frac}` : whole.toLocaleString("en-US");
}

function decodeWordAs(wordHex, type) {
  const normalized = wordHex.padStart(64, "0");
  if (type === "address") {
    return {
      raw: `0x${normalized}`,
      formatted: `0x${normalized.slice(24)}`,
      note: normalized.slice(0, 24) === "000000000000000000000000" ? "valid 20-byte EVM address" : "non-zero upper padding!",
    };
  }
  const bigVal = BigInt(`0x${normalized}`);
  if (type === "uint8") {
    return { raw: `0x${normalized}`, formatted: String(bigVal), note: "uint8" };
  }
  if (type === "uint256") {
    const isMax = bigVal === (1n << 256n) - 1n;
    return {
      raw: `0x${normalized}`,
      formatted: isMax ? "MAX_UINT256 (Unlimited)" : bigVal.toString(),
      note: isMax
        ? "UNLIMITED / INFINITE APPROVAL RISK"
        : `18dp: ${formatScaledUnits(bigVal, 18)} | 6dp: ${formatScaledUnits(bigVal, 6)}`,
    };
  }
  return { raw: `0x${normalized}`, formatted: `0x${normalized}`, note: "bytes32 word" };
}

/**
 * Normalize hex calldata and decode selector + 32-byte ABI argument slots cleanly offline.
 */
export function decodeCalldata(rawInput) {
  const cleaned = String(rawInput || "").trim().replace(/\s+/g, "").toLowerCase();
  const hex = cleaned.startsWith("0x") ? cleaned.slice(2) : cleaned;

  if (!hex || !/^[0-9a-f]+$/.test(hex) || hex.length < 8 || hex.length % 2 !== 0) {
    return { ok: false, error: "Invalid hex calldata (need >= 4 bytes / 8 hex chars, even length)." };
  }

  const selector = `0x${hex.slice(0, 8)}`;
  const body = hex.slice(8);
  const words = [];
  for (let i = 0; i < body.length; i += 64) {
    words.push(body.slice(i, i + 64));
  }

  const match = KNOWN_SELECTORS[selector] || null;
  const decodedArgs = words.map((w, idx) => {
    const spec = match?.params?.[idx];
    const type = spec?.type || (w.length === 64 && w.startsWith("000000000000000000000000") && w.slice(24) !== "0".repeat(40) ? "address" : "uint256");
    const parsed = w.length === 64 ? decodeWordAs(w, type) : { raw: `0x${w}`, formatted: `0x${w}`, note: "partial trailing bytes" };
    return {
      slot: idx,
      name: spec?.name || `arg${idx}`,
      type: spec?.type || `inferred:${type}`,
      ...parsed,
    };
  });

  return {
    ok: true,
    selector,
    known: Boolean(match),
    signature: match?.sig || "Unknown 4-byte selector (raw ABI slot inspection)",
    category: match?.category || "Custom Contract",
    risk: match?.risk || "UNKNOWN",
    byteLength: hex.length / 2,
    wordCount: words.length,
    args: decodedArgs,
  };
}

export function buildReviewInvoicePayload(decoded) {
  const inv = createDefaultInvoice();
  inv.clientName = "Web3 Protocol / Treasury Ops";
  inv.taxPercent = 0;
  inv.discountPercent = 0;
  inv.notes = `Decoded ${decoded?.selector || "calldata"} (${decoded?.signature || "custom ABI"}) via ForgeSuite ABI Decoder.`;
  inv.items = [
    {
      description: `Smart Contract Calldata & Security Sign-Off Review (${decoded?.selector || "0x"})`,
      qty: 1,
      unitPrice: 150,
    },
  ];
  return inv;
}

function initTxDecodeApp() {
  if (typeof document === "undefined" || document.body?.dataset?.page !== "txdecode") return;

  bindCheckoutTriggers();
  const bundleBtn = document.getElementById("txdBundleBtn");
  if (bundleBtn) bundleBtn.addEventListener("click", () => openCheckoutModal("BUNDLE"));

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

  const inputEl = document.getElementById("txdInputHex");
  const statusEl = document.getElementById("txdStatusMsg");
  const sigEl = document.getElementById("txdSigLabel");
  const riskBadgeEl = document.getElementById("txdRiskBadge");
  const tableBodyEl = document.getElementById("txdArgsBody");
  let lastDecoded = null;

  function runDecode() {
    const res = decodeCalldata(inputEl?.value || "");
    lastDecoded = res.ok ? res : null;
    if (!res.ok) {
      if (statusEl) statusEl.textContent = res.error;
      if (sigEl) sigEl.textContent = "Waiting for valid hex calldata...";
      if (riskBadgeEl) riskBadgeEl.textContent = "INVALID";
      if (tableBodyEl) tableBodyEl.innerHTML = "";
      return;
    }
    if (statusEl) statusEl.textContent = `Parsed ${res.byteLength} bytes (${res.wordCount} ABI slots) locally.`;
    if (sigEl) sigEl.textContent = `${res.selector} → ${res.signature}`;
    if (riskBadgeEl) {
      riskBadgeEl.textContent = `${res.category} · ${res.risk}`;
      riskBadgeEl.className = `fs-badge ${res.risk.includes("HIGH") || res.risk === "ALLOWANCE" ? "fs-badge-accent" : "fs-badge-success"}`;
    }
    if (tableBodyEl) {
      tableBodyEl.innerHTML = res.args
        .map(
          (a) => `<tr>
            <td>#${a.slot}</td>
            <td><code>${a.name}</code><br><small class="inv-muted">${a.type}</small></td>
            <td style="word-break:break-all;"><code>${a.formatted}</code></td>
            <td>${a.note}</td>
          </tr>`
        )
        .join("");
    }
  }

  document.querySelectorAll("[data-txd-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const k = btn.getAttribute("data-txd-sample");
      if (inputEl && CALLDATA_SAMPLES[k]) {
        inputEl.value = CALLDATA_SAMPLES[k];
        runDecode();
      }
    });
  });

  if (inputEl) {
    inputEl.addEventListener("input", runDecode);
    if (!inputEl.value.trim()) inputEl.value = CALLDATA_SAMPLES.usdt_transfer;
  }

  const billBtn = document.getElementById("txdSendInvoiceBtn");
  if (billBtn) {
    billBtn.addEventListener("click", () => {
      const hash = encodeInvoicePayload(buildReviewInvoicePayload(lastDecoded));
      window.location.href = `cryptobill.html#inv=${hash}`;
    });
  }

  runDecode();
}

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", initTxDecodeApp);
}
