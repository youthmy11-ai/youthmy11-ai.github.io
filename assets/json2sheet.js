import {
  bindCheckoutTriggers,
  openCheckoutModal,
} from "./checkout.js";

const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const BEARER_RE = /\b(?:Bearer\s+[A-Za-z0-9\-._~+/]+=*|sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{30,})\b/g;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const PHONE_RE = /(?<!\w)\+?\d[\d\s()-]{8,}\d(?!\w)/g;

/**
 * Redact common PII / API secrets inside arbitrary text strings before exporting or prompting LLMs.
 * @param {string} value
 * @param {{ emails?: boolean, tokens?: boolean, ips?: boolean, phones?: boolean }} [opts]
 */
export function maskSensitiveText(value, opts = {}) {
  let out = String(value ?? "");
  const cfg = {
    emails: opts.emails !== false,
    tokens: opts.tokens !== false,
    ips: opts.ips !== false,
    phones: Boolean(opts.phones),
  };
  if (cfg.tokens) out = out.replace(BEARER_RE, "[REDACTED_TOKEN]");
  if (cfg.emails) out = out.replace(EMAIL_RE, "[REDACTED_EMAIL]");
  if (cfg.ips) out = out.replace(IPV4_RE, "[REDACTED_IP]");
  if (cfg.phones) out = out.replace(PHONE_RE, "[REDACTED_PHONE]");
  return out;
}

/**
 * Recursively flatten nested objects and compact primitive arrays using dot notation.
 * @param {unknown} node
 * @param {string} [prefix]
 * @param {Record<string, unknown>} [target]
 */
export function flattenObject(node, prefix = "", target = {}) {
  if (node === null || node === undefined) {
    if (prefix) target[prefix] = "";
    return target;
  }
  if (Array.isArray(node)) {
    const allPrimitive = node.every(
      (x) => x === null || x === undefined || typeof x !== "object"
    );
    if (allPrimitive) {
      target[prefix || "value"] = node.map((x) => (x ?? "")).join("; ");
      return target;
    }
    for (let i = 0; i < node.length; i += 1) {
      const key = prefix ? `${prefix}.${i}` : String(i);
      flattenObject(node[i], key, target);
    }
    return target;
  }
  if (typeof node === "object") {
    const entries = Object.entries(node);
    if (entries.length === 0 && prefix) {
      target[prefix] = "{}";
      return target;
    }
    for (const [k, v] of entries) {
      const nextKey = prefix ? `${prefix}.${k}` : k;
      flattenObject(v, nextKey, target);
    }
    return target;
  }
  target[prefix || "value"] = node;
  return target;
}

/**
 * Locate the primary tabular array inside parsed JSON (top-level array, common wrapper keys, or single object).
 * @param {unknown} parsed
 * @returns {Array<Record<string, unknown>>}
 */
export function extractRecordArray(parsed) {
  if (Array.isArray(parsed)) {
    return parsed.map((row) => flattenObject(row));
  }
  if (parsed && typeof parsed === "object") {
    const wrapperKeys = ["data", "items", "results", "records", "rows", "entries", "users", "orders"];
    for (const key of wrapperKeys) {
      if (Array.isArray(parsed[key])) {
        return parsed[key].map((row) => flattenObject(row));
      }
    }
    const anyArray = Object.values(parsed).find(
      (v) => Array.isArray(v) && v.length > 0 && typeof v[0] === "object"
    );
    if (anyArray) {
      return anyArray.map((row) => flattenObject(row));
    }
    return [flattenObject(parsed)];
  }
  return [{ value: parsed }];
}

function escapeCsvCell(raw, guardFormula = true) {
  let s = String(raw ?? "");
  if (guardFormula && s.length > 0 && /^[=+\-@]/.test(s)) {
    s = "'" + s;
  }
  if (/[",\r\n]/.test(s)) {
    return `"${s.replaceAll('"', '""')}"`;
  }
  return s;
}

/**
 * Convert flattened records to RFC-4180 CSV (or TSV) with optional formula-injection guard and PII masking.
 */
export function recordsToCsv(rows, options = {}) {
  const safeRows = Array.isArray(rows) ? rows : [];
  if (safeRows.length === 0) return { columns: [], rows: [], text: "" };

  const delimiter = options.delimiter === "\t" ? "\t" : ",";
  const guardFormula = options.guardFormula !== false;
  const maskPii = Boolean(options.maskPii);
  const maskOpts = options.maskOpts || {};

  const colSet = new Set();
  for (const r of safeRows) {
    Object.keys(r || {}).forEach((k) => colSet.add(k));
  }
  const columns = [...colSet];

  const mappedRows = safeRows.map((row) =>
    columns.map((col) => {
      let val = row && Object.prototype.hasOwnProperty.call(row, col) ? row[col] : "";
      if (maskPii && typeof val === "string") {
        val = maskSensitiveText(val, maskOpts);
      }
      return val;
    })
  );

  const headerLine = columns.map((c) => escapeCsvCell(c, false)).join(delimiter);
  const dataLines = mappedRows.map((cells) =>
    cells.map((v) => escapeCsvCell(v, guardFormula)).join(delimiter)
  );
  return {
    columns,
    rows: mappedRows,
    text: [headerLine, ...dataLines].join("\n"),
  };
}

/**
 * Render flattened records as a clean GitHub-Flavored Markdown table.
 */
export function recordsToMarkdownTable(rows, options = {}) {
  const safeRows = Array.isArray(rows) ? rows : [];
  if (safeRows.length === 0) return "";
  const maskPii = Boolean(options.maskPii);
  const maskOpts = options.maskOpts || {};

  const colSet = new Set();
  for (const r of safeRows) Object.keys(r || {}).forEach((k) => colSet.add(k));
  const columns = [...colSet];
  if (columns.length === 0) return "";

  const cleanMd = (v) => {
    let s = String(v ?? "").replace(/\r?\n/g, " ").replaceAll("|", "\\|");
    if (maskPii) s = maskSensitiveText(s, maskOpts);
    return s;
  };

  const head = `| ${columns.map(cleanMd).join(" | ")} |`;
  const sep = `| ${columns.map(() => "---").join(" | ")} |`;
  const body = safeRows.map(
    (r) => `| ${columns.map((c) => cleanMd(r?.[c] ?? "")).join(" | ")} |`
  );
  return [head, sep, ...body].join("\n");
}

function initJson2SheetApp() {
  if (typeof document === "undefined" || document.body?.dataset?.page !== "json2sheet") {
    return;
  }
  bindCheckoutTriggers();
  const bundleBtn = document.getElementById("j2sBundleBtn");
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

  const inputEl = document.getElementById("j2sJsonInput");
  const formatEl = document.getElementById("j2sFormatSelect");
  const maskCheck = document.getElementById("j2sMaskPii");
  const formulaCheck = document.getElementById("j2sGuardFormula");
  const outputEl = document.getElementById("j2sOutputText");
  const statusEl = document.getElementById("j2sParseStatus");
  const statsEl = document.getElementById("j2sStatsPill");

  const samples = {
    stripe: JSON.stringify(
      {
        object: "list",
        data: [
          {
            id: "pi_3Qx8A9",
            amount_usd: 49.5,
            customer: { name: "Alex Rivera", email: "alex@northstar.example", ip: "198.51.100.42" },
            tags: ["pro", "annual"],
            status: "succeeded",
          },
          {
            id: "pi_3Qx8B2",
            amount_usd: 35.0,
            customer: { name: "Minh Tran", email: "minh.dev@acme.io", ip: "203.0.113.19" },
            tags: ["bundle"],
            status: "succeeded",
          },
        ],
      },
      null,
      2
    ),
    webhook: JSON.stringify(
      [
        {
          event: "invoice.paid",
          api_key: "sk-live-secret9988776655443322",
          recipient: { handle: "@studio", contact: "billing@studio.dev" },
          meta: { chain: "BSC", asset: "USDT", amount: 15 },
        },
        {
          event: "license.activated",
          api_key: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
          recipient: { handle: "@creator", contact: "creator@media.co" },
          meta: { chain: "TRON", asset: "USDT", amount: 19 },
        },
      ],
      null,
      2
    ),
  };

  function convert() {
    if (!inputEl || !outputEl) return;
    try {
      const parsed = JSON.parse(inputEl.value);
      const records = extractRecordArray(parsed);
      const maskPii = Boolean(maskCheck?.checked);
      const guardFormula = Boolean(formulaCheck?.checked);
      const fmt = formatEl?.value || "csv";
      let resultText = "";
      let colsCount = 0;

      if (fmt === "md") {
        resultText = recordsToMarkdownTable(records, { maskPii });
        colsCount = records[0] ? Object.keys(records[0]).length : 0;
      } else {
        const res = recordsToCsv(records, {
          delimiter: fmt === "tsv" ? "\t" : ",",
          guardFormula,
          maskPii,
        });
        resultText = res.text;
        colsCount = res.columns.length;
      }
      outputEl.value = resultText;
      if (statusEl) {
        statusEl.textContent = "Valid JSON converted locally in browser.";
        statusEl.style.color = "#4ade80";
      }
      if (statsEl) {
        statsEl.textContent = `${records.length} ROWS · ${colsCount} COLS`;
      }
    } catch (err) {
      if (statusEl) {
        statusEl.textContent = `JSON Parse Error: ${err.message}`;
        statusEl.style.color = "#f87171";
      }
    }
  }

  document.querySelectorAll("[data-j2s-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const k = btn.getAttribute("data-j2s-sample");
      if (inputEl && samples[k]) {
        inputEl.value = samples[k];
        convert();
      }
    });
  });

  [inputEl, formatEl, maskCheck, formulaCheck].forEach((el) => {
    if (el) el.addEventListener("input", convert);
  });

  const copyBtn = document.getElementById("j2sCopyOutBtn");
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      if (!outputEl) return;
      try {
        await navigator.clipboard.writeText(outputEl.value);
        copyBtn.textContent = "Copied!";
        setTimeout(() => { copyBtn.textContent = "Copy Output"; }, 1400);
      } catch {
        outputEl.select();
        document.execCommand("copy");
      }
    });
  }

  const dlBtn = document.getElementById("j2sDownloadCsvBtn");
  if (dlBtn) {
    dlBtn.addEventListener("click", () => {
      if (!outputEl || !outputEl.value) return;
      const fmt = formatEl?.value || "csv";
      const ext = fmt === "md" ? "md" : fmt === "tsv" ? "tsv" : "csv";
      const blob = new Blob([outputEl.value], { type: "text/plain;charset=utf-8" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `forgesuite-export.${ext}`;
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }

  if (inputEl && !inputEl.value.trim()) inputEl.value = samples.stripe;
  convert();
}

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", initJson2SheetApp);
}
