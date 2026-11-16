import {
  bindCheckoutTriggers,
  openCheckoutModal,
} from "./checkout.js";
import {
  createDefaultInvoice,
  encodeInvoicePayload,
} from "./cryptobill.js";

/**
 * Curated public LLM API pricing catalog (USD per 1,000,000 tokens).
 * Client-side editable overrides are supported in the UI.
 */
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

/**
 * Estimate token count offline across ASCII prose, code syntax, JSON, and CJK/Unicode text.
 * @param {string} text
 * @returns {{ tokens: number, chars: number, words: number, lines: number, bytesUtf8: number }}
 */
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

/**
 * Compute per-request, daily, and monthly API cost + client retainer quote with margin.
 */
export function calculateRunCosts({
  model,
  inputTokens,
  cachedRatioPct = 0,
  outputTokens = 500,
  requestsPerDay = 1000,
  daysPerMonth = 30,
  marginMultiplier = 1.5,
}) {
  const m = model || MODEL_PRICING[0];
  const inTok = Math.max(0, Number(inputTokens) || 0);
  const outTok = Math.max(0, Number(outputTokens) || 0);
  const cacheShare = Math.min(1, Math.max(0, (Number(cachedRatioPct) || 0) / 100));
  const reqDay = Math.max(0, Number(requestsPerDay) || 0);
  const days = Math.max(1, Number(daysPerMonth) || 30);
  const margin = Math.max(1, Number(marginMultiplier) || 1);

  const cachedTok = inTok * cacheShare;
  const uncachedTok = inTok - cachedTok;

  const costPerReqInput =
    (uncachedTok / 1_000_000) * m.inputPer1M +
    (cachedTok / 1_000_000) * (m.cachedInputPer1M ?? m.inputPer1M);
  const costPerReqOutput = (outTok / 1_000_000) * m.outputPer1M;
  const costPerReqTotal = costPerReqInput + costPerReqOutput;

  const dailyCost = costPerReqTotal * reqDay;
  const monthlyRawCost = dailyCost * days;
  const monthlyClientQuote = monthlyRawCost * margin;
  const contextFillPct = m.contextWindow > 0
    ? Math.min(999, ((inTok + outTok) / m.contextWindow) * 100)
    : 0;

  return {
    modelId: m.id,
    modelName: m.name,
    provider: m.provider,
    contextWindow: m.contextWindow,
    contextFillPct,
    costPerReqInput,
    costPerReqOutput,
    costPerReqTotal,
    dailyCost,
    monthlyRawCost,
    monthlyClientQuote,
    monthlyRuns: reqDay * days,
  };
}

/**
 * Convert an AI cost calculation into a CryptoBill Forge invoice payload for #inv import.
 */
export function buildCryptoBillQuotePayload({
  modelName,
  requestsPerDay,
  daysPerMonth,
  inputTokens,
  outputTokens,
  monthlyRawCost,
  monthlyClientQuote,
}) {
  const base = createDefaultInvoice();
  const marginFee = Math.max(0, monthlyClientQuote - monthlyRawCost);
  base.clientName = `AI Workload Client (${modelName})`;
  base.notes = `Monthly LLM workload: ${requestsPerDay.toLocaleString("en-US")} req/day x ${daysPerMonth} days (${inputTokens.toLocaleString("en-US")} in / ${outputTokens.toLocaleString("en-US")} out tokens/req). Generated via ForgeSuite TokenCost Lab.`;
  base.taxPercent = 0;
  base.discountPercent = 0;
  base.items = [
    {
      description: `${modelName} Token Usage (${requestsPerDay * daysPerMonth} runs/mo)`,
      qty: 1,
      unitPrice: Number(monthlyRawCost.toFixed(2)),
    },
    {
      description: "Prompt Routing, Guardrails & Monitoring Retainer",
      qty: 1,
      unitPrice: Number(marginFee.toFixed(2)),
    },
  ];
  return base;
}

function fmtUsd(value, digits = 4) {
  const n = Number(value) || 0;
  if (n >= 10) return `$${n.toFixed(2)}`;
  if (n >= 0.1) return `$${n.toFixed(3)}`;
  return `$${n.toFixed(digits)}`;
}

function initTokenCalcApp() {
  if (typeof document === "undefined" || document.body?.dataset?.page !== "tokencalc") {
    return;
  }

  bindCheckoutTriggers();
  const upgradeBtn = document.getElementById("tcUpgradeBundleBtn");
  if (upgradeBtn) {
    upgradeBtn.addEventListener("click", () => openCheckoutModal("BUNDLE"));
  }

  const promptEl = document.getElementById("tcPromptInput");
  const modelEl = document.getElementById("tcModelSelect");
  const cachedEl = document.getElementById("tcCachedPct");
  const outTokEl = document.getElementById("tcOutputTokens");
  const reqDayEl = document.getElementById("tcReqPerDay");
  const daysEl = document.getElementById("tcDaysPerMonth");
  const marginEl = document.getElementById("tcMarginMult");
  const tableBodyEl = document.getElementById("tcComparisonBody");

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

  if (modelEl) {
    modelEl.innerHTML = MODEL_PRICING.map(
      (m) => `<option value="${m.id}">${m.provider} · ${m.name} ($${m.inputPer1M}/$${m.outputPer1M} per 1M)</option>`
    ).join("");
  }

  const presets = {
    support:
      "System: You are a bilingual SaaS billing support agent. Verify invoice hashes strictly against on-chain logs without guessing.\nUser JSON:\n{\"invoice\":\"INV-2026-884\",\"amountUsd\":49.50,\"network\":\"BSC-USDT\",\"items\":[\"Pro License\",\"API Addon\"]}",
    coding:
      "System: Review this TypeScript PR for race conditions, integer truncation, and missing error boundaries.\n```ts\nexport async function settleOrder(id: string, amountWei: bigint) {\n  if (amountWei <= 0n) throw new Error('Invalid amount');\n  return { id, settledAt: Date.now() };\n}\n```",
    rag: "Document chunk (2,400+ chars simulated context): " +
      "Autonomous agents reduce support triage time by parsing structured logs, extracting error signatures, and citing immutable documentation links. ".repeat(14),
  };

  document.querySelectorAll("[data-tc-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.getAttribute("data-tc-preset");
      if (promptEl && presets[key]) {
        promptEl.value = presets[key];
        recalc();
      }
    });
  });

  let lastQuote = null;

  function recalc() {
    const stats = estimateTokenCount(promptEl?.value || "");
    const selectedId = modelEl?.value || MODEL_PRICING[0].id;
    const model = MODEL_PRICING.find((m) => m.id === selectedId) || MODEL_PRICING[0];
    const params = {
      model,
      inputTokens: stats.tokens,
      cachedRatioPct: Number(cachedEl?.value ?? 30),
      outputTokens: Number(outTokEl?.value ?? 600),
      requestsPerDay: Number(reqDayEl?.value ?? 500),
      daysPerMonth: Number(daysEl?.value ?? 30),
      marginMultiplier: Number(marginEl?.value ?? 1.4),
    };
    const res = calculateRunCosts(params);
    lastQuote = {
      modelName: res.modelName,
      requestsPerDay: params.requestsPerDay,
      daysPerMonth: params.daysPerMonth,
      inputTokens: stats.tokens,
      outputTokens: params.outputTokens,
      monthlyRawCost: res.monthlyRawCost,
      monthlyClientQuote: res.monthlyClientQuote,
    };

    const set = (id, v) => {
      const el = document.getElementById(id);
      if (el) el.textContent = v;
    };
    set("tcStatTokens", stats.tokens.toLocaleString("en-US"));
    set("tcStatWords", stats.words.toLocaleString("en-US"));
    set("tcStatChars", stats.chars.toLocaleString("en-US"));
    set("tcStatBytes", `${stats.bytesUtf8.toLocaleString("en-US")} B`);
    set("tcCostPerReq", fmtUsd(res.costPerReqTotal, 5));
    set("tcDailyCost", fmtUsd(res.dailyCost, 2));
    set("tcMonthlyRaw", fmtUsd(res.monthlyRawCost, 2));
    set("tcMonthlyQuote", fmtUsd(res.monthlyClientQuote, 2));
    set("tcContextFill", `${res.contextFillPct.toFixed(2)}% of ${(res.contextWindow / 1000).toFixed(0)}k`);

    if (tableBodyEl) {
      tableBodyEl.innerHTML = MODEL_PRICING.map((rowModel) => {
        const row = calculateRunCosts({ ...params, model: rowModel });
        const activeStyle = rowModel.id === model.id ? ' style="background:rgba(59,130,246,0.12);font-weight:600;"' : "";
        return `<tr${activeStyle}>
          <td>${rowModel.provider}</td>
          <td>${rowModel.name}</td>
          <td>${(rowModel.contextWindow / 1000).toFixed(0)}k</td>
          <td>${fmtUsd(row.costPerReqTotal, 5)}</td>
          <td>${fmtUsd(row.monthlyRawCost, 2)}</td>
          <td>${fmtUsd(row.monthlyClientQuote, 2)}</td>
        </tr>`;
      }).join("");
    }
  }

  [promptEl, modelEl, cachedEl, outTokEl, reqDayEl, daysEl, marginEl].forEach((el) => {
    if (el) el.addEventListener("input", recalc);
  });

  const exportBtn = document.getElementById("tcSendToCryptoBillBtn");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      if (!lastQuote) recalc();
      const inv = buildCryptoBillQuotePayload(lastQuote);
      const hash = encodeInvoicePayload(inv);
      window.location.href = `cryptobill.html#inv=${hash}`;
    });
  }

  if (promptEl && !promptEl.value.trim()) {
    promptEl.value = presets.support;
  }
  recalc();
}

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", initTokenCalcApp);
}
