import {
  bindCheckoutTriggers,
  openCheckoutModal,
} from "./checkout.js";
import {
  createDefaultInvoice,
  encodeInvoicePayload,
} from "./cryptobill.js";

export const SETTLEMENT_RAILS = Object.freeze({
  "usdt-bep20": "USDT (BNB Smart Chain / BEP20)",
  "usdt-trc20": "USDT (TRON / TRC20)",
  "sol-usdc": "USDC / SOL (Solana Mainnet)",
  "binance-pay": "Binance Pay (Instant Zero-Fee)",
  "paypal": "PayPal Goods & Services / Invoice",
});

export const SOW_PRESETS = Object.freeze({
  ai_mvp: {
    projectTitle: "Autonomous AI Workflow & API Integration MVP",
    providerName: "ForgeSuite Engineering",
    clientName: "Acme SaaS Labs Inc.",
    totalBudget: 2400,
    revisionsIncluded: 2,
    noticeDays: 5,
    settlementRail: "usdt-bep20",
    deliverables:
      "- REST/Webhook ingestion service + schema validation\n- LLM prompt router with rate limits & fallback handling\n- Automated test suite + deployment runbook",
    milestones: [
      { title: "M1: Architecture & Initial Deposit", percent: 40, due: "On signing" },
      { title: "M2: Staging Delivery & Integration Tests", percent: 40, due: "Day 10" },
      { title: "M3: Production Handoff & Source IP Transfer", percent: 20, due: "Day 14" },
    ],
  },
  web3_audit: {
    projectTitle: "Smart Contract Security Review & PoC Verification",
    providerName: "Independent Security Researcher",
    clientName: "Protocol Foundation",
    totalBudget: 3500,
    revisionsIncluded: 1,
    noticeDays: 3,
    settlementRail: "sol-usdc",
    deliverables:
      "- Line-by-line review of core vault & periphery contracts\n- Foundry/Hardhat PoC suite for any High/Critical findings\n- Fix verification pass on remediation commits",
    milestones: [
      { title: "M1: Audit Kickoff Deposit", percent: 50, due: "Before commit freeze" },
      { title: "M2: Final Report & Fix Verification", percent: 50, due: "Report delivery" },
    ],
  },
  chrome_ext: {
    projectTitle: "Custom Chrome Extension & Data Pipeline Build",
    providerName: "ForgeSuite Studio",
    clientName: "GrowthOps Media LLC",
    totalBudget: 1200,
    revisionsIncluded: 2,
    noticeDays: 5,
    settlementRail: "usdt-trc20",
    deliverables:
      "- Manifest V3 Chrome Extension package (.zip + source)\n- Local CSV/JSON export with PII guardrails\n- Installation guide & 14-day bug-fix warranty",
    milestones: [
      { title: "M1: Project Kickoff & UI Wireframe", percent: 50, due: "On kickoff" },
      { title: "M2: Packaged Extension & CSV Export Delivery", percent: 50, due: "Day 7" },
    ],
  },
});

function num(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Compute per-milestone USD payouts and allocation balance checks.
 */
export function computeSowTotals({ totalBudget = 0, milestones = [] }) {
  const budget = Math.max(0, num(totalBudget, 0));
  let totalPercent = 0;
  let allocatedUsd = 0;

  const computed = milestones.map((m, idx) => {
    const pct = Math.max(0, Math.min(100, num(m?.percent, 0)));
    const amountUsd = Number(((budget * pct) / 100).toFixed(2));
    totalPercent += pct;
    allocatedUsd += amountUsd;
    return {
      index: idx,
      title: String(m?.title || `Milestone ${idx + 1}`).trim(),
      percent: pct,
      due: String(m?.due || "TBD").trim(),
      amountUsd,
    };
  });

  const roundedPct = Number(totalPercent.toFixed(2));
  return {
    budget,
    milestones: computed,
    totalPercent: roundedPct,
    allocatedUsd: Number(allocatedUsd.toFixed(2)),
    isBalanced: Math.abs(roundedPct - 100) < 0.01,
  };
}

/**
 * Render an editable client-ready Statement of Work & Milestone Agreement in Markdown.
 */
export function renderSowMarkdown(state) {
  const calc = computeSowTotals({
    totalBudget: state?.totalBudget,
    milestones: state?.milestones || [],
  });
  const railLabel = SETTLEMENT_RAILS[state?.settlementRail] || SETTLEMENT_RAILS["usdt-bep20"];
  const title = String(state?.projectTitle || "Software Engineering Statement of Work").trim();
  const provider = String(state?.providerName || "Service Provider").trim();
  const client = String(state?.clientName || "Client Organization").trim();
  const revisions = Math.max(0, Math.round(num(state?.revisionsIncluded, 2)));
  const noticeDays = Math.max(1, Math.round(num(state?.noticeDays, 5)));
  const deliverables = String(state?.deliverables || "- Core engineering deliverables per repository spec").trim();
  const dateIso = new Date().toISOString().slice(0, 10);

  const milestoneLines = calc.milestones
    .map(
      (m, i) =>
        `| ${i + 1} | ${m.title.replace(/\|/g, "\\|")} | ${m.percent}% | $${m.amountUsd.toLocaleString("en-US", {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        })} | ${m.due.replace(/\|/g, "\\|")} |`
    )
    .join("\n");

  return `# STATEMENT OF WORK & MILESTONE ESCROW AGREEMENT

**Date:** ${dateIso}
**Project:** ${title}
**Service Provider:** ${provider}
**Client:** ${client}
**Total Contract Value:** $${calc.budget.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} USD
**Preferred Settlement Rail:** ${railLabel}

---

## 1. Scope of Deliverables
${deliverables}

---

## 2. Milestone Schedule & Payment Split
| # | Milestone | Split | Amount (USD) | Trigger / Due |
|---:|---|---:|---:|---|
${milestoneLines}

- **Allocation Check:** ${calc.totalPercent}% allocated ($${calc.allocatedUsd.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} USD)
- **Payment Settlement:** Invoices are generated per milestone via CryptoBill Forge and due prior to release of production source repositories/credentials for that milestone.

---

## 3. ScopeGuard Terms (IP, Revisions & Pausing)
1. **Included Revisions:** Up to **${revisions}** consolidated revision round(s) within the defined deliverables above. Requests outside Section 1 require a written Change Order.
2. **Intellectual Property Transfer:** Full source code & artifact IP transfers to **${client}** only upon cleared settlement of the corresponding milestone payment. Until full settlement of the final milestone, Provider retains ownership of unpaid deliverables.
3. **Kill Fee & Dormancy:** If Client pauses or cancels mid-milestone after kickoff, earned work-in-progress through notice date (${noticeDays}-day written notice) remains non-refundable.
4. **No Custodial Liability:** Both parties confirm milestone transfers are settled peer-to-peer over agreed rails without third-party custody.

---

**Accepted — Client (${client}):** _______________________  Date: __________

**Accepted — Provider (${provider}):** _______________________  Date: __________
`;
}

/**
 * Export any milestone into a pre-filled CryptoBill Forge invoice payload (#inv=...).
 */
export function buildMilestoneInvoicePayload(state, milestoneIndex = 0) {
  const calc = computeSowTotals({
    totalBudget: state?.totalBudget,
    milestones: state?.milestones || [],
  });
  const m = calc.milestones[milestoneIndex] || calc.milestones[0] || {
    title: "Project Kickoff Deposit",
    percent: 100,
    amountUsd: calc.budget,
    due: "Due on receipt",
  };
  const inv = createDefaultInvoice();
  inv.clientName = String(state?.clientName || "Client Organization").trim();
  inv.issuerName = String(state?.providerName || "ForgeSuite Studio").trim();
  inv.taxPercent = 0;
  inv.discountPercent = 0;
  inv.notes = `Contract: ${String(state?.projectTitle || "SOW").trim()} | ${m.title} (${m.percent}% of $${calc.budget.toFixed(2)}) | Trigger: ${m.due} | Rail: ${SETTLEMENT_RAILS[state?.settlementRail] || "USDT"}`;
  inv.items = [
    {
      description: `${String(state?.projectTitle || "Engineering SOW").trim()} — ${m.title} (${m.percent}%)`,
      qty: 1,
      unitPrice: Number(m.amountUsd.toFixed(2)),
    },
  ];
  return inv;
}

function initSowApp() {
  if (typeof document === "undefined" || document.body?.dataset?.page !== "sowbuilder") {
    return;
  }

  bindCheckoutTriggers();
  const bundleBtn = document.getElementById("sowBundleBtn");
  if (bundleBtn) {
    bundleBtn.addEventListener("click", () => openCheckoutModal("BUNDLE"));
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

  const fields = {
    projectTitle: document.getElementById("sowProjectTitle"),
    providerName: document.getElementById("sowProviderName"),
    clientName: document.getElementById("sowClientName"),
    totalBudget: document.getElementById("sowBudgetUsd"),
    revisionsIncluded: document.getElementById("sowRevisions"),
    noticeDays: document.getElementById("sowNoticeDays"),
    settlementRail: document.getElementById("sowRailSelect"),
    deliverables: document.getElementById("sowDeliverables"),
  };
  const milestoneListEl = document.getElementById("sowMilestonesList");
  const balanceBadgeEl = document.getElementById("sowBalanceBadge");
  const previewEl = document.getElementById("sowPreviewOutput");
  const invoiceSelectEl = document.getElementById("sowMilestoneInvoiceSelect");

  let milestones = structuredClone(SOW_PRESETS.ai_mvp.milestones);

  function readState() {
    return {
      projectTitle: fields.projectTitle?.value || "",
      providerName: fields.providerName?.value || "",
      clientName: fields.clientName?.value || "",
      totalBudget: Number(fields.totalBudget?.value || 0),
      revisionsIncluded: Number(fields.revisionsIncluded?.value || 2),
      noticeDays: Number(fields.noticeDays?.value || 5),
      settlementRail: fields.settlementRail?.value || "usdt-bep20",
      deliverables: fields.deliverables?.value || "",
      milestones,
    };
  }

  function renderMilestoneInputs() {
    if (!milestoneListEl) return;
    milestoneListEl.innerHTML = milestones
      .map(
        (m, idx) => `
        <div class="cb-grid-3" data-ms-row="${idx}" style="margin-bottom:8px;gap:8px;align-items:end;">
          <label class="fs-field">
            <span class="fs-field-label">Title #${idx + 1}</span>
            <input type="text" class="fs-input" data-ms-field="title" data-ms-idx="${idx}" value="${String(m.title).replace(/"/g, "&quot;")}">
          </label>
          <label class="fs-field">
            <span class="fs-field-label">% Split</span>
            <input type="number" class="fs-input" min="0" max="100" step="1" data-ms-field="percent" data-ms-idx="${idx}" value="${Number(m.percent)}">
          </label>
          <label class="fs-field">
            <span class="fs-field-label">Trigger / Due</span>
            <input type="text" class="fs-input" data-ms-field="due" data-ms-idx="${idx}" value="${String(m.due).replace(/"/g, "&quot;")}">
          </label>
        </div>`
      )
      .join("");

    milestoneListEl.querySelectorAll("[data-ms-field]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const idx = Number(inp.getAttribute("data-ms-idx"));
        const key = inp.getAttribute("data-ms-field");
        if (!milestones[idx]) return;
        milestones[idx][key] = key === "percent" ? Number(inp.value || 0) : inp.value;
        refreshOutput();
      });
    });
  }

  function refreshOutput() {
    const state = readState();
    const calc = computeSowTotals(state);
    if (balanceBadgeEl) {
      balanceBadgeEl.textContent = calc.isBalanced
        ? `100% BALANCED ($${calc.allocatedUsd.toLocaleString("en-US")})`
        : `${calc.totalPercent}% ALLOCATED (TARGET 100%)`;
      balanceBadgeEl.className = `fs-badge ${calc.isBalanced ? "fs-badge-success" : "fs-badge-muted"}`;
    }
    if (invoiceSelectEl) {
      const prevIdx = invoiceSelectEl.value || "0";
      invoiceSelectEl.innerHTML = calc.milestones
        .map((m, idx) => `<option value="${idx}">${m.title} — $${m.amountUsd.toFixed(2)} (${m.percent}%)</option>`)
        .join("");
      if (calc.milestones[Number(prevIdx)]) invoiceSelectEl.value = prevIdx;
    }
    if (previewEl) {
      previewEl.value = renderSowMarkdown(state);
    }
  }

  function loadPreset(key) {
    const p = SOW_PRESETS[key];
    if (!p) return;
    if (fields.projectTitle) fields.projectTitle.value = p.projectTitle;
    if (fields.providerName) fields.providerName.value = p.providerName;
    if (fields.clientName) fields.clientName.value = p.clientName;
    if (fields.totalBudget) fields.totalBudget.value = String(p.totalBudget);
    if (fields.revisionsIncluded) fields.revisionsIncluded.value = String(p.revisionsIncluded);
    if (fields.noticeDays) fields.noticeDays.value = String(p.noticeDays);
    if (fields.settlementRail) fields.settlementRail.value = p.settlementRail;
    if (fields.deliverables) fields.deliverables.value = p.deliverables;
    milestones = structuredClone(p.milestones);
    renderMilestoneInputs();
    refreshOutput();
  }

  document.querySelectorAll("[data-sow-preset]").forEach((btn) => {
    btn.addEventListener("click", () => loadPreset(btn.getAttribute("data-sow-preset")));
  });

  Object.values(fields).forEach((el) => {
    if (el) el.addEventListener("input", refreshOutput);
  });

  const addMsBtn = document.getElementById("sowAddMilestoneBtn");
  if (addMsBtn) {
    addMsBtn.addEventListener("click", () => {
      milestones.push({ title: `M${milestones.length + 1}: Final Acceptance`, percent: 0, due: "Completion" });
      renderMilestoneInputs();
      refreshOutput();
    });
  }

  const copyBtn = document.getElementById("sowCopyBtn");
  if (copyBtn && previewEl) {
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(previewEl.value);
        copyBtn.textContent = "Copied!";
        setTimeout(() => (copyBtn.textContent = "Copy Markdown"), 1500);
      } catch {
        previewEl.select();
      }
    });
  }

  const dlBtn = document.getElementById("sowDownloadBtn");
  if (dlBtn && previewEl) {
    dlBtn.addEventListener("click", () => {
      const blob = new Blob([previewEl.value], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "Statement_of_Work_Escrow.md";
      a.click();
      URL.revokeObjectURL(url);
    });
  }

  const sendInvBtn = document.getElementById("sowSendInvoiceBtn");
  if (sendInvBtn) {
    sendInvBtn.addEventListener("click", () => {
      const idx = Number(invoiceSelectEl?.value || 0);
      const inv = buildMilestoneInvoicePayload(readState(), idx);
      const hash = encodeInvoicePayload(inv);
      window.location.href = `cryptobill.html#inv=${hash}`;
    });
  }

  loadPreset("ai_mvp");
}

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", initSowApp);
}
