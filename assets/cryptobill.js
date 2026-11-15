import {
  buildPaypalCheckoutUrl,
  getActiveLicenseForTier,
  hasUnlockedTier,
  openCheckoutModal,
} from "./checkout.js";
import { renderQrSvg, renderQrToCanvas } from "./qr.js";

export const FREE_TIER_LIMITS = Object.freeze({
  maxLineItems: 3,
  maxSavedTemplates: 2,
});

export const SUPPORTED_CURRENCIES = Object.freeze({
  USD: { code: "USD", symbol: "$", position: "prefix" },
  EUR: { code: "EUR", symbol: "€", position: "prefix" },
  USDT: { code: "USDT", symbol: "USDT", position: "suffix" },
});

export const DEFAULT_ACCENT_COLOR = "#2563eb";
const STORAGE_TEMPLATES_KEY = "cryptobill_templates_v1";
const STORAGE_DRAFT_KEY = "cryptobill_draft_v1";
const STORAGE_THEME_KEY = "forgesuite_theme";

export const PRO_BATCH_PRESETS = Object.freeze([
  {
    name: "Monthly SaaS Engineering Retainer",
    businessName: "Apex Digital Labs",
    businessEmail: "billing@apexlabs.example",
    clientName: "Northstar AI Inc.",
    clientEmail: "ap@northstar.example",
    invoiceNumber: "INV-2026-101",
    currency: "USDT",
    taxPercent: 0,
    discountPercent: 0,
    notes: "Monthly engineering retainer. Payment due within 7 days via USDT or PayPal.",
    items: [
      { description: "Full-Stack Architecture & API Sprint", qty: 1, unitPrice: 1800 },
      { description: "Automated CI/CD & Test Coverage Suite", qty: 1, unitPrice: 650 },
      { description: "Cloudflare Workers Edge Caching Setup", qty: 4, unitPrice: 120 },
      { description: "Priority Slack Support SLA", qty: 1, unitPrice: 300 },
    ],
  },
  {
    name: "Design & Conversion Landing Page Sprint",
    businessName: "Studio Kinetix",
    businessEmail: "hello@studiokinetix.example",
    clientName: "CloudMetrics SaaS",
    clientEmail: "finance@cloudmetrics.example",
    invoiceNumber: "INV-2026-102",
    currency: "USD",
    taxPercent: 8,
    discountPercent: 10,
    notes: "Thank you for partnering with Studio Kinetix. 10% early-settlement partner discount applied.",
    items: [
      { description: "Hero Positioning & Interactive Wireframes", qty: 1, unitPrice: 950 },
      { description: "Responsive Dark/Light UI System", qty: 1, unitPrice: 1100 },
      { description: "Custom SVG Iconography & Print Assets", qty: 1, unitPrice: 400 },
      { description: "Deployment & Lighthouse Performance Audit", qty: 1, unitPrice: 350 },
    ],
  },
  {
    name: "Smart Contract & Web3 Integration Audit",
    businessName: "ChainShield Security",
    businessEmail: "audit@chainshield.example",
    clientName: "VeloSwap Protocol",
    clientEmail: "treasury@veloswap.example",
    invoiceNumber: "INV-2026-103",
    currency: "USDT",
    taxPercent: 0,
    discountPercent: 0,
    notes: "Final milestone release upon delivery of verified audit report.",
    items: [
      { description: "ERC-20 Treasury & Escrow Contract Review", qty: 1, unitPrice: 2200 },
      { description: "Gas Optimization & Invariant Fuzz Suite", qty: 1, unitPrice: 850 },
      { description: "Client-Side RPC Receipt Verifier Integration", qty: 1, unitPrice: 550 },
      { description: "Executive Sign-off & Fix Re-Verification", qty: 1, unitPrice: 400 },
    ],
  },
]);

function round2(num) {
  return Math.round((Number(num) + Number.EPSILON) * 100) / 100;
}

function clamp(num, min, max) {
  if (!Number.isFinite(num)) return min;
  return Math.min(max, Math.max(min, num));
}

function getTodayIso(offsetDays = 0) {
  const d = new Date();
  d.setDate(d.getDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

export function createDefaultInvoice() {
  return {
    businessName: "Forge Freelance Studio",
    businessEmail: "billing@yourstudio.com",
    clientName: "Acme Global LLC",
    clientEmail: "accounts@acmeglobal.com",
    invoiceNumber: "INV-2026-001",
    issueDate: getTodayIso(0),
    dueDate: getTodayIso(14),
    currency: "USD",
    taxPercent: 0,
    discountPercent: 0,
    notes:
      "Thank you for your business! Please include the Invoice # as payment reference when sending crypto or PayPal transfers.",
    paymentMethods: {
      bep20: "",
      trc20: "",
      paypalEmail: "",
      binancePayId: "",
    },
    qrMethod: "auto",
    branding: {
      accentColor: DEFAULT_ACCENT_COLOR,
      logoText: "FS",
      hideFooterBadge: false,
    },
    items: [
      { description: "Product UI Design & Prototype", qty: 1, unitPrice: 450 },
      { description: "Frontend Development & Responsive QA", qty: 12, unitPrice: 65 },
    ],
  };
}

/**
 * Pure invoice calculator: computes row totals, subtotal, discount, tax, and grand total.
 * @param {Array<{ description?: string, qty?: number|string, unitPrice?: number|string }>} items
 * @param {number|string} [taxPercent=0]
 * @param {number|string} [discountPercent=0]
 */
export function calculateInvoiceTotals(items = [], taxPercent = 0, discountPercent = 0) {
  const safeItems = Array.isArray(items) ? items : [];
  const normalizedItems = safeItems.map((item) => {
    const qty = Math.max(0, Number(item && item.qty) || 0);
    const unitPrice = Math.max(0, Number(item && item.unitPrice) || 0);
    const lineTotal = round2(qty * unitPrice);
    return {
      description: String((item && item.description) || "").trim(),
      qty,
      unitPrice: round2(unitPrice),
      lineTotal,
    };
  });

  const subtotal = round2(
    normalizedItems.reduce((acc, item) => acc + item.lineTotal, 0)
  );
  const safeDiscountPct = clamp(Number(discountPercent) || 0, 0, 100);
  const safeTaxPct = clamp(Number(taxPercent) || 0, 0, 100);
  const discountAmount = round2(subtotal * (safeDiscountPct / 100));
  const taxableAmount = round2(Math.max(0, subtotal - discountAmount));
  const taxAmount = round2(taxableAmount * (safeTaxPct / 100));
  const grandTotal = round2(taxableAmount + taxAmount);

  return {
    items: normalizedItems,
    subtotal,
    discountPercent: safeDiscountPct,
    discountAmount,
    taxableAmount,
    taxPercent: safeTaxPct,
    taxAmount,
    grandTotal,
  };
}

/**
 * Formats an amount in USD, EUR, or USDT.
 * @param {number} amount
 * @param {'USD'|'EUR'|'USDT'} [currency='USD']
 */
export function formatCurrencyAmount(amount, currency = "USD") {
  const num = Number.isFinite(Number(amount)) ? Number(amount) : 0;
  const formatted = num.toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
  const spec = SUPPORTED_CURRENCIES[currency] || SUPPORTED_CURRENCIES.USD;
  return spec.position === "suffix"
    ? `${formatted} ${spec.symbol}`
    : `${spec.symbol}${formatted}`;
}

/**
 * Sanitizes arbitrary invoice JSON into a safe, complete invoice structure.
 * @param {object} raw
 */
export function sanitizeInvoiceData(raw) {
  const fallback = createDefaultInvoice();
  if (!raw || typeof raw !== "object") return fallback;

  const currency = SUPPORTED_CURRENCIES[raw.currency] ? raw.currency : "USD";
  const pm = raw.paymentMethods && typeof raw.paymentMethods === "object"
    ? raw.paymentMethods
    : {};
  const br = raw.branding && typeof raw.branding === "object" ? raw.branding : {};
  const accentColor = /^#[0-9a-fA-F]{6}$/.test(String(br.accentColor || ""))
    ? br.accentColor
    : DEFAULT_ACCENT_COLOR;

  const rawItems = Array.isArray(raw.items) && raw.items.length > 0
    ? raw.items
    : [{ description: "Consulting Services", qty: 1, unitPrice: 0 }];

  const items = rawItems.map((it) => ({
    description: String((it && it.description) || "").slice(0, 240),
    qty: Math.max(0, Number(it && it.qty) || 0),
    unitPrice: Math.max(0, Number(it && it.unitPrice) || 0),
  }));

  const allowedQrMethods = new Set(["auto", "bep20", "trc20", "paypal", "binance"]);
  return {
    businessName: String(raw.businessName ?? fallback.businessName).slice(0, 120),
    businessEmail: String(raw.businessEmail ?? "").slice(0, 120),
    clientName: String(raw.clientName ?? fallback.clientName).slice(0, 120),
    clientEmail: String(raw.clientEmail ?? "").slice(0, 120),
    invoiceNumber: String(raw.invoiceNumber ?? fallback.invoiceNumber).slice(0, 60),
    issueDate: String(raw.issueDate ?? fallback.issueDate).slice(0, 20),
    dueDate: String(raw.dueDate ?? fallback.dueDate).slice(0, 20),
    currency,
    taxPercent: clamp(Number(raw.taxPercent) || 0, 0, 100),
    discountPercent: clamp(Number(raw.discountPercent) || 0, 0, 100),
    notes: String(raw.notes ?? "").slice(0, 1000),
    paymentMethods: {
      bep20: String(pm.bep20 || "").trim().slice(0, 100),
      trc20: String(pm.trc20 || "").trim().slice(0, 100),
      paypalEmail: String(pm.paypalEmail || "").trim().slice(0, 120),
      binancePayId: String(pm.binancePayId || "").trim().slice(0, 80),
    },
    qrMethod: allowedQrMethods.has(raw.qrMethod) ? raw.qrMethod : "auto",
    branding: {
      accentColor,
      logoText: String(br.logoText || "FS").trim().slice(0, 6) || "FS",
      hideFooterBadge: Boolean(br.hideFooterBadge),
    },
    items,
  };
}

function bytesToBase64Url(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes)
      .toString("base64")
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replace(/=+$/, "");
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlToBytes(b64url) {
  const padded = b64url
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(b64url.length / 4) * 4, "=");
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encodes an invoice object into a URL-safe Base64URL string for `#inv=<token>`.
 * Supports full UTF-8 across Node and Browser.
 * @param {object} invoiceData
 * @returns {string}
 */
export function encodeInvoicePayload(invoiceData) {
  const clean = sanitizeInvoiceData(invoiceData);
  const json = JSON.stringify(clean);
  const bytes = new TextEncoder().encode(json);
  return bytesToBase64Url(bytes);
}

/**
 * Decodes a `#inv=<base64url>` hash string or raw Base64URL token into a sanitized invoice.
 * Returns null if the input is empty, malformed, or corrupted.
 * @param {string} hashOrToken
 */
export function decodeInvoicePayload(hashOrToken) {
  if (typeof hashOrToken !== "string" || !hashOrToken.trim()) return null;
  let token = hashOrToken.trim();
  if (token.startsWith("#")) token = token.slice(1);
  if (token.startsWith("inv=")) token = token.slice(4);
  if (!token || !/^[A-Za-z0-9\-_]+$/.test(token)) return null;

  try {
    const bytes = base64UrlToBytes(token);
    const json = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const parsed = JSON.parse(json);
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.items)) {
      return null;
    }
    return sanitizeInvoiceData(parsed);
  } catch {
    return null;
  }
}

/**
 * Enforces Free vs Pro feature limits.
 * @param {object} invoiceData
 * @param {boolean} isPro
 */
export function validateInvoiceLimits(invoiceData, isPro) {
  const itemCount = Array.isArray(invoiceData?.items) ? invoiceData.items.length : 0;
  if (isPro) {
    return {
      allowed: true,
      isPro: true,
      maxLineItems: Infinity,
      maxSavedTemplates: Infinity,
    };
  }
  if (itemCount > FREE_TIER_LIMITS.maxLineItems) {
    return {
      allowed: false,
      isPro: false,
      maxLineItems: FREE_TIER_LIMITS.maxLineItems,
      maxSavedTemplates: FREE_TIER_LIMITS.maxSavedTemplates,
      reason: `Free tier supports up to ${FREE_TIER_LIMITS.maxLineItems} line items. Unlock Pro ($15 lifetime) for unlimited line items.`,
    };
  }
  return {
    allowed: true,
    isPro: false,
    maxLineItems: FREE_TIER_LIMITS.maxLineItems,
    maxSavedTemplates: FREE_TIER_LIMITS.maxSavedTemplates,
  };
}

/**
 * Builds the PayPal payment button URL for a freelancer's client invoice.
 */
export function buildClientPaypalLink(invoiceData, grandTotal) {
  const email = invoiceData?.paymentMethods?.paypalEmail?.trim();
  if (!email) return null;
  return buildPaypalCheckoutUrl({
    itemName: `Invoice ${invoiceData.invoiceNumber || "Payment"} - ${invoiceData.businessName || "Freelancer"}`,
    amountUsd: grandTotal,
    businessEmail: email,
    currencyCode: invoiceData.currency === "EUR" ? "EUR" : "USD",
  });
}

/**
 * Resolves the active payment QR payload for the invoice preview & client payment panel.
 */
export function resolvePrimaryQrPayload(invoiceData, totals) {
  const pm = invoiceData?.paymentMethods || {};
  const grandTotal = totals?.grandTotal ?? 0;
  const paypalUrl = pm.paypalEmail ? buildClientPaypalLink(invoiceData, grandTotal) : null;

  const candidates = {
    bep20: pm.bep20
      ? { method: "bep20", label: "USDT (BEP20 / BSC)", value: pm.bep20, qrString: pm.bep20 }
      : null,
    trc20: pm.trc20
      ? { method: "trc20", label: "USDT (TRC20 / TRON)", value: pm.trc20, qrString: pm.trc20 }
      : null,
    paypal: paypalUrl
      ? { method: "paypal", label: "PayPal Checkout", value: pm.paypalEmail, qrString: paypalUrl }
      : null,
    binance: pm.binancePayId
      ? {
          method: "binance",
          label: "Binance Pay ID",
          value: pm.binancePayId,
          qrString: `BinancePayID:${pm.binancePayId}`,
        }
      : null,
  };

  const preferred = invoiceData?.qrMethod || "auto";
  if (preferred !== "auto" && candidates[preferred]) {
    return candidates[preferred];
  }
  return candidates.bep20 || candidates.trc20 || candidates.paypal || candidates.binance || null;
}

/* ============================================================================
 * Browser Application Controller
 * ========================================================================== */

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function getStorage() {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function loadSavedTemplates() {
  const storage = getStorage();
  if (!storage) return [];
  try {
    const raw = storage.getItem(STORAGE_TEMPLATES_KEY);
    const list = raw ? JSON.parse(raw) : [];
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function persistTemplates(templates) {
  const storage = getStorage();
  if (!storage) return;
  storage.setItem(STORAGE_TEMPLATES_KEY, JSON.stringify(templates));
}

function initThemeToggle() {
  const storage = getStorage();
  const saved = storage ? storage.getItem(STORAGE_THEME_KEY) : null;
  const preferred =
    saved ||
    (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
      ? "light"
      : "dark");
  document.documentElement.dataset.theme = preferred;

  const btn = document.getElementById("themeToggleBtn");
  if (!btn) return;
  const syncLabel = () => {
    const isLight = document.documentElement.dataset.theme === "light";
    btn.textContent = isLight ? "☀ Light" : "🌙 Dark";
    btn.setAttribute("aria-label", `Switch to ${isLight ? "dark" : "light"} theme`);
  };
  syncLabel();
  btn.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    if (storage) storage.setItem(STORAGE_THEME_KEY, next);
    syncLabel();
  });
}

async function copyTextWithFeedback(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  if (btn) {
    const orig = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => {
      btn.textContent = orig;
    }, 1600);
  }
}

export function initCryptoBillApp() {
  if (typeof document === "undefined") return;
  const root = document.getElementById("cryptobillApp");
  if (!root) return;

  initThemeToggle();

  let isClientView = false;
  let state = createDefaultInvoice();
  let toastTimer = null;

  // Check URL hash or local draft
  const initialDecoded = decodeInvoicePayload(window.location.hash);
  if (initialDecoded) {
    state = initialDecoded;
    isClientView = true;
  } else {
    const storage = getStorage();
    try {
      const draftRaw = storage ? storage.getItem(STORAGE_DRAFT_KEY) : null;
      if (draftRaw) state = sanitizeInvoiceData(JSON.parse(draftRaw));
    } catch {
      state = createDefaultInvoice();
    }
  }

  const els = {
    appShell: document.getElementById("cbWorkspaceShell"),
    editorPane: document.getElementById("cbEditorPane"),
    clientBanner: document.getElementById("cbClientViewBanner"),
    clientActionPanel: document.getElementById("cbClientPaymentPanel"),
    proBadgePill: document.getElementById("cbProStatusPill"),
    upgradeTopBtn: document.getElementById("cbUpgradeProBtn"),
    tierBanner: document.getElementById("cbTierNotice"),
    toast: document.getElementById("cbToast"),
    lineItemsWrap: document.getElementById("cbLineItemsWrap"),
    addItemBtn: document.getElementById("cbAddLineItemBtn"),
    itemsLimitBadge: document.getElementById("cbItemsLimitBadge"),
    proBrandingLock: document.getElementById("cbProBrandingLock"),
    proPresetsCard: document.getElementById("cbProPresetsCard"),
    proPresetSelect: document.getElementById("cbProPresetSelect"),
    loadProPresetBtn: document.getElementById("cbLoadProPresetBtn"),
    batchImportInput: document.getElementById("cbBatchImportInput"),
    exportBatchBtn: document.getElementById("cbExportBatchBtn"),
    templatesList: document.getElementById("cbSavedTemplatesList"),
    templatesCountBadge: document.getElementById("cbTemplatesCountBadge"),
    saveTemplateBtn: document.getElementById("cbSaveTemplateBtn"),
    templateNameInput: document.getElementById("cbTemplateNameInput"),
    previewSheet: document.getElementById("cbInvoiceSheet"),
    qrCanvas: document.getElementById("cbQrExportCanvas"),
    downloadQrBtn: document.getElementById("cbDownloadQrBtn"),
  };

  function showToast(msg, variant = "info") {
    if (!els.toast) return;
    els.toast.textContent = msg;
    els.toast.dataset.variant = variant;
    els.toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      els.toast.hidden = true;
    }, 3200);
  }

  function isProUnlocked() {
    return hasUnlockedTier("CB");
  }

  function saveDraft() {
    if (isClientView) return;
    const storage = getStorage();
    if (!storage) return;
    try {
      storage.setItem(STORAGE_DRAFT_KEY, JSON.stringify(state));
    } catch {
      // ignore
    }
  }

  function bindField(id, getter, setter) {
    const el = document.getElementById(id);
    if (!el) return;
    const syncVal = () => {
      if (el.type === "checkbox") {
        el.checked = Boolean(getter());
      } else {
        el.value = getter() ?? "";
      }
    };
    syncVal();
    el.addEventListener("input", () => {
      const val = el.type === "checkbox" ? el.checked : el.value;
      setter(val);
      saveDraft();
      renderPreviewOnly();
    });
    return syncVal;
  }

  const fieldSyncFns = [
    bindField("cbBusinessName", () => state.businessName, (v) => (state.businessName = v)),
    bindField("cbBusinessEmail", () => state.businessEmail, (v) => (state.businessEmail = v)),
    bindField("cbClientName", () => state.clientName, (v) => (state.clientName = v)),
    bindField("cbClientEmail", () => state.clientEmail, (v) => (state.clientEmail = v)),
    bindField("cbInvoiceNumber", () => state.invoiceNumber, (v) => (state.invoiceNumber = v)),
    bindField("cbIssueDate", () => state.issueDate, (v) => (state.issueDate = v)),
    bindField("cbDueDate", () => state.dueDate, (v) => (state.dueDate = v)),
    bindField("cbCurrency", () => state.currency, (v) => (state.currency = v)),
    bindField("cbTaxPercent", () => state.taxPercent, (v) => (state.taxPercent = clamp(Number(v) || 0, 0, 100))),
    bindField("cbDiscountPercent", () => state.discountPercent, (v) => (state.discountPercent = clamp(Number(v) || 0, 0, 100))),
    bindField("cbNotes", () => state.notes, (v) => (state.notes = v)),
    bindField("cbPayBep20", () => state.paymentMethods.bep20, (v) => (state.paymentMethods.bep20 = v.trim())),
    bindField("cbPayTrc20", () => state.paymentMethods.trc20, (v) => (state.paymentMethods.trc20 = v.trim())),
    bindField("cbPayPaypal", () => state.paymentMethods.paypalEmail, (v) => (state.paymentMethods.paypalEmail = v.trim())),
    bindField("cbPayBinance", () => state.paymentMethods.binancePayId, (v) => (state.paymentMethods.binancePayId = v.trim())),
    bindField("cbQrMethod", () => state.qrMethod, (v) => (state.qrMethod = v)),
    bindField("cbAccentColor", () => state.branding.accentColor, (v) => (state.branding.accentColor = v)),
    bindField("cbLogoText", () => state.branding.logoText, (v) => (state.branding.logoText = v.slice(0, 6))),
    bindField("cbHideBadge", () => state.branding.hideFooterBadge, (v) => (state.branding.hideFooterBadge = Boolean(v))),
  ].filter(Boolean);

  function syncAllInputs() {
    fieldSyncFns.forEach((fn) => fn());
  }

  function renderLineItemsEditor() {
    if (!els.lineItemsWrap) return;
    const pro = isProUnlocked();
    els.lineItemsWrap.innerHTML = "";

    state.items.forEach((item, idx) => {
      const row = document.createElement("div");
      row.className = "cb-item-row";
      const lineTotal = round2((Number(item.qty) || 0) * (Number(item.unitPrice) || 0));
      row.innerHTML = `
        <input type="text" class="fs-input cb-item-desc" placeholder="Service or deliverable description" value="${escapeHtml(item.description)}" data-idx="${idx}" data-field="description">
        <input type="number" min="0" step="any" class="fs-input cb-item-qty" placeholder="Qty" value="${item.qty}" data-idx="${idx}" data-field="qty">
        <input type="number" min="0" step="0.01" class="fs-input cb-item-price" placeholder="Price" value="${item.unitPrice}" data-idx="${idx}" data-field="unitPrice">
        <div class="cb-item-total" data-row-total="${idx}">${formatCurrencyAmount(lineTotal, state.currency)}</div>
        <button type="button" class="fs-icon-btn cb-remove-item" data-remove-idx="${idx}" aria-label="Remove line item" ${state.items.length <= 1 ? "disabled" : ""}>✕</button>
      `;
      els.lineItemsWrap.appendChild(row);
    });

    els.lineItemsWrap.querySelectorAll("input").forEach((input) => {
      input.addEventListener("input", () => {
        const idx = Number(input.dataset.idx);
        const field = input.dataset.field;
        if (!state.items[idx]) return;
        state.items[idx][field] =
          field === "description" ? input.value : Math.max(0, Number(input.value) || 0);
        const rowTotalEl = els.lineItemsWrap.querySelector(`[data-row-total="${idx}"]`);
        if (rowTotalEl) {
          const lt = round2(
            (Number(state.items[idx].qty) || 0) * (Number(state.items[idx].unitPrice) || 0)
          );
          rowTotalEl.textContent = formatCurrencyAmount(lt, state.currency);
        }
        saveDraft();
        renderPreviewOnly();
      });
    });

    els.lineItemsWrap.querySelectorAll("[data-remove-idx]").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (state.items.length <= 1) return;
        const idx = Number(btn.dataset.removeIdx);
        state.items.splice(idx, 1);
        saveDraft();
        renderLineItemsEditor();
        renderPreviewOnly();
      });
    });

    if (els.itemsLimitBadge) {
      els.itemsLimitBadge.textContent = pro
        ? `${state.items.length} items (Pro Unlimited)`
        : `${state.items.length} / ${FREE_TIER_LIMITS.maxLineItems} Free Limit`;
    }
  }

  function renderTemplatesPanel() {
    if (!els.templatesList) return;
    const pro = isProUnlocked();
    const templates = loadSavedTemplates();

    if (els.templatesCountBadge) {
      els.templatesCountBadge.textContent = pro
        ? `${templates.length} saved (Pro Unlimited)`
        : `${templates.length} / ${FREE_TIER_LIMITS.maxSavedTemplates} Free`;
    }

    if (templates.length === 0) {
      els.templatesList.innerHTML = `<div class="cb-empty-note">No saved templates yet. Save your current invoice layout for 1-click reuse.</div>`;
      return;
    }

    els.templatesList.innerHTML = templates
      .map(
        (tpl, i) => `
      <div class="cb-tpl-item">
        <div>
          <strong>${escapeHtml(tpl.name || `Template #${i + 1}`)}</strong>
          <div class="cb-tpl-meta">${escapeHtml(tpl.data?.clientName || "")} · ${escapeHtml(tpl.data?.currency || "USD")}</div>
        </div>
        <div class="cb-tpl-actions">
          <button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-load-tpl="${i}">Load</button>
          <button type="button" class="fs-icon-btn" data-del-tpl="${i}" aria-label="Delete template">✕</button>
        </div>
      </div>
    `
      )
      .join("");

    els.templatesList.querySelectorAll("[data-load-tpl]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const idx = Number(btn.dataset.loadTpl);
        const tpl = templates[idx];
        if (!tpl) return;
        state = sanitizeInvoiceData(tpl.data);
        if (!isProUnlocked() && state.items.length > FREE_TIER_LIMITS.maxLineItems) {
          state.items = state.items.slice(0, FREE_TIER_LIMITS.maxLineItems);
          showToast("Trimmed to 3 line items for Free tier. Unlock Pro for unlimited items.", "warn");
        } else {
          showToast(`Loaded template "${tpl.name}".`, "success");
        }
        saveDraft();
        syncAllInputs();
        renderLineItemsEditor();
        renderPreviewOnly();
      });
    });

    els.templatesList.querySelectorAll("[data-del-tpl]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const idx = Number(btn.dataset.delTpl);
        templates.splice(idx, 1);
        persistTemplates(templates);
        renderTemplatesPanel();
      });
    });
  }

  function renderTierUi() {
    const pro = isProUnlocked();
    const activeLicense = getActiveLicenseForTier("CB");

    if (els.proBadgePill) {
      els.proBadgePill.textContent = pro
        ? `PRO ACTIVE (${activeLicense?.tier || "CB"})`
        : "FREE TIER";
      els.proBadgePill.className = pro
        ? "fs-badge fs-badge-success"
        : "fs-badge fs-badge-muted";
    }
    if (els.upgradeTopBtn) {
      els.upgradeTopBtn.textContent = pro ? "Pro Active ✓" : "Unlock Pro ($15)";
    }
    if (els.tierBanner) {
      els.tierBanner.innerHTML = pro
        ? `<strong>CryptoBill Forge Pro Active:</strong> Unlimited line items, white-label branding, custom accents, unlimited templates, and batch JSON presets unlocked.`
        : `<strong>Free Tier:</strong> Includes live A4 print/PDF, QR codes, and shareable client links up to 3 line items &amp; 2 templates. <button type="button" class="cb-inline-link" id="cbInlineUpgrade">Unlock Pro ($15 Lifetime)</button>`;
      const inlineBtn = document.getElementById("cbInlineUpgrade");
      if (inlineBtn) {
        inlineBtn.addEventListener("click", () =>
          openCheckoutModal("CB", { onUnlocked: handleProUnlocked })
        );
      }
    }

    // Gate Pro-only controls in editor
    const accentEl = document.getElementById("cbAccentColor");
    const logoEl = document.getElementById("cbLogoText");
    const hideBadgeEl = document.getElementById("cbHideBadge");
    [accentEl, logoEl, hideBadgeEl].forEach((el) => {
      if (el) el.disabled = !pro;
    });
    if (els.proBrandingLock) els.proBrandingLock.hidden = pro;
    if (els.proPresetsCard) {
      els.proPresetsCard.classList.toggle("is-locked", !pro);
    }
    const proPresetBtn = els.loadProPresetBtn;
    const exportBatchBtn = els.exportBatchBtn;
    const batchFileInput = els.batchImportInput;
    if (proPresetBtn) proPresetBtn.disabled = !pro;
    if (exportBatchBtn) exportBatchBtn.disabled = !pro;
    if (batchFileInput) batchFileInput.disabled = !pro;

    if (els.proPresetSelect && els.proPresetSelect.options.length === 0) {
      PRO_BATCH_PRESETS.forEach((p, idx) => {
        const opt = document.createElement("option");
        opt.value = String(idx);
        opt.textContent = `${p.name} (${p.items.length} items)`;
        els.proPresetSelect.appendChild(opt);
      });
    }
  }

  function renderClientPaymentSection(totals) {
    if (!els.clientActionPanel) return;
    if (!isClientView) {
      els.clientActionPanel.hidden = true;
      return;
    }

    const pm = state.paymentMethods;
    const paypalUrl = buildClientPaypalLink(state, totals.grandTotal);
    const activeRails = [];

    if (pm.bep20) {
      activeRails.push({
        id: "bep20",
        title: "USDT (BEP20 / BSC)",
        detail: pm.bep20,
        qrSvg: renderQrSvg(pm.bep20, { size: 120, margin: 2, label: "Pay USDT BEP20 QR" }),
      });
    }
    if (pm.trc20) {
      activeRails.push({
        id: "trc20",
        title: "USDT (TRC20 / TRON)",
        detail: pm.trc20,
        qrSvg: renderQrSvg(pm.trc20, { size: 120, margin: 2, label: "Pay USDT TRC20 QR" }),
      });
    }
    if (pm.binancePayId) {
      activeRails.push({
        id: "binance",
        title: "Binance Pay ID",
        detail: pm.binancePayId,
        qrSvg: renderQrSvg(`BinancePayID:${pm.binancePayId}`, {
          size: 120,
          margin: 2,
          label: "Binance Pay QR",
        }),
      });
    }

    els.clientActionPanel.hidden = false;
    els.clientActionPanel.innerHTML = `
      <div class="cb-client-pay-card">
        <div class="cb-client-pay-head">
          <div>
            <span class="fs-badge fs-badge-accent">CLIENT PAYMENT OPTIONS</span>
            <h3>Pay ${formatCurrencyAmount(totals.grandTotal, state.currency)} to ${escapeHtml(state.businessName)}</h3>
          </div>
          <div class="cb-client-pay-btns">
            ${
              paypalUrl
                ? `<a href="${escapeHtml(paypalUrl)}" target="_blank" rel="noopener noreferrer" class="fs-btn fs-btn-primary">Pay Now with PayPal →</a>`
                : ""
            }
            <button type="button" class="fs-btn fs-btn-secondary" id="cbClientPrintBtn">Print / Save PDF</button>
          </div>
        </div>
        ${
          activeRails.length > 0
            ? `<div class="cb-client-rails">
                ${activeRails
                  .map(
                    (rail) => `
                  <div class="cb-rail-card">
                    <div class="cb-rail-qr">${rail.qrSvg}</div>
                    <div class="cb-rail-info">
                      <div class="fs-field-label">${escapeHtml(rail.title)}</div>
                      <code class="fs-code-val">${escapeHtml(rail.detail)}</code>
                      <button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-copy-rail="${escapeHtml(rail.detail)}">Copy Address / ID</button>
                    </div>
                  </div>
                `
                  )
                  .join("")}
              </div>`
            : `<p class="cb-empty-note">No crypto addresses specified on this invoice. Use PayPal or contact ${escapeHtml(state.businessEmail || "the sender")}.</p>`
        }
      </div>
    `;

    const printBtn = document.getElementById("cbClientPrintBtn");
    if (printBtn) printBtn.addEventListener("click", () => window.print());
    els.clientActionPanel.querySelectorAll("[data-copy-rail]").forEach((btn) => {
      btn.addEventListener("click", () => copyTextWithFeedback(btn.dataset.copyRail, btn));
    });
  }

  function renderPreviewOnly() {
    if (!els.previewSheet) return;
    const pro = isProUnlocked();
    const totals = calculateInvoiceTotals(
      state.items,
      state.taxPercent,
      state.discountPercent
    );

    const accent = pro ? state.branding.accentColor : DEFAULT_ACCENT_COLOR;
    const logoText = pro ? state.branding.logoText || "FS" : "CB";
    const hideFooterBadge = pro && state.branding.hideFooterBadge;
    const primaryQr = resolvePrimaryQrPayload(state, totals);

    const qrSvg = primaryQr
      ? renderQrSvg(primaryQr.qrString, {
          size: 112,
          margin: 2,
          darkColor: "#0f172a",
          lightColor: "#ffffff",
          label: `${primaryQr.label} QR Code`,
        })
      : "";

    if (els.downloadQrBtn) {
      els.downloadQrBtn.disabled = !primaryQr;
    }

    const pmRows = [];
    if (state.paymentMethods.bep20) {
      pmRows.push(
        `<div><span>USDT (BEP20):</span> <code>${escapeHtml(state.paymentMethods.bep20)}</code></div>`
      );
    }
    if (state.paymentMethods.trc20) {
      pmRows.push(
        `<div><span>USDT (TRC20):</span> <code>${escapeHtml(state.paymentMethods.trc20)}</code></div>`
      );
    }
    if (state.paymentMethods.paypalEmail) {
      pmRows.push(
        `<div><span>PayPal:</span> <code>${escapeHtml(state.paymentMethods.paypalEmail)}</code></div>`
      );
    }
    if (state.paymentMethods.binancePayId) {
      pmRows.push(
        `<div><span>Binance Pay ID:</span> <code>${escapeHtml(state.paymentMethods.binancePayId)}</code></div>`
      );
    }

    els.previewSheet.style.setProperty("--inv-accent", accent);
    els.previewSheet.innerHTML = `
      <div class="inv-top-bar"></div>
      <div class="inv-header">
        <div class="inv-brand">
          <div class="inv-monogram">${escapeHtml(logoText)}</div>
          <div>
            <h2 class="inv-biz-name">${escapeHtml(state.businessName || "Your Business Name")}</h2>
            ${state.businessEmail ? `<div class="inv-muted">${escapeHtml(state.businessEmail)}</div>` : ""}
          </div>
        </div>
        <div class="inv-meta-right">
          <div class="inv-word">INVOICE</div>
          <div class="inv-number">#${escapeHtml(state.invoiceNumber || "INV-001")}</div>
          <div class="inv-dates">
            <div><span>Issued:</span> ${escapeHtml(state.issueDate || "-")}</div>
            <div><span>Due:</span> ${escapeHtml(state.dueDate || "-")}</div>
          </div>
        </div>
      </div>

      <div class="inv-parties">
        <div>
          <div class="inv-section-label">BILL TO</div>
          <div class="inv-client-name">${escapeHtml(state.clientName || "Client Name")}</div>
          ${state.clientEmail ? `<div class="inv-muted">${escapeHtml(state.clientEmail)}</div>` : ""}
        </div>
        <div class="inv-amount-box">
          <div class="inv-section-label">AMOUNT DUE (${escapeHtml(state.currency)})</div>
          <div class="inv-amount-due">${formatCurrencyAmount(totals.grandTotal, state.currency)}</div>
        </div>
      </div>

      <table class="inv-table">
        <thead>
          <tr>
            <th>Description</th>
            <th class="num">Qty</th>
            <th class="num">Unit Price</th>
            <th class="num">Total</th>
          </tr>
        </thead>
        <tbody>
          ${totals.items
            .map(
              (item) => `
            <tr>
              <td>${escapeHtml(item.description || "Untitled Service")}</td>
              <td class="num">${item.qty}</td>
              <td class="num">${formatCurrencyAmount(item.unitPrice, state.currency)}</td>
              <td class="num">${formatCurrencyAmount(item.lineTotal, state.currency)}</td>
            </tr>
          `
            )
            .join("")}
        </tbody>
      </table>

      <div class="inv-bottom-grid">
        <div class="inv-notes-col">
          ${
            pmRows.length > 0
              ? `<div class="inv-pay-box">
                  <div class="inv-section-label">PAYMENT METHODS</div>
                  <div class="inv-pm-list">${pmRows.join("")}</div>
                </div>`
              : `<div class="inv-pay-box inv-pay-empty">
                  <div class="inv-section-label">PAYMENT METHODS</div>
                  <div class="inv-muted">Enter your USDT BEP20/TRC20, PayPal, or Binance Pay ID to generate a scannable payment QR code.</div>
                </div>`
          }
          ${
            state.notes
              ? `<div class="inv-notes-block">
                  <div class="inv-section-label">NOTES &amp; TERMS</div>
                  <p>${escapeHtml(state.notes)}</p>
                </div>`
              : ""
          }
        </div>

        <div class="inv-totals-col">
          <div class="inv-totals-card">
            <div class="inv-tot-row"><span>Subtotal</span><span>${formatCurrencyAmount(totals.subtotal, state.currency)}</span></div>
            ${
              totals.discountPercent > 0
                ? `<div class="inv-tot-row"><span>Discount (${totals.discountPercent}%)</span><span>-${formatCurrencyAmount(totals.discountAmount, state.currency)}</span></div>`
                : ""
            }
            ${
              totals.taxPercent > 0
                ? `<div class="inv-tot-row"><span>Tax (${totals.taxPercent}%)</span><span>+${formatCurrencyAmount(totals.taxAmount, state.currency)}</span></div>`
                : ""
            }
            <div class="inv-tot-grand"><span>Total Due</span><span>${formatCurrencyAmount(totals.grandTotal, state.currency)}</span></div>
          </div>

          ${
            primaryQr
              ? `<div class="inv-qr-card">
                  ${qrSvg}
                  <div class="inv-qr-caption">Scan to Pay · ${escapeHtml(primaryQr.label)}</div>
                </div>`
              : ""
          }
        </div>
      </div>

      ${
        hideFooterBadge
          ? ""
          : `<div class="inv-footer-badge">Created with CryptoBill Forge · Zero-Backend Invoicing</div>`
      }
    `;

    renderClientPaymentSection(totals);
  }

  function applyViewMode() {
    const toolbar = document.querySelector(".cb-toolbar");
    if (toolbar) toolbar.hidden = isClientView;
    if (els.editorPane) els.editorPane.hidden = isClientView;
    if (els.clientBanner) els.clientBanner.hidden = !isClientView;
    if (els.appShell) els.appShell.classList.toggle("is-client-mode", isClientView);
  }

  function handleProUnlocked(record) {
    state.branding.hideFooterBadge = true;
    saveDraft();
    syncAllInputs();
    renderTierUi();
    renderLineItemsEditor();
    renderTemplatesPanel();
    renderPreviewOnly();
    showToast(`Unlocked ${record?.tier || "CB"} Pro features!`, "success");
  }

  // Wire buttons
  if (els.upgradeTopBtn) {
    els.upgradeTopBtn.addEventListener("click", () =>
      openCheckoutModal("CB", {
        initialTab: isProUnlocked() ? "license" : "bep20",
        onUnlocked: handleProUnlocked,
      })
    );
  }

  if (els.addItemBtn) {
    els.addItemBtn.addEventListener("click", () => {
      const pro = isProUnlocked();
      const check = validateInvoiceLimits(
        { ...state, items: [...state.items, { description: "", qty: 1, unitPrice: 0 }] },
        pro
      );
      if (!check.allowed) {
        showToast(check.reason, "warn");
        openCheckoutModal("CB", { onUnlocked: handleProUnlocked });
        return;
      }
      state.items.push({ description: "", qty: 1, unitPrice: 0 });
      saveDraft();
      renderLineItemsEditor();
      renderPreviewOnly();
    });
  }

  if (els.saveTemplateBtn) {
    els.saveTemplateBtn.addEventListener("click", () => {
      const pro = isProUnlocked();
      const templates = loadSavedTemplates();
      if (!pro && templates.length >= FREE_TIER_LIMITS.maxSavedTemplates) {
        showToast(
          `Free tier allows up to ${FREE_TIER_LIMITS.maxSavedTemplates} saved templates. Unlock Pro for unlimited templates.`,
          "warn"
        );
        openCheckoutModal("CB", { onUnlocked: handleProUnlocked });
        return;
      }
      const name =
        (els.templateNameInput?.value || "").trim() ||
        `${state.clientName || "Client"} (${state.invoiceNumber})`;
      templates.unshift({
        name,
        savedAt: new Date().toISOString(),
        data: sanitizeInvoiceData(state),
      });
      persistTemplates(templates);
      if (els.templateNameInput) els.templateNameInput.value = "";
      renderTemplatesPanel();
      showToast(`Saved template "${name}".`, "success");
    });
  }

  const printBtn = document.getElementById("cbPrintPdfBtn");
  if (printBtn) {
    printBtn.addEventListener("click", () => window.print());
  }

  const shareBtn = document.getElementById("cbCopyShareLinkBtn");
  if (shareBtn) {
    shareBtn.addEventListener("click", async () => {
      const token = encodeInvoicePayload(state);
      const baseUrl = window.location.href.split("#")[0];
      const shareUrl = `${baseUrl}#inv=${token}`;
      await copyTextWithFeedback(shareUrl, shareBtn);
      showToast("Shareable client invoice link copied to clipboard!", "success");
    });
  }

  const previewClientBtn = document.getElementById("cbPreviewClientModeBtn");
  if (previewClientBtn) {
    previewClientBtn.addEventListener("click", () => {
      const token = encodeInvoicePayload(state);
      window.location.hash = `inv=${token}`;
    });
  }

  const switchEditBtn = document.getElementById("cbSwitchToEditorBtn");
  if (switchEditBtn) {
    switchEditBtn.addEventListener("click", () => {
      isClientView = false;
      history.replaceState(null, "", window.location.pathname + window.location.search);
      applyViewMode();
      syncAllInputs();
      renderLineItemsEditor();
      renderPreviewOnly();
      showToast("Switched to editable builder mode.", "info");
    });
  }

  const demoBtn = document.getElementById("cbLoadDemoBtn");
  if (demoBtn) {
    demoBtn.addEventListener("click", () => {
      state = sanitizeInvoiceData({
        ...createDefaultInvoice(),
        businessName: "NovaByte Consulting",
        businessEmail: "billing@novabyte.example",
        clientName: "Horizon Commerce Ltd.",
        clientEmail: "finance@horizoncommerce.example",
        invoiceNumber: "INV-2026-042",
        currency: "USDT",
        taxPercent: 0,
        discountPercent: 5,
        notes: "5% partner discount applied. Pay via USDT BEP20/TRC20, Binance Pay, or PayPal.",
        paymentMethods: {
          bep20: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
          trc20: "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
          paypalEmail: "payments@novabyte.example",
          binancePayId: "901245678",
        },
        items: [
          { description: "API Performance Optimization & Caching", qty: 1, unitPrice: 620 },
          { description: "Automated Reporting Dashboard Build", qty: 1, unitPrice: 880 },
          { description: "Deployment & Production Handover", qty: 2, unitPrice: 150 },
        ],
      });
      saveDraft();
      syncAllInputs();
      renderLineItemsEditor();
      renderPreviewOnly();
      showToast("Sample invoice & payment methods loaded!", "success");
    });
  }

  const exportJsonBtn = document.getElementById("cbExportJsonBtn");
  if (exportJsonBtn) {
    exportJsonBtn.addEventListener("click", () => {
      const blob = new Blob([JSON.stringify(sanitizeInvoiceData(state), null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${(state.invoiceNumber || "invoice").replace(/[^a-zA-Z0-9_-]/g, "_")}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("Invoice JSON exported.", "success");
    });
  }

  const importJsonInput = document.getElementById("cbImportJsonInput");
  if (importJsonInput) {
    importJsonInput.addEventListener("change", async () => {
      const file = importJsonInput.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        const candidate = Array.isArray(parsed) ? parsed[0] : parsed;
        let nextState = sanitizeInvoiceData(candidate);
        if (!isProUnlocked() && nextState.items.length > FREE_TIER_LIMITS.maxLineItems) {
          nextState.items = nextState.items.slice(0, FREE_TIER_LIMITS.maxLineItems);
          showToast("Imported (trimmed to 3 Free line items). Unlock Pro for unlimited.", "warn");
        } else {
          showToast("Invoice JSON imported!", "success");
        }
        state = nextState;
        saveDraft();
        syncAllInputs();
        renderLineItemsEditor();
        renderPreviewOnly();
      } catch {
        showToast("Invalid JSON file.", "error");
      } finally {
        importJsonInput.value = "";
      }
    });
  }

  if (els.loadProPresetBtn) {
    els.loadProPresetBtn.addEventListener("click", () => {
      if (!isProUnlocked()) {
        openCheckoutModal("CB", { onUnlocked: handleProUnlocked });
        return;
      }
      const idx = Number(els.proPresetSelect?.value || 0);
      const preset = PRO_BATCH_PRESETS[idx] || PRO_BATCH_PRESETS[0];
      state = sanitizeInvoiceData({
        ...state,
        ...preset,
        paymentMethods: state.paymentMethods,
        branding: state.branding,
      });
      saveDraft();
      syncAllInputs();
      renderLineItemsEditor();
      renderPreviewOnly();
      showToast(`Loaded Pro preset: ${preset.name}`, "success");
    });
  }

  if (els.exportBatchBtn) {
    els.exportBatchBtn.addEventListener("click", () => {
      if (!isProUnlocked()) {
        openCheckoutModal("CB", { onUnlocked: handleProUnlocked });
        return;
      }
      const templates = loadSavedTemplates();
      const batch =
        templates.length > 0
          ? templates.map((t) => sanitizeInvoiceData(t.data))
          : PRO_BATCH_PRESETS.map((p) => sanitizeInvoiceData(p));
      const blob = new Blob([JSON.stringify(batch, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "cryptobill-batch-presets.json";
      a.click();
      URL.revokeObjectURL(url);
      showToast(`Exported ${batch.length} invoices as batch JSON.`, "success");
    });
  }

  if (els.batchImportInput) {
    els.batchImportInput.addEventListener("change", async () => {
      if (!isProUnlocked()) return;
      const file = els.batchImportInput.files?.[0];
      if (!file) return;
      try {
        const parsed = JSON.parse(await file.text());
        const arr = Array.isArray(parsed) ? parsed : [parsed];
        const templates = loadSavedTemplates();
        let added = 0;
        arr.forEach((entry) => {
          const clean = sanitizeInvoiceData(entry);
          templates.unshift({
            name: `${clean.clientName} (${clean.invoiceNumber})`,
            savedAt: new Date().toISOString(),
            data: clean,
          });
          added += 1;
        });
        persistTemplates(templates);
        if (arr[0]) {
          state = sanitizeInvoiceData(arr[0]);
          saveDraft();
          syncAllInputs();
          renderLineItemsEditor();
          renderPreviewOnly();
        }
        renderTemplatesPanel();
        showToast(`Imported ${added} batch invoice template(s)!`, "success");
      } catch {
        showToast("Invalid batch JSON array.", "error");
      } finally {
        els.batchImportInput.value = "";
      }
    });
  }

  if (els.downloadQrBtn && els.qrCanvas) {
    els.downloadQrBtn.addEventListener("click", () => {
      const totals = calculateInvoiceTotals(
        state.items,
        state.taxPercent,
        state.discountPercent
      );
      const payload = resolvePrimaryQrPayload(state, totals);
      if (!payload) return;
      renderQrToCanvas(els.qrCanvas, payload.qrString, { size: 320, margin: 4 });
      const a = document.createElement("a");
      a.href = els.qrCanvas.toDataURL("image/png");
      a.download = `${(state.invoiceNumber || "invoice")}-qr-${payload.method}.png`;
      a.click();
      showToast(`Downloaded ${payload.label} QR PNG.`, "success");
    });
  }

  window.addEventListener("hashchange", () => {
    const decoded = decodeInvoicePayload(window.location.hash);
    if (decoded) {
      state = decoded;
      isClientView = true;
      applyViewMode();
      renderPreviewOnly();
    } else if (isClientView && !window.location.hash) {
      isClientView = false;
      applyViewMode();
      syncAllInputs();
      renderLineItemsEditor();
      renderPreviewOnly();
    }
  });

  window.addEventListener("forgesuite:license-updated", () => {
    renderTierUi();
    renderLineItemsEditor();
    renderTemplatesPanel();
    renderPreviewOnly();
  });

  // Initial render
  applyViewMode();
  renderTierUi();
  renderLineItemsEditor();
  renderTemplatesPanel();
  renderPreviewOnly();
}

if (typeof document !== "undefined" && document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initCryptoBillApp);
} else if (typeof document !== "undefined") {
  initCryptoBillApp();
}
