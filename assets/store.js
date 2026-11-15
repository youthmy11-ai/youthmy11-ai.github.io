import {
  activateLicenseKey,
  bindCheckoutTriggers,
  buildMailtoReceiptUrl,
  getStoredLicenses,
  hasUnlockedTier,
  OFFICIAL_CHANNELS,
  openCheckoutModal,
  PRODUCTS,
  saveVerifiedLicense,
  verifyBscUsdtTxOnChain,
} from "./checkout.js";
import {
  calculateInvoiceTotals,
  createDefaultInvoice,
  encodeInvoicePayload,
  formatCurrencyAmount,
} from "./cryptobill.js";
import { renderQrSvg } from "./qr.js";

const STORAGE_THEME_KEY = "forgesuite_theme";

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function initStoreTheme() {
  let saved = null;
  try {
    saved = window.localStorage.getItem(STORAGE_THEME_KEY);
  } catch {
    saved = null;
  }
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
    try {
      window.localStorage.setItem(STORAGE_THEME_KEY, next);
    } catch {
      // ignore
    }
    syncLabel();
  });
}

function initMobileNav() {
  const toggle = document.getElementById("navMenuToggle");
  const nav = document.getElementById("mainNavLinks");
  if (!toggle || !nav) return;
  toggle.addEventListener("click", () => {
    const expanded = toggle.getAttribute("aria-expanded") === "true";
    toggle.setAttribute("aria-expanded", String(!expanded));
    nav.classList.toggle("is-open", !expanded);
  });
  nav.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      toggle.setAttribute("aria-expanded", "false");
      nav.classList.remove("is-open");
    });
  });
}

function refreshLicenseUi() {
  const licenses = getStoredLicenses();
  const statusPill = document.getElementById("storeLicensePill");
  if (statusPill) {
    if (licenses.length > 0) {
      const tiers = [...new Set(licenses.flatMap((l) => l.unlocks || [l.tier]))];
      statusPill.textContent = `PRO UNLOCKED (${tiers.join(", ")})`;
      statusPill.className = "fs-badge fs-badge-success";
    } else {
      statusPill.textContent = "NO ACTIVE PRO KEY";
      statusPill.className = "fs-badge fs-badge-muted";
    }
  }

  ["CB", "AS", "WL", "BUNDLE"].forEach((sku) => {
    const unlocked =
      sku === "BUNDLE" ? hasUnlockedTier("BUNDLE") : hasUnlockedTier(sku);
    document.querySelectorAll(`[data-sku-owned="${sku}"]`).forEach((badge) => {
      badge.hidden = !unlocked;
    });
  });

  const activeListEl = document.getElementById("storeActiveLicensesList");
  if (activeListEl) {
    if (licenses.length === 0) {
      activeListEl.innerHTML = `<div class="cb-empty-note">No Pro licenses activated in this browser yet. Purchase via instant BSC USDT auto-verification or paste your key below.</div>`;
    } else {
      activeListEl.innerHTML = licenses
        .map(
          (item) => `
          <div class="fs-license-row">
            <div>
              <span class="fs-badge fs-badge-success">${escapeHtml(item.tier)} PRO</span>
              <code class="fs-code-val">${escapeHtml(item.key)}</code>
            </div>
            <div class="fs-license-meta">
              ${item.txHash ? `<span>Tx: ${escapeHtml(item.txHash.slice(0, 12))}…</span>` : `<span>${escapeHtml(item.token || "ACTIVE")}</span>`}
              ${
                item.unlocks?.includes("CB")
                  ? `<a href="cryptobill.html" class="fs-btn fs-btn-sm fs-btn-primary">Open CryptoBill Pro</a>`
                  : `<a href="${escapeHtml(buildMailtoReceiptUrl({ productName: PRODUCTS[item.tier]?.name || item.tier, sku: item.tier, amountUsd: PRODUCTS[item.tier]?.priceUsd || 15, paymentMethod: item.token || "USDT-BEP20", referenceId: `${item.txHash || ""} | Key: ${item.key}` }))}" class="fs-btn fs-btn-sm fs-btn-secondary">Request Package</a>`
              }
            </div>
          </div>`
        )
        .join("");
    }
  }
}

function initLiveDemoWidget() {
  const form = document.getElementById("storeDemoForm");
  if (!form) return;

  const bizInput = document.getElementById("demoBizName");
  const clientInput = document.getElementById("demoClientName");
  const itemInput = document.getElementById("demoItemName");
  const amountInput = document.getElementById("demoAmount");
  const currencySelect = document.getElementById("demoCurrency");
  const railSelect = document.getElementById("demoPayRail");
  const openFullBtn = document.getElementById("demoOpenFullLink");
  const previewCard = document.getElementById("demoMiniInvoice");

  const demoAddresses = {
    bep20: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
    trc20: "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
    paypal: "billing@yourstudio.example",
  };

  const renderDemo = () => {
    const biz = bizInput.value.trim() || "Apex Freelance";
    const client = clientInput.value.trim() || "Northstar Tech";
    const itemDesc = itemInput.value.trim() || "Full-Stack Product Sprint";
    const price = Math.max(1, Number(amountInput.value) || 450);
    const currency = currencySelect.value || "USDT";
    const rail = railSelect.value || "bep20";

    const inv = createDefaultInvoice();
    inv.businessName = biz;
    inv.clientName = client;
    inv.invoiceNumber = "INV-DEMO-088";
    inv.currency = currency;
    inv.items = [{ description: itemDesc, qty: 1, unitPrice: price }];
    inv.paymentMethods = {
      bep20: rail === "bep20" ? demoAddresses.bep20 : "",
      trc20: rail === "trc20" ? demoAddresses.trc20 : "",
      paypalEmail: rail === "paypal" ? demoAddresses.paypal : "",
      binancePayId: "",
    };

    const totals = calculateInvoiceTotals(inv.items, 0, 0);
    const qrPayload =
      rail === "bep20"
        ? demoAddresses.bep20
        : rail === "trc20"
          ? demoAddresses.trc20
          : `https://www.paypal.com/cgi-bin/webscr?cmd=_xclick&business=${encodeURIComponent(demoAddresses.paypal)}&amount=${price.toFixed(2)}`;

    const qrLabel =
      rail === "bep20"
        ? "USDT (BEP20)"
        : rail === "trc20"
          ? "USDT (TRC20)"
          : "PayPal Direct";

    const qrSvg = renderQrSvg(qrPayload, {
      size: 112,
      margin: 2,
      label: `Demo ${qrLabel} QR`,
    });

    previewCard.innerHTML = `
      <div class="demo-inv-head">
        <div>
          <span class="inv-section-label">FROM</span>
          <strong>${escapeHtml(biz)}</strong>
          <div class="inv-muted">Bill To: ${escapeHtml(client)}</div>
        </div>
        <div class="demo-inv-total">
          <span class="inv-section-label">AMOUNT DUE</span>
          <strong>${formatCurrencyAmount(totals.grandTotal, currency)}</strong>
        </div>
      </div>
      <div class="demo-inv-line">
        <span>${escapeHtml(itemDesc)}</span>
        <strong>${formatCurrencyAmount(totals.grandTotal, currency)}</strong>
      </div>
      <div class="demo-inv-foot">
        <div class="demo-inv-qr">${qrSvg}</div>
        <div>
          <div class="fs-field-label">Offline QR · ${escapeHtml(qrLabel)}</div>
          <code class="fs-code-val">${escapeHtml(qrPayload.slice(0, 44))}${qrPayload.length > 44 ? "…" : ""}</code>
          <p class="cb-empty-note">Generated 100% locally via pure ES module JS (<code>qr.js</code>). Zero external QR APIs.</p>
        </div>
      </div>
    `;

    const hashToken = encodeInvoicePayload(inv);
    if (openFullBtn) {
      openFullBtn.href = `cryptobill.html#inv=${hashToken}`;
    }
  };

  [bizInput, clientInput, itemInput, amountInput, currencySelect, railSelect].forEach(
    (el) => el && el.addEventListener("input", renderDemo)
  );
  renderDemo();
}

function initInlineVerifierAndRails() {
  // Copy buttons for receiving channels on storefront
  document.querySelectorAll("[data-copy-text]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const value = btn.dataset.copyText || "";
      try {
        await navigator.clipboard.writeText(value);
      } catch {
        const ta = document.createElement("textarea");
        ta.value = value;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      }
      const orig = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => {
        btn.textContent = orig;
      }, 1600);
    });
  });

  // Render BEP20 & TRC20 QR thumbnails on storefront verification section
  const bepQr = document.getElementById("storeBep20Qr");
  if (bepQr) {
    bepQr.innerHTML = renderQrSvg(OFFICIAL_CHANNELS.usdtBep20, {
      size: 118,
      margin: 2,
      label: "Official USDT BEP20 QR",
    });
  }
  const trcQr = document.getElementById("storeTrc20Qr");
  if (trcQr) {
    trcQr.innerHTML = renderQrSvg(OFFICIAL_CHANNELS.usdtTrc20, {
      size: 118,
      margin: 2,
      label: "Official USDT TRC20 QR",
    });
  }

  // Inline BSC RPC verifier form
  const verifyBtn = document.getElementById("inlineVerifyBtn");
  if (verifyBtn) {
    verifyBtn.addEventListener("click", async () => {
      const sku = document.getElementById("inlineVerifySku")?.value || "CB";
      const txHash = document.getElementById("inlineVerifyTx")?.value.trim() || "";
      const statusEl = document.getElementById("inlineVerifyStatus");
      const product = PRODUCTS[sku] || PRODUCTS.CB;

      verifyBtn.disabled = true;
      verifyBtn.textContent = "Checking BSC RPC...";
      if (statusEl) {
        statusEl.className = "fs-status-msg is-loading";
        statusEl.textContent = `Checking BSC transaction against ${product.name} ($${product.priceUsd})...`;
      }

      const res = await verifyBscUsdtTxOnChain(txHash, product.priceUsd, {
        tier: product.sku,
      });

      verifyBtn.disabled = false;
      verifyBtn.textContent = "Verify TxHash";

      if (res.verified) {
        saveVerifiedLicense({
          key: res.licenseKey,
          txHash: res.txHash,
          token: res.token,
          amountUsd: res.amountUsd,
        });
        if (statusEl) {
          statusEl.className = "fs-status-msg is-success";
          statusEl.textContent = `Verified ${res.amountUsd.toFixed(2)} USDT! Unlocked Key: ${res.licenseKey}`;
        }
        refreshLicenseUi();
      } else if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = res.reason;
      }
    });
  }

  // Inline License Key activator
  const activateBtn = document.getElementById("inlineActivateKeyBtn");
  if (activateBtn) {
    activateBtn.addEventListener("click", () => {
      const keyInput = document.getElementById("inlineKeyInput")?.value || "";
      const statusEl = document.getElementById("inlineKeyStatus");
      const res = activateLicenseKey(keyInput);
      if (res.ok) {
        if (statusEl) {
          statusEl.className = "fs-status-msg is-success";
          statusEl.textContent = `Activated ${res.tier} Pro License (${res.key})!`;
        }
        refreshLicenseUi();
      } else if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = res.reason;
      }
    });
  }
}

export function initStorefront() {
  if (typeof document === "undefined") return;
  if (document.body?.dataset.page !== "store") return;

  initStoreTheme();
  initMobileNav();
  initLiveDemoWidget();
  initInlineVerifierAndRails();
  bindCheckoutTriggers({ onUnlocked: refreshLicenseUi });
  refreshLicenseUi();

  const openLicenseBtn = document.getElementById("openLicenseModalBtn");
  if (openLicenseBtn) {
    openLicenseBtn.addEventListener("click", () =>
      openCheckoutModal("CB", { initialTab: "license", onUnlocked: refreshLicenseUi })
    );
  }

  window.addEventListener("forgesuite:license-updated", refreshLicenseUi);
}

if (typeof document !== "undefined" && document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initStorefront);
} else if (typeof document !== "undefined") {
  initStorefront();
}
