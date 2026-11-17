import { bindCheckoutTriggers, openCheckoutModal } from "./checkout.js";
import { createDefaultInvoice, encodeInvoicePayload } from "./cryptobill.js";

/**
 * Curated deterministic secret & private-key patterns for offline redaction.
 * Zero network requests: runs 100% in the local browser memory.
 */
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

export const ENVSHIELD_SAMPLES = Object.freeze({
  agent_env: [
    "# Sample leaked AI agent + Web3 config (fake dummy secrets for local test)",
    "OPENAI_API_KEY=sk-proj-fakeDemoKey1234567890abcdefXYZ987654321",
    "GITHUB_TOKEN=ghp_DemoTokenValue1234567890abcdefghij",
    "DEPLOYER_PRIVATE_KEY=0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
    "DATABASE_URL=postgres://admin:S3cur3Passw0rd!@db.example.internal:5432/prod",
    "TELEGRAM_BOT_TOKEN=123456789:AAFakeBotToken1234567890abcdefghijklmnop",
    "PUBLIC_APP_NAME=ForgeSuite Studio",
    "CUSTOM_EXCHANGE_SECRET=k9QmL8vX2pR7nW4zJ6cT1bY5hF3sD0aG",
  ].join("\n"),
  clean_config: [
    "NODE_ENV=production",
    "PORT=3000",
    "PUBLIC_BSC_USDT=0x55d398326f99059fF775485246999027B3197955",
    "PAYOUT_ADDRESS=0x0a1e9c96755a7962306cf2ca9a80113a61559852",
    "LOG_LEVEL=info",
  ].join("\n"),
});

/**
 * Compute Shannon entropy in bits per character.
 */
export function shannonEntropy(input) {
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

export function maskSecretValue(secret) {
  const s = String(secret || "");
  if (s.length <= 8) return "****";
  return `${s.slice(0, 4)}...${s.slice(-4)}`;
}

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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

/**
 * Scan raw text (.env, JSON, logs) for known secret patterns and high-entropy credentials.
 * Returns structured findings plus deterministically redacted output.
 */
export function scanSecrets(rawInput) {
  const text = String(rawInput || "");
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

  // Secondary heuristic: high-entropy generic secret assignments (e.g. *_SECRET=..., *_API_KEY=...)
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

  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const mediumCount = findings.filter((f) => f.severity === "MEDIUM").length;

  return {
    totalFindings: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    findings,
    redactedText: outChunks.join(""),
  };
}

export function buildSanitizationInvoice(scanRes) {
  const inv = createDefaultInvoice();
  inv.clientName = "Engineering / DevSecOps Client";
  inv.taxPercent = 0;
  inv.discountPercent = 0;
  inv.notes = `Secret Hygiene & Key Rotation Review (${scanRes?.totalFindings || 0} findings redacted offline via ForgeSuite EnvShield).`;
  inv.items = [
    {
      description: "EnvShield Secret Hygiene Scan, Key Rotation & Config Hardening",
      qty: 1,
      unitPrice: 95,
    },
  ];
  return inv;
}

function initEnvShieldApp() {
  if (typeof document === "undefined" || document.body?.dataset?.page !== "envshield") return;

  bindCheckoutTriggers();
  const bundleBtn = document.getElementById("envBundleBtn");
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

  const inputEl = document.getElementById("envInputText");
  const redactedEl = document.getElementById("envRedactedOut");
  const badgeEl = document.getElementById("envSummaryBadge");
  const statusEl = document.getElementById("envStatusMsg");
  const tableBodyEl = document.getElementById("envFindingsBody");
  let lastScan = null;

  function runScan() {
    const res = scanSecrets(inputEl?.value || "");
    lastScan = res;
    if (redactedEl) redactedEl.value = res.redactedText;
    if (statusEl) {
      statusEl.textContent =
        res.totalFindings === 0
          ? "No exposed secret signatures detected in local scan."
          : `Detected ${res.totalFindings} exposed secret(s): ${res.criticalCount} Critical, ${res.highCount} High, ${res.mediumCount} Medium — safely redacted below.`;
    }
    if (badgeEl) {
      if (res.totalFindings === 0) {
        badgeEl.textContent = "CLEAN · 0 LEAKS";
        badgeEl.className = "fs-badge fs-badge-success";
      } else {
        badgeEl.textContent = `${res.totalFindings} LEAK(S) DETECTED`;
        badgeEl.className = "fs-badge fs-badge-accent";
      }
    }
    if (tableBodyEl) {
      if (res.findings.length === 0) {
        tableBodyEl.innerHTML =
          '<tr><td colspan="4" class="inv-muted">Zero secret signatures matched. Note: always verify custom credentials manually before committing.</td></tr>';
      } else {
        tableBodyEl.innerHTML = res.findings
          .map(
            (f) => `<tr>
              <td>L${f.line}</td>
              <td><strong>${escapeHtml(f.label)}</strong><br><small class="inv-muted"><code>${escapeHtml(f.ruleId)}</code></small></td>
              <td><span class="fs-badge ${f.severity === "CRITICAL" ? "fs-badge-accent" : "fs-badge-muted"}">${escapeHtml(f.severity)}</span></td>
              <td><code>${escapeHtml(f.previewMasked)}</code> (${f.length} chars)</td>
            </tr>`
          )
          .join("");
      }
    }
  }

  document.querySelectorAll("[data-env-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const k = btn.getAttribute("data-env-sample");
      if (inputEl && ENVSHIELD_SAMPLES[k]) {
        inputEl.value = ENVSHIELD_SAMPLES[k];
        runScan();
      }
    });
  });

  if (inputEl) {
    inputEl.addEventListener("input", runScan);
    if (!inputEl.value.trim()) inputEl.value = ENVSHIELD_SAMPLES.agent_env;
  }

  const copyBtn = document.getElementById("envCopyRedactedBtn");
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      if (!redactedEl?.value) return;
      try {
        await navigator.clipboard.writeText(redactedEl.value);
        copyBtn.textContent = "Copied Safe Text ✓";
        setTimeout(() => {
          copyBtn.textContent = "Copy Redacted Output";
        }, 1800);
      } catch {}
    });
  }

  const dlBtn = document.getElementById("envDownloadRedactedBtn");
  if (dlBtn) {
    dlBtn.addEventListener("click", () => {
      const blob = new Blob([redactedEl?.value || ""], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "sanitized.env.txt";
      a.click();
      URL.revokeObjectURL(url);
    });
  }

  const invBtn = document.getElementById("envSendInvoiceBtn");
  if (invBtn) {
    invBtn.addEventListener("click", () => {
      const hash = encodeInvoicePayload(buildSanitizationInvoice(lastScan));
      window.location.href = `cryptobill.html#inv=${hash}`;
    });
  }

  runScan();
}

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", initEnvShieldApp);
}
