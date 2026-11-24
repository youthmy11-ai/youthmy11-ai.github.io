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
 * BrandGuard — 100% CORS-Clean Browser & Node 20+ Brand, 8-TLD Domain,
 * Developer Registry, Social Handle & iOS App Store Availability Engine.
 * Zero npm dependencies, zero custom request headers (pure CORS Simple GETs).
 */

export const BRANDGUARD_DEFAULT_TLDS = Object.freeze([
  "com",
  "io",
  "ai",
  "dev",
  "app",
  "org",
  "net",
  "xyz",
]);

export const CORS_RDAP_BY_TLD = Object.freeze({
  com: "https://rdap.verisign.com/com/v1/domain/",
  net: "https://rdap.verisign.com/net/v1/domain/",
  org: "https://rdap.publicinterestregistry.org/rdap/domain/",
  dev: "https://pubapi.registry.google/rdap/domain/",
  app: "https://pubapi.registry.google/rdap/domain/",
  io: "https://rdap.identitydigital.services/rdap/domain/",
  ai: "https://rdap.identitydigital.services/rdap/domain/",
  xyz: "https://rdap.centralnic.com/xyz/domain/",
});

export const RDAP_ORG_FALLBACK_BASE = "https://rdap.org/domain/";
export const GOOGLE_DOH_ENDPOINT = "https://dns.google/resolve";

export const FREE_VARIATION_LIMIT = 4;
export const MAX_BATCH_BRANDS = 25;

export const NEAR_BRAND_CHECKER_URL =
  "https://market.near.ai/agents/forge-brand-checker";
export const NEAR_BRAND_CHECKER_PROFILE_URL =
  "https://market.near.ai/a/forge-brand-checker";
export const NEAR_BRAND_CHECKER_A2A_URL =
  "https://forge-brand-checker.market.near.ai/a2a/v1";

export const BRANDGUARD_SAMPLES = Object.freeze({
  kestrelquant: "KestrelQuant",
  novaforgex: "NovaForgeX",
  forgesuite: "ForgeSuite",
  vercel: "Vercel",
});

export const DEFAULT_BATCH_BRANDS_SAMPLE = [
  "NovaForgeX",
  "ZephyrPilot",
  "KestrelQuant",
  "ForgeSuite",
  "OrbitLedger",
].join("\n");

const TLD_SCORE_WEIGHTS = Object.freeze({
  com: 22,
  ai: 10,
  io: 10,
  dev: 7,
  app: 6,
  org: 5,
  net: 4,
  xyz: 4,
});

const REGISTRY_SCORE_WEIGHTS = Object.freeze({
  github: 10,
  npm: 7,
  pypi: 5,
  bluesky: 4,
  iosAppStore: 6,
});

/* ============================================================================
 * 1. Normalization & Smart Name Variations Generator
 * ========================================================================== */

export function normalizeBrandName(rawName) {
  const cleanedDisplay = String(rawName ?? "")
    .trim()
    .replace(/^@+/, "")
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "");

  const strippedTld = cleanedDisplay
    .replace(/\.(?:com|io|ai|dev|app|org|net|xyz|co)$/i, "")
    .trim();

  const domainLabel = strippedTld
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63)
    .replace(/-+$/g, "");

  const compactKey = domainLabel.replace(/-/g, "");
  if (!domainLabel || compactKey.length < 2) {
    throw new Error(
      `Invalid brand name "${rawName}". Enter at least 2 alphanumeric characters.`
    );
  }

  const githubHandle = domainLabel.slice(0, 39).replace(/-+$/g, "");
  const bskySub = domainLabel.slice(0, 50).replace(/-+$/g, "");

  return {
    displayName: strippedTld || domainLabel,
    domainLabel,
    packageSlug: domainLabel,
    githubHandle,
    blueskyHandle: `${bskySub}.bsky.social`,
    compactKey,
  };
}

/**
 * Generates deterministic smart launch variations:
 * get<name>, use<name>, <name>hq, <name>labs, <name>ai, try<name>
 */
export function generateBrandVariations(rawName) {
  const spec = normalizeBrandName(rawName);
  const core = spec.compactKey.slice(0, 48);
  const templates = [
    `get${core}`,
    `use${core}`,
    `${core}hq`,
    `${core}labs`,
    `${core}ai`,
    `try${core}`,
  ];
  const unique = [];
  const seen = new Set([spec.compactKey, spec.domainLabel]);
  for (const candidate of templates) {
    const lower = candidate.toLowerCase();
    if (!seen.has(lower)) {
      seen.add(lower);
      unique.push(lower);
    }
  }
  return unique;
}

/**
 * Parses URL query parameters for 1-click BrandGuard deep-links:
 * ?brand=NovaForgeX&variations=1&autorun=1
 */
export function parseBrandCheckQueryParams(rawSearch = "") {
  const qs = String(rawSearch || "").replace(/^\?/, "");
  const params = new URLSearchParams(qs);
  const rawBrand = (
    params.get("brand") ||
    params.get("name") ||
    params.get("q") ||
    params.get("candidate") ||
    ""
  ).trim();
  const autorunParam = (params.get("autorun") || "").trim().toLowerCase();
  const autorunOverride =
    autorunParam === "0" || autorunParam === "false"
      ? false
      : autorunParam === "1" || autorunParam === "true"
        ? true
        : null;
  const modeParam = (params.get("mode") || "").trim().toLowerCase();
  const runVariations =
    modeParam === "variations" ||
    params.get("variations") === "1" ||
    params.get("variations") === "true";

  if (!rawBrand) {
    return {
      hasTarget: false,
      brand: "",
      normalizedSlug: "",
      autorun: false,
      runVariations: false,
    };
  }
  try {
    const spec = normalizeBrandName(rawBrand);
    return {
      hasTarget: true,
      brand: spec.displayName,
      normalizedSlug: spec.domainLabel,
      autorun: autorunOverride ?? true,
      runVariations,
    };
  } catch {
    return {
      hasTarget: false,
      brand: "",
      normalizedSlug: "",
      autorun: false,
      runVariations: false,
    };
  }
}

/* ============================================================================
 * 2. CORS-Safe Simple GET Fetcher (No Custom Headers -> Zero Preflight)
 * ========================================================================== */

async function corsSimpleGetJson(url, options = {}) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 7000;
  const signal =
    typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function"
      ? AbortSignal.timeout(timeoutMs)
      : undefined;

  const res = await fetchImpl(url, signal ? { method: "GET", signal } : { method: "GET" });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return {
    ok: Boolean(res.ok),
    status: Number(res.status) || 0,
    text,
    json,
  };
}

function mapDnsRcode(rcode) {
  if (rcode === 0) return "NOERROR";
  if (rcode === 2) return "SERVFAIL";
  if (rcode === 3) return "NXDOMAIN";
  return typeof rcode === "number" ? `RCODE_${rcode}` : null;
}

/* ============================================================================
 * 3. Live 8-TLD Domain Check (Google DoH NS + A + CORS RDAP with Clean Fallback)
 * ========================================================================== */

export async function checkDomainBrowserCors(domainLabel, rawTld, options = {}) {
  const tld = String(rawTld || "")
    .trim()
    .toLowerCase()
    .replace(/^\.+/, "");
  const domain = `${domainLabel}.${tld}`;

  const nsUrl = `${GOOGLE_DOH_ENDPOINT}?name=${encodeURIComponent(domain)}&type=NS`;
  const aUrl = `${GOOGLE_DOH_ENDPOINT}?name=${encodeURIComponent(domain)}&type=A`;
  const directRdapBase = CORS_RDAP_BY_TLD[tld] || null;
  const primaryRdapUrl = directRdapBase
    ? `${directRdapBase}${encodeURIComponent(domain)}`
    : `${RDAP_ORG_FALLBACK_BASE}${encodeURIComponent(domain)}`;

  const [nsOutcome, aOutcome, rdapOutcome] = await Promise.allSettled([
    corsSimpleGetJson(nsUrl, options),
    corsSimpleGetJson(aUrl, options),
    corsSimpleGetJson(primaryRdapUrl, options),
  ]);

  let rdapRes = rdapOutcome.status === "fulfilled" ? rdapOutcome.value : null;
  let rdapFallbackTriggered = rdapOutcome.status === "rejected";

  // If authoritative RDAP had a transient server error (not 200/404), try rdap.org once;
  // if rdap.org redirects to a non-CORS registry or returns 403, swallow cleanly and rely on DoH.
  if (
    directRdapBase &&
    (!rdapRes || (rdapRes.status !== 200 && rdapRes.status !== 404))
  ) {
    try {
      const fallbackRes = await corsSimpleGetJson(
        `${RDAP_ORG_FALLBACK_BASE}${encodeURIComponent(domain)}`,
        options
      );
      if (fallbackRes.status === 200 || fallbackRes.status === 404) {
        rdapRes = fallbackRes;
        rdapFallbackTriggered = false;
      } else {
        rdapFallbackTriggered = true;
      }
    } catch {
      rdapFallbackTriggered = true;
    }
  } else if (!directRdapBase && rdapRes && rdapRes.status !== 200 && rdapRes.status !== 404) {
    rdapFallbackTriggered = true;
  }

  const nsRes = nsOutcome.status === "fulfilled" ? nsOutcome.value : null;
  const aRes = aOutcome.status === "fulfilled" ? aOutcome.value : null;
  const checkedAt = new Date().toISOString();

  const nsRcode =
    nsRes?.json && typeof nsRes.json.Status === "number" ? nsRes.json.Status : null;
  const aRcode =
    aRes?.json && typeof aRes.json.Status === "number" ? aRes.json.Status : null;

  const hasNsRecords = Boolean(
    nsRcode === 0 && Array.isArray(nsRes?.json?.Answer) && nsRes.json.Answer.length > 0
  );
  const hasARecords = Boolean(
    aRcode === 0 && Array.isArray(aRes?.json?.Answer) && aRes.json.Answer.length > 0
  );
  const hasActiveDns = hasNsRecords || hasARecords;
  const isNxDomain = nsRcode === 3 || aRcode === 3;

  const rdapStatus =
    rdapRes && (rdapRes.status === 200 || rdapRes.status === 404)
      ? rdapRes.status
      : null;

  let expirationDate = null;
  if (rdapStatus === 200 && Array.isArray(rdapRes?.json?.events)) {
    const expEvt = rdapRes.json.events.find((e) => e?.eventAction === "expiration");
    if (expEvt?.eventDate) expirationDate = String(expEvt.eventDate);
  }

  let available = null;
  let status = "unknown";
  let statusLabel = "Unconfirmed (Check Registrar)";
  let source = "unverified";

  if (rdapStatus === 200 || hasActiveDns) {
    available = false;
    status = "registered";
    statusLabel = "Registered (Active DNS/RDAP)";
    source =
      rdapStatus === 200 && (nsRes?.ok || aRes?.ok)
        ? "rdap+doh"
        : rdapStatus === 200
          ? "rdap"
          : "doh";
  } else if (rdapStatus === 404 && isNxDomain) {
    available = true;
    status = "available";
    statusLabel = "Likely Available (NXDOMAIN + RDAP 404)";
    source = "rdap+doh";
  } else if (rdapStatus === 404) {
    available = true;
    status = "available";
    statusLabel = "Likely Available (RDAP 404)";
    source = nsRes?.ok || aRes?.ok ? "rdap+doh" : "rdap";
  } else if (isNxDomain) {
    available = true;
    status = "likely_available";
    statusLabel = "Likely Available (NXDOMAIN)";
    source = "doh";
  }

  return {
    domain,
    tld,
    available,
    status,
    statusLabel,
    rdapStatus,
    rdapFallbackToDoh: Boolean(rdapFallbackTriggered && rdapStatus === null),
    dnsNsStatus: mapDnsRcode(nsRcode),
    dnsAStatus: mapDnsRcode(aRcode),
    hasNsRecords,
    hasARecords,
    hasActiveDns,
    expirationDate,
    source,
    checkedAt,
  };
}

/* ============================================================================
 * 4. CORS-Verified Developer, Social & App Store Registries
 * ========================================================================== */

export async function checkNpmRegistry(packageSlug, options = {}) {
  const apiUrl = `https://registry.npmjs.org/${encodeURIComponent(packageSlug)}`;
  const profileUrl = `https://www.npmjs.com/package/${packageSlug}`;
  try {
    const res = await corsSimpleGetJson(apiUrl, options);
    const checkedAt = new Date().toISOString();
    if (res.status === 404) {
      return {
        platform: "npm",
        label: "npm Registry",
        target: packageSlug,
        available: true,
        status: "available",
        detail: "Available (404 Not Found)",
        latestVersion: null,
        url: profileUrl,
        checkedAt,
      };
    }
    if (res.status === 200) {
      const latestVersion = res.json?.["dist-tags"]?.latest || null;
      return {
        platform: "npm",
        label: "npm Registry",
        target: packageSlug,
        available: false,
        status: "taken",
        detail: latestVersion ? `Registered (v${latestVersion})` : "Registered",
        latestVersion,
        url: profileUrl,
        checkedAt,
      };
    }
    return {
      platform: "npm",
      label: "npm Registry",
      target: packageSlug,
      available: null,
      status: `http_${res.status}`,
      detail: `HTTP ${res.status}`,
      latestVersion: null,
      url: profileUrl,
      checkedAt,
    };
  } catch (err) {
    return {
      platform: "npm",
      label: "npm Registry",
      target: packageSlug,
      available: null,
      status: "error",
      detail: err instanceof Error ? err.message : "Network error",
      latestVersion: null,
      url: profileUrl,
      checkedAt: new Date().toISOString(),
    };
  }
}

export async function checkPypiRegistry(packageSlug, options = {}) {
  const apiUrl = `https://pypi.org/pypi/${encodeURIComponent(packageSlug)}/json`;
  const profileUrl = `https://pypi.org/project/${packageSlug}/`;
  try {
    const res = await corsSimpleGetJson(apiUrl, options);
    const checkedAt = new Date().toISOString();
    if (res.status === 404) {
      return {
        platform: "pypi",
        label: "PyPI Registry",
        target: packageSlug,
        available: true,
        status: "available",
        detail: "Available (404 Not Found)",
        latestVersion: null,
        url: profileUrl,
        checkedAt,
      };
    }
    if (res.status === 200) {
      const latestVersion = res.json?.info?.version || null;
      return {
        platform: "pypi",
        label: "PyPI Registry",
        target: packageSlug,
        available: false,
        status: "taken",
        detail: latestVersion ? `Registered (v${latestVersion})` : "Registered",
        latestVersion,
        url: profileUrl,
        checkedAt,
      };
    }
    return {
      platform: "pypi",
      label: "PyPI Registry",
      target: packageSlug,
      available: null,
      status: `http_${res.status}`,
      detail: `HTTP ${res.status}`,
      latestVersion: null,
      url: profileUrl,
      checkedAt,
    };
  } catch (err) {
    return {
      platform: "pypi",
      label: "PyPI Registry",
      target: packageSlug,
      available: null,
      status: "error",
      detail: err instanceof Error ? err.message : "Network error",
      latestVersion: null,
      url: profileUrl,
      checkedAt: new Date().toISOString(),
    };
  }
}

export async function checkGithubHandle(githubHandle, options = {}) {
  const apiUrl = `https://api.github.com/users/${encodeURIComponent(githubHandle)}`;
  const profileUrl = `https://github.com/${githubHandle}`;
  try {
    const res = await corsSimpleGetJson(apiUrl, options);
    const checkedAt = new Date().toISOString();
    if (res.status === 404) {
      return {
        platform: "github",
        label: "GitHub User/Org",
        target: `@${githubHandle}`,
        available: true,
        status: "available",
        detail: "Available (404 Not Found)",
        accountType: null,
        url: profileUrl,
        checkedAt,
      };
    }
    if (res.status === 200) {
      const accountType = res.json?.type || "Account";
      return {
        platform: "github",
        label: "GitHub User/Org",
        target: `@${githubHandle}`,
        available: false,
        status: "taken",
        detail: `Registered (${accountType})`,
        accountType,
        url: profileUrl,
        checkedAt,
      };
    }
    if (res.status === 403 || res.status === 429) {
      return {
        platform: "github",
        label: "GitHub User/Org",
        target: `@${githubHandle}`,
        available: null,
        status: "rate_limited",
        detail: "GitHub API Rate Limit (60/hr unauthenticated)",
        accountType: null,
        url: profileUrl,
        checkedAt,
      };
    }
    return {
      platform: "github",
      label: "GitHub User/Org",
      target: `@${githubHandle}`,
      available: null,
      status: `http_${res.status}`,
      detail: `HTTP ${res.status}`,
      accountType: null,
      url: profileUrl,
      checkedAt,
    };
  } catch (err) {
    return {
      platform: "github",
      label: "GitHub User/Org",
      target: `@${githubHandle}`,
      available: null,
      status: "error",
      detail: err instanceof Error ? err.message : "Network error",
      accountType: null,
      url: profileUrl,
      checkedAt: new Date().toISOString(),
    };
  }
}

export async function checkBlueskyHandle(blueskyHandle, options = {}) {
  const apiUrl = `https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(blueskyHandle)}`;
  const profileUrl = `https://bsky.app/profile/${blueskyHandle}`;
  try {
    const res = await corsSimpleGetJson(apiUrl, options);
    const checkedAt = new Date().toISOString();
    if (res.status === 200 && res.json?.did) {
      return {
        platform: "bluesky",
        label: "Bluesky Handle",
        target: `@${blueskyHandle}`,
        available: false,
        status: "taken",
        detail: `Registered (${String(res.json.did).slice(0, 22)}...)`,
        did: res.json.did,
        url: profileUrl,
        checkedAt,
      };
    }
    if (
      res.status === 404 ||
      (res.status === 400 &&
        /unable to resolve handle/i.test(String(res.json?.message || res.text)))
    ) {
      return {
        platform: "bluesky",
        label: "Bluesky Handle",
        target: `@${blueskyHandle}`,
        available: true,
        status: "available",
        detail: "Available (Unclaimed Handle)",
        did: null,
        url: profileUrl,
        checkedAt,
      };
    }
    return {
      platform: "bluesky",
      label: "Bluesky Handle",
      target: `@${blueskyHandle}`,
      available: null,
      status: `http_${res.status}`,
      detail: `HTTP ${res.status}`,
      did: null,
      url: profileUrl,
      checkedAt,
    };
  } catch (err) {
    return {
      platform: "bluesky",
      label: "Bluesky Handle",
      target: `@${blueskyHandle}`,
      available: null,
      status: "error",
      detail: err instanceof Error ? err.message : "Network error",
      did: null,
      url: profileUrl,
      checkedAt: new Date().toISOString(),
    };
  }
}

export async function checkIosAppStore(candidateSpec, options = {}) {
  const spec =
    typeof candidateSpec === "string"
      ? normalizeBrandName(candidateSpec)
      : candidateSpec;
  const searchUrl = `https://itunes.apple.com/search?term=${encodeURIComponent(spec.displayName)}&country=US&entity=software&limit=5`;
  const webSearchUrl = `https://apps.apple.com/us/iphone/search?term=${encodeURIComponent(spec.displayName)}`;

  try {
    const res = await corsSimpleGetJson(searchUrl, options);
    const checkedAt = new Date().toISOString();
    if (!res.ok || !res.json || !Array.isArray(res.json.results)) {
      return {
        platform: "iosAppStore",
        label: "Apple iOS App Store",
        target: spec.displayName,
        available: null,
        status: `http_${res.status}`,
        detail: `HTTP ${res.status}`,
        exactMatchFound: false,
        totalSearchHits: 0,
        topMatches: [],
        url: webSearchUrl,
        checkedAt,
      };
    }

    const results = res.json.results;
    const targetLower = spec.displayName.toLowerCase();
    let collidingApp = null;

    for (const item of results) {
      const trackName = String(item?.trackName || "").trim();
      if (!trackName) continue;
      const trackLower = trackName.toLowerCase();
      const trackCompact = trackLower.replace(/[^a-z0-9]+/g, "");
      const leadingBrand = trackLower
        .split(/[:\-–—|]/)[0]
        .trim()
        .replace(/[^a-z0-9]+/g, "");
      if (
        trackLower === targetLower ||
        trackCompact === spec.compactKey ||
        leadingBrand === spec.compactKey
      ) {
        collidingApp = item;
        break;
      }
    }

    const exactMatchFound = Boolean(collidingApp);
    return {
      platform: "iosAppStore",
      label: "Apple iOS App Store",
      target: spec.displayName,
      available: !exactMatchFound,
      status: exactMatchFound ? "collision_detected" : "clear",
      detail: exactMatchFound
        ? `Collision: "${collidingApp.trackName}" (${collidingApp.sellerName || "Published"})`
        : `Clear (0 exact title collisions across ${results.length} US hits)`,
      exactMatchFound,
      totalSearchHits: Number(res.json.resultCount ?? results.length) || 0,
      topMatches: results.slice(0, 3).map((r) => ({
        trackName: r.trackName || null,
        sellerName: r.sellerName || null,
        bundleId: r.bundleId || null,
        trackViewUrl: r.trackViewUrl || null,
      })),
      url: collidingApp?.trackViewUrl || webSearchUrl,
      checkedAt,
    };
  } catch (err) {
    return {
      platform: "iosAppStore",
      label: "Apple iOS App Store",
      target: spec.displayName,
      available: null,
      status: "error",
      detail: err instanceof Error ? err.message : "Network error",
      exactMatchFound: false,
      totalSearchHits: 0,
      topMatches: [],
      url: webSearchUrl,
      checkedAt: new Date().toISOString(),
    };
  }
}

/* ============================================================================
 * 5. Deterministic Brand Launch Readiness Scorer (0-100) & Markdown Formatter
 * ========================================================================== */

export function scoreBrandReadiness({ domains = [], registries = {} } = {}) {
  let earned = 0;
  let possible = 0;

  const addWeight = (avail, weight) => {
    if (typeof avail !== "boolean") return;
    possible += weight;
    if (avail) earned += weight;
  };

  const domainMap = new Map(domains.map((d) => [d.tld, d.available]));
  for (const d of domains) {
    const weight = TLD_SCORE_WEIGHTS[d.tld] ?? 4;
    addWeight(d.available, weight);
  }

  addWeight(registries.github?.available, REGISTRY_SCORE_WEIGHTS.github);
  addWeight(registries.npm?.available, REGISTRY_SCORE_WEIGHTS.npm);
  addWeight(registries.pypi?.available, REGISTRY_SCORE_WEIGHTS.pypi);
  addWeight(registries.bluesky?.available, REGISTRY_SCORE_WEIGHTS.bluesky);
  addWeight(registries.iosAppStore?.available, REGISTRY_SCORE_WEIGHTS.iosAppStore);

  const readinessScore =
    possible > 0
      ? Math.max(0, Math.min(100, Math.round((earned / possible) * 100)))
      : 0;

  const verdict =
    readinessScore >= 80
      ? "LAUNCH_READY"
      : readinessScore >= 55
        ? "VIABLE_WITH_TRADEOFFS"
        : "HIGH_COLLISION";

  const allChecks = [
    ...domains.map((d) => d.available),
    registries.npm?.available ?? null,
    registries.pypi?.available ?? null,
    registries.github?.available ?? null,
    registries.bluesky?.available ?? null,
    registries.iosAppStore?.available ?? null,
  ];

  const comAvailable = domainMap.get("com") ?? null;
  const allDevRegistriesClear =
    registries.npm?.available === true &&
    registries.pypi?.available === true &&
    registries.github?.available === true;

  const recommendations = [];
  if (comAvailable === false) {
    const openAltTlds = domains
      .filter((d) => d.available === true && ["ai", "io", "dev", "app"].includes(d.tld))
      .map((d) => `.${d.tld}`);
    if (openAltTlds.length > 0) {
      recommendations.push(
        `Primary .com is registered — consider ${openAltTlds.join(", ")} or test a 1-click prefix/suffix variation (get/use/hq/labs).`
      );
    } else {
      recommendations.push(
        "Primary .com and major tech TLDs are registered — run the Smart Name Variations scanner to find an uncontested namespace."
      );
    }
  } else if (comAvailable === true) {
    recommendations.push(
      "Primary .com shows NXDOMAIN / RDAP 404 — register the .com and matching GitHub/npm handles simultaneously before public announcement."
    );
  }

  if (!allDevRegistriesClear) {
    const takenRegs = ["npm", "pypi", "github"].filter(
      (k) => registries[k]?.available === false
    );
    if (takenRegs.length > 0) {
      recommendations.push(
        `Developer namespace collision on ${takenRegs.join(", ")} — use a scoped package (@${domains[0]?.domain?.split(".")[0] || "org"}/sdk) or select an alternate variation.`
      );
    }
  }

  if (registries.iosAppStore?.available === false) {
    recommendations.push(
      "Exact or leading title match detected on the US Apple iOS App Store — run USPTO Class 009/042 trademark screening before shipping mobile apps."
    );
  }

  recommendations.push(
    "Before incorporating or filing domains, run the $0.35 USDC Brand Name Availability Checker A2A Agent for official USPTO Serial/Registration trademark screening + Google Play + X/Instagram/TikTok/YouTube/Reddit/Telegram."
  );

  return {
    readinessScore,
    verdict,
    availableCount: allChecks.filter((v) => v === true).length,
    takenCount: allChecks.filter((v) => v === false).length,
    unknownCount: allChecks.filter((v) => v === null).length,
    totalChecks: allChecks.length,
    comAvailable,
    allDevRegistriesClear,
    recommendations,
  };
}

export function formatBrandMarkdownReport(report) {
  if (!report || !report.ok) return "";
  const domRows = (report.domains || [])
    .map(
      (d) =>
        `| \`${d.domain}\` | ${d.available === true ? "AVAILABLE" : d.available === false ? "REGISTERED" : "UNKNOWN"} | ${d.statusLabel} | \`${d.source}\` |`
    )
    .join("\n");

  const regList = [
    report.registries?.npm,
    report.registries?.pypi,
    report.registries?.github,
    report.registries?.bluesky,
    report.registries?.iosAppStore,
  ].filter(Boolean);

  const regRows = regList
    .map(
      (r) =>
        `| ${r.label} | \`${r.target}\` | ${r.available === true ? "CLEAR" : r.available === false ? "TAKEN" : "UNCONFIRMED"} | ${r.detail} |`
    )
    .join("\n");

  return [
    `# BrandGuard Launch Readiness Dossier — ${report.candidate}`,
    `- **Normalized Slug:** \`${report.normalizedSlug}\``,
    `- **Brand Launch Readiness Score:** **${report.summary.readinessScore}/100** (\`${report.summary.verdict}\`)`,
    `- **Signals Clear:** ${report.summary.availableCount}/${report.summary.totalChecks} (${report.summary.takenCount} taken, ${report.summary.unknownCount} unconfirmed)`,
    `- **Checked At (UTC):** \`${report.checkedAt}\``,
    "",
    "## 1. Domain Availability (8 TLDs via Google DoH + CORS RDAP)",
    "| Domain | Status | Evidence | Source |",
    "| :--- | :---: | :--- | :---: |",
    domRows,
    "",
    "## 2. Developer, Social & App Store Registries",
    "| Platform | Target | Status | Evidence |",
    "| :--- | :--- | :---: | :--- |",
    regRows,
    "",
    "## 3. Smart Name Variations",
    `- Suggested 1-Click Alternatives: ${(report.variations || []).map((v) => `\`${v}\``).join(", ")}`,
    `- Deep USPTO Trademark + 10-Platform A2A Scan ($0.35 USDC): ${NEAR_BRAND_CHECKER_URL}`,
  ].join("\n");
}

/* ============================================================================
 * 6. Single Scan, Variations Scan, Pro 25-Brand Batch Matrix & Exports
 * ========================================================================== */

export async function scanSingleBrand(rawName, options = {}) {
  const spec = normalizeBrandName(rawName);
  const tlds =
    Array.isArray(options.tlds) && options.tlds.length > 0
      ? options.tlds.map((t) => String(t).trim().toLowerCase().replace(/^\.+/, ""))
      : [...BRANDGUARD_DEFAULT_TLDS];

  const [domains, npm, pypi, github, bluesky, iosAppStore] = await Promise.all([
    Promise.all(tlds.map((tld) => checkDomainBrowserCors(spec.domainLabel, tld, options))),
    checkNpmRegistry(spec.packageSlug, options),
    checkPypiRegistry(spec.packageSlug, options),
    checkGithubHandle(spec.githubHandle, options),
    checkBlueskyHandle(spec.blueskyHandle, options),
    checkIosAppStore(spec, options),
  ]);

  const registries = { npm, pypi, github, bluesky, iosAppStore };
  const summary = scoreBrandReadiness({ domains, registries });
  const variations = generateBrandVariations(spec.displayName);
  const checkedAt = new Date().toISOString();

  const report = {
    ok: true,
    candidate: spec.displayName,
    normalizedSlug: spec.domainLabel,
    checkedAt,
    tldsChecked: tlds,
    summary,
    domains,
    registries,
    variations,
    markdownSummary: "",
  };
  report.markdownSummary = formatBrandMarkdownReport(report);
  return report;
}

/**
 * Scans Smart Name Variations in parallel.
 * Free Tier scans 4 variations (`get<name>`, `use<name>`, `<name>hq`, `<name>labs`);
 * Pro Tier (`options.isPro === true`) scans all 6 variations.
 */
export async function scanBrandVariations(rawName, options = {}) {
  const allVariations = generateBrandVariations(rawName);
  const limit = options.isPro ? allVariations.length : FREE_VARIATION_LIMIT;
  const selected = allVariations.slice(0, limit);

  const results = await Promise.all(
    selected.map((variant) => scanSingleBrand(variant, options))
  );
  const ranked = [...results].sort(
    (a, b) => b.summary.readinessScore - a.summary.readinessScore
  );

  return {
    ok: true,
    baseBrand: normalizeBrandName(rawName).displayName,
    checkedAt: new Date().toISOString(),
    allVariations,
    scannedCount: results.length,
    isProUnlocked: Boolean(options.isPro),
    bestVariation: ranked[0]?.candidate || null,
    results,
  };
}

export function parseBatchBrandList(rawInput) {
  if (Array.isArray(rawInput)) {
    const seen = new Set();
    const out = [];
    for (const item of rawInput) {
      const trimmed = String(item ?? "").trim();
      if (!trimmed) continue;
      const key = trimmed.toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        out.push(trimmed);
      }
    }
    return out;
  }

  const parts = String(rawInput ?? "")
    .split(/[\r\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const seen = new Set();
  const out = [];
  for (const p of parts) {
    const key = p.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      out.push(p);
    }
  }
  return out;
}

export async function runBatchBrandScan(rawInput, options = {}) {
  const candidates = parseBatchBrandList(rawInput);
  if (candidates.length === 0) {
    throw new Error("Provide at least 1 brand candidate name to scan.");
  }
  if (candidates.length > MAX_BATCH_BRANDS) {
    throw new Error(
      `Batch Agency Matrix supports up to ${MAX_BATCH_BRANDS} brand names per run (received ${candidates.length}).`
    );
  }

  const concurrency = Math.max(1, Math.min(5, Number(options.concurrency ?? 4)));
  const reports = new Array(candidates.length);
  let cursor = 0;

  async function worker() {
    while (cursor < candidates.length) {
      const idx = cursor;
      cursor += 1;
      const raw = candidates[idx];
      try {
        reports[idx] = await scanSingleBrand(raw, options);
      } catch (err) {
        reports[idx] = {
          ok: false,
          candidate: raw,
          error: err instanceof Error ? err.message : String(err),
          checkedAt: new Date().toISOString(),
        };
      }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, candidates.length) }, () => worker())
  );
  return reports;
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

export function exportBrandMatrixCsv(reports = []) {
  const headers = [
    "candidate",
    "slug",
    "readiness_score",
    "verdict",
    "com",
    "io",
    "ai",
    "dev",
    "app",
    "org",
    "net",
    "xyz",
    "npm",
    "pypi",
    "github",
    "bluesky",
    "ios_app_store",
    "checked_at_utc",
  ];

  const statusToken = (avail) =>
    avail === true ? "AVAILABLE" : avail === false ? "TAKEN" : "UNKNOWN";

  const rows = reports.map((r) => {
    if (!r || !r.ok) {
      return [
        r?.candidate || "",
        "",
        0,
        "ERROR",
        r?.error || "Scan failed",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        r?.checkedAt || "",
      ];
    }
    const domByTld = new Map((r.domains || []).map((d) => [d.tld, d.available]));
    return [
      r.candidate,
      r.normalizedSlug,
      r.summary.readinessScore,
      r.summary.verdict,
      statusToken(domByTld.get("com")),
      statusToken(domByTld.get("io")),
      statusToken(domByTld.get("ai")),
      statusToken(domByTld.get("dev")),
      statusToken(domByTld.get("app")),
      statusToken(domByTld.get("org")),
      statusToken(domByTld.get("net")),
      statusToken(domByTld.get("xyz")),
      statusToken(r.registries?.npm?.available),
      statusToken(r.registries?.pypi?.available),
      statusToken(r.registries?.github?.available),
      statusToken(r.registries?.bluesky?.available),
      statusToken(r.registries?.iosAppStore?.available),
      r.checkedAt || "",
    ];
  });

  return [
    headers.join(","),
    ...rows.map((row) => row.map(csvSafeCell).join(",")),
  ].join("\n");
}

/* ============================================================================
 * 7. CryptoBill Invoice & ScopeGuard SOW 1-Click Handoff Builders
 * ========================================================================== */

export function buildBrandAuditInvoicePayload(scanOrBatch) {
  const inv = createDefaultInvoice();
  inv.clientName = "Venture Studio / Product Launch Team";
  inv.taxPercent = 0;
  inv.discountPercent = 0;

  if (Array.isArray(scanOrBatch) && scanOrBatch.length > 0) {
    const okReports = scanOrBatch.filter((r) => r && r.ok);
    const best = [...okReports].sort(
      (a, b) => b.summary.readinessScore - a.summary.readinessScore
    )[0];
    inv.notes = `Agency Batch Brand, 8-TLD Domain & Developer Handle Clearance Matrix (${okReports.length}/${scanOrBatch.length} candidates audited via ForgeSuite BrandGuard${best ? `; top pick: ${best.candidate} ${best.summary.readinessScore}/100` : ""}).`;
    inv.items = [
      {
        description: `Agency Batch Brand & 8-TLD Domain Clearance Matrix (${scanOrBatch.length} Candidates)`,
        qty: 1,
        unitPrice: Math.max(195, scanOrBatch.length * 25),
      },
    ];
    return inv;
  }

  const candidate = scanOrBatch?.candidate || "New Product Brand";
  const scoreSuffix =
    scanOrBatch?.summary && typeof scanOrBatch.summary.readinessScore === "number"
      ? ` — Readiness ${scanOrBatch.summary.readinessScore}/100 (${scanOrBatch.summary.verdict})`
      : "";

  inv.notes = `Brand naming, 8-TLD domain (.com/.io/.ai/.dev/.app/.org/.net/.xyz), developer registry (npm/PyPI/GitHub), Bluesky & iOS App Store clearance dossier for "${candidate}"${scoreSuffix} via ForgeSuite BrandGuard.`;
  inv.items = [
    {
      description: `Brand Naming, Domain & Handle Clearance Report (${candidate})`,
      qty: 1,
      unitPrice: 145,
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
      : Buffer.from(json, "utf8").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function buildBrandSowState(scanOrBatch) {
  const isBatch = Array.isArray(scanOrBatch) && scanOrBatch.length > 0;
  const primaryName = isBatch
    ? `${scanOrBatch.length}-Candidate Agency Brand Cohort`
    : scanOrBatch?.candidate || "Product Launch Brand";
  const totalBudget = isBatch ? Math.max(650, scanOrBatch.length * 45) : 450;

  return {
    projectTitle: `Brand Naming, 8-TLD Domain & Handle Clearance — ${primaryName}`,
    providerName: "ForgeSuite Brand & Launch Ops",
    clientName: "Founder / Venture Studio",
    totalBudget,
    revisionsIncluded: 2,
    noticeDays: 3,
    settlementRail: "sol-usdc",
    deliverables: [
      `- 8-TLD Domain (.com, .io, .ai, .dev, .app, .org, .net, .xyz) DNS + RDAP availability matrix for ${primaryName}`,
      "- Developer & Social handle lockup checklist (GitHub, npm, PyPI, Bluesky, Apple iOS App Store)",
      "- USPTO Class 009/042 trademark conflict screening & CSV/JSON launch dossier handoff",
    ].join("\n"),
    milestones: [
      { title: "M1: Shortlist Screening & Collision Matrix", percent: 50, due: "On kickoff" },
      { title: "M2: Final Brand Dossier & Registrar Lockup Handoff", percent: 50, due: "Day 3" },
    ],
  };
}

/* ============================================================================
 * 8. Browser UI Controller for brandcheck.html
 * ========================================================================== */

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function badgeClassForVerdict(verdict) {
  if (verdict === "LAUNCH_READY") return "fs-badge-success";
  if (verdict === "VIABLE_WITH_TRADEOFFS") return "fs-badge-accent";
  if (verdict === "HIGH_COLLISION" || verdict === "ERROR") return "fs-badge-warn";
  return "fs-badge-muted";
}

function badgeForAvailability(available, trueText = "AVAILABLE", falseText = "REGISTERED") {
  if (available === true) {
    return `<span class="fs-badge fs-badge-success">${escapeHtml(trueText)}</span>`;
  }
  if (available === false) {
    return `<span class="fs-badge fs-badge-warn">${escapeHtml(falseText)}</span>`;
  }
  return `<span class="fs-badge fs-badge-muted">UNCONFIRMED</span>`;
}

function isBrandGuardProUnlocked() {
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

function initBrandGuardApp() {
  if (typeof document === "undefined" || document.body?.dataset?.page !== "brandcheck") {
    return;
  }

  const nameInputEl = document.getElementById("bgNameInput");
  const scanBtn = document.getElementById("bgScanBtn");
  const scanVarsBtn = document.getElementById("bgScanVariationsBtn");
  const statusEl = document.getElementById("bgStatusMsg");
  const variationsChipsEl = document.getElementById("bgVariationsChips");
  const variationsTableWrapEl = document.getElementById("bgVariationsTableWrap");
  const variationsBodyEl = document.getElementById("bgVariationsBody");

  const scoreBadgeEl = document.getElementById("bgScoreBadge");
  const scoreSummaryEl = document.getElementById("bgScoreSummary");
  const metaGridEl = document.getElementById("bgMetaGrid");
  const domainsBodyEl = document.getElementById("bgDomainsBody");
  const registriesBodyEl = document.getElementById("bgRegistriesBody");
  const recsListEl = document.getElementById("bgRecsList");
  const copyMdBtn = document.getElementById("bgCopyMdBtn");

  const proBadgeEl = document.getElementById("bgProStatusBadge");
  const proLockBannerEl = document.getElementById("bgProLockBanner");
  const batchInputEl = document.getElementById("bgBatchInput");
  const batchRunBtn = document.getElementById("bgBatchRunBtn");
  const exportJsonBtn = document.getElementById("bgExportJsonBtn");
  const exportCsvBtn = document.getElementById("bgExportCsvBtn");
  const batchStatusEl = document.getElementById("bgBatchStatusMsg");
  const batchBodyEl = document.getElementById("bgBatchBody");

  const invoiceBtn = document.getElementById("bgSendInvoiceBtn");
  const sowBtn = document.getElementById("bgSendSowBtn");

  let lastSingleReport = null;
  let lastBatchReports = [];

  function syncProUi() {
    const unlocked = isBrandGuardProUnlocked();
    if (proBadgeEl) {
      proBadgeEl.textContent = unlocked
        ? "PRO ACTIVE · 25-BRAND MATRIX UNLOCKED ✓"
        : "PRO FEATURE · $15 PRO / $35 BUNDLE";
      proBadgeEl.className = `fs-badge ${unlocked ? "fs-badge-success" : "fs-badge-warn"}`;
    }
    if (proLockBannerEl) {
      proLockBannerEl.hidden = unlocked;
    }
    if (batchRunBtn) {
      batchRunBtn.textContent = unlocked
        ? "Run 25-Brand Agency Matrix"
        : "Unlock 25-Brand Matrix — Bundle ($35)";
    }
    if (scanVarsBtn) {
      scanVarsBtn.textContent = unlocked
        ? "Scan All 6 Smart Variations"
        : "Check 4 Free Variations";
    }
  }

  bindCheckoutTriggers({ onUnlocked: syncProUi });
  window.addEventListener("forgesuite:license-updated", syncProUi);

  const navBundleBtn = document.getElementById("bgBundleBtn");
  if (navBundleBtn) {
    navBundleBtn.addEventListener("click", () =>
      openCheckoutModal("BUNDLE", { onUnlocked: syncProUi })
    );
  }
  const activateKeyBtn = document.getElementById("bgActivateKeyBtn");
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

  function renderVariationChips(baseName) {
    if (!variationsChipsEl) return;
    let variations = [];
    try {
      variations = generateBrandVariations(baseName);
    } catch {
      variationsChipsEl.innerHTML = "";
      return;
    }
    variationsChipsEl.innerHTML = variations
      .map(
        (v, idx) =>
          `<button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-bg-variant="${escapeHtml(v)}" title="1-click live scan for ${escapeHtml(v)}">${escapeHtml(v)}${idx >= FREE_VARIATION_LIMIT && !isBrandGuardProUnlocked() ? " · 1-Click" : ""}</button>`
      )
      .join("");

    variationsChipsEl.querySelectorAll("[data-bg-variant]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const v = btn.getAttribute("data-bg-variant");
        if (!v) return;
        if (nameInputEl) nameInputEl.value = v;
        executeSingleScan();
      });
    });
  }

  function renderReport(report) {
    lastSingleReport = report;
    if (!report || !report.ok) return;

    if (scoreBadgeEl) {
      scoreBadgeEl.textContent = `${report.summary.readinessScore}/100 · ${report.summary.verdict}`;
      scoreBadgeEl.className = `fs-badge ${badgeClassForVerdict(report.summary.verdict)}`;
    }

    if (scoreSummaryEl) {
      scoreSummaryEl.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;">
          <div>
            <strong>${escapeHtml(report.candidate)}</strong>
            <span class="inv-muted">· slug:</span> <code>${escapeHtml(report.normalizedSlug)}</code>
          </div>
          <span class="inv-muted" style="font-size:0.82rem;">Checked UTC: <code>${escapeHtml(report.checkedAt)}</code></span>
        </div>
      `;
    }

    if (metaGridEl) {
      const s = report.summary;
      metaGridEl.innerHTML = `
        <div class="fs-mono-chip"><strong>Readiness Score:</strong> ${escapeHtml(s.readinessScore)}/100 (${escapeHtml(s.verdict)})</div>
        <div class="fs-mono-chip"><strong>Primary .com:</strong> ${s.comAvailable === true ? "Likely Available ✓" : s.comAvailable === false ? "Registered ✗" : "Unconfirmed"}</div>
        <div class="fs-mono-chip"><strong>Signals Clear:</strong> ${escapeHtml(s.availableCount)}/${escapeHtml(s.totalChecks)} clear (${escapeHtml(s.takenCount)} taken)</div>
        <div class="fs-mono-chip"><strong>Dev Namespace:</strong> ${s.allDevRegistriesClear ? "npm + PyPI + GitHub All Clear ✓" : "Partial / Taken Collision"}</div>
      `;
    }

    if (domainsBodyEl) {
      domainsBodyEl.innerHTML = (report.domains || [])
        .map(
          (d) => `<tr>
            <td><strong><code>${escapeHtml(d.domain)}</code></strong></td>
            <td>${badgeForAvailability(d.available, d.status === "likely_available" ? "LIKELY AVAILABLE" : "AVAILABLE", "REGISTERED")}</td>
            <td>${escapeHtml(d.statusLabel)}${d.expirationDate ? ` <small class="inv-muted">(exp ${escapeHtml(d.expirationDate.slice(0, 10))})</small>` : ""}</td>
            <td><code>${escapeHtml(d.source)}</code> <small class="inv-muted">(NS:${escapeHtml(d.dnsNsStatus || "-")} / A:${escapeHtml(d.dnsAStatus || "-")})</small></td>
          </tr>`
        )
        .join("");
    }

    if (registriesBodyEl) {
      const regs = [
        report.registries?.npm,
        report.registries?.pypi,
        report.registries?.github,
        report.registries?.bluesky,
        report.registries?.iosAppStore,
      ].filter(Boolean);

      registriesBodyEl.innerHTML = regs
        .map(
          (r) => `<tr>
            <td><strong>${escapeHtml(r.label)}</strong></td>
            <td><code>${escapeHtml(r.target)}</code></td>
            <td>${badgeForAvailability(r.available, "CLEAR", "REGISTERED")}</td>
            <td>
              ${escapeHtml(r.detail)}
              ${r.url ? ` · <a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer" style="text-decoration:underline;">Inspect ↗</a>` : ""}
            </td>
          </tr>`
        )
        .join("");
    }

    if (recsListEl) {
      recsListEl.innerHTML = (report.summary.recommendations || [])
        .map((rec) => `<li>${escapeHtml(rec)}</li>`)
        .join("");
    }

    renderVariationChips(report.candidate);
  }

  async function executeSingleScan() {
    const raw = String(nameInputEl?.value || "").trim();
    if (!raw) {
      if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = "Enter a candidate brand, startup, or package name (min 2 alphanumeric chars).";
      }
      return;
    }

    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.textContent = "Scanning 13 Endpoints...";
    }
    if (statusEl) {
      statusEl.className = "fs-status-msg is-loading";
      statusEl.textContent =
        "Querying Google DoH (NS + A), CORS RDAP (8 TLDs), npm, PyPI, GitHub, Bluesky & Apple iOS App Store...";
    }

    try {
      const report = await scanSingleBrand(raw);
      renderReport(report);
      if (statusEl) {
        statusEl.className = "fs-status-msg is-success";
        statusEl.textContent = `Completed live scan for "${report.candidate}" at ${report.checkedAt} — Launch Readiness ${report.summary.readinessScore}/100 (${report.summary.verdict}).`;
      }
    } catch (err) {
      if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = err instanceof Error ? err.message : String(err);
      }
    } finally {
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.textContent = "Scan Brand Availability";
      }
    }
  }

  async function executeVariationsScan() {
    const raw = String(nameInputEl?.value || lastSingleReport?.candidate || "").trim();
    if (!raw) {
      if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = "Enter a base brand name first to scan smart variations.";
      }
      return;
    }

    const isPro = isBrandGuardProUnlocked();
    if (scanVarsBtn) {
      scanVarsBtn.disabled = true;
      scanVarsBtn.textContent = "Scanning Variations...";
    }
    if (statusEl) {
      statusEl.className = "fs-status-msg is-loading";
      statusEl.textContent = `Scanning ${isPro ? 6 : FREE_VARIATION_LIMIT} smart name variations in parallel...`;
    }

    try {
      const varPack = await scanBrandVariations(raw, { isPro });
      if (variationsTableWrapEl) variationsTableWrapEl.hidden = false;
      if (variationsBodyEl) {
        variationsBodyEl.innerHTML = varPack.results
          .map((r, idx) => {
            const comCell =
              r.summary.comAvailable === true
                ? "✓ .com free"
                : r.summary.comAvailable === false
                  ? "✗ .com taken"
                  : "? .com";
            return `<tr>
              <td><strong><code>${escapeHtml(r.candidate)}</code></strong></td>
              <td><span class="fs-badge ${badgeClassForVerdict(r.summary.verdict)}">${escapeHtml(r.summary.readinessScore)}/100</span></td>
              <td>${escapeHtml(comCell)} · ${escapeHtml(r.summary.availableCount)}/${escapeHtml(r.summary.totalChecks)} clear</td>
              <td><button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-var-inspect="${idx}">View Full</button></td>
            </tr>`;
          })
          .join("");

        variationsBodyEl.querySelectorAll("[data-var-inspect]").forEach((b) => {
          b.addEventListener("click", () => {
            const i = Number(b.getAttribute("data-var-inspect"));
            if (varPack.results[i]) {
              if (nameInputEl) nameInputEl.value = varPack.results[i].candidate;
              renderReport(varPack.results[i]);
            }
          });
        });
      }

      if (statusEl) {
        statusEl.className = "fs-status-msg is-success";
        statusEl.textContent = `Scanned ${varPack.scannedCount} variations — top match: ${varPack.bestVariation || "none"}.`;
      }
    } catch (err) {
      if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = err instanceof Error ? err.message : String(err);
      }
    } finally {
      if (scanVarsBtn) scanVarsBtn.disabled = false;
      syncProUi();
    }
  }

  document.querySelectorAll("[data-bg-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.getAttribute("data-bg-sample");
      const sample = BRANDGUARD_SAMPLES[key] || key;
      if (!sample) return;
      if (nameInputEl) nameInputEl.value = sample;
      executeSingleScan();
    });
  });

  if (scanBtn) scanBtn.addEventListener("click", executeSingleScan);
  if (scanVarsBtn) scanVarsBtn.addEventListener("click", executeVariationsScan);
  if (nameInputEl) {
    nameInputEl.addEventListener("keydown", (e) => {
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
      const payload = buildBrandAuditInvoicePayload(
        lastBatchReports.length > 0 ? lastBatchReports : lastSingleReport
      );
      const hash = encodeInvoicePayload(payload);
      window.location.href = `cryptobill.html#inv=${hash}`;
    });
  }

  if (sowBtn) {
    sowBtn.addEventListener("click", () => {
      const sowState = buildBrandSowState(
        lastBatchReports.length > 0 ? lastBatchReports : lastSingleReport
      );
      const hash = encodeSowHandoffPayload(sowState);
      window.location.href = `sowbuilder.html#sow=${hash}`;
    });
  }

  if (batchInputEl && !batchInputEl.value.trim()) {
    batchInputEl.value = DEFAULT_BATCH_BRANDS_SAMPLE;
  }

  if (batchRunBtn) {
    batchRunBtn.addEventListener("click", async () => {
      if (!isBrandGuardProUnlocked()) {
        openCheckoutModal("BUNDLE", { onUnlocked: syncProUi });
        return;
      }

      const candidates = parseBatchBrandList(batchInputEl?.value || "");
      if (candidates.length === 0) {
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-error";
          batchStatusEl.textContent = "Enter 1 to 25 candidate brand names (one per line or comma-separated).";
        }
        return;
      }
      if (candidates.length > MAX_BATCH_BRANDS) {
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-error";
          batchStatusEl.textContent = `Maximum ${MAX_BATCH_BRANDS} brands per batch matrix (found ${candidates.length}).`;
        }
        return;
      }

      batchRunBtn.disabled = true;
      batchRunBtn.textContent = `Scanning ${candidates.length} Brands...`;
      if (batchStatusEl) {
        batchStatusEl.className = "fs-status-msg is-loading";
        batchStatusEl.textContent = `Auditing ${candidates.length} brands across 8 TLDs + 5 registries...`;
      }

      try {
        const reports = await runBatchBrandScan(candidates);
        lastBatchReports = reports;

        if (batchBodyEl) {
          batchBodyEl.innerHTML = reports
            .map((r, idx) => {
              if (!r.ok) {
                return `<tr>
                  <td><code>${escapeHtml(r.candidate)}</code></td>
                  <td><span class="fs-badge fs-badge-warn">ERROR</span></td>
                  <td colspan="3" class="inv-muted">${escapeHtml(r.error)}</td>
                </tr>`;
              }
              const domMap = new Map(r.domains.map((d) => [d.tld, d.available]));
              const tldPills = ["com", "ai", "io", "dev"]
                .map((t) => `${domMap.get(t) === true ? "✓" : domMap.get(t) === false ? "✗" : "?"} .${t}`)
                .join(" · ");
              const regSummary = `${r.summary.allDevRegistriesClear ? "✓ npm/PyPI/GH" : "⚠ Dev collision"} · ${r.registries.iosAppStore.available ? "✓ iOS" : "⚠ iOS"}`;

              return `<tr>
                <td><strong><code>${escapeHtml(r.candidate)}</code></strong></td>
                <td><span class="fs-badge ${badgeClassForVerdict(r.summary.verdict)}">${escapeHtml(r.summary.readinessScore)}/100</span></td>
                <td><small>${escapeHtml(tldPills)}</small></td>
                <td><small>${escapeHtml(regSummary)}</small></td>
                <td><button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-batch-brand-idx="${idx}">Inspect</button></td>
              </tr>`;
            })
            .join("");

          batchBodyEl.querySelectorAll("[data-batch-brand-idx]").forEach((b) => {
            b.addEventListener("click", () => {
              const i = Number(b.getAttribute("data-batch-brand-idx"));
              if (lastBatchReports[i]?.ok) {
                if (nameInputEl) nameInputEl.value = lastBatchReports[i].candidate;
                renderReport(lastBatchReports[i]);
              }
            });
          });
        }

        if (exportJsonBtn) exportJsonBtn.disabled = false;
        if (exportCsvBtn) exportCsvBtn.disabled = false;
        if (batchStatusEl) {
          const okCount = reports.filter((x) => x.ok).length;
          batchStatusEl.className = "fs-status-msg is-success";
          batchStatusEl.textContent = `Agency Matrix complete: ${okCount}/${reports.length} brands scanned. Client CSV & JSON exports ready.`;
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

  if (exportJsonBtn) {
    exportJsonBtn.addEventListener("click", () => {
      if (!isBrandGuardProUnlocked()) {
        openCheckoutModal("BUNDLE", { onUnlocked: syncProUi });
        return;
      }
      if (lastBatchReports.length === 0) return;
      downloadBlob(
        "brandguard-agency-matrix.json",
        JSON.stringify(
          {
            suite: "ForgeSuite BrandGuard Pro",
            generatedAt: new Date().toISOString(),
            totalBrands: lastBatchReports.length,
            reports: lastBatchReports,
          },
          null,
          2
        ),
        "application/json;charset=utf-8"
      );
    });
  }

  if (exportCsvBtn) {
    exportCsvBtn.addEventListener("click", () => {
      if (!isBrandGuardProUnlocked()) {
        openCheckoutModal("BUNDLE", { onUnlocked: syncProUi });
        return;
      }
      if (lastBatchReports.length === 0) return;
      downloadBlob(
        "brandguard-agency-matrix.csv",
        exportBrandMatrixCsv(lastBatchReports),
        "text/csv;charset=utf-8"
      );
    });
  }

  syncProUi();

  const qp = parseBrandCheckQueryParams(window.location.search);
  if (qp.hasTarget && nameInputEl) {
    nameInputEl.value = qp.brand;
    if (qp.autorun) {
      executeSingleScan();
      if (qp.runVariations) {
        executeVariationsScan();
      }
    }
  } else if (nameInputEl && !nameInputEl.value.trim()) {
    nameInputEl.value = BRANDGUARD_SAMPLES.kestrelquant;
    executeSingleScan();
  }
}

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", initBrandGuardApp);
}
