import {
  bindCheckoutTriggers,
  getStoredLicenses,
  hasUnlockedTier,
  openCheckoutModal,
  validateLicenseKeyFormat,
} from "./checkout.js";
import { createDefaultInvoice, encodeInvoicePayload } from "./cryptobill.js";

/**
 * MediaBrief Studio — 100% Client-Side Script-to-Duration Pacing Calculator,
 * Rights & Consent Pre-Flight Scanner, Multi-Aspect Safe-Zone Spec Builder,
 * and Pro 25-Asset Campaign Batch Matrix.
 * Zero external dependencies. Runs identically in Browser ES Modules & Node.js 20+.
 */

export const MAX_BATCH_MEDIA_BRIEFS = 25;
export const DEFAULT_WPM = 150;
export const WPM_PRESETS = Object.freeze([135, 150, 165]);
export const ATEMPO_MIN_SAFE = 0.85;
export const ATEMPO_MAX_SAFE = 1.2;
export const GOLDEN_WINDOW_TOLERANCE_SEC = 0.5;
export const CJK_CHARS_PER_EFFECTIVE_WORD = 1.65;

export const NEAR_MEDIA_GEN_URL =
  "https://market.near.ai/agents/pay-per-use-media-gen";
export const NEAR_VIDEO_CLIPPER_URL =
  "https://market.near.ai/agents/short-video-clipper";
export const NEAR_VIDEO_DUBBER_URL =
  "https://market.near.ai/agents/multi-lang-video-dubber";

export const ASPECT_RATIO_SPECS = Object.freeze({
  "1:1": {
    ratio: "1:1",
    width: 1024,
    height: 1024,
    resolution: "1024x1024",
    label: "1:1 Square (1024×1024 · Studio Product Photo / Carousel)",
    cssAspect: "1 / 1",
    previewWidthPx: 236,
    platforms: ["Instagram Feed", "Shopify / E-Commerce", "LinkedIn Carousel"],
    safeZone: {
      xMin: 80,
      xMax: 944,
      yMin: 690,
      yMax: 854,
      widthPx: 864,
      heightPx: 164,
      topDangerPct: 9,
      rightDangerPct: 8,
      bottomDangerPct: 17,
      maxCharsPerLine: 34,
      maxLines: 2,
      assPlayResX: 1024,
      assPlayResY: 1024,
      assMarginL: 80,
      assMarginR: 80,
      assMarginV: 170,
    },
  },
  "9:16": {
    ratio: "9:16",
    width: 1080,
    height: 1920,
    resolution: "1080x1920",
    label: "9:16 Vertical (1080×1920 · TikTok / Reels / YouTube Shorts)",
    cssAspect: "9 / 16",
    previewWidthPx: 212,
    platforms: ["TikTok", "Instagram Reels", "YouTube Shorts"],
    safeZone: {
      xMin: 90,
      xMax: 905,
      yMin: 1180,
      yMax: 1490,
      widthPx: 815,
      heightPx: 310,
      topDangerPct: 13,
      rightDangerPct: 16,
      bottomDangerPct: 22,
      maxCharsPerLine: 32,
      maxLines: 2,
      assPlayResX: 1080,
      assPlayResY: 1920,
      assMarginL: 90,
      assMarginR: 175,
      assMarginV: 420,
    },
  },
  "16:9": {
    ratio: "16:9",
    width: 1920,
    height: 1080,
    resolution: "1920x1080",
    label: "16:9 Widescreen (1920×1080 · YouTube / Landing Hero / CTV)",
    cssAspect: "16 / 9",
    previewWidthPx: 296,
    platforms: ["YouTube Long-Form", "SaaS Product Demo", "Connected TV"],
    safeZone: {
      xMin: 160,
      xMax: 1760,
      yMin: 780,
      yMax: 940,
      widthPx: 1600,
      heightPx: 160,
      topDangerPct: 9,
      rightDangerPct: 6,
      bottomDangerPct: 13,
      maxCharsPerLine: 42,
      maxLines: 2,
      assPlayResX: 1920,
      assPlayResY: 1080,
      assMarginL: 160,
      assMarginR: 160,
      assMarginV: 140,
    },
  },
  "4:5": {
    ratio: "4:5",
    width: 1080,
    height: 1350,
    resolution: "1080x1350",
    label: "4:5 Portrait Feed (1080×1350 · Meta / IG / Paid Social)",
    cssAspect: "4 / 5",
    previewWidthPx: 224,
    platforms: ["Meta Paid Ads", "Instagram Feed Portrait", "Reddit / X Promoted"],
    safeZone: {
      xMin: 90,
      xMax: 990,
      yMin: 890,
      yMax: 1110,
      widthPx: 900,
      heightPx: 220,
      topDangerPct: 9,
      rightDangerPct: 8,
      bottomDangerPct: 18,
      maxCharsPerLine: 36,
      maxLines: 2,
      assPlayResX: 1080,
      assPlayResY: 1350,
      assMarginL: 90,
      assMarginR: 90,
      assMarginV: 240,
    },
  },
});

export const MEDIASTUDIO_SAMPLES = Object.freeze({
  golden_30s_spot: {
    title: "Ceramic Mug 30s Spot (Golden Window ±0.5s)",
    ratio: "9:16",
    targetSec: 30,
    wpm: 150,
    consentVerified: false,
    ownedBrands: "ForgeSuite, Artisan Kiln",
    targetAgent: "pay-per-use-media-gen",
    brief:
      "Warm sunlit wooden kitchen counter, slow pour-over coffee into a matte stoneware ceramic mug with soft morning steam, shallow depth of field, studio lighting.",
    script:
      "Every great morning begins with one quiet moment before the daily rush starts. Handcrafted from natural stoneware clay and glazed for lasting warmth, our Artisan Kiln ceramic mug keeps pour-over coffee rich from the very first sip to the final drop. Designed by ForgeSuite creators for sunlit desks, cozy kitchens, and everyday focus rituals, each balanced handle feels effortless in your hand. Order yours today with fast shipping, honest craftsmanship, and zero recurring subscriptions.",
  },
  overlong_8s_hook: {
    title: "Overlong 8.0s Vertical Hook (atempo > 1.20x Distortion)",
    ratio: "9:16",
    targetSec: 8,
    wpm: 150,
    consentVerified: false,
    ownedBrands: "ForgeSuite",
    targetAgent: "short-video-clipper",
    brief:
      "Fast vertical 9:16 SaaS dashboard reveal showing mobile subtitle safe zones and real-time voiceover pacing meters.",
    script:
      "Stop wasting studio render budgets on ad scripts that run way too long for an eight second vertical video slot and force ugly chipmunk speedups that ruin viewer retention before your call to action.",
  },
  rights_preflight_block: {
    title: "Rights & Consent Block (Celebrity + Disney/Nintendo IP)",
    ratio: "1:1",
    targetSec: 15,
    wpm: 150,
    consentVerified: false,
    ownedBrands: "ForgeSuite",
    targetAgent: "pay-per-use-media-gen",
    brief:
      "Image of a well-known celebrity like Taylor Swift holding a sneaker with the Nike swoosh beside Spider-Man and Pikachu.",
    script:
      "Breaking news alert: Taylor Swift and Elon Musk just teamed up with Mickey Mouse to promise a guaranteed 100x return on this limited drop.",
  },
  multilang_cjk_15s: {
    title: "Bilingual CJK + English 15s Dub Spec",
    ratio: "16:9",
    targetSec: 15,
    wpm: 150,
    consentVerified: true,
    ownedBrands: "ForgeSuite, NEAR Protocol",
    targetAgent: "multi-lang-video-dubber",
    brief:
      "Clean 1920x1080 product walkthrough with founder presenter (signed talent release on file) demonstrating multi-language dubbing.",
    script:
      "ForgeSuite Studio delivers global video localization on NEAR Protocol. 高品質なAI音声吹き替えと正確な字幕で、世界中の視聴者に届けましょう。 Ship clean dubs across twenty six languages today.",
  },
});

export const DEMO_CAMPAIGN_BATCH = Object.freeze([
  {
    title: "Ad_01_Stoneware_Mug_30s",
    ratio: "9:16",
    targetSec: 30,
    consentVerified: false,
    ownedBrands: "ForgeSuite, Artisan Kiln",
    brief: "9:16 vertical slow-motion coffee pour into matte ceramic mug on oak table.",
    script: MEDIASTUDIO_SAMPLES.golden_30s_spot.script,
  },
  {
    title: "Ad_02_Square_Catalog_8s",
    ratio: "1:1",
    targetSec: 8,
    consentVerified: false,
    ownedBrands: "ForgeSuite",
    brief: "1024x1024 minimalist product hero shot of matte black insulated tumbler.",
    script:
      "Cold for twenty four hours, forged from recycled steel, and built by ForgeSuite Studio for every daily morning commute anywhere.",
  },
  {
    title: "Ad_03_Overlong_Hook_8s",
    ratio: "9:16",
    targetSec: 8,
    consentVerified: false,
    ownedBrands: "ForgeSuite",
    brief: "Vertical split-screen retention hook for short-form clipper.",
    script: MEDIASTUDIO_SAMPLES.overlong_8s_hook.script,
  },
  {
    title: "Ad_04_Unconsented_Celeb_Check",
    ratio: "4:5",
    targetSec: 15,
    consentVerified: false,
    ownedBrands: "ForgeSuite",
    brief: "4:5 portrait ad featuring a well-known celebrity and Pikachu.",
    script:
      "Watch Elon Musk unbox our new wireless charger alongside Pikachu in studio.",
  },
]);

const REAL_PERSON_TRIGGERS = Object.freeze([
  { label: "well-known celebrity", rx: /\bwell[- ]known\s+celebrit(?:y|ies)\b/i },
  { label: "famous celebrity", rx: /\bfamous\s+celebrit(?:y|ies)\b/i },
  { label: "celebrity endorsement/likeness", rx: /\bcelebrit(?:y|ies)\s+(?:holding|endors\w+|wearing|using|spokesperson)\b/i },
  { label: "unconsented voice clone", rx: /\b(?:voice\s+clone\s+of|in\s+the\s+voice\s+of|sound\s+just\s+like|deepfake\s+of)\b/i },
  { label: "world leader / politician", rx: /\b(?:world\s+leader|sitting\s+president|famous\s+politician)\b/i },
  { label: "Elon Musk", rx: /\belon\s+musk\b/i },
  { label: "Taylor Swift", rx: /\btaylor\s+swift\b/i },
  { label: "Donald Trump", rx: /\bdonald\s+trump\b/i },
  { label: "Joe Biden", rx: /\bjoe\s+biden\b/i },
  { label: "Barack Obama", rx: /\bbarack\s+obama\b/i },
  { label: "Kamala Harris", rx: /\bkamala\s+harris\b/i },
  { label: "Vladimir Putin", rx: /\bvladimir\s+putin\b/i },
  { label: "Xi Jinping", rx: /\bxi\s+jinping\b/i },
  { label: "Sam Altman", rx: /\bsam\s+altman\b/i },
  { label: "Jensen Huang", rx: /\bjensen\s+huang\b/i },
  { label: "Vitalik Buterin", rx: /\bvitalik\s+buterin\b/i },
  { label: "Mark Zuckerberg", rx: /\bmark\s+zuckerberg\b/i },
  { label: "Jeff Bezos", rx: /\bjeff\s+bezos\b/i },
  { label: "Bill Gates", rx: /\bbill\s+gates\b/i },
  { label: "Tim Cook", rx: /\btim\s+cook\b/i },
  { label: "Cristiano Ronaldo", rx: /\bcristiano\s+ronaldo\b/i },
  { label: "Lionel Messi", rx: /\blionel\s+messi\b/i },
  { label: "LeBron James", rx: /\blebron\s+james\b/i },
  { label: "MrBeast", rx: /\bmr\s*beast\b/i },
  { label: "Kim Kardashian", rx: /\bkim\s+kardashian\b/i },
  { label: "Beyonce", rx: /\bbeyonc[eé]\b/i },
  { label: "Rihanna", rx: /\brihanna\b/i },
  { label: "Ariana Grande", rx: /\bariana\s+grande\b/i },
  { label: "Scarlett Johansson", rx: /\bscarlett\s+johansson\b/i },
  { label: "Morgan Freeman", rx: /\bmorgan\s+freeman\b/i },
  { label: "Tom Cruise", rx: /\btom\s+cruise\b/i },
  { label: "Keanu Reeves", rx: /\bkeanu\s+reeves\b/i },
  { label: "Dwayne Johnson", rx: /\bdwayne\s+johnson\b/i },
  { label: "Robert Downey Jr", rx: /\brobert\s+downey\b/i },
]);

const COPYRIGHTED_CHARACTER_TRIGGERS = Object.freeze([
  { label: "Mickey Mouse (Disney)", rx: /\bmickey\s+mouse\b/i },
  { label: "Minnie Mouse (Disney)", rx: /\bminnie\s+mouse\b/i },
  { label: "Donald Duck (Disney)", rx: /\bdonald\s+duck\b/i },
  { label: "Disney / Pixar IP", rx: /\b(?:disney\s+princess|disney\s+character|pixar\s+character|buzz\s+lightyear|elsa\s+from\s+frozen)\b/i },
  { label: "Star Wars / Darth Vader / Baby Yoda", rx: /\b(?:darth\s+vader|luke\s+skywalker|baby\s+yoda|grogu|lightsaber\s+duel|star\s+wars)\b/i },
  { label: "Spider-Man (Marvel/Sony)", rx: /\bspider[- ]?man\b/i },
  { label: "Iron Man (Marvel)", rx: /\biron\s+man\b/i },
  { label: "Captain America / Avengers (Marvel)", rx: /\b(?:captain\s+america|the\s+avengers|deadpool|wolverine)\b/i },
  { label: "Batman / Superman / Joker (DC)", rx: /\b(?:batman|superman|wonder\s+woman|harley\s+quinn)\b/i },
  { label: "Super Mario (Nintendo)", rx: /\b(?:super\s+mario|mario\s+bros|princess\s+peach|bowser)\b/i },
  { label: "Pokemon / Pikachu (Nintendo)", rx: /\b(?:pikachu|pok[eé]mon|charizard|mewtwo)\b/i },
  { label: "Legend of Zelda (Nintendo)", rx: /\b(?:legend\s+of\s+zelda|hyrule)\b/i },
  { label: "Sonic the Hedgehog (Sega)", rx: /\bsonic\s+the\s+hedgehog\b/i },
  { label: "Naruto / Dragon Ball / One Piece (Anime IP)", rx: /\b(?:naruto|uzumaki|son\s+goku|dragon\s+ball|monkey\s+d\.?\s+luffy|one\s+piece|gojo\s+satoru|demon\s+slayer|totoro|studio\s+ghibli)\b/i },
  { label: "Hello Kitty / SpongeBob / Harry Potter / Minions", rx: /\b(?:hello\s+kitty|spongebob|harry\s+potter|hogwarts|minions|shrek|james\s+bond)\b/i },
]);

const THIRD_PARTY_BRAND_TRIGGERS = Object.freeze([
  { label: "Apple Logo / iPhone Trademark", brandKey: "apple", rx: /\b(?:apple\s+logo|official\s+iphone)\b/i },
  { label: "Nike / Swoosh Logo", brandKey: "nike", rx: /\b(?:nike\s+swoosh|nike\s+logo|air\s+jordan\s+logo)\b/i },
  { label: "Adidas Three Stripes", brandKey: "adidas", rx: /\b(?:adidas\s+logo|adidas\s+stripes)\b/i },
  { label: "Coca-Cola / Pepsi Trademark", brandKey: "coca-cola", rx: /\b(?:coca[- ]?cola|pepsi\s+logo)\b/i },
  { label: "Starbucks / McDonald's Logo", brandKey: "starbucks", rx: /\b(?:starbucks\s+logo|mcdonald'?s\s+arches|mcdonald'?s\s+logo)\b/i },
  { label: "Luxury Fashion Trademark (Louis Vuitton / Gucci / Rolex)", brandKey: "luxury", rx: /\b(?:louis\s+vuitton|gucci\s+monogram|chanel\s+logo|rolex\s+crown|rolex\s+watch)\b/i },
  { label: "Automotive Emblem (Ferrari / Lamborghini / Tesla Logo)", brandKey: "automotive", rx: /\b(?:ferrari\s+logo|lamborghini\s+crest|porsche\s+crest|tesla\s+logo)\b/i },
  { label: "Olympic Rings / FIFA World Cup", brandKey: "sports-federation", rx: /\b(?:olympic\s+rings|fifa\s+world\s+cup)\b/i },
]);

const DECEPTIVE_OR_SENSITIVE_TRIGGERS = Object.freeze([
  { label: "Fake Breaking News / Emergency Broadcast", rx: /\b(?:breaking\s+news\s+alert|emergency\s+broadcast\s+alert|leaked\s+secret\s+footage)\b/i },
  { label: "Guaranteed Financial Return / Crypto Scam Claim", rx: /\b(?:guaranteed\s+100x|guaranteed\s+(?:profit|return)|double\s+your\s+(?:crypto|bitcoin|money)|risk[- ]free\s+profit)\b/i },
  { label: "Unverified Miracle Medical Claim", rx: /\b(?:miracle\s+cure|cures\s+cancer|instant\s+medical\s+cure|fda\s+approved\s+miracle)\b/i },
  { label: "NSFW / Explicit / Graphic Violence", rx: /\b(?:nsfw|explicit\s+nudity|nude\s+portrait|graphic\s+violence|gore\s+scene|self[- ]harm|bomb\s+making)\b/i },
]);

const CJK_CHAR_GLOBAL_RX =
  /[\u3040-\u30FF\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF\uAC00-\uD7AF]/g;

function encodeBase64UrlUtf8(str) {
  const bytes = new TextEncoder().encode(String(str ?? ""));
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 =
    typeof btoa === "function"
      ? btoa(binary)
      : Buffer.from(bytes).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeBase64UrlUtf8(token) {
  const clean = String(token || "")
    .trim()
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  if (!clean) return "";
  const padded = clean + "=".repeat((4 - (clean.length % 4)) % 4);
  if (typeof atob === "function") {
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }
  return Buffer.from(padded, "base64").toString("utf8");
}

export function guardCsvCell(val) {
  const raw = String(val ?? "");
  const safe = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  if (/[",\r\n]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

export function normalizeAspectRatio(rawRatio) {
  const clean = String(rawRatio ?? "")
    .trim()
    .toLowerCase();
  if (clean === "1:1" || clean === "1x1" || clean === "1024x1024" || clean === "square") {
    return "1:1";
  }
  if (clean === "16:9" || clean === "16x9" || clean === "1920x1080" || clean === "landscape" || clean === "widescreen") {
    return "16:9";
  }
  if (clean === "4:5" || clean === "4x5" || clean === "1080x1350" || clean === "portrait") {
    return "4:5";
  }
  return "9:16";
}

export function parseOwnedBrandsInput(rawBrands) {
  if (Array.isArray(rawBrands)) {
    return [...new Set(rawBrands.map((b) => String(b || "").trim()).filter(Boolean))];
  }
  if (typeof rawBrands === "string" && rawBrands.trim()) {
    return [
      ...new Set(
        rawBrands
          .split(/[,;\n|]+/)
          .map((b) => b.trim())
          .filter(Boolean)
      ),
    ];
  }
  return [];
}

function estimateWordSyllables(rawToken) {
  const token = String(rawToken || "").trim();
  if (!token) return 0;

  // Numeric/currency/ratio tokens take multiple spoken syllables (e.g. "$0.45", "1080x1920", "2026")
  const digitMatches = token.match(/\d/g);
  if (digitMatches && digitMatches.length > 0) {
    let numSyl = digitMatches.length;
    if (/[$€£¥]/.test(token)) numSyl += 1;
    if (/%/.test(token)) numSyl += 2;
    if (/[x×]/i.test(token) && /\d+[x×]\d+/i.test(token)) numSyl += 1;
    return Math.min(10, Math.max(1, numSyl));
  }

  const alpha = token
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/đ/g, "d")
    .replace(/[^a-z]/g, "");

  if (!alpha) return 0;
  if (alpha.length <= 3) return 1;

  const trimmed = alpha
    .replace(/(?:[^laeiouy]es|ed|[^laeiouy]e)$/, "")
    .replace(/^y/, "");
  const groups = trimmed.match(/[aeiouy]{1,2}/g);
  return Math.max(1, groups ? groups.length : 1);
}

/**
 * Counts spoken words & syllables accurately across Latin/Cyrillic/Vietnamese and CJK scripts.
 */
export function countScriptWordsAndSyllables(rawScript) {
  const cleaned = String(rawScript ?? "")
    .replace(/^\uFEFF/, "")
    .replace(/\r\n/g, "\n")
    .trim();

  if (!cleaned) {
    return {
      charCount: 0,
      latinWords: 0,
      cjkChars: 0,
      totalWords: 0,
      effectiveWords: 0,
      syllableCount: 0,
      sentenceCount: 0,
      hasCjk: false,
    };
  }

  const cjkMatches = cleaned.match(CJK_CHAR_GLOBAL_RX);
  const cjkChars = cjkMatches ? cjkMatches.length : 0;

  // Replace CJK chars with spaces to tokenize non-CJK words cleanly
  const nonCjkText = cleaned.replace(CJK_CHAR_GLOBAL_RX, " ");
  const latinTokens = nonCjkText
    .split(/\s+/)
    .map((tok) => tok.replace(/^[^\p{L}\p{N}$€£¥]+|[^\p{L}\p{N}%]+$/gu, ""))
    .filter((tok) => /[\p{L}\p{N}]/u.test(tok));

  const latinWords = latinTokens.length;
  let latinSyllables = 0;
  for (const tok of latinTokens) {
    latinSyllables += estimateWordSyllables(tok);
  }

  const totalWords = latinWords + cjkChars;
  const effectiveWords = Number(
    (latinWords + cjkChars / CJK_CHARS_PER_EFFECTIVE_WORD).toFixed(2)
  );
  const syllableCount = latinSyllables + cjkChars;

  const sentences = cleaned
    .split(/[.!?…\u3002\uFF01\uFF1F]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  return {
    charCount: cleaned.length,
    latinWords,
    cjkChars,
    totalWords,
    effectiveWords,
    syllableCount,
    sentenceCount: Math.max(1, sentences.length),
    hasCjk: cjkChars > 0,
  };
}

/**
 * Builds a valid FFmpeg `atempo` filter chain respecting libavfilter's [0.5, 2.0] per-node bounds.
 */
export function buildFfmpegAtempoChain(rawTempo) {
  const tempo = Number(rawTempo);
  if (!Number.isFinite(tempo) || tempo <= 0) {
    return "atempo=1.000";
  }
  const factors = [];
  let remaining = tempo;
  let guard = 0;
  while (remaining > 2.0001 && guard < 6) {
    factors.push(2.0);
    remaining /= 2.0;
    guard += 1;
  }
  while (remaining < 0.4999 && guard < 6) {
    factors.push(0.5);
    remaining /= 0.5;
    guard += 1;
  }
  factors.push(remaining);
  return factors.map((f) => `atempo=${f.toFixed(3)}`).join(",");
}

/**
 * Computes exact voiceover durations at 135/150/165 WPM, FFmpeg atempo ratio vs targetSec,
 * distortion/underrun warnings, and word delta to hit the ±0.5s golden window.
 */
export function calculateScriptPacing(
  rawScript,
  { targetSec = 30, wpm = DEFAULT_WPM } = {}
) {
  const safeTargetSec = Math.max(
    1,
    Math.min(3600, Number(targetSec) > 0 ? Number(targetSec) : 30)
  );
  const selectedWpm = Math.max(
    80,
    Math.min(260, Number(wpm) > 0 ? Number(wpm) : DEFAULT_WPM)
  );

  const counts = countScriptWordsAndSyllables(rawScript);
  const dur135 = Number(((counts.effectiveWords / 135) * 60).toFixed(2));
  const dur150 = Number(((counts.effectiveWords / 150) * 60).toFixed(2));
  const dur165 = Number(((counts.effectiveWords / 165) * 60).toFixed(2));
  const estimatedSec = Number(
    ((counts.effectiveWords / selectedWpm) * 60).toFixed(2)
  );

  const goldenMinSec = Number(
    Math.max(0.5, safeTargetSec - GOLDEN_WINDOW_TOLERANCE_SEC).toFixed(2)
  );
  const goldenMaxSec = Number(
    (safeTargetSec + GOLDEN_WINDOW_TOLERANCE_SEC).toFixed(2)
  );

  const idealWordsExact = (safeTargetSec / 60) * selectedWpm;
  const goldenMinWords = Math.max(1, Math.ceil((goldenMinSec / 60) * selectedWpm));
  const goldenMaxWords = Math.max(
    goldenMinWords,
    Math.floor((goldenMaxSec / 60) * selectedWpm)
  );
  const idealWords = Math.max(1, Math.round(idealWordsExact));

  if (counts.totalWords === 0) {
    return {
      counts,
      selectedWpm,
      targetSec: safeTargetSec,
      durationsSec: {
        wpm135: 0,
        wpm150: 0,
        wpm165: 0,
        atSelectedWpm: 0,
      },
      deltaSec: Number((-safeTargetSec).toFixed(2)),
      inGoldenWindow: false,
      goldenWindowSec: { min: goldenMinSec, max: goldenMaxSec },
      goldenWordRange: {
        minWords: goldenMinWords,
        idealWords,
        maxWords: goldenMaxWords,
      },
      wordDelta: idealWords,
      wordsToTrim: 0,
      wordsToAdd: idealWords,
      requiredAtempo: 0,
      ffmpegAtempoFilter: "atempo=1.000",
      atempoDistortionRisk: false,
      atempoUnderrunRisk: false,
      pacingStatus: "EMPTY_SCRIPT",
      pacingScore: 40,
      recommendation: `No spoken voiceover script provided (visual-only mode). Add ~${idealWords} words at ${selectedWpm} WPM if you want a ${safeTargetSec.toFixed(1)}s voiceover.`,
    };
  }

  const deltaSec = Number((estimatedSec - safeTargetSec).toFixed(2));
  const inGoldenWindow = Math.abs(deltaSec) <= GOLDEN_WINDOW_TOLERANCE_SEC;
  const requiredAtempo = Number((estimatedSec / safeTargetSec).toFixed(3));
  const ffmpegAtempoFilter = buildFfmpegAtempoChain(requiredAtempo);

  const atempoDistortionRisk = requiredAtempo > ATEMPO_MAX_SAFE;
  const atempoUnderrunRisk = requiredAtempo < ATEMPO_MIN_SAFE;

  let wordsToTrim = 0;
  let wordsToAdd = 0;
  let wordDelta = 0;

  if (!inGoldenWindow) {
    if (estimatedSec > goldenMaxSec) {
      wordsToTrim = Math.max(
        1,
        Math.round(counts.effectiveWords - idealWordsExact)
      );
      wordDelta = -wordsToTrim;
    } else if (estimatedSec < goldenMinSec) {
      wordsToAdd = Math.max(
        1,
        Math.round(idealWordsExact - counts.effectiveWords)
      );
      wordDelta = wordsToAdd;
    }
  }

  let pacingStatus = "GOLDEN_WINDOW";
  let pacingScore = 100;
  let recommendation = `Script hits the ${safeTargetSec.toFixed(1)}s ±0.5s golden window (${estimatedSec.toFixed(2)}s at ${selectedWpm} WPM; atempo ${requiredAtempo.toFixed(2)}x).`;

  if (inGoldenWindow) {
    pacingStatus = "GOLDEN_WINDOW";
    pacingScore = 100;
  } else if (atempoDistortionRisk) {
    pacingStatus = "TOO_LONG_ATEMPO_DISTORTION";
    const excessPenalty = Math.min(60, Math.round((requiredAtempo - 1.2) * 90) + 22);
    pacingScore = Math.max(15, 100 - excessPenalty);
    recommendation = `Script runs ${estimatedSec.toFixed(2)}s vs ${safeTargetSec.toFixed(1)}s target (requires FFmpeg ${ffmpegAtempoFilter} = ${requiredAtempo.toFixed(2)}x > 1.20x distortion ceiling). Trim ~${wordsToTrim} word(s) to land inside ${goldenMinWords}–${goldenMaxWords} words (${goldenMinSec}s–${goldenMaxSec}s).`;
  } else if (atempoUnderrunRisk) {
    pacingStatus = "TOO_SHORT_UNDERRUN";
    const shortPenalty = Math.min(55, Math.round((0.85 - requiredAtempo) * 90) + 18);
    pacingScore = Math.max(25, 100 - shortPenalty);
    recommendation = `Script runs only ${estimatedSec.toFixed(2)}s vs ${safeTargetSec.toFixed(1)}s target (atempo ${requiredAtempo.toFixed(2)}x < 0.85x causes robotic drag or dead air). Add ~${wordsToAdd} word(s) to reach ${goldenMinWords}–${goldenMaxWords} words.`;
  } else if (deltaSec > 0) {
    pacingStatus = "SLIGHTLY_OVER_TARGET";
    pacingScore = 86;
    recommendation = `Script is ${deltaSec.toFixed(2)}s over ${safeTargetSec.toFixed(1)}s (atempo ${requiredAtempo.toFixed(2)}x is safe <= 1.20x, or trim ~${wordsToTrim} word(s) for natural 1.00x pacing).`;
  } else {
    pacingStatus = "SLIGHTLY_UNDER_TARGET";
    pacingScore = 88;
    recommendation = `Script is ${Math.abs(deltaSec).toFixed(2)}s under ${safeTargetSec.toFixed(1)}s (atempo ${requiredAtempo.toFixed(2)}x >= 0.85x, or add ~${wordsToAdd} word(s) to hit ${safeTargetSec.toFixed(1)}s ±0.5s).`;
  }

  return {
    counts,
    selectedWpm,
    targetSec: safeTargetSec,
    durationsSec: {
      wpm135: dur135,
      wpm150: dur150,
      wpm165: dur165,
      atSelectedWpm: estimatedSec,
    },
    deltaSec,
    inGoldenWindow,
    goldenWindowSec: { min: goldenMinSec, max: goldenMaxSec },
    goldenWordRange: {
      minWords: goldenMinWords,
      idealWords,
      maxWords: goldenMaxWords,
    },
    wordDelta,
    wordsToTrim,
    wordsToAdd,
    requiredAtempo,
    ffmpegAtempoFilter,
    atempoDistortionRisk,
    atempoUnderrunRisk,
    pacingStatus,
    pacingScore,
    recommendation,
  };
}

/**
 * Scans visual brief & spoken script for unconsented real-person/celebrity likeness,
 * copyrighted characters (Disney/Marvel/Nintendo/Pixar/Anime), third-party logos,
 * and deceptive/sensitive ad claims. Returns a 0–100 safetyScore.
 */
export function scanMediaRightsAndConsent({
  script = "",
  brief = "",
  consentVerified = false,
  ownedBrands = [],
} = {}) {
  const combined = `${String(brief || "")}\n${String(script || "")}`.trim();
  const normalizedOwned = parseOwnedBrandsInput(ownedBrands);
  const ownedLower = normalizedOwned.map((b) => b.toLowerCase());

  const flags = [];
  let realPersonHits = 0;
  let consentedPersonNotes = 0;
  let copyrightedCharacterHits = 0;
  let thirdPartyBrandHits = 0;
  let deceptiveOrSensitiveHits = 0;

  if (combined) {
    for (const item of REAL_PERSON_TRIGGERS) {
      const m = combined.match(item.rx);
      if (m) {
        if (consentVerified) {
          consentedPersonNotes += 1;
          flags.push({
            severity: "LOW",
            category: "consent",
            ruleId: "CONSENT_ATTESTED_KEEP_RELEASE",
            trigger: m[0],
            message: `Real-person/likeness reference "${m[0]}" (${item.label}) detected with Consent Flag = VERIFIED. Retain signed talent release on file.`,
          });
        } else {
          realPersonHits += 1;
          flags.push({
            severity: "CRITICAL",
            category: "real_person_no_consent",
            ruleId: "REAL_PERSON_NO_CONSENT",
            trigger: m[0],
            message: `Real-person / celebrity / politician likeness "${m[0]}" (${item.label}) requires documented identity & consent verification before AI media generation.`,
          });
        }
      }
    }

    for (const item of COPYRIGHTED_CHARACTER_TRIGGERS) {
      const m = combined.match(item.rx);
      if (m) {
        copyrightedCharacterHits += 1;
        flags.push({
          severity: "HIGH",
          category: "copyrighted_character",
          ruleId: "COPYRIGHTED_CHARACTER_IP",
          trigger: m[0],
          message: `Protected character/franchise "${m[0]}" (${item.label}) triggers copyright/IP rejection on commercial AI media & ad networks.`,
        });
      }
    }

    for (const item of THIRD_PARTY_BRAND_TRIGGERS) {
      const m = combined.match(item.rx);
      if (m) {
        const matchedTextLower = m[0].toLowerCase();
        const isOwned = ownedLower.some(
          (owned) =>
            owned.length >= 2 &&
            (matchedTextLower.includes(owned) || owned.includes(item.brandKey))
        );
        if (!isOwned) {
          thirdPartyBrandHits += 1;
          flags.push({
            severity: "MEDIUM",
            category: "third_party_trademark",
            ruleId: "THIRD_PARTY_TRADEMARK_LOGO",
            trigger: m[0],
            message: `Third-party trademark/logo reference "${m[0]}" (${item.label}) detected outside declared owned brands.`,
          });
        }
      }
    }

    for (const item of DECEPTIVE_OR_SENSITIVE_TRIGGERS) {
      const m = combined.match(item.rx);
      if (m) {
        deceptiveOrSensitiveHits += 1;
        flags.push({
          severity: "CRITICAL",
          category: "deceptive_or_sensitive",
          ruleId: "DECEPTIVE_OR_SENSITIVE_CONTENT",
          trigger: m[0],
          message: `Policy-violating or deceptive claim "${m[0]}" (${item.label}) will fail ad-network and creative agent safety moderation.`,
        });
      }
    }
  }

  const penalty =
    realPersonHits * 45 +
    deceptiveOrSensitiveHits * 50 +
    copyrightedCharacterHits * 35 +
    thirdPartyBrandHits * 20;

  const safetyScore = Math.max(0, Math.min(100, 100 - penalty));
  const hasCriticalOrHigh =
    realPersonHits > 0 ||
    deceptiveOrSensitiveHits > 0 ||
    copyrightedCharacterHits > 0;

  const verdict =
    safetyScore >= 90 && !hasCriticalOrHigh
      ? "CLEARED_FOR_GENERATION"
      : safetyScore >= 65 && realPersonHits === 0 && deceptiveOrSensitiveHits === 0
        ? "REVIEW_TRADEMARKS_OR_CLAIMS"
        : "BLOCKED_PREFLIGHT_RISK";

  return {
    safetyScore,
    verdict,
    consentVerified: Boolean(consentVerified),
    ownedBrands: normalizedOwned,
    counts: {
      realPersonHits,
      consentedPersonNotes,
      copyrightedCharacterHits,
      thirdPartyBrandHits,
      deceptiveOrSensitiveHits,
      totalBlockingFlags:
        realPersonHits +
        copyrightedCharacterHits +
        thirdPartyBrandHits +
        deceptiveOrSensitiveHits,
    },
    flags,
  };
}

function wrapSampleCaptionPreview(rawScript, maxChars = 32) {
  const clean = String(rawScript || "")
    .replace(/\s+/g, " ")
    .trim();
  if (!clean) return ["(Visual-only brief — add spoken script to preview safe-zone captions)"];
  const firstClause = clean.split(/(?<=[.!?…\u3002\uFF01\uFF1F])\s+/)[0] || clean;
  const words = firstClause.split(" ").filter(Boolean);
  const lines = [];
  let cur = "";
  for (const w of words) {
    if (!cur) cur = w;
    else if (cur.length + 1 + w.length <= maxChars) cur += ` ${w}`;
    else {
      lines.push(cur);
      cur = w;
      if (lines.length >= 2) break;
    }
  }
  if (cur && lines.length < 2) lines.push(cur);
  return lines.slice(0, 2);
}

/**
 * Builds normalized resolution, safe-zone geometry, and copy-paste JSON specs for
 * @pay-per-use-media-gen ($0.45), @short-video-clipper ($0.50), and @multi-lang-video-dubber ($0.65).
 */
export function buildAspectAndProviderSpecs({
  title = "Untitled Creative Asset",
  script = "",
  brief = "",
  ratio = "9:16",
  targetSec = 30,
  wpm = DEFAULT_WPM,
  voicePreset = "en-US-AvaMultilingualNeural",
  targetLanguages = ["es", "de", "ja"],
  ownedBrands = [],
  consentVerified = false,
  pacing = null,
  rights = null,
} = {}) {
  const normRatio = normalizeAspectRatio(ratio);
  const spec = ASPECT_RATIO_SPECS[normRatio];
  const computedPacing =
    pacing || calculateScriptPacing(script, { targetSec, wpm });
  const computedRights =
    rights ||
    scanMediaRightsAndConsent({ script, brief, consentVerified, ownedBrands });

  const cleanScript = String(script || "").trim();
  const cleanBrief = String(brief || "").trim();
  const normalizedBrands = parseOwnedBrandsInput(ownedBrands);
  const normalizedLangs = Array.isArray(targetLanguages)
    ? targetLanguages.map((l) => String(l).trim()).filter(Boolean)
    : String(targetLanguages || "es,de,ja")
        .split(/[,;\s]+/)
        .filter(Boolean);

  const sampleCaptionLines = wrapSampleCaptionPreview(
    cleanScript || cleanBrief,
    spec.safeZone.maxCharsPerLine
  );

  const agentPayloads = {
    "pay-per-use-media-gen": {
      agent: "@pay-per-use-media-gen",
      priceUsdc: 0.45,
      marketUrl: NEAR_MEDIA_GEN_URL,
      a2aEndpoint: "https://pay-per-use-media-gen.market.near.ai/a2a/v1",
      jobSpec: {
        asset_title: title,
        deliverable_mode:
          cleanScript && cleanBrief
            ? "video_and_verbatim_voiceover"
            : cleanScript
              ? "verbatim_voiceover_mp3"
              : normRatio === "1:1"
                ? "studio_product_image_png"
                : "vertical_or_widescreen_video_mp4",
        aspect_ratio: spec.ratio,
        resolution: spec.resolution,
        width: spec.width,
        height: spec.height,
        target_duration_sec: computedPacing.targetSec,
        visual_prompt:
          cleanBrief ||
          `Studio ${spec.resolution} (${spec.ratio}) commercial visual matching spoken script.`,
        verbatim_script: cleanScript || null,
        voice_preset: voicePreset,
        speaking_rate_wpm: computedPacing.selectedWpm,
        estimated_natural_duration_sec:
          computedPacing.durationsSec.atSelectedWpm,
        ffmpeg_atempo_chain: computedPacing.ffmpegAtempoFilter,
        caption_safe_zone: spec.safeZone,
        compliance_preflight: {
          likeness_consent_verified: Boolean(consentVerified),
          safety_score: computedRights.safetyScore,
          verdict: computedRights.verdict,
          protected_brand_terms: normalizedBrands,
        },
      },
    },
    "short-video-clipper": {
      agent: "@short-video-clipper",
      priceUsdc: 0.5,
      marketUrl: NEAR_VIDEO_CLIPPER_URL,
      a2aEndpoint: "https://short-video-clipper.market.near.ai/a2a/v1",
      jobSpec: {
        asset_title: title,
        source_video_url: "https://www.youtube.com/watch?v=REPLACE_WITH_SOURCE_ID",
        output_aspect_ratio: spec.ratio,
        output_resolution: spec.resolution,
        target_clip_duration_sec: computedPacing.targetSec,
        anchor_to_most_replayed: true,
        zero_mid_sentence_cuts: true,
        burn_in_captions: true,
        caption_constraints: {
          max_cps: 20,
          max_chars_per_line: spec.safeZone.maxCharsPerLine,
          max_lines_per_cue: spec.safeZone.maxLines,
          safe_box_px: {
            xMin: spec.safeZone.xMin,
            xMax: spec.safeZone.xMax,
            yMin: spec.safeZone.yMin,
            yMax: spec.safeZone.yMax,
          },
          ass_play_res: `${spec.safeZone.assPlayResX}x${spec.safeZone.assPlayResY}`,
          ass_margin_v: spec.safeZone.assMarginV,
        },
        hook_script_reference: cleanScript || cleanBrief || null,
        protected_brand_terms: normalizedBrands,
      },
    },
    "multi-lang-video-dubber": {
      agent: "@multi-lang-video-dubber",
      priceUsdc: 0.65,
      marketUrl: NEAR_VIDEO_DUBBER_URL,
      a2aEndpoint: "https://multi-lang-video-dubber.market.near.ai/a2a/v1",
      jobSpec: {
        asset_title: title,
        source_media_url: "https://example.com/source-video.mp4",
        aspect_ratio: spec.ratio,
        resolution: spec.resolution,
        target_languages: normalizedLangs.length ? normalizedLangs : ["es", "de", "ja"],
        preserve_music_sfx_mid_side: true,
        sub_second_lip_and_phrase_sync: true,
        max_allowed_atempo: ATEMPO_MAX_SAFE,
        min_allowed_atempo: ATEMPO_MIN_SAFE,
        source_script_verbatim: cleanScript || null,
        source_target_duration_sec: computedPacing.targetSec,
        do_not_translate_brand_terms: normalizedBrands,
        deliverables: ["dubbed_mp4", "synced_srt"],
        compliance_preflight_score: computedRights.safetyScore,
      },
    },
  };

  return {
    ...spec,
    sampleCaptionLines,
    agentPayloads,
  };
}

/**
 * Runs the complete deterministic MediaBrief Studio audit across script pacing,
 * rights/consent safety, and multi-aspect provider JSON spec generation.
 */
export function auditMediaBrief(input = {}) {
  const title = String(input.title || "Media Production Brief").trim();
  const script = String(input.script ?? "");
  const brief = String(input.brief ?? input.visualBrief ?? "");

  if (!script.trim() && !brief.trim()) {
    return {
      ok: false,
      error:
        "Provide a spoken voiceover 'script' and/or a visual 'brief' to run MediaBrief Studio audit.",
    };
  }

  const ratio = normalizeAspectRatio(input.ratio || input.aspectRatio || "9:16");
  const targetSec =
    Number(input.targetSec ?? input.targetDurationSec) > 0
      ? Number(input.targetSec ?? input.targetDurationSec)
      : 30;
  const wpm = Number(input.wpm) > 0 ? Number(input.wpm) : DEFAULT_WPM;
  const consentVerified = Boolean(
    input.consentVerified === true ||
      input.consent === true ||
      input.consent === 1 ||
      input.consent === "1" ||
      String(input.consent || "").toLowerCase() === "true"
  );
  const ownedBrands = parseOwnedBrandsInput(
    input.ownedBrands ?? input.brandTerms ?? ""
  );
  const voicePreset = String(
    input.voicePreset || "en-US-AvaMultilingualNeural"
  ).trim();
  const targetAgentKey = [
    "pay-per-use-media-gen",
    "short-video-clipper",
    "multi-lang-video-dubber",
  ].includes(String(input.targetAgent || "").trim())
    ? String(input.targetAgent).trim()
    : "pay-per-use-media-gen";

  const pacing = calculateScriptPacing(script, { targetSec, wpm });
  const rightsAndConsent = scanMediaRightsAndConsent({
    script,
    brief,
    consentVerified,
    ownedBrands,
  });
  const aspectSpec = buildAspectAndProviderSpecs({
    title,
    script,
    brief,
    ratio,
    targetSec,
    wpm,
    voicePreset,
    targetLanguages: input.targetLanguages,
    ownedBrands,
    consentVerified,
    pacing,
    rights: rightsAndConsent,
  });

  const issues = [];
  if (pacing.pacingStatus === "TOO_LONG_ATEMPO_DISTORTION") {
    issues.push({
      severity: "HIGH",
      code: "SCRIPT_ATEMPO_DISTORTION_OVER_1_20X",
      message: pacing.recommendation,
    });
  } else if (pacing.pacingStatus === "TOO_SHORT_UNDERRUN") {
    issues.push({
      severity: "HIGH",
      code: "SCRIPT_ATEMPO_UNDERRUN_BELOW_0_85X",
      message: pacing.recommendation,
    });
  } else if (
    pacing.pacingStatus === "SLIGHTLY_OVER_TARGET" ||
    pacing.pacingStatus === "SLIGHTLY_UNDER_TARGET"
  ) {
    issues.push({
      severity: "LOW",
      code: pacing.pacingStatus,
      message: pacing.recommendation,
    });
  }

  for (const flag of rightsAndConsent.flags) {
    issues.push({
      severity: flag.severity,
      code: flag.ruleId,
      message: flag.message,
    });
  }

  // Overall production readiness combines rights safety (65% weight, hard-capped if blocked) + pacing (35%)
  let readinessScore = Math.round(
    rightsAndConsent.safetyScore * 0.65 + pacing.pacingScore * 0.35
  );
  if (rightsAndConsent.verdict === "BLOCKED_PREFLIGHT_RISK") {
    readinessScore = Math.min(readinessScore, rightsAndConsent.safetyScore);
  }
  readinessScore = Math.max(0, Math.min(100, readinessScore));

  const verdict =
    rightsAndConsent.verdict === "BLOCKED_PREFLIGHT_RISK"
      ? "BLOCKED_RIGHTS_OR_CONSENT"
      : pacing.atempoDistortionRisk || pacing.atempoUnderrunRisk
        ? "PACING_REVISION_NEEDED"
        : readinessScore >= 88
          ? "PRODUCTION_READY"
          : "REVIEW_RECOMMENDED";

  const mdLines = [
    `# MediaBrief Studio — Pre-Flight Pacing & Compliance Report`,
    `- **Asset:** \`${title}\` · **Overall Readiness:** **${readinessScore}/100** (\`${verdict}\`)`,
    `- **Safety & Rights Score:** **${rightsAndConsent.safetyScore}/100** (\`${rightsAndConsent.verdict}\` · Consent Verified: \`${consentVerified}\`)`,
    `- **Canvas & Safe Zone:** \`${aspectSpec.ratio}\` (\`${aspectSpec.resolution}\`) · Safe Caption Width \`<= ${aspectSpec.safeZone.maxCharsPerLine} chars\`, \`<= ${aspectSpec.safeZone.maxLines} lines\``,
    `- **Script Pacing (${pacing.selectedWpm} WPM):** \`${pacing.counts.totalWords}\` words (\`${pacing.counts.syllableCount}\` syllables${pacing.counts.hasCjk ? `, ${pacing.counts.cjkChars} CJK chars` : ""}) -> **${pacing.durationsSec.atSelectedWpm.toFixed(2)}s** vs Target **${pacing.targetSec.toFixed(1)}s**`,
    `- **WPM Matrix:** 135 WPM = \`${pacing.durationsSec.wpm135.toFixed(2)}s\` · 150 WPM = \`${pacing.durationsSec.wpm150.toFixed(2)}s\` · 165 WPM = \`${pacing.durationsSec.wpm165.toFixed(2)}s\``,
    `- **FFmpeg Tempo:** \`${pacing.ffmpegAtempoFilter}\` (\`${pacing.requiredAtempo.toFixed(3)}x\`) — ${pacing.recommendation}`,
  ];

  if (issues.length > 0) {
    mdLines.push("", "## Pre-Flight Diagnostics");
    for (const iss of issues) {
      mdLines.push(`- **[${iss.severity}]** \`${iss.code}\`: ${iss.message}`);
    }
  } else {
    mdLines.push(
      "",
      "## Pre-Flight Diagnostics",
      "- ✓ Zero rights/consent blocks and voiceover duration lands inside the ±0.5s golden window."
    );
  }

  return {
    ok: true,
    title,
    readinessScore,
    verdict,
    pacing,
    rightsAndConsent,
    aspectSpec: {
      ratio: aspectSpec.ratio,
      resolution: aspectSpec.resolution,
      width: aspectSpec.width,
      height: aspectSpec.height,
      label: aspectSpec.label,
      platforms: aspectSpec.platforms,
      safeZone: aspectSpec.safeZone,
      sampleCaptionLines: aspectSpec.sampleCaptionLines,
    },
    targetAgent: targetAgentKey,
    selectedAgentSpec: aspectSpec.agentPayloads[targetAgentKey],
    agentPayloads: aspectSpec.agentPayloads,
    issues,
    markdownReport: mdLines.join("\n"),
  };
}

/**
 * Parses pipe-separated (`Title | Ratio | TargetSec | Brief | Script`) or JSON array campaign inputs.
 */
export function parseBatchMediaBriefs(rawInput) {
  if (Array.isArray(rawInput)) {
    return rawInput;
  }
  const text = String(rawInput ?? "").trim();
  if (!text) return [];

  if (text.startsWith("[")) {
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) {
      throw new Error("JSON campaign input must be an array of media brief objects.");
    }
    return parsed;
  }

  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((line, idx) => {
      const parts = line.split("|").map((p) => p.trim());
      if (parts.length >= 5) {
        return {
          title: parts[0] || `Asset_${idx + 1}`,
          ratio: parts[1] || "9:16",
          targetSec: Number(parts[2]) || 30,
          brief: parts[3] || "",
          script: parts.slice(4).join(" | "),
        };
      }
      if (parts.length === 4) {
        return {
          title: parts[0] || `Asset_${idx + 1}`,
          ratio: parts[1] || "9:16",
          targetSec: Number(parts[2]) || 30,
          brief: "",
          script: parts[3],
        };
      }
      return {
        title: `Asset_${idx + 1}`,
        ratio: "9:16",
        targetSec: 30,
        brief: "",
        script: line,
      };
    });
}

/**
 * Pro 25-Asset Campaign Batch Matrix processor.
 */
export function runBatchMediaBriefAudit(entriesInput, options = {}) {
  const entries = parseBatchMediaBriefs(entriesInput);
  if (entries.length === 0) {
    throw new Error(
      "Provide 1 to 25 media briefs/scripts for Pro Campaign Batch Matrix processing."
    );
  }
  if (entries.length > MAX_BATCH_MEDIA_BRIEFS) {
    throw new Error(
      `Batch processing supports up to ${MAX_BATCH_MEDIA_BRIEFS} media assets per campaign (received ${entries.length}).`
    );
  }

  const reports = entries.map((entry, idx) => {
    const merged = {
      title: entry?.title || `Campaign_Asset_${idx + 1}`,
      ratio: entry?.ratio || options.ratio || "9:16",
      targetSec: entry?.targetSec ?? options.targetSec ?? 30,
      wpm: entry?.wpm ?? options.wpm ?? DEFAULT_WPM,
      consentVerified:
        entry?.consentVerified !== undefined
          ? entry.consentVerified
          : Boolean(options.consentVerified),
      ownedBrands: entry?.ownedBrands ?? options.ownedBrands ?? "",
      targetAgent: entry?.targetAgent || options.targetAgent || "pay-per-use-media-gen",
      brief: entry?.brief ?? "",
      script: entry?.script ?? "",
    };
    return auditMediaBrief(merged);
  });

  const valid = reports.filter((r) => r.ok);
  const avgReadiness =
    valid.length > 0
      ? Math.round(valid.reduce((s, r) => s + r.readinessScore, 0) / valid.length)
      : 0;
  const avgSafety =
    valid.length > 0
      ? Math.round(
          valid.reduce((s, r) => s + r.rightsAndConsent.safetyScore, 0) / valid.length
        )
      : 0;
  const blockedCount = valid.filter(
    (r) => r.rightsAndConsent.verdict === "BLOCKED_PREFLIGHT_RISK"
  ).length;
  const distortionCount = valid.filter(
    (r) => r.pacing.atempoDistortionRisk || r.pacing.atempoUnderrunRisk
  ).length;

  return {
    ok: true,
    processedAtUtc: new Date().toISOString(),
    totalAssets: reports.length,
    okAssets: valid.length,
    averageReadinessScore: avgReadiness,
    averageSafetyScore: avgSafety,
    blockedAssetsCount: blockedCount,
    pacingOutlierCount: distortionCount,
    estimatedMediaGenBudgetUsdc: Number((valid.length * 0.45).toFixed(2)),
    reports,
  };
}

/**
 * Exports formula-injection-guarded RFC-4180 CSV for Pro 25-Asset Campaign Batch Matrix.
 */
export function exportBatchMediaBriefCsv(batchPack) {
  const headers = [
    "asset_title",
    "aspect_ratio",
    "resolution",
    "words",
    "syllables",
    "est_duration_150wpm_sec",
    "target_sec",
    "ffmpeg_atempo",
    "word_delta_golden",
    "pacing_status",
    "safety_score",
    "rights_verdict",
    "readiness_score",
    "overall_verdict",
  ];
  const rows = [headers.join(",")];
  for (const r of batchPack?.reports || []) {
    if (!r.ok) continue;
    rows.push(
      [
        guardCsvCell(r.title),
        guardCsvCell(r.aspectSpec.ratio),
        guardCsvCell(r.aspectSpec.resolution),
        r.pacing.counts.totalWords,
        r.pacing.counts.syllableCount,
        r.pacing.durationsSec.wpm150.toFixed(2),
        r.pacing.targetSec.toFixed(1),
        r.pacing.requiredAtempo.toFixed(3),
        r.pacing.wordDelta,
        guardCsvCell(r.pacing.pacingStatus),
        r.rightsAndConsent.safetyScore,
        guardCsvCell(r.rightsAndConsent.verdict),
        r.readinessScore,
        guardCsvCell(r.verdict),
      ].join(",")
    );
  }
  return `${rows.join("\n")}\n`;
}

/**
 * Parses URL query parameters (?script=...&targetSec=...&ratio=9:16&consent=0) and #brief= hash.
 */
export function parseMediaStudioQueryParams(searchStr = "", hashStr = "") {
  const sp = new URLSearchParams(String(searchStr || "").replace(/^\?/, ""));
  const sample = sp.get("sample")?.trim() || null;
  const script = sp.has("script") ? sp.get("script") : null;
  const brief = sp.has("brief") ? sp.get("brief") : null;
  const targetSec =
    sp.has("targetSec") && Number(sp.get("targetSec")) > 0
      ? Number(sp.get("targetSec"))
      : null;
  const wpm =
    sp.has("wpm") && Number(sp.get("wpm")) > 0 ? Number(sp.get("wpm")) : DEFAULT_WPM;
  const ratio = sp.has("ratio") ? normalizeAspectRatio(sp.get("ratio")) : "9:16";

  const consentRaw = (sp.get("consent") ?? "0").trim().toLowerCase();
  const consentVerified =
    consentRaw === "1" || consentRaw === "true" || consentRaw === "yes";

  const ownedBrands = sp.get("brands")?.trim() || "";
  const agentRaw = (sp.get("agent") || "").trim();
  const targetAgent = [
    "pay-per-use-media-gen",
    "short-video-clipper",
    "multi-lang-video-dubber",
  ].includes(agentRaw)
    ? agentRaw
    : "pay-per-use-media-gen";

  let hashPayload = null;
  const cleanHash = String(hashStr || "").replace(/^#/, "");
  if (cleanHash.startsWith("brief=")) {
    try {
      hashPayload = JSON.parse(decodeBase64UrlUtf8(cleanHash.slice(6)));
    } catch {
      hashPayload = null;
    }
  }

  return {
    sample,
    script,
    brief,
    targetSec,
    wpm,
    ratio,
    consentVerified,
    ownedBrands,
    targetAgent,
    hashPayload,
  };
}

export function buildMediaBriefInvoicePayload(reportOrBatch = null) {
  const inv = createDefaultInvoice();
  inv.businessName = "ForgeSuite Creative Media Ops";
  inv.clientName = "Brand & Performance Marketing Team";
  inv.currency = "USDC";
  const isBatch = Boolean(
    reportOrBatch?.reports && Array.isArray(reportOrBatch.reports)
  );
  if (isBatch) {
    const count = reportOrBatch.totalAssets || 10;
    inv.items = [
      {
        description: `Multi-Format AI Ad Production, Script Pacing QC & Rights Clearance (${count} campaign assets)`,
        qty: 1,
        unitPrice: 240,
      },
      {
        description: "9:16 / 1:1 / 16:9 / 4:5 Safe-Zone Mastering & Verbatim Neural Voiceovers",
        qty: 1,
        unitPrice: 120,
      },
    ];
  } else {
    const res = reportOrBatch?.aspectSpec?.resolution || "1080x1920";
    inv.items = [
      {
        description: `AI Video, Studio Product Visual & Verbatim Voiceover Production (${res})`,
        qty: 1,
        unitPrice: 135,
      },
    ];
  }
  return inv;
}

export function buildMediaBriefSowState(reportOrBatch = null) {
  const isBatch = Boolean(
    reportOrBatch?.reports && Array.isArray(reportOrBatch.reports)
  );
  return {
    projectTitle: isBatch
      ? `Multi-Aspect AI Creative Campaign, Voiceover Sync & Rights Pre-Flight (${reportOrBatch.totalAssets} Assets)`
      : "AI Product Visuals, 9:16 Short-Form Video & Verbatim Voiceover Sprint",
    providerName: "ForgeSuite MediaBrief Studio",
    clientName: "Growth & Creative Marketing Lead",
    totalBudget: isBatch ? 760 : 450,
    revisionsIncluded: 2,
    noticeDays: 5,
    settlementRail: "sol-usdc",
    deliverables: [
      "- Script-to-duration locked voiceovers within ±0.5s target window (0.85x <= FFmpeg atempo <= 1.20x)",
      "- Pre-flight cleared 1:1 (1024x1024), 9:16 (1080x1920), 16:9 (1920x1080), and 4:5 (1080x1350) creative assets",
      "- Verified likeness consent & trademark hygiene dossier + mobile safe-zone burned captions",
    ].join("\n"),
    milestones: [
      {
        title: "M1: Script Pacing Lock, Rights/Consent Pre-Flight & Storyboard Spec",
        percent: 40,
        due: "On kickoff",
      },
      {
        title: "M2: Final Multi-Aspect Renders, Verbatim Voiceover & Safe-Zone Captions",
        percent: 60,
        due: "Final delivery",
      },
    ],
  };
}

export function isMediaStudioProUnlocked() {
  return (
    hasUnlockedTier("BUNDLE") ||
    hasUnlockedTier("AS") ||
    hasUnlockedTier("CB") ||
    getStoredLicenses().length > 0
  );
}

/* ============================================================================
 * Browser UI Controller for mediastudio.html
 * ========================================================================== */

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function downloadTextFile(filename, content, mime = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function initMediaBriefStudio() {
  if (
    typeof document === "undefined" ||
    document.body?.dataset?.page !== "mediastudio"
  ) {
    return;
  }

  const titleEl = document.getElementById("msAssetTitle");
  const briefEl = document.getElementById("msVisualBrief");
  const scriptEl = document.getElementById("msScriptInput");
  const targetSecEl = document.getElementById("msTargetSec");
  const wpmEl = document.getElementById("msWpmSelect");
  const ratioEl = document.getElementById("msRatioSelect");
  const brandsEl = document.getElementById("msOwnedBrands");
  const consentEl = document.getElementById("msConsentCheck");

  const runBtn = document.getElementById("msAuditBtn");
  const shareBtn = document.getElementById("msShareBtn");
  const sendToSrtBtn = document.getElementById("msOpenSrtLabBtn");
  const statusEl = document.getElementById("msStatusMsg");

  const verdictBadgeEl = document.getElementById("msVerdictBadge");
  const copyMdBtn = document.getElementById("msCopyMdBtn");
  const metricsGridEl = document.getElementById("msMetricsGrid");
  const wpmTableBodyEl = document.getElementById("msWpmBody");

  // Live Multi-Aspect Canvas Preview
  const canvasFrameEl = document.getElementById("msCanvasFrame");
  const canvasTopZoneEl = document.getElementById("msCanvasTopZone");
  const canvasRightZoneEl = document.getElementById("msCanvasRightZone");
  const canvasSafeBoxEl = document.getElementById("msCanvasSafeBox");
  const canvasCaptionEl = document.getElementById("msCanvasCaption");
  const canvasBottomZoneEl = document.getElementById("msCanvasBottomZone");
  const canvasMetaEl = document.getElementById("msCanvasMeta");

  // Agent Spec JSON Tabs
  const agentTabs = Array.from(document.querySelectorAll("[data-ms-agent-tab]"));
  const jsonSpecOutEl = document.getElementById("msAgentJsonOutput");
  const copyJsonBtn = document.getElementById("msCopyJsonBtn");
  const downloadJsonBtn = document.getElementById("msDownloadJsonBtn");
  const hireSelectedAgentLink = document.getElementById("msHireSelectedAgentLink");

  const issuesBodyEl = document.getElementById("msIssuesBody");

  // Handoffs
  const sendInvoiceBtn = document.getElementById("msSendInvoiceBtn");
  const sendSowBtn = document.getElementById("msSendSowBtn");

  // Pro 25-Asset Batch Matrix
  const proBadgeEl = document.getElementById("msProBadge");
  const proLockBannerEl = document.getElementById("msProLockBanner");
  const batchInputAreaEl = document.getElementById("msBatchInputArea");
  const batchDemoBtn = document.getElementById("msBatchDemoBtn");
  const batchFileInputEl = document.getElementById("msBatchFileInput");
  const batchRunBtn = document.getElementById("msBatchRunBtn");
  const batchCsvBtn = document.getElementById("msBatchCsvBtn");
  const batchJsonBtn = document.getElementById("msBatchJsonBtn");
  const batchStatusEl = document.getElementById("msBatchStatusMsg");
  const batchBodyEl = document.getElementById("msBatchBody");

  let lastReport = null;
  let lastBatchPack = null;
  let activeAgentTab = "pay-per-use-media-gen";

  function syncProUi() {
    const unlocked = isMediaStudioProUnlocked();
    if (proBadgeEl) {
      proBadgeEl.textContent = unlocked
        ? "PRO ACTIVE · 25-ASSET CAMPAIGN MATRIX UNLOCKED ✓"
        : "PRO FEATURE · $15 PRO / $19 AUTOSHORTS / $35 BUNDLE";
      proBadgeEl.className = `fs-badge ${unlocked ? "fs-badge-success" : "fs-badge-warn"}`;
    }
    if (proLockBannerEl) {
      proLockBannerEl.hidden = unlocked;
    }
    if (batchRunBtn) {
      batchRunBtn.textContent = unlocked
        ? "Run 25-Asset Campaign Batch Audit"
        : "Unlock 25-Asset Batch Matrix — Pro ($15 / $19 / $35)";
    }
  }

  bindCheckoutTriggers({ onUnlocked: syncProUi });
  window.addEventListener("forgesuite:license-updated", syncProUi);

  const navBundleBtn = document.getElementById("msBundleBtn");
  if (navBundleBtn) {
    navBundleBtn.addEventListener("click", () =>
      openCheckoutModal("BUNDLE", { onUnlocked: syncProUi })
    );
  }
  const activateKeyBtn = document.getElementById("msActivateKeyBtn");
  if (activateKeyBtn) {
    activateKeyBtn.addEventListener("click", () =>
      openCheckoutModal("CB", { initialTab: "license", onUnlocked: syncProUi })
    );
  }

  const themeBtn = document.getElementById("themeToggleBtn");
  if (themeBtn) {
    let saved = "dark";
    try {
      saved = window.localStorage.getItem("forgesuite_theme") || "dark";
    } catch {}
    document.documentElement.dataset.theme = saved;
    themeBtn.textContent = saved === "light" ? "☀ Light" : "🌙 Dark";
    themeBtn.addEventListener("click", () => {
      const next =
        document.documentElement.dataset.theme === "light" ? "dark" : "light";
      document.documentElement.dataset.theme = next;
      try {
        window.localStorage.setItem("forgesuite_theme", next);
      } catch {}
      themeBtn.textContent = next === "light" ? "☀ Light" : "🌙 Dark";
    });
  }

  function renderAgentSpecPane() {
    if (!lastReport?.ok || !jsonSpecOutEl) return;
    const payload =
      lastReport.agentPayloads[activeAgentTab] ||
      lastReport.agentPayloads["pay-per-use-media-gen"];
    jsonSpecOutEl.value = JSON.stringify(payload, null, 2);
    if (hireSelectedAgentLink) {
      hireSelectedAgentLink.href = payload.marketUrl;
      hireSelectedAgentLink.textContent = `Hire ${payload.agent} ($${payload.priceUsdc.toFixed(2)} USDC) ↗`;
    }
  }

  function renderCanvasPreview(report) {
    if (!canvasFrameEl || !report?.ok) return;
    const spec = ASPECT_RATIO_SPECS[report.aspectSpec.ratio] || ASPECT_RATIO_SPECS["9:16"];
    const sz = spec.safeZone;
    canvasFrameEl.style.aspectRatio = spec.cssAspect;
    canvasFrameEl.style.width = `${spec.previewWidthPx}px`;

    if (canvasTopZoneEl) {
      canvasTopZoneEl.style.height = `${sz.topDangerPct}%`;
      canvasTopZoneEl.textContent = `Top UI (${sz.topDangerPct}%)`;
    }
    if (canvasRightZoneEl) {
      canvasRightZoneEl.style.width = `${Math.max(22, Math.round((sz.rightDangerPct / 100) * spec.previewWidthPx))}px`;
      canvasRightZoneEl.style.top = `${sz.topDangerPct + 8}%`;
      canvasRightZoneEl.style.bottom = `${sz.bottomDangerPct + 2}%`;
    }
    if (canvasBottomZoneEl) {
      canvasBottomZoneEl.style.height = `${sz.bottomDangerPct}%`;
      canvasBottomZoneEl.innerHTML = `<strong>${escapeHtml(spec.ratio)} · ${escapeHtml(spec.resolution)}</strong><span>Bottom UI Danger (${sz.bottomDangerPct}%)</span>`;
    }
    if (canvasSafeBoxEl) {
      canvasSafeBoxEl.style.bottom = `${sz.bottomDangerPct + 2}%`;
      canvasSafeBoxEl.style.right = `${Math.max(26, Math.round((sz.rightDangerPct / 100) * spec.previewWidthPx) + 6)}px`;
    }
    if (canvasCaptionEl) {
      canvasCaptionEl.innerHTML = report.aspectSpec.sampleCaptionLines
        .map((line) => `<div>${escapeHtml(line)}</div>`)
        .join("");
    }
    if (canvasMetaEl) {
      canvasMetaEl.innerHTML = `
        <div><strong>Resolution:</strong> <code>${escapeHtml(spec.resolution)}</code> (<code>${escapeHtml(spec.ratio)}</code>)</div>
        <div><strong>Safe Box:</strong> <code>X=${sz.xMin}..${sz.xMax}px</code>, <code>Y=${sz.yMin}..${sz.yMax}px</code></div>
        <div><strong>Caption Cap:</strong> <code>&lt;= ${sz.maxCharsPerLine} chars/line</code> · <code>&lt;= ${sz.maxLines} lines</code></div>
        <div><strong>FFmpeg Tempo:</strong> <code>${escapeHtml(report.pacing.ffmpegAtempoFilter)}</code></div>
      `;
    }
  }

  function executeAudit() {
    const report = auditMediaBrief({
      title: titleEl?.value || "Media Production Brief",
      brief: briefEl?.value || "",
      script: scriptEl?.value || "",
      targetSec: Number(targetSecEl?.value || 30),
      wpm: Number(wpmEl?.value || DEFAULT_WPM),
      ratio: ratioEl?.value || "9:16",
      ownedBrands: brandsEl?.value || "",
      consentVerified: Boolean(consentEl?.checked),
      targetAgent: activeAgentTab,
    });
    lastReport = report;

    if (!report.ok) {
      if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = report.error;
      }
      return;
    }

    if (verdictBadgeEl) {
      verdictBadgeEl.textContent = `${report.readinessScore}/100 · ${report.verdict}`;
      verdictBadgeEl.className =
        report.verdict === "PRODUCTION_READY"
          ? "fs-badge fs-badge-success"
          : report.verdict.startsWith("BLOCKED")
            ? "fs-badge fs-badge-warn"
            : "fs-badge fs-badge-accent";
    }

    const p = report.pacing;
    const r = report.rightsAndConsent;

    if (metricsGridEl) {
      const deltaBadge = p.inGoldenWindow
        ? "Golden Window ±0.5s ✓"
        : p.wordsToTrim > 0
          ? `Trim ~${p.wordsToTrim} word(s)`
          : `Add ~${p.wordsToAdd} word(s)`;
      metricsGridEl.innerHTML = `
        <div class="fs-rail-box" style="padding:12px;">
          <span class="fs-field-label">Words &amp; Syllables</span>
          <strong style="font-size:1.03rem;">${p.counts.totalWords} words · ${p.counts.syllableCount} syllables${p.counts.hasCjk ? ` (${p.counts.cjkChars} CJK)` : ""}</strong>
        </div>
        <div class="fs-rail-box" style="padding:12px;">
          <span class="fs-field-label">Duration vs ${p.targetSec.toFixed(1)}s Target</span>
          <strong style="font-size:1.03rem;color:${p.inGoldenWindow ? "var(--emerald)" : p.atempoDistortionRisk || p.atempoUnderrunRisk ? "var(--amber)" : "var(--text)"};">${p.durationsSec.atSelectedWpm.toFixed(2)}s (${deltaBadge})</strong>
        </div>
        <div class="fs-rail-box" style="padding:12px;">
          <span class="fs-field-label">FFmpeg <code>atempo</code> Ratio</span>
          <strong style="font-size:1.03rem;color:${p.atempoDistortionRisk || p.atempoUnderrunRisk ? "var(--danger)" : "var(--emerald)"};">${p.requiredAtempo.toFixed(3)}x ${p.atempoDistortionRisk ? "⚠ >1.20x Distortion" : p.atempoUnderrunRisk ? "⚠ <0.85x Drag" : "✓ Clean"}</strong>
        </div>
        <div class="fs-rail-box" style="padding:12px;">
          <span class="fs-field-label">Rights &amp; Consent Safety</span>
          <strong style="font-size:1.03rem;color:${r.safetyScore >= 90 ? "var(--emerald)" : r.safetyScore >= 65 ? "var(--amber)" : "var(--danger)"};">${r.safetyScore}/100 · ${escapeHtml(r.verdict)}</strong>
        </div>
      `;
    }

    if (wpmTableBodyEl) {
      const rows = [
        { label: "135 WPM (Calm / Luxury Storytelling)", wpm: 135, sec: p.durationsSec.wpm135 },
        { label: "150 WPM (Broadcast / Neural TTS Standard)", wpm: 150, sec: p.durationsSec.wpm150 },
        { label: "165 WPM (Energetic TikTok / Reels Hook)", wpm: 165, sec: p.durationsSec.wpm165 },
      ];
      wpmTableBodyEl.innerHTML = rows
        .map((row) => {
          const atempo = p.counts.totalWords > 0 ? row.sec / p.targetSec : 0;
          const inGold = Math.abs(row.sec - p.targetSec) <= 0.5;
          const status =
            p.counts.totalWords === 0
              ? "Visual-Only"
              : inGold
                ? "Golden ±0.5s ✓"
                : atempo > 1.2
                  ? "Too Long (>1.20x)"
                  : atempo < 0.85
                    ? "Too Short (<0.85x)"
                    : "Safe atempo";
          return `<tr>
            <td><strong>${escapeHtml(row.label)}</strong></td>
            <td><code>${row.sec.toFixed(2)}s</code></td>
            <td><code>${atempo.toFixed(2)}x</code></td>
            <td><span class="fs-badge ${inGold ? "fs-badge-success" : atempo > 1.2 || (atempo > 0 && atempo < 0.85) ? "fs-badge-warn" : "fs-badge-muted"}">${escapeHtml(status)}</span></td>
          </tr>`;
        })
        .join("");
    }

    if (issuesBodyEl) {
      if (report.issues.length === 0) {
        issuesBodyEl.innerHTML = `<tr><td colspan="3" style="color:var(--emerald);font-weight:600;">✓ Pre-flight passed: script hits the ±0.5s golden duration window and cleared all likeness, copyright &amp; brand safety checks!</td></tr>`;
      } else {
        issuesBodyEl.innerHTML = report.issues
          .map(
            (iss) => `<tr>
              <td><span class="fs-badge ${iss.severity === "CRITICAL" || iss.severity === "HIGH" ? "fs-badge-warn" : "fs-badge-muted"}">${escapeHtml(iss.severity)}</span></td>
              <td><code>${escapeHtml(iss.code)}</code></td>
              <td>${escapeHtml(iss.message)}</td>
            </tr>`
          )
          .join("");
      }
    }

    renderCanvasPreview(report);
    renderAgentSpecPane();

    if (statusEl) {
      statusEl.className = "fs-status-msg is-success";
      statusEl.textContent = `${p.recommendation} Safety: ${r.safetyScore}/100 (${r.verdict}).`;
    }
  }

  document.querySelectorAll("[data-ms-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.getAttribute("data-ms-sample");
      const preset = MEDIASTUDIO_SAMPLES[key];
      if (!preset) return;
      if (titleEl) titleEl.value = preset.title;
      if (briefEl) briefEl.value = preset.brief;
      if (scriptEl) scriptEl.value = preset.script;
      if (targetSecEl) targetSecEl.value = String(preset.targetSec);
      if (wpmEl) wpmEl.value = String(preset.wpm);
      if (ratioEl) ratioEl.value = preset.ratio;
      if (brandsEl) brandsEl.value = preset.ownedBrands;
      if (consentEl) consentEl.checked = Boolean(preset.consentVerified);
      activeAgentTab = preset.targetAgent || "pay-per-use-media-gen";
      agentTabs.forEach((b) => {
        b.className =
          b.getAttribute("data-ms-agent-tab") === activeAgentTab
            ? "fs-btn fs-btn-sm fs-btn-primary"
            : "fs-btn fs-btn-sm fs-btn-secondary";
      });
      executeAudit();
    });
  });

  agentTabs.forEach((tabBtn) => {
    tabBtn.addEventListener("click", () => {
      activeAgentTab =
        tabBtn.getAttribute("data-ms-agent-tab") || "pay-per-use-media-gen";
      agentTabs.forEach((b) => {
        b.className =
          b === tabBtn
            ? "fs-btn fs-btn-sm fs-btn-primary"
            : "fs-btn fs-btn-sm fs-btn-secondary";
      });
      renderAgentSpecPane();
    });
  });

  if (runBtn) runBtn.addEventListener("click", executeAudit);
  [targetSecEl, wpmEl, ratioEl, consentEl].forEach((el) => {
    if (el) el.addEventListener("change", executeAudit);
  });
  if (scriptEl) {
    scriptEl.addEventListener("input", () => {
      executeAudit();
    });
  }

  if (shareBtn) {
    shareBtn.addEventListener("click", async () => {
      const params = new URLSearchParams();
      if (scriptEl?.value) params.set("script", scriptEl.value.slice(0, 600));
      params.set("targetSec", String(Number(targetSecEl?.value || 30)));
      params.set("ratio", normalizeAspectRatio(ratioEl?.value || "9:16"));
      params.set("consent", consentEl?.checked ? "1" : "0");
      if (brandsEl?.value) params.set("brands", brandsEl.value);
      const url = `${window.location.origin}${window.location.pathname}?${params.toString()}`;
      window.history.replaceState({}, "", `?${params.toString()}`);
      const prev = shareBtn.textContent;
      try {
        await navigator.clipboard.writeText(url);
        shareBtn.textContent = "Share URL Copied ✓";
        setTimeout(() => {
          shareBtn.textContent = prev;
        }, 1600);
      } catch {}
    });
  }

  if (sendToSrtBtn) {
    sendToSrtBtn.addEventListener("click", () => {
      const txt = scriptEl?.value?.trim() || "";
      if (!txt) {
        window.location.href = "srtlab.html";
        return;
      }
      const encoded = encodeBase64UrlUtf8(txt);
      window.location.href = `srtlab.html#srt=${encoded}`;
    });
  }

  if (copyMdBtn) {
    copyMdBtn.addEventListener("click", async () => {
      if (!lastReport?.markdownReport) return;
      const prev = copyMdBtn.textContent;
      try {
        await navigator.clipboard.writeText(lastReport.markdownReport);
        copyMdBtn.textContent = "Copied MD ✓";
        setTimeout(() => {
          copyMdBtn.textContent = prev;
        }, 1600);
      } catch {}
    });
  }

  if (copyJsonBtn) {
    copyJsonBtn.addEventListener("click", async () => {
      if (!jsonSpecOutEl?.value) return;
      const prev = copyJsonBtn.textContent;
      try {
        await navigator.clipboard.writeText(jsonSpecOutEl.value);
        copyJsonBtn.textContent = "Copied Spec ✓";
        setTimeout(() => {
          copyJsonBtn.textContent = prev;
        }, 1600);
      } catch {}
    });
  }

  if (downloadJsonBtn) {
    downloadJsonBtn.addEventListener("click", () => {
      if (!jsonSpecOutEl?.value) return;
      downloadTextFile(
        `mediabrief-${activeAgentTab}-spec.json`,
        jsonSpecOutEl.value,
        "application/json;charset=utf-8"
      );
    });
  }

  if (sendInvoiceBtn) {
    sendInvoiceBtn.addEventListener("click", () => {
      const inv = buildMediaBriefInvoicePayload(lastBatchPack || lastReport);
      window.location.href = `cryptobill.html#inv=${encodeInvoicePayload(inv)}`;
    });
  }

  if (sendSowBtn) {
    sendSowBtn.addEventListener("click", () => {
      const sow = buildMediaBriefSowState(lastBatchPack || lastReport);
      const encoded = encodeBase64UrlUtf8(JSON.stringify(sow));
      window.location.href = `sowbuilder.html#sow=${encoded}`;
    });
  }

  if (batchDemoBtn && batchInputAreaEl) {
    batchDemoBtn.addEventListener("click", () => {
      batchInputAreaEl.value = DEMO_CAMPAIGN_BATCH.map(
        (item) =>
          `${item.title} | ${item.ratio} | ${item.targetSec} | ${item.brief} | ${item.script}`
      ).join("\n");
      if (batchStatusEl) {
        batchStatusEl.className = "fs-status-msg is-success";
        batchStatusEl.textContent =
          "Loaded 4-asset multi-format campaign (9:16 30s spot, 1:1 8s square, 9:16 overlong hook, 4:5 rights block).";
      }
    });
  }

  if (batchFileInputEl && batchInputAreaEl) {
    batchFileInputEl.addEventListener("change", async () => {
      const f = batchFileInputEl.files?.[0];
      if (!f) return;
      batchInputAreaEl.value = await f.text();
      if (batchStatusEl) {
        batchStatusEl.className = "fs-status-msg is-loading";
        batchStatusEl.textContent = `Loaded ${f.name} into Campaign Batch Matrix editor.`;
      }
    });
  }

  if (batchRunBtn) {
    batchRunBtn.addEventListener("click", () => {
      if (!isMediaStudioProUnlocked()) {
        openCheckoutModal("BUNDLE", { onUnlocked: syncProUi });
        return;
      }
      if (batchInputAreaEl && !batchInputAreaEl.value.trim()) {
        batchInputAreaEl.value = DEMO_CAMPAIGN_BATCH.map(
          (item) =>
            `${item.title} | ${item.ratio} | ${item.targetSec} | ${item.brief} | ${item.script}`
        ).join("\n");
      }
      try {
        const pack = runBatchMediaBriefAudit(batchInputAreaEl?.value || "", {
          wpm: Number(wpmEl?.value || DEFAULT_WPM),
          consentVerified: Boolean(consentEl?.checked),
          ownedBrands: brandsEl?.value || "",
          targetAgent: activeAgentTab,
        });
        lastBatchPack = pack;
        if (batchBodyEl) {
          batchBodyEl.innerHTML = pack.reports
            .map(
              (r) => `<tr>
                <td><strong>${escapeHtml(r.title)}</strong> <small class="inv-muted">(${escapeHtml(r.aspectSpec.ratio)} · ${escapeHtml(r.aspectSpec.resolution)})</small></td>
                <td>${r.pacing.counts.totalWords}w · <code>${r.pacing.durationsSec.wpm150.toFixed(1)}s/${r.pacing.targetSec}s</code></td>
                <td><code>${r.pacing.requiredAtempo.toFixed(2)}x</code></td>
                <td><span class="fs-badge ${r.rightsAndConsent.safetyScore >= 90 ? "fs-badge-success" : "fs-badge-warn"}">${r.rightsAndConsent.safetyScore}/100</span></td>
                <td><span class="fs-badge ${r.verdict === "PRODUCTION_READY" ? "fs-badge-success" : "fs-badge-warn"}">${escapeHtml(r.verdict)}</span></td>
              </tr>`
            )
            .join("");
        }
        if (batchCsvBtn) batchCsvBtn.disabled = false;
        if (batchJsonBtn) batchJsonBtn.disabled = false;
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-success";
          batchStatusEl.textContent = `Audited ${pack.okAssets}/${pack.totalAssets} campaign assets · Avg Readiness ${pack.averageReadinessScore}/100 · Blocked: ${pack.blockedAssetsCount} · Est. @pay-per-use-media-gen run: $${pack.estimatedMediaGenBudgetUsdc.toFixed(2)} USDC.`;
        }
      } catch (err) {
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-error";
          batchStatusEl.textContent =
            err instanceof Error ? err.message : String(err);
        }
      }
    });
  }

  if (batchCsvBtn) {
    batchCsvBtn.addEventListener("click", () => {
      if (!isMediaStudioProUnlocked() || !lastBatchPack) return;
      downloadTextFile(
        "mediabrief-campaign-matrix.csv",
        exportBatchMediaBriefCsv(lastBatchPack),
        "text/csv;charset=utf-8"
      );
    });
  }

  if (batchJsonBtn) {
    batchJsonBtn.addEventListener("click", () => {
      if (!isMediaStudioProUnlocked() || !lastBatchPack) return;
      downloadTextFile(
        "mediabrief-campaign-manifest.json",
        JSON.stringify(
          { suite: "ForgeSuite MediaBrief Studio Pro", ...lastBatchPack },
          null,
          2
        ),
        "application/json;charset=utf-8"
      );
    });
  }

  syncProUi();

  const qp = parseMediaStudioQueryParams(
    window.location.search,
    window.location.hash
  );
  if (qp.hashPayload && typeof qp.hashPayload === "object") {
    if (titleEl && qp.hashPayload.title) titleEl.value = qp.hashPayload.title;
    if (briefEl && qp.hashPayload.brief) briefEl.value = qp.hashPayload.brief;
    if (scriptEl && qp.hashPayload.script) scriptEl.value = qp.hashPayload.script;
    if (targetSecEl && qp.hashPayload.targetSec) {
      targetSecEl.value = String(qp.hashPayload.targetSec);
    }
    if (ratioEl && qp.hashPayload.ratio) {
      ratioEl.value = normalizeAspectRatio(qp.hashPayload.ratio);
    }
    if (consentEl) consentEl.checked = Boolean(qp.hashPayload.consentVerified);
  } else if (qp.sample && MEDIASTUDIO_SAMPLES[qp.sample]) {
    const preset = MEDIASTUDIO_SAMPLES[qp.sample];
    if (titleEl) titleEl.value = preset.title;
    if (briefEl) briefEl.value = preset.brief;
    if (scriptEl) scriptEl.value = preset.script;
    if (targetSecEl) targetSecEl.value = String(qp.targetSec ?? preset.targetSec);
    if (wpmEl) wpmEl.value = String(qp.wpm || preset.wpm);
    if (ratioEl) ratioEl.value = spHasRatio(window.location.search) ? qp.ratio : preset.ratio;
    if (brandsEl) brandsEl.value = qp.ownedBrands || preset.ownedBrands;
    if (consentEl) {
      consentEl.checked = window.location.search.includes("consent=")
        ? qp.consentVerified
        : Boolean(preset.consentVerified);
    }
    activeAgentTab = qp.targetAgent || preset.targetAgent || "pay-per-use-media-gen";
  } else if (qp.script !== null || qp.brief !== null) {
    if (scriptEl && qp.script !== null) scriptEl.value = qp.script;
    if (briefEl && qp.brief !== null) briefEl.value = qp.brief;
    if (targetSecEl && qp.targetSec) targetSecEl.value = String(qp.targetSec);
    if (wpmEl && qp.wpm) wpmEl.value = String(qp.wpm);
    if (ratioEl) ratioEl.value = qp.ratio;
    if (brandsEl && qp.ownedBrands) brandsEl.value = qp.ownedBrands;
    if (consentEl) consentEl.checked = qp.consentVerified;
    activeAgentTab = qp.targetAgent;
  } else {
    const def = MEDIASTUDIO_SAMPLES.golden_30s_spot;
    if (titleEl && !titleEl.value) titleEl.value = def.title;
    if (briefEl && !briefEl.value) briefEl.value = def.brief;
    if (scriptEl && !scriptEl.value) scriptEl.value = def.script;
    if (targetSecEl) targetSecEl.value = String(def.targetSec);
    if (wpmEl) wpmEl.value = String(def.wpm);
    if (ratioEl) ratioEl.value = def.ratio;
    if (brandsEl && !brandsEl.value) brandsEl.value = def.ownedBrands;
    if (consentEl) consentEl.checked = false;
  }

  agentTabs.forEach((b) => {
    b.className =
      b.getAttribute("data-ms-agent-tab") === activeAgentTab
        ? "fs-btn fs-btn-sm fs-btn-primary"
        : "fs-btn fs-btn-sm fs-btn-secondary";
  });

  executeAudit();
}

function spHasRatio(searchStr) {
  const sp = new URLSearchParams(String(searchStr || "").replace(/^\?/, ""));
  return sp.has("ratio");
}

export { validateLicenseKeyFormat };

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", initMediaBriefStudio);
}
