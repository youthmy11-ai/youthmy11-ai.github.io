import {
  bindCheckoutTriggers,
  getStoredLicenses,
  hasUnlockedTier,
  openCheckoutModal,
  validateLicenseKeyFormat,
} from "./checkout.js";
import { createDefaultInvoice, encodeInvoicePayload } from "./cryptobill.js";

/**
 * ClipCaption Lab — 100% Client-Side Subtitle & Caption Analyzer, Time-Shifter,
 * 9:16 Vertical Safe-Zone Previewer & Pro Animated .ASS / 25-File Batch Engine.
 * Zero external dependencies. Runs identically in Browser ES Modules & Node.js 20+.
 */

export const MAX_BATCH_SUBTITLE_FILES = 25;
export const DEFAULT_MAX_CPS = 20;
export const DEFAULT_MAX_LINE_CHARS = 32;
export const DEFAULT_MAX_LINES_PER_CUE = 2;

export const NEAR_VIDEO_CLIPPER_URL =
  "https://market.near.ai/agents/short-video-clipper";
export const NEAR_VIDEO_DUBBER_URL =
  "https://market.near.ai/agents/multi-lang-video-dubber";

export const ASS_STYLE_PRESETS = Object.freeze({
  mobile_bold: {
    id: "mobile_bold",
    styleName: "MobileBold",
    label: "Mobile Bold White + Deep Outline (@short-video-clipper Default)",
    fontName: "Arial",
    fontSize: 68,
    primaryColour: "&H00FFFFFF",
    secondaryColour: "&H0000FFFF",
    outlineColour: "&H00000000",
    backColour: "&H96000000",
    outline: 5.5,
    shadow: 2.5,
    marginH: 90,
    marginV: 420,
    previewColor: "#ffffff",
  },
  hormozi_gold: {
    id: "hormozi_gold",
    styleName: "CreatorGold",
    label: "High-Retention Gold Pop (TikTok / Reels / Shorts)",
    fontName: "Arial Black",
    fontSize: 70,
    primaryColour: "&H0000D7FF",
    secondaryColour: "&H00FFFFFF",
    outlineColour: "&H00000000",
    backColour: "&H96000000",
    outline: 6.0,
    shadow: 3.0,
    marginH: 90,
    marginV: 430,
    previewColor: "#ffd700",
  },
  emerald_hook: {
    id: "emerald_hook",
    styleName: "EmeraldHook",
    label: "ForgeSuite Emerald Tech Accent",
    fontName: "Arial Black",
    fontSize: 66,
    primaryColour: "&H0099F334",
    secondaryColour: "&H00FFFFFF",
    outlineColour: "&H0008110A",
    backColour: "&H96000000",
    outline: 5.5,
    shadow: 2.5,
    marginH: 90,
    marginV: 420,
    previewColor: "#34d399",
  },
});

export const SRTLAB_SAMPLES = Object.freeze({
  creator_hook_issues: [
    "1",
    "00:00:00,400 --> 00:00:02,600",
    "Most AI video editors lose 68% of viewers in the first three seconds because captions overflow the TikTok interface!",
    "",
    "2",
    "00:00:02,150 --> 00:00:03,050",
    "Watch what happens when two cues overlap and flash way too fast on mobile.",
    "",
    "3",
    "00:00:03,200 --> 00:00:05,800",
    "With ForgeSuite and AutoShorts Studio",
    "you lock crisp 9:16 safe zones",
    "and keep every call-to-action readable.",
    "",
    "4",
    "00:00:06,000 --> 00:00:07,900",
    "And the secret to doubling retention is because",
  ].join("\n"),

  clean_vertical_vtt: [
    "WEBVTT",
    "",
    "00:00:01.000 --> 00:00:04.200",
    "All right, so here we are,",
    "in front of the elephants.",
    "",
    "00:00:04.500 --> 00:00:08.000",
    "The cool thing about these guys",
    "is their really long trunks.",
    "",
    "00:00:08.300 --> 00:00:12.200",
    "Ship clean 9:16 captions fast",
    "with ForgeSuite ClipCaption Lab.",
  ].join("\n"),

  multilang_dub_srt: [
    "1",
    "00:00:01,200 --> 00:00:03,600",
    "Muy bien, aqui estamos en San Diego",
    "probando ForgeSuite Studio.",
    "",
    "2",
    "00:00:04,000 --> 00:00:06,800",
    "Cada pista de audio mantiene la musica",
    "y sincroniza OpenAI y NEAR Protocol.",
    "",
    "3",
    "00:00:07,100 --> 00:00:09,900",
    "Exporta subtitulos listos para",
    "YouTube Shorts, Reels y TikTok.",
  ].join("\n"),
});

const DANGLING_END_WORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "because",
  "before",
  "but",
  "by",
  "for",
  "from",
  "if",
  "in",
  "into",
  "is",
  "of",
  "on",
  "or",
  "since",
  "so",
  "than",
  "that",
  "the",
  "their",
  "then",
  "this",
  "through",
  "to",
  "unless",
  "until",
  "via",
  "was",
  "when",
  "where",
  "which",
  "while",
  "with",
  "without",
]);

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

function guardCsvCell(val) {
  const raw = String(val ?? "");
  const safe = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  if (/[",\r\n]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

/**
 * Parses SRT/VTT/bracketed timestamps into integer milliseconds.
 * Accepts HH:MM:SS,mmm | HH:MM:SS.mmm | MM:SS.mmm | MM:SS,mmm | SS.mmm
 */
export function parseTimestampMs(raw) {
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return Math.max(0, Math.round(raw));
  }
  const clean = String(raw ?? "")
    .trim()
    .replace(/^\[|\]$/g, "");
  if (!clean) return null;

  const m3 = clean.match(/^(\d{1,3}):([0-5]?\d):([0-5]?\d)(?:[,.](\d{1,3}))?$/);
  if (m3) {
    const h = Number(m3[1]);
    const m = Number(m3[2]);
    const s = Number(m3[3]);
    const ms = m3[4] ? Number(m3[4].padEnd(3, "0")) : 0;
    return ((h * 3600 + m * 60 + s) * 1000 + ms) >>> 0;
  }

  const m2 = clean.match(/^([0-5]?\d):([0-5]?\d)(?:[,.](\d{1,3}))?$/);
  if (m2) {
    const m = Number(m2[1]);
    const s = Number(m2[2]);
    const ms = m2[3] ? Number(m2[3].padEnd(3, "0")) : 0;
    return ((m * 60 + s) * 1000 + ms) >>> 0;
  }

  return null;
}

export function formatSrtTimestamp(msInput) {
  const total = Math.max(0, Math.round(Number(msInput) || 0));
  const ms = total % 1000;
  const totalSec = Math.floor(total / 1000);
  const s = totalSec % 60;
  const m = Math.floor(totalSec / 60) % 60;
  const h = Math.floor(totalSec / 3600);
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")},${String(ms).padStart(3, "0")}`;
}

export function formatVttTimestamp(msInput) {
  return formatSrtTimestamp(msInput).replace(",", ".");
}

/**
 * Formats integer ms to SubStation Alpha v4.00+ H:MM:SS.cc (centiseconds).
 */
export function formatAssTimestamp(msInput) {
  const totalCs = Math.max(0, Math.round((Number(msInput) || 0) / 10));
  const cs = totalCs % 100;
  const totalSec = Math.floor(totalCs / 100);
  const s = totalSec % 60;
  const m = Math.floor(totalSec / 60) % 60;
  const h = Math.floor(totalSec / 3600);
  return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}.${String(cs).padStart(2, "0")}`;
}

export function stripSubtitleMarkup(rawLine) {
  let text = String(rawLine ?? "");
  let speaker = null;
  const voiceMatch = text.match(/^<v(?:\.[^>\s]+)*\s+([^>]+)>([\s\S]*)$/i);
  if (voiceMatch) {
    speaker = voiceMatch[1].trim();
    text = voiceMatch[2];
  }
  text = text
    // Strip inline VTT karaoke timestamps like <00:00:01.240>
    .replace(/<\d{1,2}:\d{2}(?::\d{2})?[.,]\d{1,3}>/g, "")
    // Strip VTT/SRT formatting tags (<b>, <i>, <u>, <c.yellow>, </v>, <font ...>)
    .replace(/<\/?[a-zA-Z][^>]*>/g, "")
    // Strip ASS override blocks {\an8}
    .replace(/\{\\[^}]*\}/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return { text, speaker };
}

export function detectSubtitleFormat(rawInput) {
  const norm = String(rawInput ?? "")
    .replace(/^\uFEFF/, "")
    .replace(/\r\n/g, "\n")
    .trim();
  if (!norm) return "srt";
  if (/^WEBVTT(?:\s|$)/i.test(norm)) return "vtt";
  if (
    /(?:^|\n)\d{1,3}:\d{2}:\d{2},\d{1,3}\s*-->\s*\d{1,3}:\d{2}:\d{2},\d{1,3}/.test(
      norm
    )
  ) {
    return "srt";
  }
  if (
    /(?:^|\n)(?:\d{1,3}:)?\d{2}:\d{2}\.\d{1,3}\s*-->\s*(?:\d{1,3}:)?\d{2}:\d{2}\.\d{1,3}/.test(
      norm
    )
  ) {
    return "vtt";
  }
  return "txt";
}

/**
 * Balanced greedy/two-line splitter tailored for 9:16 mobile safe zones.
 */
export function wrapCueLinesForVertical(
  rawText,
  maxCharsPerLine = DEFAULT_MAX_LINE_CHARS
) {
  const limit = Math.max(12, Math.min(80, Number(maxCharsPerLine) || DEFAULT_MAX_LINE_CHARS));
  const words = String(rawText ?? "")
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .filter(Boolean);

  if (words.length === 0) return [];
  const joined = words.join(" ");
  if (joined.length <= limit) return [joined];

  // If fits cleanly on 2 lines, choose the split point closest to visual midpoint
  if (joined.length <= limit * 2 + 1) {
    let bestIdx = -1;
    let bestDiff = Infinity;
    for (let i = 1; i < words.length; i += 1) {
      const left = words.slice(0, i).join(" ");
      const right = words.slice(i).join(" ");
      if (left.length <= limit && right.length <= limit) {
        const diff = Math.abs(left.length - right.length);
        if (diff < bestDiff) {
          bestDiff = diff;
          bestIdx = i;
        }
      }
    }
    if (bestIdx > 0) {
      return [words.slice(0, bestIdx).join(" "), words.slice(bestIdx).join(" ")];
    }
  }

  const lines = [];
  let current = "";
  for (const word of words) {
    if (!current) {
      current = word;
    } else if (current.length + 1 + word.length <= limit) {
      current += ` ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines;
}

/**
 * Parses .srt, .vtt, or timestamped/plain .txt transcripts into normalized cue objects.
 */
export function parseSubtitles(rawInput, options = {}) {
  const cleaned = String(rawInput ?? "")
    .replace(/^\uFEFF/, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .trim();

  if (!cleaned) {
    return { format: "srt", cues: [] };
  }

  const format = detectSubtitleFormat(cleaned);
  const cues = [];

  if (format === "srt" || format === "vtt") {
    const blocks = cleaned.split(/\n{2,}/);
    const arrowRx =
      /^((?:\d{1,3}:)?\d{1,2}:\d{2}(?:[,.]\d{1,3})?)\s*-->\s*((?:\d{1,3}:)?\d{1,2}:\d{2}(?:[,.]\d{1,3})?)(?:\s+.*)?$/;

    for (const rawBlock of blocks) {
      const lines = rawBlock
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      if (lines.length === 0) continue;

      const headUpper = lines[0].toUpperCase();
      if (
        headUpper.startsWith("WEBVTT") ||
        headUpper.startsWith("NOTE") ||
        headUpper.startsWith("STYLE") ||
        headUpper.startsWith("REGION")
      ) {
        continue;
      }

      let arrowLineIdx = -1;
      for (let i = 0; i < Math.min(lines.length, 3); i += 1) {
        if (arrowRx.test(lines[i])) {
          arrowLineIdx = i;
          break;
        }
      }
      if (arrowLineIdx === -1) continue;

      const match = lines[arrowLineIdx].match(arrowRx);
      const startMs = parseTimestampMs(match[1]);
      const endMs = parseTimestampMs(match[2]);
      if (startMs === null || endMs === null) continue;

      const payloadLines = [];
      let detectedSpeaker = null;
      for (const rawTextLine of lines.slice(arrowLineIdx + 1)) {
        const stripped = stripSubtitleMarkup(rawTextLine);
        if (stripped.speaker && !detectedSpeaker) {
          detectedSpeaker = stripped.speaker;
        }
        if (stripped.text) {
          payloadLines.push(stripped.text);
        }
      }
      if (payloadLines.length === 0) continue;

      cues.push({
        index: cues.length + 1,
        startMs,
        endMs: Math.max(startMs + 100, endMs),
        lines: payloadLines,
        text: payloadLines.join("\n"),
        speaker: detectedSpeaker,
      });
    }
    return { format, cues };
  }

  // Transcript (.txt) mode: supports timestamped lines ([00:04.20] text) OR plain prose
  const rawLines = cleaned
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  const tsLineRx =
    /^\[?((?:\d{1,3}:)?\d{1,2}:\d{2}(?:[,.]\d{1,3})?)\]?(?:\s*[-–—:]\s*|\s+)(.+)$/;
  const timestampedEntries = [];
  for (const line of rawLines) {
    const m = line.match(tsLineRx);
    if (m) {
      const ms = parseTimestampMs(m[1]);
      if (ms !== null) {
        timestampedEntries.push({ startMs: ms, text: stripSubtitleMarkup(m[2]).text });
      }
    }
  }

  if (timestampedEntries.length > 0) {
    const maxLineChars = Number(options.maxLineLength) || DEFAULT_MAX_LINE_CHARS;
    for (let i = 0; i < timestampedEntries.length; i += 1) {
      const cur = timestampedEntries[i];
      if (!cur.text) continue;
      const wrapped = wrapCueLinesForVertical(cur.text, maxLineChars);
      const plainChars = wrapped.join(" ").length;
      const estimatedDur = Math.max(1100, Math.round((plainChars / 15) * 1000));
      const nextStart = timestampedEntries[i + 1]?.startMs;
      const endMs =
        nextStart !== undefined && nextStart > cur.startMs + 300
          ? Math.min(cur.startMs + estimatedDur + 400, nextStart - 60)
          : cur.startMs + estimatedDur;

      cues.push({
        index: cues.length + 1,
        startMs: cur.startMs,
        endMs: Math.max(cur.startMs + 400, endMs),
        lines: wrapped,
        text: wrapped.join("\n"),
        speaker: null,
      });
    }
    return { format: "txt", cues };
  }

  // Plain prose transcript -> chunk into natural sentence/phrase cues at ~14.5 CPS
  const maxLineChars = Number(options.maxLineLength) || DEFAULT_MAX_LINE_CHARS;
  const maxCueChars = maxLineChars * 2;
  const sentences = cleaned
    .replace(/\s+/g, " ")
    .split(/(?<=[.!?…])\s+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const chunks = [];
  for (const sentence of sentences) {
    if (sentence.length <= maxCueChars) {
      chunks.push(sentence);
    } else {
      const words = sentence.split(" ");
      let buf = "";
      for (const w of words) {
        if (!buf) buf = w;
        else if (buf.length + 1 + w.length <= maxCueChars) buf += ` ${w}`;
        else {
          chunks.push(buf);
          buf = w;
        }
      }
      if (buf) chunks.push(buf);
    }
  }

  let cursorMs = 0;
  for (const chunk of chunks) {
    const wrapped = wrapCueLinesForVertical(chunk, maxLineChars);
    const durMs = Math.max(1200, Math.round((chunk.length / 14.5) * 1000));
    cues.push({
      index: cues.length + 1,
      startMs: cursorMs,
      endMs: cursorMs + durMs,
      lines: wrapped,
      text: wrapped.join("\n"),
      speaker: null,
    });
    cursorMs += durMs + 120;
  }

  return { format: "txt", cues };
}

/**
 * Applies linear tempo scaling and millisecond offset to all cues.
 */
export function applyTimingTransform(cues, { shiftMs = 0, tempoScale = 1 } = {}) {
  const offset = Number.isFinite(Number(shiftMs)) ? Number(shiftMs) : 0;
  const scale =
    Number.isFinite(Number(tempoScale)) && Number(tempoScale) > 0.1
      ? Math.min(4, Math.max(0.25, Number(tempoScale)))
      : 1;

  return (Array.isArray(cues) ? cues : []).map((cue, idx) => {
    const rawStart = Math.round(cue.startMs * scale + offset);
    const rawEnd = Math.round(cue.endMs * scale + offset);
    const startMs = Math.max(0, rawStart);
    const minEnd = startMs + Math.max(120, Math.round((cue.endMs - cue.startMs) * scale));
    const endMs = rawStart < 0 ? Math.max(startMs + 250, rawEnd) : Math.max(startMs + 120, rawEnd, minEnd - 5);
    const lines = Array.isArray(cue.lines)
      ? [...cue.lines]
      : String(cue.text || "")
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean);
    return {
      ...cue,
      index: idx + 1,
      startMs,
      endMs: rawStart >= 0 ? Math.max(startMs + 120, rawEnd) : endMs,
      lines,
      text: lines.join("\n"),
    };
  });
}

/**
 * Resolves cue overlaps, reflows lines to fit 9:16 mobile safe zones, and gently extends
 * ultra-fast cues into available silent gaps so CPS drops without colliding with the next speaker.
 */
export function autoFixSubtitleCues(
  cues,
  {
    maxCharsPerLine = DEFAULT_MAX_LINE_CHARS,
    maxCps = DEFAULT_MAX_CPS,
    minGapMs = 40,
    minDurationMs = 550,
  } = {}
) {
  const list = (Array.isArray(cues) ? cues : [])
    .map((c) => {
      const flatText = (Array.isArray(c.lines) ? c.lines.join(" ") : String(c.text || ""))
        .replace(/\s+/g, " ")
        .trim();
      const wrapped = wrapCueLinesForVertical(flatText, maxCharsPerLine);
      // Cap at 2 lines where possible if 3rd line is tiny orphan
      return {
        ...c,
        startMs: Math.max(0, Math.round(c.startMs)),
        endMs: Math.max(Math.round(c.startMs) + 150, Math.round(c.endMs)),
        lines: wrapped,
        text: wrapped.join("\n"),
      };
    })
    .sort((a, b) => a.startMs - b.startMs || a.endMs - b.endMs);

  // Pass 1: Eliminate overlaps deterministically
  for (let i = 1; i < list.length; i += 1) {
    const prev = list[i - 1];
    const cur = list[i];
    if (cur.startMs < prev.endMs + minGapMs) {
      const trimmedPrevEnd = cur.startMs - minGapMs;
      if (trimmedPrevEnd - prev.startMs >= minDurationMs) {
        prev.endMs = trimmedPrevEnd;
      } else {
        prev.endMs = Math.max(prev.startMs + minDurationMs, trimmedPrevEnd);
        const origDur = Math.max(minDurationMs, cur.endMs - cur.startMs);
        cur.startMs = prev.endMs + minGapMs;
        cur.endMs = Math.max(cur.endMs, cur.startMs + origDur);
      }
    }
  }

  // Pass 2: Expand high-CPS cues into trailing silent gaps when safe
  const targetMaxCps = Math.max(10, Number(maxCps) || DEFAULT_MAX_CPS);
  for (let i = 0; i < list.length; i += 1) {
    const cur = list[i];
    const visibleChars = cur.lines.join(" ").replace(/\s+/g, " ").trim().length;
    const idealMs = Math.ceil((visibleChars / targetMaxCps) * 1000);
    const curDur = cur.endMs - cur.startMs;
    if (idealMs > curDur) {
      const nextStart = list[i + 1]?.startMs;
      const ceilingEnd =
        nextStart !== undefined ? nextStart - minGapMs : cur.startMs + Math.min(idealMs, curDur + 2000);
      if (ceilingEnd > cur.endMs) {
        cur.endMs = Math.min(cur.startMs + idealMs, ceilingEnd);
      }
    }
    cur.index = i + 1;
  }

  return list;
}

export function serializeToSrt(cues) {
  return (Array.isArray(cues) ? cues : [])
    .map(
      (cue, idx) =>
        `${idx + 1}\n${formatSrtTimestamp(cue.startMs)} --> ${formatSrtTimestamp(cue.endMs)}\n${cue.lines ? cue.lines.join("\n") : cue.text}`
    )
    .join("\n\n")
    .concat(cues?.length ? "\n" : "");
}

export function serializeToVtt(cues) {
  const body = (Array.isArray(cues) ? cues : [])
    .map(
      (cue, idx) =>
        `${idx + 1}\n${formatVttTimestamp(cue.startMs)} --> ${formatVttTimestamp(cue.endMs)}\n${cue.lines ? cue.lines.join("\n") : cue.text}`
    )
    .join("\n\n");
  return body ? `WEBVTT\n\n${body}\n` : "WEBVTT\n";
}

export function serializeToTranscriptTxt(cues, { includeTimestamps = false } = {}) {
  const list = Array.isArray(cues) ? cues : [];
  if (list.length === 0) return "";
  if (includeTimestamps) {
    return (
      list
        .map((c) => {
          const flat = (c.lines ? c.lines.join(" ") : String(c.text || ""))
            .replace(/\s+/g, " ")
            .trim();
          return `[${formatVttTimestamp(c.startMs)}] ${flat}`;
        })
        .join("\n") + "\n"
    );
  }
  return (
    list
      .map((c) =>
        (c.lines ? c.lines.join(" ") : String(c.text || ""))
          .replace(/\s+/g, " ")
          .trim()
      )
      .filter(Boolean)
      .join("\n") + "\n"
  );
}

/**
 * Generates an animated 1080x1920 vertical safe-zone SubStation Alpha (.ass) subtitle file
 * matching the @short-video-clipper burn-in pipeline (`ffmpeg -i in.mp4 -vf "ass=out.ass" out.mp4`).
 */
export function serializeToVerticalAss(
  cues,
  {
    preset = "mobile_bold",
    animatePop = true,
    playResX = 1080,
    playResY = 1920,
    marginV,
  } = {}
) {
  const styleCfg = ASS_STYLE_PRESETS[preset] || ASS_STYLE_PRESETS.mobile_bold;
  const effectiveMarginV =
    Number.isFinite(Number(marginV)) && Number(marginV) >= 80
      ? Math.round(Number(marginV))
      : styleCfg.marginV;

  const headerLines = [
    "[Script Info]",
    "; Generated by ForgeSuite ClipCaption Lab (https://youthmy11-ai.github.io/srtlab.html)",
    "ScriptType: v4.00+",
    `PlayResX: ${playResX}`,
    `PlayResY: ${playResY}`,
    "WrapStyle: 0",
    "ScaledBorderAndShadow: yes",
    "",
    "[V4+ Styles]",
    "Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding",
    `Style: ${styleCfg.styleName},${styleCfg.fontName},${styleCfg.fontSize},${styleCfg.primaryColour},${styleCfg.secondaryColour},${styleCfg.outlineColour},${styleCfg.backColour},-1,0,0,0,100,100,0,0,1,${styleCfg.outline},${styleCfg.shadow},2,${styleCfg.marginH},${styleCfg.marginH},${effectiveMarginV},1`,
    "",
    "[Events]",
    "Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text",
  ];

  const popTag = animatePop
    ? "{\\fad(70,60)\\t(0,110,\\fscx106\\fscy106)\\t(110,220,\\fscx100\\fscy100)}"
    : "";

  for (const cue of Array.isArray(cues) ? cues : []) {
    const rawLines = Array.isArray(cue.lines)
      ? cue.lines
      : String(cue.text || "").split("\n");
    const escapedAssText = rawLines
      .map((l) =>
        String(l || "")
          .replace(/\\/g, "\\\\")
          .replace(/\{/g, "\\{")
          .replace(/\}/g, "\\}")
          .trim()
      )
      .filter(Boolean)
      .join("\\N");
    if (!escapedAssText) continue;
    headerLines.push(
      `Dialogue: 0,${formatAssTimestamp(cue.startMs)},${formatAssTimestamp(cue.endMs)},${styleCfg.styleName},,0,0,0,,${popTag}${escapedAssText}`
    );
  }

  return `${headerLines.join("\n")}\n`;
}

export function parseBrandTermsInput(rawBrandTerms) {
  if (Array.isArray(rawBrandTerms)) {
    return [...new Set(rawBrandTerms.map((t) => String(t || "").trim()).filter(Boolean))];
  }
  if (typeof rawBrandTerms === "string" && rawBrandTerms.trim()) {
    return [
      ...new Set(
        rawBrandTerms
          .split(/[,;\n|]+/)
          .map((t) => t.trim())
          .filter(Boolean)
      ),
    ];
  }
  return [];
}

function isCueMidSentenceCut(cue, nextCue, isLastCue) {
  const flat = (cue.lines ? cue.lines.join(" ") : String(cue.text || ""))
    .replace(/\s+/g, " ")
    .trim();
  if (!flat) return null;

  const gapAfterMs = nextCue ? nextCue.startMs - cue.endMs : Infinity;
  // Only flag mid-sentence cuts at the end of the clip OR before a long silence (>= 1500ms)
  if (!isLastCue && gapAfterMs < 1500) return null;

  if (/[,:;—–-]$/.test(flat)) {
    return `Ends with open clause punctuation ("${flat.slice(-1)}") ${isLastCue ? "at end of clip" : `before ${(gapAfterMs / 1000).toFixed(1)}s silence`}.`;
  }

  const cleanWords = flat
    .replace(/["')\]}]+$/g, "")
    .split(/\s+/)
    .filter(Boolean);
  const lastWordRaw = cleanWords.at(-1) || "";
  const lastWordLower = lastWordRaw.toLowerCase().replace(/[^a-z']/g, "");

  if (DANGLING_END_WORDS.has(lastWordLower)) {
    return `Cut mid-sentence on connector word "${lastWordRaw}" ${isLastCue ? "at end of clip" : `before ${(gapAfterMs / 1000).toFixed(1)}s pause`}.`;
  }

  if (isLastCue && cleanWords.length >= 4 && !/[.!?…"')\]!؟。！？]$/.test(flat)) {
    return `Final caption cue lacks terminal sentence punctuation ("${flat.slice(-24)}").`;
  }

  return null;
}

/**
 * Full deterministic audit of subtitle cues for overlaps, CPS reading speed,
 * 9:16 mobile safe-zone width & line count, mid-sentence cuts, and brand term fidelity.
 */
export function auditSubtitles(rawOrParsed, options = {}) {
  const maxCps = Math.max(8, Math.min(50, Number(options.maxCps) || DEFAULT_MAX_CPS));
  const maxLineLength = Math.max(
    14,
    Math.min(80, Number(options.maxLineLength) || DEFAULT_MAX_LINE_CHARS)
  );
  const maxLinesPerCue = Math.max(
    1,
    Math.min(4, Number(options.maxLinesPerCue) || DEFAULT_MAX_LINES_PER_CUE)
  );
  const shiftMs = Number(options.shiftMs) || 0;
  const tempoScale = Number(options.tempoScale) || 1;
  const autoFix = Boolean(options.autoFix);
  const brandTerms = parseBrandTermsInput(options.brandTerms);

  const parsed =
    rawOrParsed && typeof rawOrParsed === "object" && Array.isArray(rawOrParsed.cues)
      ? rawOrParsed
      : parseSubtitles(String(rawOrParsed ?? ""), { maxLineLength });

  let workingCues = applyTimingTransform(parsed.cues, { shiftMs, tempoScale });
  if (autoFix && workingCues.length > 0) {
    workingCues = autoFixSubtitleCues(workingCues, {
      maxCharsPerLine: maxLineLength,
      maxCps,
    });
  }

  if (workingCues.length === 0) {
    return {
      ok: false,
      detectedFormat: parsed.format,
      cueCount: 0,
      totalDurationMs: 0,
      qualityScore: 0,
      verdict: "EMPTY_OR_UNPARSEABLE",
      metrics: {
        overlapCount: 0,
        highCpsCount: 0,
        safeZoneOverflowCount: 0,
        multiLineOverflowCount: 0,
        midSentenceCutCount: 0,
        maxCpsObserved: 0,
        avgCps: 0,
        maxLineCharsObserved: 0,
      },
      brandCheck: {
        requestedTerms: brandTerms,
        exactMatches: [],
        caseMismatches: [],
        missingTerms: brandTerms,
      },
      cues: [],
      issues: [
        {
          cueIndex: 0,
          timestamp: "00:00:00,000",
          severity: "HIGH",
          code: "NO_CUES_DETECTED",
          message: "No valid .srt, .vtt, or transcript subtitle cues were found in the input.",
        },
      ],
      outputs: {
        srt: "",
        vtt: "WEBVTT\n",
        txt: "",
      },
      markdownReport: "# ClipCaption Lab Audit\n\nNo valid subtitle cues found.",
    };
  }

  const issues = [];
  let overlapCount = 0;
  let highCpsCount = 0;
  let safeZoneOverflowCount = 0;
  let multiLineOverflowCount = 0;
  let midSentenceCutCount = 0;
  let maxCpsObserved = 0;
  let cpsSum = 0;
  let maxLineCharsObserved = 0;

  const enrichedCues = workingCues.map((cue, idx) => {
    const prev = idx > 0 ? workingCues[idx - 1] : null;
    const next = idx + 1 < workingCues.length ? workingCues[idx + 1] : null;
    const durationMs = Math.max(1, cue.endMs - cue.startMs);
    const flatVisible = cue.lines.join(" ").replace(/\s+/g, " ").trim();
    const charCount = flatVisible.length;
    const cps = Number(((charCount / durationMs) * 1000).toFixed(1));
    const longestLineChars = cue.lines.reduce((m, l) => Math.max(m, l.length), 0);

    if (cps > maxCpsObserved) maxCpsObserved = cps;
    cpsSum += cps;
    if (longestLineChars > maxLineCharsObserved) maxLineCharsObserved = longestLineChars;

    const cueFlags = [];

    if (prev && cue.startMs < prev.endMs) {
      overlapCount += 1;
      const overlapMs = prev.endMs - cue.startMs;
      cueFlags.push("OVERLAP");
      issues.push({
        cueIndex: idx + 1,
        timestamp: formatSrtTimestamp(cue.startMs),
        severity: "CRITICAL",
        code: "TIMESTAMP_OVERLAP",
        message: `Cue #${idx + 1} starts ${overlapMs}ms before Cue #${idx} ends (${formatSrtTimestamp(prev.endMs)}).`,
      });
    }

    if (cps > maxCps) {
      highCpsCount += 1;
      cueFlags.push("HIGH_CPS");
      issues.push({
        cueIndex: idx + 1,
        timestamp: formatSrtTimestamp(cue.startMs),
        severity: cps > maxCps + 8 ? "HIGH" : "MEDIUM",
        code: "HIGH_READING_SPEED_CPS",
        message: `Cue #${idx + 1} reading speed is ${cps} CPS (exceeds ${maxCps} CPS mobile threshold; ${charCount} chars in ${(durationMs / 1000).toFixed(2)}s).`,
      });
    }

    if (longestLineChars > maxLineLength) {
      safeZoneOverflowCount += 1;
      cueFlags.push("SAFEZONE_WIDTH");
      issues.push({
        cueIndex: idx + 1,
        timestamp: formatSrtTimestamp(cue.startMs),
        severity: "HIGH",
        code: "VERTICAL_9_16_LINE_OVERFLOW",
        message: `Cue #${idx + 1} has a ${longestLineChars}-char line (exceeds ${maxLineLength}-char 9:16 TikTok/Reels/Shorts safe width).`,
      });
    }

    if (cue.lines.length > maxLinesPerCue) {
      multiLineOverflowCount += 1;
      cueFlags.push("TOO_MANY_LINES");
      issues.push({
        cueIndex: idx + 1,
        timestamp: formatSrtTimestamp(cue.startMs),
        severity: "MEDIUM",
        code: "VERTICAL_STACK_OVERFLOW",
        message: `Cue #${idx + 1} stacks ${cue.lines.length} lines (max recommended for 9:16 vertical safe zone is ${maxLinesPerCue} lines).`,
      });
    }

    const cutReason = isCueMidSentenceCut(cue, next, idx === workingCues.length - 1);
    if (cutReason) {
      midSentenceCutCount += 1;
      cueFlags.push("MID_SENTENCE_CUT");
      issues.push({
        cueIndex: idx + 1,
        timestamp: formatSrtTimestamp(cue.startMs),
        severity: "MEDIUM",
        code: "MID_SENTENCE_CUT_WARNING",
        message: `Cue #${idx + 1}: ${cutReason}`,
      });
    }

    return {
      index: idx + 1,
      startMs: cue.startMs,
      endMs: cue.endMs,
      durationMs,
      startSrt: formatSrtTimestamp(cue.startMs),
      endSrt: formatSrtTimestamp(cue.endMs),
      lines: cue.lines,
      text: cue.lines.join("\n"),
      speaker: cue.speaker || null,
      charCount,
      longestLineChars,
      cps,
      flags: cueFlags,
    };
  });

  // Brand / Do-Not-Translate Term Audit
  const fullCorpus = enrichedCues.map((c) => c.lines.join(" ")).join("\n");
  const fullCorpusLower = fullCorpus.toLowerCase();
  const exactMatches = [];
  const caseMismatches = [];
  const missingTerms = [];

  for (const term of brandTerms) {
    if (fullCorpus.includes(term)) {
      exactMatches.push(term);
    } else if (fullCorpusLower.includes(term.toLowerCase())) {
      caseMismatches.push(term);
      issues.push({
        cueIndex: 0,
        timestamp: "GLOBAL",
        severity: "MEDIUM",
        code: "BRAND_TERM_CASE_MISMATCH",
        message: `Brand keyword "${term}" appears with non-canonical casing in captions.`,
      });
    } else {
      missingTerms.push(term);
      issues.push({
        cueIndex: 0,
        timestamp: "GLOBAL",
        severity: "LOW",
        code: "BRAND_TERM_MISSING",
        message: `Expected brand/protected term "${term}" was not found in the subtitle track.`,
      });
    }
  }

  let penalty =
    overlapCount * 18 +
    safeZoneOverflowCount * 10 +
    highCpsCount * 8 +
    multiLineOverflowCount * 6 +
    midSentenceCutCount * 7 +
    caseMismatches.length * 6 +
    missingTerms.length * 4;
  const qualityScore = Math.max(0, Math.min(100, 100 - penalty));
  const verdict =
    qualityScore >= 88
      ? "PUBLISH_READY"
      : qualityScore >= 65
        ? "NEEDS_POLISH"
        : "TIMING_OR_SAFEZONE_ISSUES";

  const totalDurationMs = Math.max(
    0,
    enrichedCues.at(-1).endMs - enrichedCues[0].startMs
  );
  const avgCps = Number((cpsSum / enrichedCues.length).toFixed(1));

  const srtOut = serializeToSrt(enrichedCues);
  const vttOut = serializeToVtt(enrichedCues);
  const txtOut = serializeToTranscriptTxt(enrichedCues, { includeTimestamps: false });

  const mdLines = [
    `# ClipCaption Lab — 9:16 Subtitle & Timing Audit Report`,
    `- **Quality Score:** **${qualityScore}/100** (\`${verdict}\`)`,
    `- **Input Format:** \`${parsed.format.toUpperCase()}\` · **Cues:** \`${enrichedCues.length}\` · **Span:** \`${(totalDurationMs / 1000).toFixed(2)}s\``,
    `- **Overlaps:** \`${overlapCount}\` · **High CPS (>${maxCps}):** \`${highCpsCount}\` (Max \`${maxCpsObserved}\` CPS, Avg \`${avgCps}\` CPS)`,
    `- **9:16 Safe-Zone Overflows (>${maxLineLength} chars):** \`${safeZoneOverflowCount}\` (Max \`${maxLineCharsObserved}\` chars) · **Mid-Sentence Cuts:** \`${midSentenceCutCount}\``,
  ];
  if (brandTerms.length > 0) {
    mdLines.push(
      `- **Brand Terms (${brandTerms.length}):** Exact=${exactMatches.length}, CaseMismatch=${caseMismatches.length}, Missing=${missingTerms.length}`
    );
  }
  if (issues.length > 0) {
    mdLines.push("", "## Detected Caption Issues");
    for (const iss of issues.slice(0, 20)) {
      mdLines.push(
        `- **[${iss.severity}]** \`${iss.timestamp}\` (${iss.code}): ${iss.message}`
      );
    }
  } else {
    mdLines.push("", "## Detected Caption Issues", "- Zero timing, CPS, or 9:16 safe-zone issues detected.");
  }

  return {
    ok: true,
    detectedFormat: parsed.format,
    cueCount: enrichedCues.length,
    totalDurationMs,
    qualityScore,
    verdict,
    appliedTransform: { shiftMs, tempoScale, autoFix, maxCps, maxLineLength },
    metrics: {
      overlapCount,
      highCpsCount,
      safeZoneOverflowCount,
      multiLineOverflowCount,
      midSentenceCutCount,
      maxCpsObserved,
      avgCps,
      maxLineCharsObserved,
    },
    brandCheck: {
      requestedTerms: brandTerms,
      exactMatches,
      caseMismatches,
      missingTerms,
    },
    cues: enrichedCues,
    issues,
    outputs: {
      srt: srtOut,
      vtt: vttOut,
      txt: txtOut,
    },
    markdownReport: mdLines.join("\n"),
  };
}

/**
 * Pro Batch 25-File Subtitle Audit & Normalization Engine.
 */
export function runBatchSubtitleAudit(filesInput, options = {}) {
  const entries = Array.isArray(filesInput) ? filesInput : [];
  if (entries.length === 0) {
    throw new Error("Provide 1 to 25 subtitle files (.srt, .vtt, or .txt) for batch processing.");
  }
  if (entries.length > MAX_BATCH_SUBTITLE_FILES) {
    throw new Error(
      `Batch processing supports up to ${MAX_BATCH_SUBTITLE_FILES} subtitle files per run (received ${entries.length}).`
    );
  }

  const reports = entries.map((entry, idx) => {
    const fileName = String(entry?.name || `subtitle_${idx + 1}.srt`).trim();
    const content = String(entry?.content ?? "");
    const audit = auditSubtitles(content, options);
    const ass = audit.ok
      ? serializeToVerticalAss(audit.cues, {
          preset: options.assPreset || "mobile_bold",
          animatePop: options.animatePop !== false,
        })
      : "";
    return {
      fileName,
      ...audit,
      assOutput: ass,
    };
  });

  const validReports = reports.filter((r) => r.ok);
  const avgScore =
    validReports.length > 0
      ? Math.round(
          validReports.reduce((acc, r) => acc + r.qualityScore, 0) / validReports.length
        )
      : 0;

  return {
    ok: true,
    processedAtUtc: new Date().toISOString(),
    totalFiles: reports.length,
    okFiles: validReports.length,
    averageQualityScore: avgScore,
    totalCues: validReports.reduce((acc, r) => acc + r.cueCount, 0),
    totalOverlaps: validReports.reduce((acc, r) => acc + r.metrics.overlapCount, 0),
    totalSafeZoneOverflows: validReports.reduce(
      (acc, r) => acc + r.metrics.safeZoneOverflowCount,
      0
    ),
    reports,
  };
}

export function exportBatchSubtitleCsv(batchPack) {
  const headers = [
    "file_name",
    "detected_format",
    "cue_count",
    "duration_sec",
    "quality_score",
    "verdict",
    "overlaps",
    "high_cps_cues",
    "max_cps",
    "safezone_9_16_overflows",
    "mid_sentence_cuts",
  ];
  const rows = [headers.join(",")];
  for (const r of batchPack?.reports || []) {
    rows.push(
      [
        guardCsvCell(r.fileName),
        guardCsvCell(r.detectedFormat),
        r.cueCount,
        (r.totalDurationMs / 1000).toFixed(2),
        r.qualityScore,
        guardCsvCell(r.verdict),
        r.metrics.overlapCount,
        r.metrics.highCpsCount,
        r.metrics.maxCpsObserved,
        r.metrics.safeZoneOverflowCount,
        r.metrics.midSentenceCutCount,
      ].join(",")
    );
  }
  return rows.join("\n") + "\n";
}

export function parseSrtLabQueryParams(searchStr = "", hashStr = "") {
  const sp = new URLSearchParams(String(searchStr || "").replace(/^\?/, ""));
  const sample = sp.get("sample")?.trim() || null;
  const shiftMs = sp.has("shift") ? Number(sp.get("shift")) || 0 : 0;
  const tempoScale = sp.has("tempo") ? Number(sp.get("tempo")) || 1 : 1;
  const maxCps = sp.has("maxCps") ? Number(sp.get("maxCps")) || DEFAULT_MAX_CPS : DEFAULT_MAX_CPS;
  const maxLineLength = sp.has("maxLine")
    ? Number(sp.get("maxLine")) || DEFAULT_MAX_LINE_CHARS
    : DEFAULT_MAX_LINE_CHARS;
  const brandTerms = sp.get("brands")?.trim() || "";
  const autoFixRaw = (sp.get("autoFix") || "").trim().toLowerCase();
  const autoFix = autoFixRaw === "1" || autoFixRaw === "true" || autoFixRaw === "yes";
  const outRaw = (sp.get("out") || "").trim().toLowerCase();
  const outputTab = ["srt", "vtt", "txt", "ass"].includes(outRaw) ? outRaw : "srt";

  let decodedSubtitle = null;
  const cleanHash = String(hashStr || "").replace(/^#/, "");
  if (cleanHash.startsWith("srt=")) {
    try {
      decodedSubtitle = decodeBase64UrlUtf8(cleanHash.slice(4));
    } catch {
      decodedSubtitle = null;
    }
  }

  return {
    sample,
    shiftMs,
    tempoScale,
    maxCps,
    maxLineLength,
    brandTerms,
    autoFix,
    outputTab,
    decodedSubtitle,
  };
}

export function buildCaptionLocalizationInvoicePayload(reportOrBatch = null) {
  const inv = createDefaultInvoice();
  inv.businessName = "ForgeSuite Creator Ops";
  inv.clientName = "Media & Creator Channel";
  inv.currency = "USDT";
  const isBatch = Boolean(reportOrBatch?.reports && Array.isArray(reportOrBatch.reports));
  if (isBatch) {
    const count = reportOrBatch.totalFiles || 10;
    inv.items = [
      {
        description: `Short-Form 9:16 Caption QC, Time-Sync & Animated .ASS Mastering (${count} episodes)`,
        qty: 1,
        unitPrice: 185,
      },
      {
        description: "Multi-Language Subtitle Localization & Brand Term QA",
        qty: 1,
        unitPrice: 95,
      },
    ];
  } else {
    const cueCount = reportOrBatch?.cueCount || 12;
    inv.items = [
      {
        description: `Vertical 9:16 Video Caption Sync, Safe-Zone Formatting & Burn-In Prep (${cueCount} cues)`,
        qty: 1,
        unitPrice: 120,
      },
    ];
  }
  return inv;
}

export function buildCaptionSowState(reportOrBatch = null) {
  const isBatch = Boolean(reportOrBatch?.reports && Array.isArray(reportOrBatch.reports));
  return {
    projectTitle: isBatch
      ? `Batch Short-Form Video Clipping, 9:16 Captions & Multi-Language Dubbing (${reportOrBatch.totalFiles} Videos)`
      : "Short-Form 9:16 Video Clipping, Mobile Safe-Zone Captions & Localization Sprint",
    providerName: "ForgeSuite Media Studio",
    clientName: "Creator / Brand Marketing Team",
    totalBudget: isBatch ? 680 : 420,
    revisionsIncluded: 2,
    noticeDays: 5,
    settlementRail: "sol-usdc",
    deliverables: [
      "- Retention-peak 9:16 (1080x1920), 1:1, and 16:9 MP4 highlight clips with zero mid-sentence cuts",
      "- Line-synced .SRT, .VTT, and animated mobile-safe .ASS caption tracks (<= 20 CPS, <= 32 chars/line)",
      "- Multi-language neural dubbing with preserved background music/SFX and verbatim brand-term lock",
    ].join("\n"),
    milestones: [
      { title: "M1: Source Transcript Sync, 9:16 Caption Audit & Hook Selection", percent: 40, due: "On kickoff" },
      { title: "M2: Final MP4 Render, Animated .ASS Burn-In & Multi-Language Delivery", percent: 60, due: "Final delivery" },
    ],
  };
}

export function isClipCaptionProUnlocked() {
  return (
    hasUnlockedTier("BUNDLE") ||
    hasUnlockedTier("AS") ||
    hasUnlockedTier("CB") ||
    getStoredLicenses().length > 0
  );
}

/* ============================================================================
 * Browser UI Controller for srtlab.html
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

export function initClipCaptionLab() {
  if (typeof document === "undefined" || document.body?.dataset?.page !== "srtlab") {
    return;
  }

  const inputEl = document.getElementById("srtInputArea");
  const fileUploadEl = document.getElementById("srtSingleFileInput");
  const shiftInputEl = document.getElementById("srtShiftMs");
  const tempoInputEl = document.getElementById("srtTempoScale");
  const maxCpsInputEl = document.getElementById("srtMaxCps");
  const maxLineInputEl = document.getElementById("srtMaxLineChars");
  const brandInputEl = document.getElementById("srtBrandTerms");
  const autoFixCheckEl = document.getElementById("srtAutoFixToggle");
  const assStyleSelectEl = document.getElementById("srtAssPresetSelect");
  const assPopCheckEl = document.getElementById("srtAssPopToggle");

  const runAuditBtn = document.getElementById("srtAuditBtn");
  const autoFixNowBtn = document.getElementById("srtAutoFixBtn");
  const statusEl = document.getElementById("srtStatusMsg");

  const downloadSrtBtn = document.getElementById("srtDownloadSrtBtn");
  const downloadVttBtn = document.getElementById("srtDownloadVttBtn");
  const downloadTxtBtn = document.getElementById("srtDownloadTxtBtn");
  const downloadAssBtn = document.getElementById("srtDownloadAssBtn");
  const copyMdBtn = document.getElementById("srtCopyMdBtn");
  const shareLinkBtn = document.getElementById("srtShareLinkBtn");

  const scoreBadgeEl = document.getElementById("srtVerdictBadge");
  const kpiGridEl = document.getElementById("srtMetricsGrid");
  const outputFormatTabs = Array.from(document.querySelectorAll("[data-srt-out-tab]"));
  const normalizedPreviewEl = document.getElementById("srtNormalizedOutput");
  const copyOutputBtn = document.getElementById("srtCopyOutputBtn");

  // 9:16 Live Phone Preview Controls
  const phoneCaptionBoxEl = document.getElementById("srtPhoneCaptionBox");
  const phoneTimeBadgeEl = document.getElementById("srtPhoneTimeBadge");
  const phoneSafeAlertEl = document.getElementById("srtPhoneSafeAlert");
  const timelineRangeEl = document.getElementById("srtTimelineRange");
  const playToggleBtn = document.getElementById("srtPlayPreviewBtn");

  const issuesBodyEl = document.getElementById("srtIssuesBody");
  const cuesBodyEl = document.getElementById("srtCuesBody");

  // Pro & Batch 25-File Controls
  const proBadgeEl = document.getElementById("srtProBadge");
  const proLockBannerEl = document.getElementById("srtProLockBanner");
  const batchFilesInputEl = document.getElementById("srtBatchFilesInput");
  const batchLoadDemoBtn = document.getElementById("srtBatchDemoBtn");
  const batchRunBtn = document.getElementById("srtBatchRunBtn");
  const batchExportCsvBtn = document.getElementById("srtBatchCsvBtn");
  const batchExportJsonBtn = document.getElementById("srtBatchJsonBtn");
  const batchStatusEl = document.getElementById("srtBatchStatusMsg");
  const batchTableBodyEl = document.getElementById("srtBatchBody");

  const sendInvoiceBtn = document.getElementById("srtSendInvoiceBtn");
  const sendSowBtn = document.getElementById("srtSendSowBtn");

  let lastAudit = null;
  let lastBatchPack = null;
  let stagedBatchFiles = [];
  let activeOutputTab = "srt";
  let playTimer = null;
  let currentPlayMs = 0;

  function syncProUi() {
    const unlocked = isClipCaptionProUnlocked();
    if (proBadgeEl) {
      proBadgeEl.textContent = unlocked
        ? "PRO ACTIVE · ANIMATED .ASS + 25-FILE BATCH UNLOCKED ✓"
        : "PRO FEATURE · $15 PRO / $19 AUTOSHORTS / $35 BUNDLE";
      proBadgeEl.className = `fs-badge ${unlocked ? "fs-badge-success" : "fs-badge-warn"}`;
    }
    if (proLockBannerEl) {
      proLockBannerEl.hidden = unlocked;
    }
    if (downloadAssBtn) {
      downloadAssBtn.textContent = unlocked
        ? "⚡ Export 9:16 Animated .ASS"
        : "🔒 Export 9:16 .ASS (Pro)";
    }
    if (batchRunBtn) {
      batchRunBtn.textContent = unlocked
        ? "Run 25-File Batch Audit & Convert"
        : "Unlock 25-File Batch & .ASS — Pro ($19 / $35)";
    }
    renderNormalizedOutputPane();
  }

  bindCheckoutTriggers({ onUnlocked: syncProUi });
  window.addEventListener("forgesuite:license-updated", syncProUi);

  const navBundleBtn = document.getElementById("srtBundleBtn");
  if (navBundleBtn) {
    navBundleBtn.addEventListener("click", () =>
      openCheckoutModal("BUNDLE", { onUnlocked: syncProUi })
    );
  }
  const activateKeyBtn = document.getElementById("srtActivateKeyBtn");
  if (activateKeyBtn) {
    activateKeyBtn.addEventListener("click", () =>
      openCheckoutModal("AS", { initialTab: "license", onUnlocked: syncProUi })
    );
  }

  const themeBtn = document.getElementById("themeToggleBtn");
  if (themeBtn) {
    let saved = "dark";
    try {
      saved = window.localStorage.getItem("forgesuite_theme") || "dark";
    } catch {
      saved = "dark";
    }
    document.documentElement.dataset.theme = saved;
    themeBtn.textContent = saved === "light" ? "☀ Light" : "🌙 Dark";
    themeBtn.addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
      document.documentElement.dataset.theme = next;
      try {
        window.localStorage.setItem("forgesuite_theme", next);
      } catch {}
      themeBtn.textContent = next === "light" ? "☀ Light" : "🌙 Dark";
    });
  }

  function getAuditOptionsFromUi(overrideAutoFix = null) {
    return {
      shiftMs: Number(shiftInputEl?.value || 0),
      tempoScale: Number(tempoInputEl?.value || 1),
      maxCps: Number(maxCpsInputEl?.value || DEFAULT_MAX_CPS),
      maxLineLength: Number(maxLineInputEl?.value || DEFAULT_MAX_LINE_CHARS),
      brandTerms: brandInputEl?.value || "",
      autoFix:
        overrideAutoFix !== null ? overrideAutoFix : Boolean(autoFixCheckEl?.checked),
      assPreset: assStyleSelectEl?.value || "mobile_bold",
      animatePop: assPopCheckEl ? assPopCheckEl.checked : true,
    };
  }

  function renderPhoneAtMs(ms) {
    currentPlayMs = Math.max(0, Math.round(ms));
    const cues = lastAudit?.cues || [];
    const maxEnd = cues.length > 0 ? cues.at(-1).endMs : 10000;
    if (phoneTimeBadgeEl) {
      phoneTimeBadgeEl.textContent = `${formatVttTimestamp(currentPlayMs).slice(3)} / ${formatVttTimestamp(maxEnd).slice(3)}`;
    }

    const activeCues = cues.filter(
      (c) => currentPlayMs >= c.startMs && currentPlayMs <= c.endMs
    );
    const presetCfg =
      ASS_STYLE_PRESETS[assStyleSelectEl?.value || "mobile_bold"] ||
      ASS_STYLE_PRESETS.mobile_bold;

    if (phoneCaptionBoxEl) {
      phoneCaptionBoxEl.style.color = presetCfg.previewColor;
      if (activeCues.length === 0) {
        phoneCaptionBoxEl.innerHTML = `<span style="opacity:0.42;font-weight:600;font-size:0.82rem;">(Silent interval — scrub timeline or press Play)</span>`;
      } else {
        phoneCaptionBoxEl.innerHTML = activeCues
          .map((c) =>
            c.lines.map((line) => `<div>${escapeHtml(line)}</div>`).join("")
          )
          .join('<hr style="border:none;border-top:1px dashed rgba(239,68,68,0.8);margin:4px 0;">');
      }
    }

    if (phoneSafeAlertEl) {
      if (activeCues.length > 1) {
        phoneSafeAlertEl.hidden = false;
        phoneSafeAlertEl.textContent = `⚠ OVERLAP: ${activeCues.length} cues colliding simultaneously!`;
      } else if (activeCues[0]?.flags?.length > 0) {
        phoneSafeAlertEl.hidden = false;
        phoneSafeAlertEl.textContent = `⚠ Cue #${activeCues[0].index}: ${activeCues[0].flags.join(" · ")} (${activeCues[0].cps} CPS, ${activeCues[0].longestLineChars} chars)`;
      } else {
        phoneSafeAlertEl.hidden = true;
      }
    }
  }

  function stopPlayback() {
    if (playTimer) {
      clearInterval(playTimer);
      playTimer = null;
    }
    if (playToggleBtn) playToggleBtn.textContent = "▶ Play 9:16 Preview";
  }

  function renderNormalizedOutputPane() {
    if (!normalizedPreviewEl || !lastAudit) return;
    if (!lastAudit.ok) {
      normalizedPreviewEl.value = "";
      return;
    }
    if (activeOutputTab === "vtt") {
      normalizedPreviewEl.value = lastAudit.outputs.vtt;
    } else if (activeOutputTab === "txt") {
      normalizedPreviewEl.value = lastAudit.outputs.txt;
    } else if (activeOutputTab === "ass") {
      const fullAss = serializeToVerticalAss(lastAudit.cues, {
        preset: assStyleSelectEl?.value || "mobile_bold",
        animatePop: assPopCheckEl ? assPopCheckEl.checked : true,
      });
      if (isClipCaptionProUnlocked()) {
        normalizedPreviewEl.value = fullAss;
      } else {
        const previewLines = fullAss.split("\n").slice(0, 18).join("\n");
        normalizedPreviewEl.value = `${previewLines}\n; 🔒 Unlock Pro ($15 CB / $19 AutoShorts / $35 Bundle) to export full animated 1080x1920 .ASS file...`;
      }
    } else {
      normalizedPreviewEl.value = lastAudit.outputs.srt;
    }
  }

  function executeAudit(overrideAutoFix = null) {
    stopPlayback();
    const raw = inputEl?.value || "";
    const opts = getAuditOptionsFromUi(overrideAutoFix);
    const report = auditSubtitles(raw, opts);
    lastAudit = report;

    if (!report.ok) {
      if (scoreBadgeEl) {
        scoreBadgeEl.textContent = "EMPTY INPUT";
        scoreBadgeEl.className = "fs-badge fs-badge-warn";
      }
      if (statusEl) {
        statusEl.className = "fs-status-msg is-error";
        statusEl.textContent = report.issues[0]?.message || "Unable to parse subtitle input.";
      }
      renderNormalizedOutputPane();
      return;
    }

    if (overrideAutoFix === true && inputEl) {
      inputEl.value =
        report.detectedFormat === "vtt" ? report.outputs.vtt : report.outputs.srt;
      if (shiftInputEl) shiftInputEl.value = "0";
      if (tempoInputEl) tempoInputEl.value = "1";
    }

    if (scoreBadgeEl) {
      scoreBadgeEl.textContent = `${report.qualityScore}/100 · ${report.verdict}`;
      scoreBadgeEl.className =
        report.qualityScore >= 88
          ? "fs-badge fs-badge-success"
          : report.qualityScore >= 65
            ? "fs-badge fs-badge-warn"
            : "fs-badge fs-badge-accent";
    }

    if (kpiGridEl) {
      kpiGridEl.innerHTML = `
        <div class="fs-rail-box" style="padding:12px;">
          <span class="fs-field-label">Format &amp; Cue Count</span>
          <strong style="font-size:1.05rem;">${escapeHtml(report.detectedFormat.toUpperCase())} · ${report.cueCount} cues (${(report.totalDurationMs / 1000).toFixed(1)}s)</strong>
        </div>
        <div class="fs-rail-box" style="padding:12px;">
          <span class="fs-field-label">Timestamp Overlaps</span>
          <strong style="font-size:1.05rem;color:${report.metrics.overlapCount > 0 ? "var(--danger)" : "var(--emerald)"};">${report.metrics.overlapCount} overlap(s)</strong>
        </div>
        <div class="fs-rail-box" style="padding:12px;">
          <span class="fs-field-label">Reading Speed (CPS)</span>
          <strong style="font-size:1.05rem;color:${report.metrics.highCpsCount > 0 ? "var(--amber)" : "var(--emerald)"};">Max ${report.metrics.maxCpsObserved} · Avg ${report.metrics.avgCps} CPS (${report.metrics.highCpsCount} fast)</strong>
        </div>
        <div class="fs-rail-box" style="padding:12px;">
          <span class="fs-field-label">9:16 Safe Zone &amp; Cuts</span>
          <strong style="font-size:1.05rem;color:${report.metrics.safeZoneOverflowCount + report.metrics.midSentenceCutCount > 0 ? "var(--amber)" : "var(--emerald)"};">${report.metrics.safeZoneOverflowCount} wide · ${report.metrics.midSentenceCutCount} cut(s)</strong>
        </div>
      `;
    }

    if (issuesBodyEl) {
      if (report.issues.length === 0) {
        issuesBodyEl.innerHTML = `<tr><td colspan="4" style="color:var(--emerald);font-weight:600;">✓ Zero overlaps, reading-speed spikes, 9:16 safe-zone overflows, or mid-sentence cuts detected!</td></tr>`;
      } else {
        issuesBodyEl.innerHTML = report.issues
          .map(
            (iss) => `<tr>
              <td><span class="fs-badge ${iss.severity === "CRITICAL" || iss.severity === "HIGH" ? "fs-badge-warn" : "fs-badge-muted"}">${escapeHtml(iss.severity)}</span></td>
              <td><code>${escapeHtml(iss.timestamp)}</code></td>
              <td><code>${escapeHtml(iss.code)}</code></td>
              <td>${escapeHtml(iss.message)}</td>
            </tr>`
          )
          .join("");
      }
    }

    if (cuesBodyEl) {
      cuesBodyEl.innerHTML = report.cues
        .map(
          (c) => `<tr data-srt-jump-ms="${c.startMs + 20}" style="cursor:pointer;" title="Click to preview Cue #${c.index} on 9:16 Phone Screen">
            <td><strong>#${c.index}</strong></td>
            <td><code>${escapeHtml(c.startSrt)} → ${escapeHtml(c.endSrt)}</code></td>
            <td><strong>${c.cps}</strong> <small class="inv-muted">CPS</small> · <small>${c.longestLineChars}ch</small></td>
            <td>${c.lines.map((l) => escapeHtml(l)).join("<br>")}</td>
            <td>${
              c.flags.length === 0
                ? `<span class="fs-badge fs-badge-success">OK</span>`
                : c.flags
                    .map((f) => `<span class="fs-badge fs-badge-warn">${escapeHtml(f)}</span>`)
                    .join(" ")
            }</td>
          </tr>`
        )
        .join("");

      cuesBodyEl.querySelectorAll("[data-srt-jump-ms]").forEach((row) => {
        row.addEventListener("click", () => {
          stopPlayback();
          const jumpMs = Number(row.getAttribute("data-srt-jump-ms")) || 0;
          if (timelineRangeEl) timelineRangeEl.value = String(jumpMs);
          renderPhoneAtMs(jumpMs);
        });
      });
    }

    const maxEnd = report.cues.at(-1).endMs;
    const firstStart = report.cues[0].startMs;
    if (timelineRangeEl) {
      timelineRangeEl.min = "0";
      timelineRangeEl.max = String(Math.max(1000, maxEnd));
      timelineRangeEl.value = String(firstStart + 50);
    }
    renderPhoneAtMs(firstStart + 50);
    renderNormalizedOutputPane();

    if (statusEl) {
      statusEl.className = "fs-status-msg is-success";
      statusEl.textContent = `Audited ${report.cueCount} cues (${report.detectedFormat.toUpperCase()}) — Score ${report.qualityScore}/100 (${report.verdict}).`;
    }
  }

  document.querySelectorAll("[data-srt-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.getAttribute("data-srt-sample");
      if (!SRTLAB_SAMPLES[key] || !inputEl) return;
      inputEl.value = SRTLAB_SAMPLES[key];
      if (brandInputEl) {
        brandInputEl.value =
          key === "multilang_dub_srt"
            ? "San Diego, ForgeSuite, OpenAI, NEAR Protocol"
            : "ForgeSuite";
      }
      if (autoFixCheckEl) autoFixCheckEl.checked = false;
      executeAudit(false);
    });
  });

  outputFormatTabs.forEach((tabBtn) => {
    tabBtn.addEventListener("click", () => {
      activeOutputTab = tabBtn.getAttribute("data-srt-out-tab") || "srt";
      outputFormatTabs.forEach((b) => {
        b.className =
          b === tabBtn
            ? "fs-btn fs-btn-sm fs-btn-primary"
            : "fs-btn fs-btn-sm fs-btn-secondary";
      });
      renderNormalizedOutputPane();
    });
  });

  if (fileUploadEl) {
    fileUploadEl.addEventListener("change", async () => {
      const f = fileUploadEl.files?.[0];
      if (!f || !inputEl) return;
      inputEl.value = await f.text();
      executeAudit();
    });
  }

  if (runAuditBtn) runAuditBtn.addEventListener("click", () => executeAudit());
  if (autoFixNowBtn) {
    autoFixNowBtn.addEventListener("click", () => executeAudit(true));
  }
  [assStyleSelectEl, assPopCheckEl].forEach((el) => {
    if (el) {
      el.addEventListener("change", () => {
        renderPhoneAtMs(currentPlayMs);
        renderNormalizedOutputPane();
      });
    }
  });

  if (timelineRangeEl) {
    timelineRangeEl.addEventListener("input", () => {
      stopPlayback();
      renderPhoneAtMs(Number(timelineRangeEl.value) || 0);
    });
  }

  if (playToggleBtn) {
    playToggleBtn.addEventListener("click", () => {
      if (playTimer) {
        stopPlayback();
        return;
      }
      if (!lastAudit?.ok || lastAudit.cues.length === 0) return;
      const maxEnd = lastAudit.cues.at(-1).endMs;
      if (currentPlayMs >= maxEnd) {
        currentPlayMs = lastAudit.cues[0].startMs;
      }
      playToggleBtn.textContent = "⏸ Pause Preview";
      playTimer = setInterval(() => {
        currentPlayMs += 100;
        if (timelineRangeEl) timelineRangeEl.value = String(currentPlayMs);
        renderPhoneAtMs(currentPlayMs);
        if (currentPlayMs >= maxEnd) {
          stopPlayback();
        }
      }, 100);
    });
  }

  if (downloadSrtBtn) {
    downloadSrtBtn.addEventListener("click", () => {
      if (!lastAudit?.ok) executeAudit();
      if (lastAudit?.ok) downloadTextFile("captions-normalized.srt", lastAudit.outputs.srt);
    });
  }
  if (downloadVttBtn) {
    downloadVttBtn.addEventListener("click", () => {
      if (!lastAudit?.ok) executeAudit();
      if (lastAudit?.ok) downloadTextFile("captions-normalized.vtt", lastAudit.outputs.vtt, "text/vtt;charset=utf-8");
    });
  }
  if (downloadTxtBtn) {
    downloadTxtBtn.addEventListener("click", () => {
      if (!lastAudit?.ok) executeAudit();
      if (lastAudit?.ok) downloadTextFile("transcript-clean.txt", lastAudit.outputs.txt);
    });
  }
  if (downloadAssBtn) {
    downloadAssBtn.addEventListener("click", () => {
      if (!isClipCaptionProUnlocked()) {
        openCheckoutModal("AS", { onUnlocked: syncProUi });
        return;
      }
      if (!lastAudit?.ok) executeAudit();
      if (!lastAudit?.ok) return;
      const ass = serializeToVerticalAss(lastAudit.cues, {
        preset: assStyleSelectEl?.value || "mobile_bold",
        animatePop: assPopCheckEl ? assPopCheckEl.checked : true,
      });
      downloadTextFile("captions-9x16-mobile.ass", ass);
    });
  }

  if (copyOutputBtn) {
    copyOutputBtn.addEventListener("click", async () => {
      if (!normalizedPreviewEl?.value) return;
      if (activeOutputTab === "ass" && !isClipCaptionProUnlocked()) {
        openCheckoutModal("AS", { onUnlocked: syncProUi });
        return;
      }
      const prev = copyOutputBtn.textContent;
      try {
        await navigator.clipboard.writeText(normalizedPreviewEl.value);
        copyOutputBtn.textContent = "Copied ✓";
        setTimeout(() => {
          copyOutputBtn.textContent = prev;
        }, 1600);
      } catch {}
    });
  }

  if (copyMdBtn) {
    copyMdBtn.addEventListener("click", async () => {
      if (!lastAudit?.markdownReport) return;
      const prev = copyMdBtn.textContent;
      try {
        await navigator.clipboard.writeText(lastAudit.markdownReport);
        copyMdBtn.textContent = "Copied Report ✓";
        setTimeout(() => {
          copyMdBtn.textContent = prev;
        }, 1600);
      } catch {}
    });
  }

  if (shareLinkBtn) {
    shareLinkBtn.addEventListener("click", async () => {
      if (!lastAudit?.ok) return;
      const encoded = encodeBase64UrlUtf8(lastAudit.outputs.srt);
      const url = `${window.location.origin}${window.location.pathname}#srt=${encoded}`;
      window.history.replaceState({}, "", `#srt=${encoded}`);
      const prev = shareLinkBtn.textContent;
      try {
        await navigator.clipboard.writeText(url);
        shareLinkBtn.textContent = "Share URL Copied ✓";
        setTimeout(() => {
          shareLinkBtn.textContent = prev;
        }, 1600);
      } catch {}
    });
  }

  if (batchFilesInputEl) {
    batchFilesInputEl.addEventListener("change", async () => {
      const files = Array.from(batchFilesInputEl.files || []).slice(
        0,
        MAX_BATCH_SUBTITLE_FILES
      );
      stagedBatchFiles = await Promise.all(
        files.map(async (f) => ({ name: f.name, content: await f.text() }))
      );
      if (batchStatusEl) {
        batchStatusEl.className = "fs-status-msg is-loading";
        batchStatusEl.textContent = `Staged ${stagedBatchFiles.length} subtitle file(s) ready for Pro batch audit.`;
      }
    });
  }

  if (batchLoadDemoBtn) {
    batchLoadDemoBtn.addEventListener("click", () => {
      stagedBatchFiles = [
        { name: "ep01_shorts_hook.srt", content: SRTLAB_SAMPLES.creator_hook_issues },
        { name: "ep02_product_reel.vtt", content: SRTLAB_SAMPLES.clean_vertical_vtt },
        { name: "ep03_spanish_dub.srt", content: SRTLAB_SAMPLES.multilang_dub_srt },
      ];
      if (batchStatusEl) {
        batchStatusEl.className = "fs-status-msg is-success";
        batchStatusEl.textContent =
          "Loaded 3 sample multi-format episodes (ep01_shorts_hook.srt, ep02_product_reel.vtt, ep03_spanish_dub.srt).";
      }
    });
  }

  if (batchRunBtn) {
    batchRunBtn.addEventListener("click", () => {
      if (!isClipCaptionProUnlocked()) {
        openCheckoutModal("BUNDLE", { onUnlocked: syncProUi });
        return;
      }
      if (stagedBatchFiles.length === 0) {
        stagedBatchFiles = [
          { name: "ep01_shorts_hook.srt", content: SRTLAB_SAMPLES.creator_hook_issues },
          { name: "ep02_product_reel.vtt", content: SRTLAB_SAMPLES.clean_vertical_vtt },
          { name: "ep03_spanish_dub.srt", content: SRTLAB_SAMPLES.multilang_dub_srt },
        ];
      }
      try {
        const opts = getAuditOptionsFromUi();
        const pack = runBatchSubtitleAudit(stagedBatchFiles, opts);
        lastBatchPack = pack;
        if (batchTableBodyEl) {
          batchTableBodyEl.innerHTML = pack.reports
            .map(
              (r, idx) => `<tr>
                <td><strong>${escapeHtml(r.fileName)}</strong> <small class="inv-muted">(${escapeHtml(r.detectedFormat.toUpperCase())})</small></td>
                <td>${r.cueCount} cues</td>
                <td><span class="fs-badge ${r.qualityScore >= 88 ? "fs-badge-success" : "fs-badge-warn"}">${r.qualityScore}/100</span></td>
                <td><small>${r.metrics.overlapCount} ovlp · ${r.metrics.highCpsCount} CPS · ${r.metrics.safeZoneOverflowCount} wide</small></td>
                <td><button type="button" class="fs-btn fs-btn-sm fs-btn-secondary" data-batch-ass-idx="${idx}">.ASS</button></td>
              </tr>`
            )
            .join("");

          batchTableBodyEl.querySelectorAll("[data-batch-ass-idx]").forEach((b) => {
            b.addEventListener("click", () => {
              const i = Number(b.getAttribute("data-batch-ass-idx"));
              const item = lastBatchPack?.reports?.[i];
              if (item?.assOutput) {
                const base = item.fileName.replace(/\.[^.]+$/, "");
                downloadTextFile(`${base}-9x16.ass`, item.assOutput);
              }
            });
          });
        }
        if (batchExportCsvBtn) batchExportCsvBtn.disabled = false;
        if (batchExportJsonBtn) batchExportJsonBtn.disabled = false;
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-success";
          batchStatusEl.textContent = `Batch complete: ${pack.okFiles}/${pack.totalFiles} files · Avg Score ${pack.averageQualityScore}/100 · ${pack.totalCues} total cues.`;
        }
      } catch (err) {
        if (batchStatusEl) {
          batchStatusEl.className = "fs-status-msg is-error";
          batchStatusEl.textContent = err instanceof Error ? err.message : String(err);
        }
      }
    });
  }

  if (batchExportCsvBtn) {
    batchExportCsvBtn.addEventListener("click", () => {
      if (!isClipCaptionProUnlocked() || !lastBatchPack) return;
      downloadTextFile(
        "clipcaption-batch-audit.csv",
        exportBatchSubtitleCsv(lastBatchPack),
        "text/csv;charset=utf-8"
      );
    });
  }

  if (batchExportJsonBtn) {
    batchExportJsonBtn.addEventListener("click", () => {
      if (!isClipCaptionProUnlocked() || !lastBatchPack) return;
      downloadTextFile(
        "clipcaption-batch-dossier.json",
        JSON.stringify({ suite: "ForgeSuite ClipCaption Lab Pro", ...lastBatchPack }, null, 2),
        "application/json;charset=utf-8"
      );
    });
  }

  if (sendInvoiceBtn) {
    sendInvoiceBtn.addEventListener("click", () => {
      const inv = buildCaptionLocalizationInvoicePayload(lastBatchPack || lastAudit);
      window.location.href = `cryptobill.html#inv=${encodeInvoicePayload(inv)}`;
    });
  }

  if (sendSowBtn) {
    sendSowBtn.addEventListener("click", () => {
      const sow = buildCaptionSowState(lastBatchPack || lastAudit);
      const encoded = encodeBase64UrlUtf8(JSON.stringify(sow));
      window.location.href = `sowbuilder.html#sow=${encoded}`;
    });
  }

  syncProUi();

  const qp = parseSrtLabQueryParams(window.location.search, window.location.hash);
  if (shiftInputEl && qp.shiftMs !== 0) shiftInputEl.value = String(qp.shiftMs);
  if (tempoInputEl && qp.tempoScale !== 1) tempoInputEl.value = String(qp.tempoScale);
  if (maxCpsInputEl) maxCpsInputEl.value = String(qp.maxCps);
  if (maxLineInputEl) maxLineInputEl.value = String(qp.maxLineLength);
  if (brandInputEl && qp.brandTerms) brandInputEl.value = qp.brandTerms;
  if (autoFixCheckEl && qp.autoFix) autoFixCheckEl.checked = true;
  if (qp.outputTab && qp.outputTab !== "srt") {
    activeOutputTab = qp.outputTab;
    outputFormatTabs.forEach((b) => {
      b.className =
        b.getAttribute("data-srt-out-tab") === activeOutputTab
          ? "fs-btn fs-btn-sm fs-btn-primary"
          : "fs-btn fs-btn-sm fs-btn-secondary";
    });
  }

  if (inputEl) {
    if (qp.decodedSubtitle) {
      inputEl.value = qp.decodedSubtitle;
    } else if (qp.sample && SRTLAB_SAMPLES[qp.sample]) {
      inputEl.value = SRTLAB_SAMPLES[qp.sample];
    } else if (!inputEl.value.trim()) {
      inputEl.value = SRTLAB_SAMPLES.creator_hook_issues;
      if (brandInputEl && !brandInputEl.value) brandInputEl.value = "ForgeSuite";
    }
    executeAudit();
  }
}

export { validateLicenseKeyFormat };

if (typeof window !== "undefined") {
  window.addEventListener("DOMContentLoaded", initClipCaptionLab);
}
