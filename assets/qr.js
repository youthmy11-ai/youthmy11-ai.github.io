/**
 * Pure ES Module Deterministic QR Code Generator (ISO/IEC 18004)
 * Supports Versions 1-10, Byte Mode (UTF-8), Error Correction Levels L and M,
 * full Reed-Solomon GF(256) EC generation, optimal mask selection, SVG & Canvas output.
 * Zero external dependencies.
 */

const ALIGNMENT_POSITIONS = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
  10: [6, 28, 50],
};

// [totalCodewords, ecCodewordsPerBlock, group1Blocks, group1DataCW, group2Blocks, group2DataCW]
const VERSION_SPECS = {
  L: {
    1: [26, 7, 1, 19, 0, 0],
    2: [44, 10, 1, 34, 0, 0],
    3: [70, 15, 1, 55, 0, 0],
    4: [100, 20, 1, 80, 0, 0],
    5: [134, 26, 1, 108, 0, 0],
    6: [172, 18, 2, 68, 0, 0],
    7: [196, 20, 2, 78, 0, 0],
    8: [242, 24, 2, 97, 0, 0],
    9: [292, 30, 2, 116, 0, 0],
    10: [346, 18, 2, 68, 2, 69],
  },
  M: {
    1: [26, 10, 1, 16, 0, 0],
    2: [44, 16, 1, 28, 0, 0],
    3: [70, 26, 1, 44, 0, 0],
    4: [100, 18, 2, 32, 0, 0],
    5: [134, 24, 2, 43, 0, 0],
    6: [172, 16, 4, 27, 0, 0],
    7: [196, 18, 4, 31, 0, 0],
    8: [242, 22, 2, 38, 2, 39],
    9: [292, 22, 3, 36, 2, 37],
    10: [346, 26, 4, 43, 1, 44],
  },
};

const ECC_FORMAT_BITS = {
  L: 1, // 01
  M: 0, // 00
};

// Precompute GF(256) log/antilog tables with primitive polynomial 0x11d.
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) {
      x ^= 0x11d;
    }
  }
  for (let i = 255; i < 512; i += 1) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function getRsGeneratorPoly(ecCount) {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < ecCount; i += 1) {
    const factor = new Uint8Array([1, GF_EXP[i]]);
    const next = new Uint8Array(poly.length + 1);
    for (let j = 0; j < poly.length; j += 1) {
      next[j] ^= gfMul(poly[j], factor[0]);
      next[j + 1] ^= gfMul(poly[j], factor[1]);
    }
    poly = next;
  }
  return poly;
}

function computeRsEc(data, ecCount) {
  const gen = getRsGeneratorPoly(ecCount);
  const msg = new Uint8Array(data.length + ecCount);
  msg.set(data);
  for (let i = 0; i < data.length; i += 1) {
    const coef = msg[i];
    if (coef !== 0) {
      for (let j = 0; j < gen.length; j += 1) {
        msg[i + j] ^= gfMul(gen[j], coef);
      }
    }
  }
  return msg.slice(data.length);
}

function encodeUtf8Bytes(text) {
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(text);
  }
  // Fallback UTF-8 encoder
  const bytes = [];
  for (let i = 0; i < text.length; i += 1) {
    let code = text.charCodeAt(i);
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = 0x10000 + (((code - 0xd800) << 10) | (next - 0xdc00));
        i += 1;
        bytes.push(
          0xf0 | (code >> 18),
          0x80 | ((code >> 12) & 0x3f),
          0x80 | ((code >> 6) & 0x3f),
          0x80 | (code & 0x3f)
        );
      }
    } else {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
  }
  return new Uint8Array(bytes);
}

function getDataCapacityBytes(version, ecc) {
  const spec = VERSION_SPECS[ecc][version];
  return spec[2] * spec[3] + spec[4] * spec[5];
}

function selectVersionAndEcc(byteLen, requestedEcc = "M", strictEcc = false) {
  const ecc = requestedEcc === "L" ? "L" : "M";
  const tryOrder = strictEcc ? [ecc] : ecc === "M" ? ["M", "L"] : ["L"];

  for (const level of tryOrder) {
    for (let version = 1; version <= 10; version += 1) {
      const dataCodewords = getDataCapacityBytes(version, level);
      const countBits = version <= 9 ? 8 : 16;
      const overheadBits = 4 + countBits;
      const maxBytes = Math.floor((dataCodewords * 8 - overheadBits) / 8);
      if (byteLen <= maxBytes) {
        return { version, ecc: level };
      }
    }
  }
  throw new Error(
    `Input payload (${byteLen} bytes) exceeds QR Version 1-10 Byte capacity.`
  );
}

function buildDataCodewords(bytes, version, ecc) {
  const totalDataCw = getDataCapacityBytes(version, ecc);
  const totalBits = totalDataCw * 8;
  const bits = [];

  const pushBits = (value, length) => {
    for (let i = length - 1; i >= 0; i -= 1) {
      bits.push((value >>> i) & 1);
    }
  };

  // Byte mode indicator = 0100
  pushBits(0b0100, 4);
  // Character count indicator (8 bits for V1-9, 16 bits for V10)
  pushBits(bytes.length, version <= 9 ? 8 : 16);
  // Payload bytes
  for (let i = 0; i < bytes.length; i += 1) {
    pushBits(bytes[i], 8);
  }

  // Terminator (up to 4 zero bits)
  const terminatorLen = Math.min(4, totalBits - bits.length);
  for (let i = 0; i < terminatorLen; i += 1) {
    bits.push(0);
  }

  // Pad to byte boundary
  while (bits.length % 8 !== 0) {
    bits.push(0);
  }

  const codewords = new Uint8Array(totalDataCw);
  const dataByteLen = bits.length / 8;
  for (let i = 0; i < dataByteLen; i += 1) {
    let b = 0;
    for (let bit = 0; bit < 8; bit += 1) {
      b = (b << 1) | bits[i * 8 + bit];
    }
    codewords[i] = b;
  }

  // Alternate pad codewords 0xEC and 0x11
  for (let i = dataByteLen; i < totalDataCw; i += 1) {
    codewords[i] = (i - dataByteLen) % 2 === 0 ? 0xec : 0x11;
  }

  return codewords;
}

function interleaveCodewords(dataCodewords, version, ecc) {
  const [, ecPerBlock, g1Blocks, g1DataCw, g2Blocks, g2DataCw] = VERSION_SPECS[ecc][version];
  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;

  for (let i = 0; i < g1Blocks; i += 1) {
    const block = dataCodewords.slice(offset, offset + g1DataCw);
    offset += g1DataCw;
    dataBlocks.push(block);
    ecBlocks.push(computeRsEc(block, ecPerBlock));
  }
  for (let i = 0; i < g2Blocks; i += 1) {
    const block = dataCodewords.slice(offset, offset + g2DataCw);
    offset += g2DataCw;
    dataBlocks.push(block);
    ecBlocks.push(computeRsEc(block, ecPerBlock));
  }

  const result = [];
  const maxDataLen = Math.max(g1DataCw, g2DataCw);
  for (let col = 0; col < maxDataLen; col += 1) {
    for (let b = 0; b < dataBlocks.length; b += 1) {
      if (col < dataBlocks[b].length) {
        result.push(dataBlocks[b][col]);
      }
    }
  }
  for (let col = 0; col < ecPerBlock; col += 1) {
    for (let b = 0; b < ecBlocks.length; b += 1) {
      result.push(ecBlocks[b][col]);
    }
  }
  return new Uint8Array(result);
}

function createFunctionGrid(version) {
  const size = 17 + 4 * version;
  const modules = Array.from({ length: size }, () => new Uint8Array(size));
  const isFunc = Array.from({ length: size }, () => new Uint8Array(size));

  const setFunc = (r, c, dark) => {
    if (r >= 0 && r < size && c >= 0 && c < size) {
      modules[r][c] = dark ? 1 : 0;
      isFunc[r][c] = 1;
    }
  };

  const drawFinder = (topR, leftC) => {
    for (let dr = -1; dr <= 7; dr += 1) {
      for (let dc = -1; dc <= 7; dc += 1) {
        const r = topR + dr;
        const c = leftC + dc;
        if (r < 0 || r >= size || c < 0 || c >= size) continue;
        const inOuter = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
        const onBorder = dr === 0 || dr === 6 || dc === 0 || dc === 6;
        const inInner = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
        setFunc(r, c, inOuter && (onBorder || inInner));
      }
    }
  };

  drawFinder(0, 0);
  drawFinder(0, size - 7);
  drawFinder(size - 7, 0);

  // Timing patterns
  for (let i = 8; i < size - 8; i += 1) {
    const dark = i % 2 === 0;
    setFunc(6, i, dark);
    setFunc(i, 6, dark);
  }

  // Alignment patterns
  const centers = ALIGNMENT_POSITIONS[version];
  for (const rCenter of centers) {
    for (const cCenter of centers) {
      // Skip alignment patterns overlapping the three finder patterns
      if (
        (rCenter <= 8 && cCenter <= 8) ||
        (rCenter <= 8 && cCenter >= size - 9) ||
        (rCenter >= size - 9 && cCenter <= 8)
      ) {
        continue;
      }
      for (let dr = -2; dr <= 2; dr += 1) {
        for (let dc = -2; dc <= 2; dc += 1) {
          const dist = Math.max(Math.abs(dr), Math.abs(dc));
          setFunc(rCenter + dr, cCenter + dc, dist === 0 || dist === 2);
        }
      }
    }
  }

  // Reserve format info modules + mandatory dark module
  for (let i = 0; i <= 8; i += 1) {
    if (i !== 6) {
      setFunc(8, i, false);
      setFunc(i, 8, false);
    }
  }
  for (let i = 0; i < 8; i += 1) {
    setFunc(8, size - 1 - i, false);
    if (i < 7) {
      setFunc(size - 1 - i, 8, false);
    }
  }
  setFunc(4 * version + 9, 8, true);

  // Version info (V7+)
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i += 1) {
      rem = (rem << 1) ^ (((rem >>> 11) & 1) * 0x1f25);
    }
    const bits = (version << 12) | rem;
    for (let i = 0; i < 18; i += 1) {
      const bit = Boolean((bits >>> i) & 1);
      const r = Math.floor(i / 3);
      const c = size - 11 + (i % 3);
      setFunc(r, c, bit);
      setFunc(c, r, bit);
    }
  }

  return { size, modules, isFunc };
}

function placeDataBits(modules, isFunc, size, codewords) {
  const bitStream = [];
  for (let i = 0; i < codewords.length; i += 1) {
    for (let b = 7; b >= 0; b -= 1) {
      bitStream.push((codewords[i] >>> b) & 1);
    }
  }

  let bitIdx = 0;
  let goingUp = true;
  for (let rightCol = size - 1; rightCol >= 1; rightCol -= 2) {
    if (rightCol === 6) {
      rightCol = 5;
    }
    for (let step = 0; step < size; step += 1) {
      const r = goingUp ? size - 1 - step : step;
      for (let offset = 0; offset < 2; offset += 1) {
        const c = rightCol - offset;
        if (isFunc[r][c] === 0) {
          modules[r][c] = bitIdx < bitStream.length ? bitStream[bitIdx] : 0;
          bitIdx += 1;
        }
      }
    }
    goingUp = !goingUp;
  }
}

function applyMaskAndFormat(baseModules, isFunc, size, ecc, maskId) {
  const grid = baseModules.map((row) => Uint8Array.from(row));

  const shouldInvert = (r, c) => {
    switch (maskId) {
      case 0:
        return (r + c) % 2 === 0;
      case 1:
        return r % 2 === 0;
      case 2:
        return c % 3 === 0;
      case 3:
        return (r + c) % 3 === 0;
      case 4:
        return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
      case 5:
        return ((r * c) % 2) + ((r * c) % 3) === 0;
      case 6:
        return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
      case 7:
        return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
      default:
        return false;
    }
  };

  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c < size; c += 1) {
      if (isFunc[r][c] === 0 && shouldInvert(r, c)) {
        grid[r][c] ^= 1;
      }
    }
  }

  // Format information (BCH 15,5 masked with 0x5412)
  const data = (ECC_FORMAT_BITS[ecc] << 3) | maskId;
  let rem = data;
  for (let i = 0; i < 10; i += 1) {
    rem = (rem << 1) ^ (((rem >>> 9) & 1) * 0x537);
  }
  const formatBits = ((data << 10) | rem) ^ 0x5412;

  for (let i = 0; i < 15; i += 1) {
    const dark = (formatBits >>> i) & 1;
    // Copy 1 around top-left finder (bit 0 at (0,8) up to bit 14 at (8,0))
    if (i < 6) {
      grid[i][8] = dark;
    } else if (i < 8) {
      grid[i + 1][8] = dark;
    } else if (i === 8) {
      grid[8][7] = dark;
    } else {
      grid[8][14 - i] = dark;
    }

    // Copy 2 around top-right & bottom-left finders
    if (i < 8) {
      grid[8][size - 1 - i] = dark;
    } else {
      grid[size - 15 + i][8] = dark;
    }
  }

  return grid;
}

function computePenaltyScore(grid, size) {
  let penalty = 0;

  // Rule 1: 5+ consecutive modules of same color in rows and columns
  const scoreRuns = (getCell) => {
    for (let a = 0; a < size; a += 1) {
      let runColor = getCell(a, 0);
      let runLen = 1;
      for (let b = 1; b < size; b += 1) {
        const val = getCell(a, b);
        if (val === runColor) {
          runLen += 1;
        } else {
          if (runLen >= 5) penalty += 3 + (runLen - 5);
          runColor = val;
          runLen = 1;
        }
      }
      if (runLen >= 5) penalty += 3 + (runLen - 5);
    }
  };
  scoreRuns((r, c) => grid[r][c]);
  scoreRuns((c, r) => grid[r][c]);

  // Rule 2: 2x2 blocks of same color
  for (let r = 0; r < size - 1; r += 1) {
    for (let c = 0; c < size - 1; c += 1) {
      const v = grid[r][c];
      if (v === grid[r][c + 1] && v === grid[r + 1][c] && v === grid[r + 1][c + 1]) {
        penalty += 3;
      }
    }
  }

  // Rule 3: 1:1:3:1:1 finder-like ratio with 4 light modules on either side
  const checkPattern = (line) => {
    for (let i = 0; i <= line.length - 11; i += 1) {
      const p1 =
        line[i] === 1 &&
        line[i + 1] === 0 &&
        line[i + 2] === 1 &&
        line[i + 3] === 1 &&
        line[i + 4] === 1 &&
        line[i + 5] === 0 &&
        line[i + 6] === 1 &&
        line[i + 7] === 0 &&
        line[i + 8] === 0 &&
        line[i + 9] === 0 &&
        line[i + 10] === 0;
      const p2 =
        line[i] === 0 &&
        line[i + 1] === 0 &&
        line[i + 2] === 0 &&
        line[i + 3] === 0 &&
        line[i + 4] === 1 &&
        line[i + 5] === 0 &&
        line[i + 6] === 1 &&
        line[i + 7] === 1 &&
        line[i + 8] === 1 &&
        line[i + 9] === 0 &&
        line[i + 10] === 1;
      if (p1 || p2) penalty += 40;
    }
  };
  for (let r = 0; r < size; r += 1) {
    checkPattern(grid[r]);
  }
  const colBuf = new Uint8Array(size);
  for (let c = 0; c < size; c += 1) {
    for (let r = 0; r < size; r += 1) colBuf[r] = grid[r][c];
    checkPattern(colBuf);
  }

  // Rule 4: Dark/light ratio balance
  let darkCount = 0;
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c < size; c += 1) {
      if (grid[r][c] === 1) darkCount += 1;
    }
  }
  const percent = (darkCount * 100) / (size * size);
  const prev5 = Math.floor(percent / 5) * 5;
  const next5 = prev5 + 5;
  penalty += Math.min(Math.abs(prev5 - 50) / 5, Math.abs(next5 - 50) / 5) * 10;

  return penalty;
}

/**
 * Encodes UTF-8 text into a QR Code object with version, ecc, mask, and 2D boolean matrix.
 * @param {string} text
 * @param {{ ecc?: 'L'|'M', strictEcc?: boolean }} [options]
 */
export function encodeQr(text, options = {}) {
  if (typeof text !== "string" || text.trim().length === 0) {
    throw new Error("QR input text must be a non-empty string.");
  }
  const bytes = encodeUtf8Bytes(text);
  const { version, ecc } = selectVersionAndEcc(
    bytes.length,
    options.ecc || "M",
    Boolean(options.strictEcc)
  );
  const dataCodewords = buildDataCodewords(bytes, version, ecc);
  const fullStream = interleaveCodewords(dataCodewords, version, ecc);

  const { size, modules, isFunc } = createFunctionGrid(version);
  placeDataBits(modules, isFunc, size, fullStream);

  let bestMask = 0;
  let bestPenalty = Infinity;
  let bestGrid = null;

  for (let mask = 0; mask < 8; mask += 1) {
    const candidate = applyMaskAndFormat(modules, isFunc, size, ecc, mask);
    const score = computePenaltyScore(candidate, size);
    if (score < bestPenalty) {
      bestPenalty = score;
      bestMask = mask;
      bestGrid = candidate;
    }
  }

  const matrix = bestGrid.map((row) => Array.from(row, (cell) => cell === 1));
  return { version, size, ecc, mask: bestMask, matrix };
}

/**
 * Generates a deterministic square 2D boolean matrix (>= 21x21) for the input string.
 * @param {string} text
 * @param {{ ecc?: 'L'|'M', strictEcc?: boolean }} [options]
 * @returns {boolean[][]}
 */
export function generateQrMatrix(text, options = {}) {
  return encodeQr(text, options).matrix;
}

function escapeXmlAttr(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

/**
 * Renders a QR matrix or text string into a self-contained crisp SVG string.
 * @param {string|boolean[][]} textOrMatrix
 * @param {{ margin?: number, size?: number, darkColor?: string, lightColor?: string, ecc?: 'L'|'M', label?: string }} [options]
 * @returns {string}
 */
export function renderQrSvg(textOrMatrix, options = {}) {
  const matrix = Array.isArray(textOrMatrix)
    ? textOrMatrix
    : generateQrMatrix(textOrMatrix, { ecc: options.ecc || "M" });

  const moduleCount = matrix.length;
  const margin = Number.isFinite(options.margin) ? Math.max(0, options.margin) : 4;
  const viewSize = moduleCount + margin * 2;
  const pixelSize = Number.isFinite(options.size) ? options.size : 200;
  const darkColor = options.darkColor || "#0f172a";
  const lightColor = options.lightColor || "#ffffff";
  const ariaLabel = options.label || "QR Code";

  // Build compact horizontal run-length SVG path
  const pathParts = [];
  for (let r = 0; r < moduleCount; r += 1) {
    let c = 0;
    while (c < moduleCount) {
      if (matrix[r][c]) {
        let runEnd = c + 1;
        while (runEnd < moduleCount && matrix[r][runEnd]) {
          runEnd += 1;
        }
        const width = runEnd - c;
        pathParts.push(`M${c + margin},${r + margin}h${width}v1h-${width}z`);
        c = runEnd;
      } else {
        c += 1;
      }
    }
  }

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewSize} ${viewSize}" width="${pixelSize}" height="${pixelSize}" role="img" aria-label="${escapeXmlAttr(ariaLabel)}" shape-rendering="crispEdges">`,
    `<rect width="${viewSize}" height="${viewSize}" fill="${escapeXmlAttr(lightColor)}"/>`,
    `<path d="${pathParts.join("")}" fill="${escapeXmlAttr(darkColor)}"/>`,
    `</svg>`,
  ].join("");
}

/**
 * Renders a QR matrix or text string directly onto an HTML5 Canvas element.
 * @param {HTMLCanvasElement} canvas
 * @param {string|boolean[][]} textOrMatrix
 * @param {{ margin?: number, size?: number, darkColor?: string, lightColor?: string, ecc?: 'L'|'M' }} [options]
 */
export function renderQrToCanvas(canvas, textOrMatrix, options = {}) {
  if (!canvas || typeof canvas.getContext !== "function") {
    throw new Error("A valid HTMLCanvasElement is required.");
  }
  const matrix = Array.isArray(textOrMatrix)
    ? textOrMatrix
    : generateQrMatrix(textOrMatrix, { ecc: options.ecc || "M" });

  const moduleCount = matrix.length;
  const margin = Number.isFinite(options.margin) ? Math.max(0, options.margin) : 4;
  const totalModules = moduleCount + margin * 2;
  const targetPx = Number.isFinite(options.size) ? options.size : 220;
  const scale = Math.max(1, Math.floor(targetPx / totalModules));
  const actualPx = totalModules * scale;

  canvas.width = actualPx;
  canvas.height = actualPx;

  const ctx = canvas.getContext("2d");
  ctx.fillStyle = options.lightColor || "#ffffff";
  ctx.fillRect(0, 0, actualPx, actualPx);

  ctx.fillStyle = options.darkColor || "#0f172a";
  for (let r = 0; r < moduleCount; r += 1) {
    for (let c = 0; c < moduleCount; c += 1) {
      if (matrix[r][c]) {
        ctx.fillRect((c + margin) * scale, (r + margin) * scale, scale, scale);
      }
    }
  }
}
