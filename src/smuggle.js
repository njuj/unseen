// Reading messages smuggled through characters nobody can see.
//
// Three encodings are in real use: Unicode tag characters (each one mirrors an ASCII character; models
// read them, people do not), variation selectors appended to an emoji (one selector per byte), and
// binary written with two to four different zero-width characters.

const ZW_SET = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x180e, 0x2062, 0x2063, 0x2064, 0x034f]);

export function isZeroWidthSymbol(cp) {
  return ZW_SET.has(cp);
}

export function printableRatio(s) {
  if (!s) return 0;
  let ok = 0, n = 0;
  for (const ch of s) {
    n++;
    const cp = ch.codePointAt(0);
    if (cp === 0x0a || cp === 0x0d || cp === 0x09 || (cp >= 0x20 && cp !== 0x7f && !(cp >= 0x80 && cp <= 0x9f) && cp !== 0xfffd)) ok++;
  }
  return ok / n;
}

/** Tag characters U+E0020..E007E spell ASCII; U+E0001 and U+E007F only open and close the run. */
export function decodeTags(cps) {
  let out = "";
  for (const cp of cps) if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  return out;
}

const utf8 = new TextDecoder("utf-8", { fatal: true });

/** Variation selectors as bytes: U+FE00..FE0F are 0..15, U+E0100..E01EF are 16..255. */
export function decodeVariationSelectors(cps) {
  const bytes = [];
  for (const cp of cps) {
    if (cp >= 0xfe00 && cp <= 0xfe0f) bytes.push(cp - 0xfe00);
    else if (cp >= 0xe0100 && cp <= 0xe01ef) bytes.push(cp - 0xe0100 + 16);
  }
  try {
    const text = utf8.decode(new Uint8Array(bytes));
    return printableRatio(text) >= 0.9 ? text : null;
  } catch {
    return null;
  }
}

function permutations(items) {
  if (items.length <= 1) return [items];
  return items.flatMap((x, i) => permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((p) => [x, ...p]));
}

// How common a letter's alphabet is in real messages (and which bucket it belongs to).
function letterWeight(cp) {
  if (cp < 0x80) return [1, "ascii"];
  if (cp >= 0xc0 && cp <= 0xff) return [0.85, "latin1"];
  if (cp >= 0x100 && cp <= 0x17f) return [0.5, "latinA"];
  if (cp >= 0x180 && cp <= 0x2ff) return [0.1, "rare"];        // Latin Extended-B, IPA, modifier letters
  if (cp >= 0x370 && cp <= 0x3ff) return [0.8, "greek"];
  if (cp >= 0x400 && cp <= 0x4ff) return [0.9, "cyrillic"];
  if (cp >= 0x590 && cp <= 0x6ff) return [1, "semitic"];        // Hebrew, Arabic, Persian
  if (cp >= 0x900 && cp <= 0xdff) return [0.9, "indic"];
  if ((cp >= 0x3040 && cp <= 0x9fff) || (cp >= 0xac00 && cp <= 0xd7af)) return [0.9, "cjk"];
  return [0.3, "other"];
}

/** How much a string reads like language: common letters and spaces count up, rare symbols down. */
export function readability(text) {
  const chars = [...text];
  if (!chars.length) return 0;
  let score = 0;
  const scripts = new Set();
  for (const ch of chars) {
    if (/\p{L}/u.test(ch)) {
      const [w, bucket] = letterWeight(ch.codePointAt(0));
      score += w;
      scripts.add(bucket);
    } else if (ch === " ") score += 1.2;
    else if (/\p{N}/u.test(ch)) score += 0.6;
    else if (/[.,!?'"\-:;()\n/]/.test(ch)) score += 0.5;
    else if (/\p{Extended_Pictographic}/u.test(ch)) score += 0.5;
    else score -= 1.5;
  }
  return score / chars.length - Math.max(0, scripts.size - 2) * 0.2;   // real text rarely mixes many alphabets
}

function bytesToText(bytes) {
  try {
    return utf8.decode(new Uint8Array(bytes));
  } catch {
    return null;
  }
}

/**
 * Binary hidden in a run of zero-width characters. Tries every common scheme: two symbols as bits,
 * four symbols as bit pairs, or three symbols where one separates variable-length binary numbers.
 * Returns { text, scheme } for the most readable decoding, or null.
 */
export function decodeZeroWidthBinary(cps) {
  const symbols = [...new Set(cps)];
  if (cps.length < 8 || symbols.length < 2 || symbols.length > 4) return null;
  const candidates = [];
  if (symbols.length === 2 || symbols.length === 4) {
    const bitsPer = symbols.length === 2 ? 1 : 2;
    if ((cps.length * bitsPer) % 8 !== 0) return null;          // real encoders write whole bytes
    for (const order of permutations(symbols)) {
      const value = new Map(order.map((s, i) => [s, i]));
      let bits = "";
      for (const cp of cps) bits += value.get(cp).toString(2).padStart(bitsPer, "0");
      const bytes = [];
      for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
      const text = bytesToText(bytes);
      if (text) candidates.push({ text, scheme: `${symbols.length} symbols as ${bitsPer === 1 ? "bits" : "bit pairs"}` });
    }
  }
  if (symbols.length === 3) {
    for (const sep of symbols) {
      const rest = symbols.filter((s) => s !== sep);
      for (const [zero, one] of [rest, [...rest].reverse()]) {
        const groups = [];
        let cur = "";
        for (const cp of cps) {
          if (cp === sep) { if (cur) groups.push(cur); cur = ""; }
          else cur += cp === zero ? "0" : "1";
        }
        if (cur) groups.push(cur);
        // numbers written in binary start with a 1 and fit a code point: anything else is a wrong guess
        if (groups.length < 3 || groups.some((g) => g[0] !== "1" || g.length < 6 || g.length > 21)) continue;
        let text = "";
        try {
          text = String.fromCodePoint(...groups.map((g) => parseInt(g, 2)));
        } catch {
          continue;
        }
        candidates.push({ text, scheme: "binary numbers between separators" });
      }
    }
  }
  let best = null;
  for (const c of candidates) {
    if (printableRatio(c.text) < 0.95 || [...c.text].length < 3) continue;
    const score = readability(c.text);
    if (score < 0.55) continue;                                   // not language: noise or a wrong guess
    if (!best || score > best.score) best = { ...c, score };
  }
  return best ? { text: best.text, scheme: best.scheme } : null;
}
