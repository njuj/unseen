// Every character that can hide in plain sight: what it is called, what kind it is, and when it is
// legitimate. The same tables drive scanning, revealing and cleaning.

const SINGLE = new Map([
  [0x200b, ["ZWSP", "zero-width"]], [0x200c, ["ZWNJ", "zero-width"]], [0x200d, ["ZWJ", "zero-width"]],
  [0x2060, ["WJ", "zero-width"]], [0xfeff, ["ZWNBSP", "zero-width"]], [0x180e, ["MVS", "zero-width"]],
  [0x034f, ["CGJ", "zero-width"]], [0x061c, ["ALM", "bidi"]],
  [0x2061, ["FUNCTION APPLICATION", "invisible-math"]], [0x2062, ["INVISIBLE TIMES", "invisible-math"]],
  [0x2063, ["INVISIBLE SEPARATOR", "invisible-math"]], [0x2064, ["INVISIBLE PLUS", "invisible-math"]],
  [0x00ad, ["SHY", "soft-hyphen"]],
  [0x00a0, ["NBSP", "space"]], [0x202f, ["NNBSP", "space"]], [0x205f, ["MMSP", "space"]],
  [0x3000, ["IDEOGRAPHIC SPACE", "space"]], [0x1680, ["OGHAM SPACE", "space"]],
  [0x2028, ["LINE SEPARATOR", "line-break"]], [0x2029, ["PARAGRAPH SEPARATOR", "line-break"]],
  [0x0085, ["NEL", "line-break"]],
  [0x200e, ["LRM", "bidi"]], [0x200f, ["RLM", "bidi"]], [0x202a, ["LRE", "bidi"]], [0x202b, ["RLE", "bidi"]],
  [0x202c, ["PDF", "bidi"]], [0x202d, ["LRO", "bidi"]], [0x202e, ["RLO", "bidi"]], [0x2066, ["LRI", "bidi"]],
  [0x2067, ["RLI", "bidi"]], [0x2068, ["FSI", "bidi"]], [0x2069, ["PDI", "bidi"]],
  [0x115f, ["HANGUL CHOSEONG FILLER", "filler"]], [0x1160, ["HANGUL JUNGSEONG FILLER", "filler"]],
  [0x3164, ["HANGUL FILLER", "filler"]], [0xffa0, ["HALFWIDTH HANGUL FILLER", "filler"]],
  [0x2800, ["BRAILLE BLANK", "filler"]], [0x17b4, ["KHMER VOWEL INHERENT AQ", "filler"]],
  [0x17b5, ["KHMER VOWEL INHERENT AA", "filler"]],
  [0xfff9, ["INTERLINEAR ANNOTATION ANCHOR", "format"]], [0xfffa, ["INTERLINEAR ANNOTATION SEPARATOR", "format"]],
  [0xfffb, ["INTERLINEAR ANNOTATION TERMINATOR", "format"]],
]);

const RANGES = [
  [0x2000, 0x200a, (cp) => ["SPACE U+" + hex(cp), "space"]],
  [0x206a, 0x206f, (cp) => ["DEPRECATED FORMAT U+" + hex(cp), "format"]],
  [0xfe00, 0xfe0f, (cp) => ["VS" + (cp - 0xfe00 + 1), "variation-selector"]],
  [0xe0100, 0xe01ef, (cp) => ["VS" + (cp - 0xe0100 + 17), "variation-selector"]],
  [0xe0000, 0xe007f, (cp) => [cp >= 0xe0020 && cp <= 0xe007e ? "TAG " + JSON.stringify(String.fromCharCode(cp - 0xe0000)) : "TAG U+" + hex(cp), "tag"]],
  [0x0000, 0x001f, (cp) => ["CONTROL U+" + hex(cp), "control"]],
  [0x007f, 0x009f, (cp) => ["CONTROL U+" + hex(cp), "control"]],
  [0xe000, 0xf8ff, (cp) => ["PRIVATE USE U+" + hex(cp), "private-use"]],
  [0xf0000, 0x10ffff, (cp) => ["PRIVATE USE U+" + hex(cp), "private-use"]],
];

export function hex(cp) {
  return cp.toString(16).toUpperCase().padStart(4, "0");
}

/** [name, kind] for a character that does not show (or does not show as what it is), else null. */
export function charInfo(cp) {
  if (cp === 0x09 || cp === 0x0a || cp === 0x0d) return null;
  const single = SINGLE.get(cp);
  if (single) return single;
  for (const [lo, hi, f] of RANGES) if (cp >= lo && cp <= hi) return f(cp);
  return null;
}

export const KIND_LABEL = {
  "zero-width": "zero-width characters", "soft-hyphen": "soft hyphens", space: "unusual spaces",
  "line-break": "unusual line breaks", bidi: "bidirectional controls", tag: "Unicode tag characters",
  "variation-selector": "variation selectors", filler: "blank filler characters",
  "invisible-math": "invisible math operators", control: "control characters", "private-use": "private-use characters",
  format: "deprecated format characters",
};

// ── context: when an otherwise invisible character is doing a real job ──────

export function isEmoji(cp) {
  return (cp >= 0x1f000 && cp <= 0x1faff) || (cp >= 0x2600 && cp <= 0x27bf) || (cp >= 0x2300 && cp <= 0x23ff) ||
    (cp >= 0x2b00 && cp <= 0x2bff) || (cp >= 0x2190 && cp <= 0x21ff) || cp === 0x00a9 || cp === 0x00ae ||
    cp === 0x203c || cp === 0x2049 || cp === 0x2122 || cp === 0x2139 || cp === 0x3030 || cp === 0x303d ||
    cp === 0x3297 || cp === 0x3299 || cp === 0x2640 || cp === 0x2642;
}

/** Scripts where ZWJ / ZWNJ legitimately change how letters join (Arabic, Persian, Syriac, Indic, Myanmar...). */
export function isJoiningScript(cp) {
  return (cp >= 0x0600 && cp <= 0x08ff) || (cp >= 0xfb50 && cp <= 0xfdff) || (cp >= 0xfe70 && cp <= 0xfefe) ||
    (cp >= 0x0900 && cp <= 0x0dff) || (cp >= 0x1000 && cp <= 0x109f) || (cp >= 0x1800 && cp <= 0x18af) ||
    (cp >= 0xa8e0 && cp <= 0xa8ff) || (cp >= 0x0f00 && cp <= 0x0fff);
}

export function isRtlLetter(cp) {
  return (cp >= 0x0590 && cp <= 0x08ff) || (cp >= 0xfb1d && cp <= 0xfdff) || (cp >= 0xfe70 && cp <= 0xfefe);
}

export const BIDI_OVERRIDES = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);
export const BIDI_MARKS = new Set([0x200e, 0x200f, 0x061c]);
