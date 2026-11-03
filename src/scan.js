// The scan: every character a reader cannot see, every message smuggled in them, every hidden element,
// every lookalike letter. Pure functions over strings (and bytes for .docx): the same module runs in
// Node and in the browser.

import { BIDI_MARKS, BIDI_OVERRIDES, charInfo, hex, isEmoji, isJoiningScript, isRtlLetter, KIND_LABEL } from "./chars.js";
import { isStyledLetter, lookalikeWords, unspoof } from "./confusables.js";
import { readDocx } from "./docx.js";
import { decodeEntities, hiddenHtml, stripHidden } from "./html.js";
import { injectionSignals, injectionVerdict } from "./injection.js";
import { codeMask } from "./lexer.js";
import { decodeTags, decodeVariationSelectors, decodeZeroWidthBinary, isZeroWidthSymbol } from "./smuggle.js";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

const CODE = /\.(m?js|cjs|jsx|tsx?|py|pyw|rb|go|rs|java|kts?|c|h|cc|cpp|cxx|hpp|cs|php|swift|scala|sh|bash|zsh|ps1|psm1|lua|pl|r|dart|sql|vue|svelte|json|ya?ml|toml|ini|cfg|tf|gradle|groovy|m|mm|ex|exs|erl|hs|clj|fs|vb|bat|cmd)$/i;
export function kindOf(name = "") {
  if (/\.docx$/i.test(name)) return "docx";
  if (/\.(html?|xhtml|eml|svg|xml)$/i.test(name)) return "html";
  if (/\.(md|markdown|mdx)$/i.test(name)) return "markdown";
  if (CODE.test(name)) return "code";
  return "text";
}

const IDENT = /[\p{L}\p{N}_$]/u;

/** Each character a reader cannot see, with whether it is doing a legitimate job where it stands. */
function invisibles(text, code) {
  const out = [];
  const hasRtl = /[֐-ࣿיִ-﷿ﹰ-﻾]/.test(text);
  let i = 0, prev = 0, prevIdx = -1;
  const cpAt = (k) => (k >= 0 && k < text.length ? text.codePointAt(k) : 0);
  while (i < text.length) {
    const cp = text.codePointAt(i);
    const size = cp > 0xffff ? 2 : 1;
    const info = charInfo(cp);
    if (info) {
      const next = cpAt(i + size);
      const [name, kind] = info;
      let legit = false;
      if (cp === 0xfeff && i === 0) legit = true;                                   // byte order mark
      else if (cp === 0x200c || cp === 0x200d) {
        legit = (isJoiningScript(prev) && isJoiningScript(next)) ||
          (cp === 0x200d && (isEmoji(prev) || prev === 0xfe0f || (prev >= 0x1f3fb && prev <= 0x1f3ff)) && isEmoji(next));
      } else if (cp === 0x180e) legit = isJoiningScript(prev) && isJoiningScript(next);
      else if (kind === "variation-selector") {
        legit = !charInfo(prev) && !(next >= 0xfe00 && next <= 0xfe0f) && !(next >= 0xe0100 && next <= 0xe01ef);
      } else if (BIDI_MARKS.has(cp)) legit = !code && hasRtl;
      else if (cp === 0x0c) legit = true;                                           // form feed: page breaks in source
      out.push({ i, cp, size, name, kind, legit, prevCp: prev, prevIdx });
    }
    prevIdx = i;
    prev = cp;
    i += size;
  }
  // tag sequences that spell subdivision flags (England, Scotland, Wales) after U+1F3F4 are emoji
  for (let k = 0; k < out.length; k++) {
    if (out[k].kind !== "tag" || out[k].prevCp !== 0x1f3f4) continue;
    let j = k;
    while (j < out.length && out[j].kind === "tag" && (j === k || out[j].i === out[j - 1].i + 2)) j++;
    const run = out.slice(k, j);
    const letters = run.slice(0, -1).map((c) => c.cp);
    if (run.length >= 3 && run.length <= 8 && run.at(-1).cp === 0xe007f &&
        letters.every((c) => (c >= 0xe0061 && c <= 0xe007a) || (c >= 0xe0030 && c <= 0xe0039))) {
      run.forEach((c) => { c.legit = true; });
    }
    k = j - 1;
  }
  return out;
}

/** Consecutive invisible characters as runs: [{ start, end, chars }]. */
function runs(chars) {
  const out = [];
  for (const c of chars) {
    const last = out.at(-1);
    if (last && last.end === c.i) { last.chars.push(c); last.end = c.i + c.size; }
    else out.push({ start: c.i, end: c.i + c.size, chars: [c] });
  }
  return out;
}

function locator(text, map) {
  const starts = [0];
  for (let k = 0; k < text.length; k++) if (text.charCodeAt(k) === 10) starts.push(k + 1);
  return (index) => {
    const at = map ? map[index] : index;
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= at) lo = mid; else hi = mid - 1; }
    return { line: lo + 1, column: [...text.slice(starts[lo], at)].length + 1 };
  };
}

function clip(s, n = 300) {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

// ways of hiding text that keep it on the page for machines: the trick behind white-text resumes
const CAMOUFLAGE = /white text|colour equals|font-size|transparent|size \d|tiny/;

/** "12× display:none, 3× hidden attribute" for a list of hidden regions. */
function reasons(list) {
  const n = {};
  for (const r of list) { const k = r.reason.replace(/ \(via [^)]*\)$/, ""); n[k] = (n[k] || 0) + 1; }
  return Object.entries(n).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => `${v}× ${k}`).join(", ");
}

/**
 * Scan a string. kind: text | code | markdown | html.
 * Returns { findings, invisible: { total, legit, byKind }, messages }.
 */
export function scan(source, { kind = "text" } = {}) {
  const findings = [];
  const add = (f) => findings.push(f);
  // HTML: work on the text a browser would build (entities decoded), report positions in the source
  let text = source, map = null;
  if (kind === "html") ({ text, map } = decodeEntities(source));
  const at = locator(source, map);
  const code = kind === "code";
  const chars = invisibles(text, code);
  const suspicious = chars.filter((c) => !c.legit);
  const byKind = {};
  for (const c of suspicious) byKind[c.kind] = (byKind[c.kind] || 0) + 1;
  const consumed = new Set();
  const messages = [];

  // 1. messages smuggled in invisible characters
  for (const run of runs(suspicious)) {
    const cps = run.chars.map((c) => c.cp);
    const tags = run.chars.filter((c) => c.kind === "tag");
    const vs = run.chars.filter((c) => c.kind === "variation-selector");
    const zw = run.chars.filter((c) => isZeroWidthSymbol(c.cp));
    let message = null, how = "";
    if (tags.length >= 2) { message = decodeTags(tags.map((c) => c.cp)); how = "Unicode tag characters (ASCII smuggling)"; }
    else if (vs.length >= 2) {
      message = decodeVariationSelectors(vs.map((c) => c.cp));
      const base = String.fromCodePoint(run.chars[0].prevCp || 0x20);
      how = `variation selectors after ${JSON.stringify(base)}`;
    } else if (zw.length >= 8) {
      const d = decodeZeroWidthBinary(zw.map((c) => c.cp));
      if (d) { message = d.text; how = `zero-width characters (${d.scheme})`; }
    }
    if (!message || !message.trim()) continue;
    run.chars.forEach((c) => consumed.add(c));
    const signals = injectionSignals(message);
    messages.push({ text: message, how, ...at(run.start) });
    add({
      rule: "hidden-message", severity: signals.length ? "critical" : "high",
      title: signals.length ? "Hidden instruction smuggled in invisible characters" : "Hidden message in invisible characters",
      detail: `${cps.length} invisible characters, ${how}`, hidden: clip(message), signals, ...at(run.start),
    });
  }

  // 2. bidirectional controls: Trojan Source in code, reordering tricks in text
  const bidi = suspicious.filter((c) => c.kind === "bidi" && !consumed.has(c));
  if (bidi.length) {
    const lines = new Map();
    for (const c of bidi) {
      const pos = at(c.i);
      if (!lines.has(pos.line)) lines.set(pos.line, { ...pos, names: [] });
      lines.get(pos.line).names.push(c.name);
    }
    for (const l of [...lines.values()].slice(0, 50)) {
      const overrides = l.names.some((n) => ["LRE", "RLE", "LRO", "RLO", "LRI", "RLI", "FSI", "PDI", "PDF"].includes(n));
      if (code && overrides) {
        add({ rule: "trojan-source", severity: "critical", title: "Bidirectional controls in code (Trojan Source, CVE-2021-42574)",
          detail: `${l.names.join(", ")}: the code a reviewer sees is not the code the compiler runs`, line: l.line, column: l.column });
      } else {
        const rlo = l.names.includes("RLO");
        add({ rule: "bidi-control", severity: rlo ? "high" : overrides ? "medium" : "low",
          title: rlo ? "Right-to-left override: the text after it displays reversed" : "Bidirectional control characters",
          detail: `${l.names.join(", ")}${rlo ? " (the trick that makes invoice[RLO]fdp.exe display as invoiceexe.pdf)" : ""}`, line: l.line, column: l.column });
      }
    }
    bidi.forEach((c) => consumed.add(c));
  }

  // 3. invisible characters inside identifiers (code that looks identical but is not)
  const isCode = code ? codeMask(text) : null;
  if (code) {
    for (const c of suspicious) {
      if (consumed.has(c) || c.kind !== "zero-width" || !isCode(c.i)) continue;
      const before = String.fromCodePoint(c.prevCp || 0x20), after = text.slice(c.i + c.size, c.i + c.size + 2);
      if (IDENT.test(before) && IDENT.test([...after][0] || " ")) {
        add({ rule: "invisible-identifier", severity: "high", title: "Invisible character inside an identifier",
          detail: `${c.name} (U+${hex(c.cp)}) splits a name: two identifiers that look the same are different`, ...at(c.i) });
        consumed.add(c);
      }
    }
  }

  // 4. the remaining invisible characters, one finding per kind
  const rest = {};
  for (const c of suspicious) if (!consumed.has(c)) (rest[c.kind] ||= []).push(c);
  const SEV = { "zero-width": "medium", tag: "medium", "variation-selector": "medium", filler: "medium",
    "invisible-math": "medium", format: "medium", control: "low", "soft-hyphen": "low", space: "low",
    "line-break": "low", "private-use": "info" };
  for (const [k, list] of Object.entries(rest)) {
    const names = {};
    for (const c of list) names[c.name] = (names[c.name] || 0) + 1;
    const summary = Object.entries(names).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([n, v]) => `${v}× ${n}`).join(", ");
    const note = k === "space" && names.NNBSP ? " (U+202F was widely reported in ChatGPT output in 2025)" :
      k === "zero-width" ? " (invisible to readers; can fingerprint or watermark copied text)" : "";
    const label = KIND_LABEL[k] || k;
    add({ rule: "invisible-characters", severity: SEV[k] || "low", title: `${list.length} ${list.length === 1 ? label.replace(/s$/, "") : label}`,
      detail: summary + note, count: list.length, kind: k, ...at(list[0].i),
      more: list.slice(1, 6).map((c) => at(c.i)) });
  }

  // 5. lookalike letters
  const words = lookalikeWords(text, { identifierAt: isCode });
  for (const w of words.slice(0, 50)) {
    const high = w.link || w.spoofed || (w.identifier && w.mixed);
    add({ rule: "homoglyph", severity: high ? "high" : "medium",
      title: w.link ? "Lookalike letters in a domain or address (homograph)" : w.identifier ? "Lookalike letters in an identifier" :
        w.spoofed ? `Spoofed "${w.skeleton}" written with lookalike letters` : "Word spelled with lookalike letters",
      detail: `"${w.token}" reads as "${w.skeleton}" but ${w.mixed ? "mixes scripts" : "is not Latin"}`, ...at(w.start) });
  }
  let styled = 0, firstStyled = -1;
  for (let k = 0; k < text.length; k++) {
    const cp = text.codePointAt(k);
    if (isStyledLetter(cp)) { styled++; if (firstStyled < 0) firstStyled = k; }
    if (cp > 0xffff) k++;
  }
  if (styled) add({ rule: "styled-letters", severity: "low", title: `${styled} styled lookalike letters`,
    detail: "fullwidth or mathematical letters (𝐛𝐨𝐥𝐝, ｗｉｄｅ): they look like text but slip past keyword filters", ...at(firstStyled) });

  // 6. hidden elements and comments in HTML (and HTML inside Markdown). Pages hide things all the time
  // (menus, templates, screen-reader text), so hidden text is only a finding of its own when it reads
  // like an instruction to a model; the rest is summed up once per file.
  if (kind === "html" || kind === "markdown") {
    const h = hiddenHtml(source);
    const pos = locator(source);
    const quiet = [];
    for (const r of h.regions) {
      const v = injectionVerdict(r.text);
      if (!v.strong.length && !v.weak.length) { quiet.push(r); continue; }
      add({ rule: "hidden-html", severity: v.strong.length ? "critical" : "medium",
        title: v.strong.length ? "Hidden instruction for AI in the page" : "Hidden text asking for something to be done",
        detail: `<${r.tag}> ${r.reason}`, hidden: clip(r.text), signals: [...v.strong, ...v.weak], ...pos(r.start) });
    }
    const camouflaged = quiet.filter((r) => CAMOUFLAGE.test(r.reason) && r.text.length > 40);
    const ordinary = quiet.filter((r) => !camouflaged.includes(r));
    if (camouflaged.length) {
      add({ rule: "hidden-html", severity: "low", title: `${camouflaged.length} passage${camouflaged.length > 1 ? "s" : ""} camouflaged as background`,
        detail: `${reasons(camouflaged)}: unreadable for people, plain text for a model or a keyword filter`,
        hidden: clip(camouflaged[0].text), count: camouflaged.length, ...pos(camouflaged[0].start),
        more: camouflaged.slice(1, 6).map((r) => pos(r.start)) });
    }
    if (ordinary.length) {
      add({ rule: "hidden-html", severity: "info", title: `${ordinary.length} hidden element${ordinary.length > 1 ? "s" : ""}, none addressed to a model`,
        detail: reasons(ordinary), hidden: clip(ordinary[0].text, 120), count: ordinary.length, ...pos(ordinary[0].start),
        more: ordinary.slice(1, 6).map((r) => pos(r.start)) });
    }
    for (const c of h.comments) {
      const v = injectionVerdict(c.text);
      if (v.strong.length || v.weak.length) add({ rule: "hidden-comment", severity: v.strong.length ? "high" : "low",
        title: v.strong.length ? "Instruction for AI in a comment" : "Comment asking for something to be done",
        detail: kind === "markdown" ? "HTML comment: invisible once the Markdown is rendered" : "HTML comment",
        hidden: clip(c.text), signals: [...v.strong, ...v.weak], ...pos(c.start) });
    }
    for (const a of h.attributes) {
      const v = injectionVerdict(a.text);
      if (v.strong.length) add({ rule: "hidden-attribute", severity: "high", title: `Instruction for AI in ${a.name}`,
        detail: "attributes are not shown on the page but models read them", hidden: clip(a.text), signals: v.strong, ...pos(a.start) });
    }
  }

  findings.sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.line - b.line);
  return {
    findings,
    messages,
    invisible: { total: chars.length, legit: chars.length - suspicious.length, byKind },
  };
}

/** Scan a .docx: hidden runs plus everything scan() finds in its text. */
export async function scanDocx(bytes, inflateRaw) {
  const doc = await readDocx(bytes, inflateRaw);
  const result = scan(doc.text, { kind: "text" });
  for (const h of doc.hidden) {
    const v = injectionVerdict(h.text);
    const signals = [...v.strong, ...v.weak];
    const deleted = /tracked changes/.test(h.reason);
    result.findings.push({ rule: "hidden-docx",
      severity: v.strong.length ? "critical" : signals.length ? "medium" : deleted ? "low" : h.text.length > 40 ? "medium" : "low",
      title: v.strong.length ? "Hidden instruction for AI in the document" : deleted ? "Deleted text still inside the file" : "Text hidden in the document",
      detail: `${h.part}, paragraph ${h.paragraph}: ${h.reason}`, hidden: clip(h.text), signals, line: h.paragraph, column: 1 });
  }
  result.findings.sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  return { ...result, text: doc.text, visible: doc.visible, hiddenCount: doc.hidden.length };
}

// ── cleaning ─────────────────────────────────────────────────────────────────

/**
 * Remove what readers cannot see. Characters doing a real job (emoji joiners, Persian/Indic joiners,
 * flag tags, a variation selector after an emoji, a leading BOM, RTL marks in RTL text) are kept unless
 * strict. Unusual spaces become plain spaces; homoglyphs are fixed only on request.
 */
export function clean(source, { kind = "text", strict = false, homoglyphs = false, stripHtml = false } = {}) {
  let text = source, removedElements = 0;
  if ((kind === "html" || kind === "markdown") && stripHtml) ({ text, removed: removedElements } = stripHidden(text));
  const removed = {};
  let out = "", last = 0;
  for (const c of invisibles(text, kind === "code")) {
    out += text.slice(last, c.i);
    last = c.i + c.size;
    if (c.legit && !strict) { out += String.fromCodePoint(c.cp); continue; }
    removed[c.kind] = (removed[c.kind] || 0) + 1;
    if (c.kind === "space") out += " ";
    else if (c.kind === "line-break") out += "\n";
  }
  out += text.slice(last);
  if (kind === "html") {                                       // invisible characters written as entities
    out = out.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|zwsp|zwj|zwnj|lrm|rlm|shy|ZeroWidthSpace|NoBreak);/g, (m, e) => {
      const cp = e[0] === "#" ? (e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10))
        : { zwsp: 0x200b, ZeroWidthSpace: 0x200b, zwj: 0x200d, zwnj: 0x200c, lrm: 0x200e, rlm: 0x200f, shy: 0xad, NoBreak: 0x2060 }[e];
      const info = cp > 0x20 ? charInfo(cp) : null;
      if (!info || info[1] === "space" || (!strict && (cp === 0x200c || cp === 0x200d || cp === 0x200e || cp === 0x200f))) return m;
      removed[info[1]] = (removed[info[1]] || 0) + 1;
      return "";
    });
  }
  let fixed = 0;
  if (homoglyphs) ({ text: out, fixed } = unspoof(out));
  return { text: out, removed, removedElements, homoglyphsFixed: fixed };
}

// ── revealing ────────────────────────────────────────────────────────────────

/** The text as segments: plain text, and visible stand-ins for every invisible character. */
export function reveal(source, { kind = "text" } = {}) {
  const chars = invisibles(source, kind === "code");
  const segs = [];
  let last = 0;
  for (const c of chars) {
    if (c.i > last) segs.push({ text: source.slice(last, c.i) });
    segs.push({ hidden: true, name: c.name, kind: c.kind, legit: c.legit, cp: c.cp });
    last = c.i + c.size;
  }
  if (last < source.length) segs.push({ text: source.slice(last) });
  return segs;
}
