// Text in a web page or an HTML e-mail that a person never sees but a model reading the page does:
// elements hidden with CSS or the hidden attribute, white-on-white text, zero-size text, text pushed
// off screen, comments and attributes. No DOM needed, so it runs the same in Node and the browser.

const VOID = new Set("area base br col embed hr img input link meta param source track wbr".split(" "));
const RAW = new Set(["script", "style", "textarea", "title", "noscript", "xmp"]);
const TOKEN = /<!--[\s\S]*?(?:-->|$)|<![^>]*>|<\?[^>]*>|<\/?([a-zA-Z][\w:-]*)((?:\s+[^\s"'>/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*\/?>/g;
const ATTR = /([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

const NAMED = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\u00A0", shy: "\u00AD", zwsp: "\u200B",
  ZeroWidthSpace: "\u200B", zwj: "\u200D", zwnj: "\u200C", lrm: "\u200E", rlm: "\u200F", NoBreak: "\u2060",
  ensp: "\u2002", emsp: "\u2003", thinsp: "\u2009", hairsp: "\u200A" };

/** HTML entities decoded, plus map[i] = offset in the source of decoded character i (for positions). */
export function decodeEntities(src) {
  let out = "";
  const map = [];
  const rx = /&(#x[0-9a-fA-F]+|#[0-9]+|[A-Za-z]+);/g;
  let last = 0, m;
  while ((m = rx.exec(src))) {
    for (let i = last; i < m.index; i++) { out += src[i]; map.push(i); }
    let ch = null;
    if (m[1][0] === "#") {
      const cp = m[1][1] === "x" || m[1][1] === "X" ? parseInt(m[1].slice(2), 16) : parseInt(m[1].slice(1), 10);
      if (cp > 0 && cp <= 0x10ffff) ch = String.fromCodePoint(cp);
    } else ch = NAMED[m[1]] ?? null;
    if (ch === null) { for (let i = m.index; i < rx.lastIndex; i++) { out += src[i]; map.push(i); } }
    else for (let k = 0; k < ch.length; k++) { out += ch[k]; map.push(m.index); }
    last = rx.lastIndex;
  }
  for (let i = last; i < src.length; i++) { out += src[i]; map.push(i); }
  map.push(src.length);
  return { text: out, map };
}

function attrs(s) {
  const out = {};
  for (const m of (s || "").matchAll(ATTR)) out[m[1].toLowerCase()] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? "").text;
  return out;
}

function decls(style) {
  const out = {};
  for (const part of (style || "").split(";")) {
    const i = part.indexOf(":");
    if (i > 0) out[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim().toLowerCase().replace(/\s*!important$/, "");
  }
  return out;
}

const WHITE = /^(#fff|#ffffff|#fefefe|#fdfdfd|white|rgb\(\s*25[0-5]\s*,\s*25[0-5]\s*,\s*25[0-5]\s*\)|rgba\(\s*25[0-5]\s*,\s*25[0-5]\s*,\s*25[0-5]\s*,\s*1(\.0+)?\s*\))$/;
const px = (v) => {
  const m = /^(-?[\d.]+)(px|pt|em|rem|%)?$/.exec(v || "");
  if (!m) return null;
  const n = parseFloat(m[1]);
  return m[2] === "em" || m[2] === "rem" ? n * 16 : m[2] === "pt" ? n * 1.33 : m[2] === "%" ? null : n;
};

/** Why these declarations hide text from a reader, or null. */
export function hidingReason(style) {
  const d = decls(style);
  if (d.display === "none") return "display:none";
  if (d.visibility === "hidden" || d.visibility === "collapse") return "visibility:hidden";
  if (d.opacity !== undefined && parseFloat(d.opacity) <= 0.05) return `opacity:${d.opacity}`;
  const fs = px(d["font-size"]);
  if (fs !== null && fs <= 2) return `font-size:${d["font-size"]}`;
  if (d.color === "transparent" || /rgba\([^)]*,\s*0(\.0+)?\s*\)$/.test(d.color || "")) return "transparent text";
  const bg = d["background-color"] || d.background;
  const concrete = (c) => c && !/^(inherit|initial|unset|revert|currentcolor|transparent|none)$/.test(c) && !/var\(/.test(c) &&
    /^(#[0-9a-f]{3,8}|rgba?\([^)]*\)|hsla?\([^)]*\)|[a-z]+)$/.test(c);
  if (concrete(d.color) && concrete(bg) && d.color === bg) return `text colour equals background (${d.color})`;
  if (d.color && WHITE.test(d.color) && !(bg && !WHITE.test(bg))) return `white text (${d.color})`;
  for (const side of ["left", "top", "right", "text-indent", "margin-left", "margin-top"]) {
    const v = px(d[side]);
    if (v !== null && v <= -999) return `moved off screen (${side}:${d[side]})`;
  }
  if (/^rect\(\s*0(px)?[\s,]+0(px)?[\s,]+0(px)?[\s,]+0(px)?\s*\)$/.test(d.clip || "")) return "clip:rect(0 0 0 0)";
  if (/inset\(\s*(50%|100%)|circle\(\s*0/.test(d["clip-path"] || "")) return `clip-path:${d["clip-path"]}`;
  if (/scale\(\s*0(\.0+)?\s*\)/.test(d.transform || "")) return "transform:scale(0)";
  const zero = (v) => v !== undefined && px(v) === 0;
  if ((zero(d.width) || zero(d.height) || zero(d["max-height"]) || zero(d["max-width"])) && d.overflow === "hidden") {
    return "zero-size box with overflow:hidden";
  }
  return null;
}

/** Simple selectors (tag, .class, #id, tag.class) from <style> blocks whose rules hide text. */
function hiddenSelectors(css) {
  const out = new Map();
  for (const m of css.replace(/\/\*[\s\S]*?\*\//g, "").matchAll(/([^{}@]+)\{([^{}]*)\}/g)) {
    const reason = hidingReason(m[2]);
    if (!reason) continue;
    for (let sel of m[1].split(",")) {
      sel = sel.trim().split(/[\s>+~]+/).pop();                // the element the rule lands on
      if (sel && !/[:[]/.test(sel)) out.set(sel.toLowerCase(), reason);
    }
  }
  return out;
}

function matchesSelector(sel, tag, a) {
  const classes = (a.class || "").toLowerCase().split(/\s+/).filter(Boolean);
  const m = /^([a-z][\w-]*)?((?:[.#][\w-]+)*)$/.exec(sel);
  if (!m) return false;
  if (m[1] && m[1] !== tag) return false;
  for (const part of m[2].match(/[.#][\w-]+/g) || []) {
    if (part[0] === "." && !classes.includes(part.slice(1))) return false;
    if (part[0] === "#" && (a.id || "").toLowerCase() !== part.slice(1)) return false;
  }
  return Boolean(m[1] || m[2]);
}

/**
 * Everything hidden in an HTML document.
 * regions:  [{ start, end, tag, reason, text }]   hidden elements and the text inside them
 * comments: [{ start, end, text }]
 * attributes: [{ start, name, text }]   alt / title / aria-label / hidden input values (models read these)
 */
export function hiddenHtml(src) {
  let css = "";
  for (const m of src.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) css += m[1] + "\n";
  const selectors = hiddenSelectors(css);
  const regions = [], comments = [], attributes = [];
  const stack = [];
  let current = null;                                    // the outermost hidden element being collected
  let last = 0;
  const addText = (s) => { if (current) current.text += s; };
  TOKEN.lastIndex = 0;
  let m;
  while ((m = TOKEN.exec(src))) {
    if (m.index > last) addText(decodeEntities(src.slice(last, m.index)).text);
    last = TOKEN.lastIndex;
    const tok = m[0];
    if (tok.startsWith("<!--")) {
      const text = tok.replace(/^<!--|-->$/g, "").trim();
      if (text) comments.push({ start: m.index, end: TOKEN.lastIndex, text });
      continue;
    }
    if (!m[1]) continue;
    const tag = m[1].toLowerCase();
    if (tok[1] === "/") {                                // closing tag: pop to its opener
      const i = stack.map((s) => s.tag).lastIndexOf(tag);
      if (i < 0) continue;
      const popped = stack.splice(i);
      if (current && popped.includes(current.frame)) {
        current.end = TOKEN.lastIndex;
        current.text = current.text.replace(/\s+/g, " ").trim();
        if (current.text) regions.push({ start: current.start, end: current.end, tag: current.tag, reason: current.reason, text: current.text });
        current = null;
      }
      continue;
    }
    const a = attrs(m[2]);
    for (const name of ["alt", "title", "aria-label", "placeholder", "content"]) {
      if (a[name] && a[name].trim().length > 2) attributes.push({ start: m.index, name, text: a[name].trim() });
    }
    if (tag === "input" && (a.type || "").toLowerCase() === "hidden" && a.value) {
      attributes.push({ start: m.index, name: "hidden input value", text: a.value });
    }
    let reason = null;
    if ("hidden" in a) reason = "hidden attribute";
    else if (a.style) reason = hidingReason(a.style);
    if (!reason) for (const [sel, why] of selectors) if (matchesSelector(sel, tag, a)) { reason = `${why} (via ${sel})`; break; }
    if (tag === "template") reason = reason || "template (never rendered)";
    if (RAW.has(tag) && !tok.endsWith("/>")) {           // raw text: skip to the closing tag
      const close = src.toLowerCase().indexOf(`</${tag}`, TOKEN.lastIndex);
      const end = close < 0 ? src.length : close;
      if (tag === "noscript" || tag === "textarea") {
        const inner = src.slice(TOKEN.lastIndex, end).replace(/<[^>]+>/g, " ");
        const text = decodeEntities(inner).text.replace(/\s+/g, " ").trim();
        if (text && (reason || tag === "noscript")) {
          regions.push({ start: m.index, end, tag, reason: reason || "noscript (shown only without JavaScript)", text });
        }
      }
      TOKEN.lastIndex = close < 0 ? src.length : close;
      last = TOKEN.lastIndex;
      continue;
    }
    if (VOID.has(tag) || tok.endsWith("/>")) continue;
    const frame = { tag };
    stack.push(frame);
    if (reason && !current) current = { start: m.index, end: m.index, tag, reason, text: "", frame };
  }
  if (current) {
    current.text = (current.text + decodeEntities(src.slice(last)).text).replace(/\s+/g, " ").trim();
    current.end = src.length;
    if (current.text) regions.push({ start: current.start, end: current.end, tag: current.tag, reason: current.reason, text: current.text });
  }
  return { regions, comments, attributes };
}

/** The document without its hidden elements and comments (for cleaning). */
export function stripHidden(src) {
  const { regions, comments } = hiddenHtml(src);
  const cuts = [...regions, ...comments].map((r) => [r.start, r.end]).sort((x, y) => x[0] - y[0]);
  let out = "", pos = 0, removed = 0;
  for (const [s, e] of cuts) {
    if (s < pos) continue;
    out += src.slice(pos, s);
    pos = e;
    removed++;
  }
  return { text: out + src.slice(pos), removed };
}
