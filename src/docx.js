// Hidden text in Word documents: runs marked hidden (w:vanish), white text, and text too small to see,
// set directly or through a style. A .docx is a ZIP of XML; this reads it without dependencies, with
// the deflate step passed in (zlib in Node, DecompressionStream in the browser).

const td = new TextDecoder("utf-8");

/** { name: Uint8Array } for the entries we want, from a ZIP's central directory. */
export async function readZip(bytes, inflateRaw, want = () => true) {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (v.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("not a ZIP file (no end-of-central-directory record)");
  const count = v.getUint16(eocd + 10, true);
  let p = v.getUint32(eocd + 16, true);
  const out = {};
  for (let n = 0; n < count; n++) {
    if (v.getUint32(p, true) !== 0x02014b50) throw new Error("corrupt ZIP central directory");
    const method = v.getUint16(p + 10, true);
    const size = v.getUint32(p + 20, true);
    const nameLen = v.getUint16(p + 28, true), extraLen = v.getUint16(p + 30, true), commentLen = v.getUint16(p + 32, true);
    const local = v.getUint32(p + 42, true);
    const name = td.decode(bytes.subarray(p + 46, p + 46 + nameLen));
    p += 46 + nameLen + extraLen + commentLen;
    if (!want(name)) continue;
    const dataStart = local + 30 + v.getUint16(local + 26, true) + v.getUint16(local + 28, true);
    const data = bytes.subarray(dataStart, dataStart + size);
    if (method === 0) out[name] = data;
    else if (method === 8) out[name] = await inflateRaw(data);
    else throw new Error(`unsupported ZIP compression method ${method} in ${name}`);
  }
  return out;
}

const XML_ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
export function xmlText(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#\d+|amp|lt|gt|quot|apos);/g, (_, e) =>
    e[0] === "#" ? String.fromCodePoint(e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : XML_ENT[e]);
}

const on = (xml, tag) => {
  const m = new RegExp(`<w:${tag}(?:\\s+w:val="([^"]*)")?\\s*/>`).exec(xml);
  return Boolean(m) && !/^(0|false|off)$/i.test(m[1] || "");
};

/** Why a run's (or style's) properties hide it, or null. */
function runReason(rPr) {
  if (!rPr) return null;
  if (on(rPr, "vanish") || on(rPr, "specVanish") || on(rPr, "webHidden")) return "hidden font option (w:vanish)";
  const color = /<w:color\s+w:val="([0-9A-Fa-f]{6})"/.exec(rPr);
  const shade = /<w:shd\b[^>]*w:fill="([0-9A-Fa-f]{6})"/.exec(rPr);
  const light = (hex) => hex && [0, 2, 4].every((i) => parseInt(hex.slice(i, i + 2), 16) >= 0xf0);
  if (color && light(color[1]) && !(shade && !light(shade[1]))) return `white text (#${color[1].toUpperCase()})`;
  if (color && shade && color[1].toLowerCase() === shade[1].toLowerCase()) return "text colour equals its shading";
  const size = /<w:sz\s+w:val="(\d+)"/.exec(rPr);
  if (size && parseInt(size[1], 10) <= 4) return `${parseInt(size[1], 10) / 2}pt text`;
  return null;
}

function hiddenStyles(stylesXml) {
  const out = new Map();
  for (const m of (stylesXml || "").matchAll(/<w:style\b[^>]*w:styleId="([^"]+)"[^>]*>([\s\S]*?)<\/w:style>/g)) {
    const rPr = /<w:rPr>([\s\S]*?)<\/w:rPr>/.exec(m[2]);
    const reason = runReason(rPr && rPr[1]);
    if (reason) out.set(m[1], reason);
  }
  return out;
}

/**
 * Text of a WordprocessingML part, and its hidden stretches.
 * Returns { text, visible, hidden: [{ text, reason, paragraph }] } with consecutive hidden runs merged;
 * visible is the text a reader of the document actually sees.
 */
export function wordPart(xml, styles = new Map()) {
  const hidden = [];
  let text = "", visible = "", paragraph = 0, cur = null;
  for (const p of xml.matchAll(/<w:p\b[^>]*>([\s\S]*?)<\/w:p>|<w:p\b[^>]*\/>/g)) {
    paragraph++;
    cur = null;                                          // hidden stretches never span paragraphs
    const pStyle = /<w:pStyle\s+w:val="([^"]+)"/.exec(p[1] || "");
    const pReason = pStyle && styles.get(pStyle[1]);
    for (const r of (p[1] || "").matchAll(/<w:r\b[^>]*>([\s\S]*?)<\/w:r>/g)) {
      const rPr = /<w:rPr>([\s\S]*?)<\/w:rPr>/.exec(r[1]);
      const rStyle = rPr && /<w:rStyle\s+w:val="([^"]+)"/.exec(rPr[1]);
      const reason = runReason(rPr && rPr[1]) || (rStyle && styles.get(rStyle[1])) || pReason ||
        (r[1].includes("<w:delText") ? "deleted text still in the file (tracked changes)" : null);
      let t = "";
      for (const tm of r[1].matchAll(/<w:(t|delText)(?:\s[^>]*)?>([\s\S]*?)<\/w:\1>|<w:(tab|br)\b[^>]*\/>/g)) {
        t += tm[3] ? (tm[3] === "tab" ? "\t" : "\n") : xmlText(tm[2]);
      }
      if (!t) continue;
      text += t;
      if (reason) {
        if (cur && cur.reason === reason) cur.text += t;
        else { cur = { text: t, reason, paragraph }; hidden.push(cur); }
      } else {
        visible += t;
        if (t.trim()) cur = null;
      }
    }
    text += "\n";
    visible += "\n";
  }
  return { text, visible, hidden: hidden.map((h) => ({ ...h, text: h.text.replace(/\s+/g, " ").trim() })).filter((h) => h.text) };
}

/** All text and hidden text of a .docx (body, headers, footers, footnotes, comments). */
export async function readDocx(bytes, inflateRaw) {
  const parts = await readZip(bytes, inflateRaw, (n) => /^word\/(document|header\d*|footer\d*|footnotes|endnotes|comments|styles)\.xml$/.test(n));
  if (!parts["word/document.xml"]) throw new Error("not a Word document (no word/document.xml)");
  const styles = hiddenStyles(parts["word/styles.xml"] ? td.decode(parts["word/styles.xml"]) : "");
  const order = Object.keys(parts).filter((n) => n !== "word/styles.xml")
    .sort((a, b) => (a === "word/document.xml" ? -1 : b === "word/document.xml" ? 1 : a.localeCompare(b)));
  let text = "", visible = "";
  const hidden = [];
  for (const name of order) {
    const part = wordPart(td.decode(parts[name]), styles);
    text += part.text;
    visible += part.visible;
    for (const h of part.hidden) hidden.push({ ...h, part: name.replace(/^word\/|\.xml$/g, "") });
  }
  return { text, visible, hidden };
}
