// The attacker's side, for tests only: hide messages the ways they are hidden in the wild, and build
// real .docx files. The tool itself only ever decodes.

import { deflateRawSync } from "node:zlib";

/** ASCII smuggling: every printable ASCII character becomes the matching Unicode tag character. */
export function encodeTags(message, { frame = true } = {}) {
  const body = [...message].map((ch) => String.fromCodePoint(0xe0000 + ch.charCodeAt(0))).join("");
  return frame ? String.fromCodePoint(0xe0001) + body + String.fromCodePoint(0xe007f) : body;
}

/** Bytes appended to a base character as variation selectors (0..15 → FE00.., 16..255 → E0100..). */
export function encodeVariationSelectors(base, message) {
  const bytes = new TextEncoder().encode(message);
  return base + [...bytes].map((b) => String.fromCodePoint(b < 16 ? 0xfe00 + b : 0xe0100 + b - 16)).join("");
}

/** Binary in zero-width characters: symbols[0] is 0, symbols[1] is 1 (or bit pairs with four symbols). */
export function encodeZeroWidth(message, symbols = [0x200b, 0x200c]) {
  const bitsPer = symbols.length === 4 ? 2 : 1;
  let bits = "";
  for (const b of new TextEncoder().encode(message)) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += bitsPer) out += String.fromCodePoint(symbols[parseInt(bits.slice(i, i + bitsPer), 2)]);
  return out;
}

/** Binary numbers (one per character) between separators: the third common zero-width scheme. */
export function encodeZeroWidthSeparated(message, [zero, one, sep] = [0x200b, 0x200c, 0x200d]) {
  return [...message].map((ch) => ch.codePointAt(0).toString(2).split("").map((b) => String.fromCodePoint(b === "0" ? zero : one)).join(""))
    .join(String.fromCodePoint(sep));
}

// ── a real .docx ─────────────────────────────────────────────────────────────

const CRC = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** A ZIP archive (deflated entries) from { name: string }. */
export function zip(files) {
  const enc = new TextEncoder();
  const locals = [], centrals = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const nameBytes = enc.encode(name), data = enc.encode(content), packed = deflateRawSync(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(8, 8);
    local.writeUInt32LE(crc32(data), 14); local.writeUInt32LE(packed.length, 18); local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(8, 10);
    central.writeUInt32LE(crc32(data), 16); central.writeUInt32LE(packed.length, 20); central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28); central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, packed);
    centrals.push(central, nameBytes);
    offset += 30 + nameBytes.length + packed.length;
  }
  const dir = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(Object.keys(files).length, 8); end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(dir.length, 12); end.writeUInt32LE(offset, 16);
  return new Uint8Array(Buffer.concat([...locals, dir, end]));
}

const W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"';
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/**
 * A minimal but valid Word document. paragraphs: [[run, ...], ...] where a run is a string or
 * { text, vanish, color, size, style, deleted }. styles: { id: rPrXml }.
 */
export function docx(paragraphs, styles = {}) {
  const run = (r) => {
    if (typeof r === "string") r = { text: r };
    const pr = [r.style && `<w:rStyle w:val="${r.style}"/>`, r.vanish && "<w:vanish/>", r.color && `<w:color w:val="${r.color}"/>`,
      r.size && `<w:sz w:val="${r.size}"/>`].filter(Boolean).join("");
    const body = `<w:r>${pr ? `<w:rPr>${pr}</w:rPr>` : ""}<w:${r.deleted ? "delText" : "t"} xml:space="preserve">${esc(r.text)}</w:${r.deleted ? "delText" : "t"}></w:r>`;
    return r.deleted ? `<w:del w:id="1" w:author="x">${body}</w:del>` : body;
  };
  const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document ${W}><w:body>` +
    paragraphs.map((p) => `<w:p>${p.map(run).join("")}</w:p>`).join("") + "</w:body></w:document>";
  const stylesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles ${W}>` +
    Object.entries(styles).map(([id, rPr]) => `<w:style w:type="character" w:styleId="${id}"><w:name w:val="${id}"/><w:rPr>${rPr}</w:rPr></w:style>`).join("") +
    "</w:styles>";
  return zip({
    "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>',
    "_rels/.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
    "word/_rels/document.xml.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>',
    "word/document.xml": document,
    "word/styles.xml": stylesXml,
  });
}
