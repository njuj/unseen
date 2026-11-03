// Lookalike letters: Cyrillic and Greek characters that render like Latin ones (a Cyrillic "a" in
// "paypal" is not an "a"), and "styled" Unicode letters (fullwidth, mathematical bold) that dodge filters.

const MAP = {
  // Cyrillic
  "а": "a", "в": "b", "е": "e", "ё": "e", "і": "i", "ї": "i", "ј": "j", "к": "k", "м": "m", "н": "h", "о": "o",
  "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l",
  "А": "A", "В": "B", "Е": "E", "Ё": "E", "І": "I", "Ј": "J", "К": "K", "М": "M", "Н": "H", "О": "O",
  "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S", "Ԁ": "D", "Ԛ": "Q", "Ԝ": "W", "Һ": "H", "Ӏ": "I",
  // Greek
  "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "ι": "i", "κ": "k", "χ": "x",
  "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
  "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
};

const LATIN = /\p{Script=Latin}/u;
const SPOOF = /[\p{Script=Cyrillic}\p{Script=Greek}]/u;

export function isStyledLetter(cp) {
  return (cp >= 0xff01 && cp <= 0xff5e) || (cp >= 0x1d400 && cp <= 0x1d7ff);
}

/** Latin skeleton of a token if every non-Latin letter in it has a lookalike, else null. */
export function skeleton(token) {
  let out = "";
  for (const ch of token) {
    if (MAP[ch]) out += MAP[ch];
    else if (SPOOF.test(ch)) return null;
    else out += ch;
  }
  return out;
}

// Names attackers spell with lookalikes. A whole Cyrillic or Greek word is only suspicious when it
// impersonates one of these, or sits in a domain or address: otherwise it is simply a real word.
const SPOOFED = new Set(("paypal apple google microsoft amazon facebook meta netflix bank login signin password " +
  "account verify secure security support admin update wallet binance coinbase github gitlab outlook office icloud " +
  "instagram whatsapp telegram twitter linkedin dropbox adobe steam discord chase visa mastercard openai").split(" "));

/**
 * Words that pretend to be something else. Mixed-script words (a Latin word with one Cyrillic letter) are always
 * suspicious; a word written entirely in lookalikes only in a domain, an address, an identifier, or
 * when it impersonates a commonly spoofed name. identifierAt(index) tells code from strings/comments.
 * Returns [{ start, end, token, skeleton, mixed, link, identifier }] with UTF-16 offsets.
 */
export function lookalikeWords(text, { identifierAt = null } = {}) {
  const out = [];
  for (const m of text.matchAll(/[\p{L}\p{N}_]+(?:[.\-@][\p{L}\p{N}_]+)*/gu)) {
    let token = m[0], start = m.index;
    if (text[start - 1] === "\\") {                     // "ͅι", "\rв": an escape glued to a word is not part of it
      const esc = /^(?:[uU][0-9a-fA-F]{4,8}|x[0-9a-fA-F]{2}|N|[nrtbfvae0])/.exec(token);
      if (esc) { token = token.slice(esc[0].length); start += esc[0].length; }
    }
    if (!token || !SPOOF.test(token)) continue;
    const mixed = LATIN.test(token);
    const skel = skeleton(token);
    if (!skel || skel === token) continue;
    const link = /[.@]/.test(token) && /\p{L}{2,}$/u.test(token);
    const identifier = identifierAt ? identifierAt(start) : false;
    const spoofed = SPOOFED.has(skel.toLowerCase().replace(/[^a-z]/g, ""));
    if (!mixed && !(link || spoofed || identifier)) continue;
    if (!mixed && !/^[\x20-\x7e]+$/.test(skel)) continue;
    out.push({ start, end: start + token.length, token, skeleton: skel, mixed, link, identifier, spoofed });
  }
  return out;
}

/** Replace lookalikes in suspicious words, and styled letters anywhere, with plain Latin: { text, fixed }. */
export function unspoof(text) {
  let out = text, fixed = 0;
  for (const w of lookalikeWords(text).reverse()) {
    fixed += [...w.token].filter((ch, k) => ch !== w.skeleton[k]).length;
    out = out.slice(0, w.start) + w.skeleton + out.slice(w.end);
  }
  out = [...out].map((ch) => {
    if (!isStyledLetter(ch.codePointAt(0))) return ch;
    fixed++;
    return ch.normalize("NFKC");
  }).join("");
  return { text: out, fixed };
}
