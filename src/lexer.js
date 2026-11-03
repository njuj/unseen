// Which parts of a source file are code, and which are strings or comments. Language-agnostic and
// approximate on purpose: it only has to tell an identifier from text, so that a Russian word inside a
// string is not reported as a spoofed variable name.

/** A predicate: is this UTF-16 index real code (not inside a string literal or a comment)? */
export function codeMask(text) {
  const mask = new Uint8Array(text.length);
  const n = text.length;
  let i = 0, state = 0, quote = "", triple = false;      // state: 0 code, 1 string, 2 line comment, 3 block comment
  while (i < n) {
    const ch = text[i], next = text[i + 1];
    if (state === 0) {
      if (ch === "/" && next === "/") { state = 2; i += 2; continue; }
      if (ch === "/" && next === "*") { state = 3; i += 2; continue; }
      if (ch === "#" && (i === 0 || /\s/.test(text[i - 1])) && (next === undefined || /[\s#!]/.test(next))) { state = 2; i++; continue; }
      if (ch === "'" || ch === '"' || ch === "`") {
        triple = ch !== "`" && text.startsWith(ch.repeat(3), i);
        quote = ch; state = 1; i += triple ? 3 : 1; continue;
      }
      mask[i++] = 1;
      continue;
    }
    if (state === 1) {
      if (ch === "\\") { i += 2; continue; }
      if (triple ? text.startsWith(quote.repeat(3), i) : ch === quote) { state = 0; i += triple ? 3 : 1; continue; }
      if (ch === "\n" && !triple && quote !== "`") { state = 0; mask[i] = 1; }    // unterminated: the line ends it
      i++;
      continue;
    }
    if (state === 2) { if (ch === "\n") { state = 0; mask[i] = 1; } i++; continue; }
    if (ch === "*" && next === "/") { state = 0; i += 2; continue; }               // block comment
    i++;
  }
  return (index) => mask[index] === 1;
}
