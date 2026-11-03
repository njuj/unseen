// Characters, bidi, homoglyphs: what must be reported, and what must be left alone.
import assert from "node:assert/strict";
import { test } from "node:test";

import { clean, kindOf, reveal, scan } from "../src/index.js";

const rules = (r) => r.findings.map((f) => [f.rule, f.severity]);

test("the 'AI fingerprint' characters are found, counted and located", () => {
  const text = "The results are clear\u202Fand convincing.\nWe\u200B should\u200B act now\u00AD.";
  const r = scan(text);
  const kinds = Object.fromEntries(r.findings.map((f) => [f.kind, f]));
  assert.equal(kinds["zero-width"].count, 2);
  assert.equal(kinds["zero-width"].line, 2);
  assert.equal(kinds["zero-width"].column, 3);
  assert.match(kinds.space.detail, /NNBSP/);
  assert.equal(kinds["soft-hyphen"].count, 1);
});

test("legitimate joiners stay legitimate: Persian, Hindi, Arabic marks in RTL text", () => {
  const persian = "می\u200Cخواهم";                                 // ZWNJ in a Persian word
  const hindi = "क्\u200Dष";                                         // ZWJ in a Devanagari conjunct
  const arabic = "مرحبا \u200F(123)";                                // RLM in RTL text
  for (const t of [persian, hindi, arabic]) assert.deepEqual(scan(t).findings, [], t);
  assert.equal(scan("ab\u200Ccd").findings[0].rule, "invisible-characters");      // the same ZWNJ in Latin text
});

test("a byte order mark at the start is fine, anywhere else it is not", () => {
  assert.deepEqual(scan("\uFEFFhello").findings, []);
  assert.equal(scan("hel\uFEFFlo").findings.length, 1);
});

test("Trojan Source in code is critical; the same characters in prose are not", () => {
  // the classic "commenting out" attack from the Trojan Source paper
  const js = 'let isAdmin = false;\n/*\u202E } \u2066if (isAdmin)\u2069 \u2066 begin admins only */\nconsole.log("You are an admin");\n';
  const r = scan(js, { kind: "code" });
  assert.equal(r.findings[0].rule, "trojan-source");
  assert.equal(r.findings[0].severity, "critical");
  assert.equal(r.findings[0].line, 2);
  const prose = scan("Your file: invoice\u202Efdp.exe");
  assert.equal(prose.findings[0].rule, "bidi-control");
  assert.equal(prose.findings[0].severity, "high");
});

test("an invisible character inside an identifier is caught in code", () => {
  const py = "user_name = 'a'\nuser\u200B_name = 'b'\nprint(user_name)\n";
  const r = scan(py, { kind: "code" });
  assert.deepEqual(rules(r), [["invisible-identifier", "high"]]);
  assert.equal(r.findings[0].line, 2);
});

test("lookalike letters: mixed scripts, spoofed words, domains", () => {
  const r = scan("Log in at https://www.pаypal.com/secure to verify. Your bаnk account is locked.");  // Cyrillic а
  assert.deepEqual(rules(r), [["homoglyph", "high"], ["homoglyph", "high"]]);
  assert.match(r.findings[0].detail, /paypal/);
  assert.deepEqual(rules(scan("Thе report is ready.")), [["homoglyph", "medium"]]);           // mixed, not a spoofed name
  assert.deepEqual(rules(scan("Your раураl wallet is locked.")), [["homoglyph", "high"]]);      // all-Cyrillic "paypal"
  assert.deepEqual(scan("Привет, как дела? Это обычный русский текст.").findings, []);  // real Russian is fine
  const styled = scan("𝐅𝐫𝐞𝐞 𝐦𝐨𝐧𝐞𝐲 now");
  assert.equal(styled.findings[0].rule, "styled-letters");
});

// regressions from scanning the Python standard library: none of these is an attack
test("real words in other scripts, escapes and strings are not reported as spoofing", () => {
  const py = [
    "def test_cyrillic(self):",
    "    self.assertEqual(lower('ТЕСТ'), 'тест')       # a real Russian word in a string",
    "    s = '\\u0345ι'                                # an escape glued to a Greek letter",
    "    t = b'\\rв'.decode()",
  ].join("\n");
  assert.deepEqual(scan(py, { kind: "code" }).findings, []);
  assert.deepEqual(scan("Он сказал: тест пройден. Это кот.").findings, []);
  // an invisible character inside a string is still hidden text, but it is not part of a name
  const cgj = scan("name = 'joiner\u034Fhere'\n", { kind: "code" });
  assert.deepEqual(rules(cgj), [["invisible-characters", "medium"]]);
  // mixed-script identifiers (Cyrillic с and о) are high
  const spoofed = scan("соnst tоtal = 1;\n", { kind: "code" });
  assert.deepEqual(rules(spoofed), [["homoglyph", "high"], ["homoglyph", "high"]]);
});

test("clean removes what is hidden and keeps what is real", () => {
  const dirty = "AI\u200B text\u202Fwith\u00A0marks\u00AD and \u{E0041}\u{E0042} tags 👨\u200D👩\u200D👧 می\u200Cخواهم";
  const r = clean(dirty);
  assert.equal(r.text, "AI text with marks and  tags 👨\u200D👩\u200D👧 می\u200Cخواهم");
  assert.deepEqual(r.removed, { "zero-width": 1, space: 2, "soft-hyphen": 1, tag: 2 });
  assert.deepEqual(scan(r.text).findings, []);
  assert.equal(clean(r.text).text, r.text, "idempotent");
  const strict = clean(dirty, { strict: true }).text;
  assert.ok(!/[\u200C\u200D]/.test(strict));
});

test("clean --homoglyphs turns lookalikes back into plain Latin", () => {
  const r = clean("pаypal.com and 𝐁𝐎𝐋𝐃", { homoglyphs: true });
  assert.equal(r.text, "paypal.com and BOLD");
  assert.equal(r.homoglyphsFixed, 5);                       // one Cyrillic а, four bold letters
});

test("reveal shows every invisible character in place", () => {
  const segs = reveal("a\u200Bb\u202Ec");
  assert.deepEqual(segs.map((s) => s.hidden ? `[${s.name}]` : s.text).join(""), "a[ZWSP]b[RLO]c");
});

test("plain text, code and normal Unicode produce nothing", () => {
  for (const t of ["Hello, world! Ça va? Grüße aus München. ¡Hola! こんにちは 안녕하세요 مرحبا بالعالم",
    "def f(x):\n\treturn x * 2  # tabs and comments\n", "Price: €12 — “quotes” and ‘apostrophes’ … ok"]) {
    assert.deepEqual(scan(t, { kind: t.startsWith("def") ? "code" : "text" }).findings, [], t);
  }
});

test("kinds are chosen from file names", () => {
  assert.deepEqual(["a.py", "b.HTML", "c.md", "d.docx", "e.txt", "f.eml"].map(kindOf), ["code", "html", "markdown", "docx", "text", "html"]);
});
