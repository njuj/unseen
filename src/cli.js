// unseen: find and remove what readers cannot see but AI models read.
// Exit codes: 0 nothing at or above --fail-on · 1 findings · 2 could not run.

import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { inflateRawSync } from "node:zlib";
import { clean, kindOf, RANK, reveal, scan, scanDocx, SEVERITIES, VERSION } from "./index.js";

const HELP = `unseen ${VERSION}: find and remove what readers cannot see but AI models read

usage
  unseen [scan] <file|folder|->...     report hidden characters, smuggled messages, hidden text
  unseen -c "<text>"                   scan a string
  unseen clean <file> [-o out | --in-place] [--strict] [--homoglyphs] [--strip-hidden]
                                       the file without what readers cannot see (.docx: its visible text)
  unseen reveal <file>                 print the file with every invisible character made visible

options
  --json                 machine-readable report
  --sarif <file>         also write SARIF 2.1.0 (GitHub code scanning)
  --fail-on <severity>   exit 1 at or above: critical, high (default), medium, low, info
  --min-severity <sev>   hide findings below this
  --kind <kind>          force text | code | markdown | html | docx
  --no-color             plain output
  --strict               clean: also remove characters doing a legitimate job (emoji joiners, BOM...)
  --homoglyphs           clean: replace lookalike letters with plain Latin
  --strip-hidden         clean (HTML, Markdown): remove hidden elements and comments
`;

function parse(argv) {
  const o = { cmd: "scan", paths: [], failOn: "high", min: "info", color: process.stdout.isTTY && !process.env.NO_COLOR };
  const args = [...argv];
  if (["scan", "clean", "reveal"].includes(args[0])) o.cmd = args.shift();
  while (args.length) {
    const a = args.shift();
    if (a === "-h" || a === "--help") o.help = true;
    else if (a === "-V" || a === "--version") o.version = true;
    else if (a === "--json") o.json = true;
    else if (a === "--sarif") o.sarif = args.shift();
    else if (a === "--fail-on") o.failOn = args.shift();
    else if (a === "--min-severity") o.min = args.shift();
    else if (a === "--kind") o.kind = args.shift();
    else if (a === "--no-color") o.color = false;
    else if (a === "-c") o.text = args.shift();
    else if (a === "-o") o.out = args.shift();
    else if (a === "--in-place") o.inPlace = true;
    else if (a === "--strict") o.strict = true;
    else if (a === "--homoglyphs") o.homoglyphs = true;
    else if (a === "--strip-hidden") o.stripHidden = true;
    else if (a.startsWith("-") && a !== "-") throw new Error(`unknown option ${a}`);
    else o.paths.push(a);
  }
  for (const s of [o.failOn, o.min]) if (!SEVERITIES.includes(s)) throw new Error(`unknown severity ${s}`);
  return o;
}

const SKIP_DIRS = new Set(["node_modules", ".git", ".hg", ".svn", "__pycache__", ".venv", "venv"]);

function* walk(path) {
  const st = statSync(path);
  if (st.isFile()) { yield path; return; }
  for (const name of readdirSync(path).sort()) {
    if (SKIP_DIRS.has(name)) continue;
    yield* walk(join(path, name));
  }
}

/** File bytes as text (UTF-8, or UTF-16 by its BOM), or null for binary files. */
export function decodeText(buf) {
  if (buf[0] === 0xff && buf[1] === 0xfe) return new TextDecoder("utf-16le").decode(buf.subarray(2));
  if (buf[0] === 0xfe && buf[1] === 0xff) return new TextDecoder("utf-16be").decode(buf.subarray(2));
  if (buf.subarray(0, 8192).includes(0)) return null;
  return new TextDecoder("utf-8").decode(buf);
}

async function scanFile(path, kind) {
  const st = statSync(path);
  if (st.size > 50 * 1024 * 1024) return { skipped: "larger than 50 MB" };
  const buf = readFileSync(path);
  const k = kind || kindOf(path);
  if (k === "docx") return scanDocx(new Uint8Array(buf), (d) => inflateRawSync(d));
  const text = decodeText(buf);
  if (text === null) return { skipped: "binary" };
  return scan(text, { kind: k });
}

const ICON = { critical: "✖", high: "✖", medium: "⚠", low: "•", info: "·" };
const COLOR = { critical: "1;31", high: "31", medium: "33", low: "36", info: "2" };

function render(results, o, elapsed) {
  const paint = (s, c) => (o.color ? `\x1b[${c}m${s}\x1b[0m` : s);
  const lines = [paint(` unseen v${VERSION}`, "1;36") + paint(`  ·  ${results.length} file(s)  ·  ${elapsed.toFixed(2)}s`, "2"), ""];
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const r of results) {
    const shown = (r.findings || []).filter((f) => RANK[f.severity] <= RANK[o.min]);
    (r.findings || []).forEach((f) => counts[f.severity]++);
    if (!shown.length) continue;
    lines.push(paint(` ${r.name}`, "1"));
    for (const f of shown) {
      const where = r.kind === "docx" ? "" : `  line ${f.line}:${f.column}`;
      lines.push(`   ${paint(`${ICON[f.severity]} ${f.severity.toUpperCase().padEnd(8)}`, COLOR[f.severity])} ${f.title}${paint(where, "2")}`);
      lines.push(paint(`              └ ${f.detail}`, "2"));
      if (f.hidden) lines.push(`                ${paint("“" + f.hidden + "”", "1;35")}`);
      for (const s of f.signals || []) lines.push(paint(`                ⚑ ${s}`, "31"));
    }
    lines.push("");
  }
  const skipped = results.filter((r) => r.skipped);
  if (skipped.length) lines.push(paint(` skipped ${skipped.length} file(s): ${[...new Set(skipped.map((s) => s.skipped))].join(", ")}`, "2"));
  const summary = SEVERITIES.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join("  ·  ") || "clean: nothing hidden";
  lines.push(paint(` ${summary}`, "1"));
  return lines.join("\n") + "\n";
}

function sarif(results) {
  const level = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
    runs: [{
      tool: { driver: { name: "unseen", version: VERSION, informationUri: "https://github.com/njuj/unseen" } },
      results: results.flatMap((r) => (r.findings || []).map((f) => ({
        ruleId: f.rule, level: level[f.severity], properties: { severity: f.severity },
        message: { text: `${f.title}: ${f.detail}${f.hidden ? ` · hidden text: ${f.hidden}` : ""}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: r.name }, region: { startLine: f.line, startColumn: f.column } } }],
      }))),
    }],
  };
}

async function main(argv) {
  let o;
  try { o = parse(argv); } catch (e) { process.stderr.write(`unseen: ${e.message}\n\n${HELP}`); return 2; }
  if (o.help) { process.stdout.write(HELP); return 0; }
  if (o.version) { process.stdout.write(`unseen ${VERSION}\n`); return 0; }

  if (o.cmd === "clean" || o.cmd === "reveal") {
    const [path] = o.paths;
    if (!path) { process.stderr.write(`unseen ${o.cmd}: which file?\n`); return 2; }
    let kind = o.kind || kindOf(path);
    let text, doc = null;
    try {
      if (kind === "docx") {
        if (o.inPlace) { process.stderr.write("unseen clean: a .docx cannot be rewritten in place; use -o file.txt for its clean text\n"); return 2; }
        doc = await scanDocx(new Uint8Array(readFileSync(path)), (d) => inflateRawSync(d));
        text = o.cmd === "reveal" ? doc.text : doc.visible;   // clean keeps only what a reader of the document sees
        kind = "text";
      } else text = path === "-" ? readFileSync(0, "utf8") : decodeText(readFileSync(path));
    } catch (e) { process.stderr.write(`unseen: ${e.message}\n`); return 2; }
    if (text === null) { process.stderr.write(`unseen: ${path} looks binary\n`); return 2; }
    if (o.cmd === "reveal") {
      const paint = (s, c) => (o.color ? `\x1b[${c}m${s}\x1b[0m` : s);
      process.stdout.write(reveal(text, { kind }).map((s) => (s.hidden ? paint(`⟦${s.name}⟧`, s.legit ? "2" : "1;35") : s.text)).join(""));
      return 0;
    }
    const r = clean(text, { kind, strict: o.strict, homoglyphs: o.homoglyphs, stripHtml: o.stripHidden });
    const total = Object.values(r.removed).reduce((a, b) => a + b, 0);
    if (o.inPlace) writeFileSync(path, r.text);
    else if (o.out) writeFileSync(o.out, r.text);
    else process.stdout.write(r.text);
    const parts = [`${total} invisible character(s) removed or normalised`];
    if (r.removedElements) parts.push(`${r.removedElements} hidden element(s) removed`);
    if (doc?.hiddenCount) parts.push(`${doc.hiddenCount} hidden passage(s) of the document left out`);
    if (r.homoglyphsFixed) parts.push(`${r.homoglyphsFixed} lookalike letter(s) replaced`);
    process.stderr.write(`unseen clean: ${parts.join(", ")}${o.inPlace ? ` (${path} rewritten)` : o.out ? ` → ${o.out}` : ""}\n`);
    return 0;
  }

  const started = performance.now();
  const results = [];
  try {
    if (o.text !== undefined) results.push({ name: "<text>", kind: o.kind || "text", ...scan(o.text, { kind: o.kind || "text" }) });
    if (!o.paths.length && o.text === undefined) o.paths.push("-");
    for (const p of o.paths) {
      if (p === "-") { results.push({ name: "<stdin>", kind: o.kind || "text", ...scan(readFileSync(0, "utf8"), { kind: o.kind || "text" }) }); continue; }
      for (const file of walk(p)) {
        const name = relative(process.cwd(), file) || basename(file);
        try { results.push({ name, kind: o.kind || kindOf(file), ...(await scanFile(file, o.kind)) }); }
        catch (e) { results.push({ name, skipped: e.message }); }
      }
    }
  } catch (e) {
    process.stderr.write(`unseen: ${e.message}\n`);
    return 2;
  }
  const elapsed = (performance.now() - started) / 1000;
  if (o.sarif) writeFileSync(o.sarif, JSON.stringify(sarif(results), null, 2));
  if (o.json) process.stdout.write(JSON.stringify({ version: VERSION, results }, null, 2) + "\n");
  else process.stdout.write(render(results, o, elapsed));
  const worst = Math.min(99, ...results.flatMap((r) => (r.findings || []).map((f) => RANK[f.severity])));
  return worst <= RANK[o.failOn] ? 1 : 0;
}

export { main };
