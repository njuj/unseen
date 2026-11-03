// The page: the same engine as the command line, on whatever is pasted or opened. Nothing is sent
// anywhere (the page's CSP forbids it).

import { clean, decodeTags, decodeVariationSelectors, decodeZeroWidthBinary, kindOf, reveal, scan, scanDocx, SEVERITIES, VERSION } from "../src/index.js";
import { isZeroWidthSymbol } from "../src/smuggle.js";
import { SAMPLES } from "./samples.js";

const $ = (id) => document.getElementById(id);
const input = $("input");
const state = { doc: null, name: "", tab: "findings", cleaned: "", timer: 0 };

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}

/** Guess what pasted text is, when nobody said. */
function detectKind(text) {
  if (/^\s*(<!doctype html|<html|<\?xml)/i.test(text) || (text.match(/<\/?(div|span|p|body|head|style|table|section)\b/gi) || []).length >= 4) return "html";
  if (/<!--|<(div|span|p|img|details)\b/i.test(text) || /^#{1,6} \S/m.test(text) || /^```/m.test(text)) return "markdown";
  if (/^\s*(import |from \S+ import|def |function |const |let |var |class |#include|package |using |fn |pub )/m.test(text) && /[;{}=()]/.test(text)) return "code";
  return "text";
}

function currentKind(text) {
  const chosen = $("kind").value;
  if (chosen !== "auto") return chosen;
  if (state.name && kindOf(state.name) !== "text") return kindOf(state.name);
  return detectKind(text);
}

// ── revealing: invisible characters become visible chips, runs that carry a message are decoded ──

function chipsFor(run) {
  const cps = run.map((s) => s.cp);
  const suspicious = run.some((s) => !s.legit);
  let message = null;
  if (suspicious && run.length >= 2) {
    const tags = cps.filter((c) => c >= 0xe0000 && c <= 0xe007f);
    const vs = cps.filter((c) => (c >= 0xfe00 && c <= 0xfe0f) || (c >= 0xe0100 && c <= 0xe01ef));
    const zw = cps.filter(isZeroWidthSymbol);
    if (tags.length >= 2) message = decodeTags(tags);
    else if (vs.length >= 2) message = decodeVariationSelectors(vs);
    else if (zw.length >= 8) message = decodeZeroWidthBinary(zw)?.text ?? null;
  }
  if (message && message.trim()) {
    const kinds = [...new Set(run.map((s) => s.kind))].join(" + ");
    return [h("span", { class: "inv msg", title: `${run.length} invisible ${kinds} characters` },
      `${run.length}× ${kinds}`, h("span", { class: "said" }, `“${message}”`))];
  }
  // otherwise one chip per character, or per stretch of the same character
  const out = [];
  for (let i = 0; i < run.length; i++) {
    let j = i;
    while (j + 1 < run.length && run[j + 1].name === run[i].name && run[j + 1].legit === run[i].legit) j++;
    const n = j - i + 1, s = run[i];
    out.push(h("span", { class: s.legit ? "inv ok" : "inv", title: `U+${s.cp.toString(16).toUpperCase().padStart(4, "0")} ${s.name} · ${s.kind}${s.legit ? " · doing a real job here" : ""}` },
      n > 1 ? `${s.name}×${n}` : s.name));
    if (s.kind === "line-break") out.push("\n");
    i = j;
  }
  return out;
}

function revealed(text, kind = "text") {
  const frag = document.createDocumentFragment();
  const segs = reveal(text, { kind });
  for (let i = 0; i < segs.length; i++) {
    if (!segs[i].hidden) { frag.append(segs[i].text); continue; }
    let j = i;
    while (j + 1 < segs.length && segs[j + 1].hidden) j++;
    frag.append(...chipsFor(segs.slice(i, j + 1)));
    i = j;
  }
  return frag;
}

// ── rendering ────────────────────────────────────────────────────────────────

function card(f, kind) {
  const where = state.doc ? `paragraph ${f.line}` : `line ${f.line}:${f.column}`;
  return h("article", { class: `card sev-${f.severity}` },
    h("header", {}, h("span", { class: "sev" }, f.severity), h("h3", {}, f.title), h("span", { class: "where" }, where)),
    h("p", { class: "detail" }, revealed(f.detail)),
    f.hidden ? h("blockquote", { class: "hidden-text" }, revealed(f.hidden, kind === "code" ? "code" : "text")) : null,
    f.signals?.length ? h("ul", { class: "signals" }, f.signals.map((s) => h("li", {}, `⚑ ${s}`))) : null);
}

function verdict(result) {
  const count = (s) => result.findings.filter((f) => f.severity === s).length;
  const severe = count("critical") + count("high");
  const instruction = result.findings.some((f) => f.signals?.length && (f.severity === "critical" || f.severity === "high"));
  const trojan = result.findings.some((f) => f.rule === "trojan-source");
  const minor = result.findings.filter((f) => f.severity === "medium" || f.severity === "low").length;
  const box = $("verdict");
  box.replaceChildren();
  box.hidden = false;
  const summary = SEVERITIES.filter(count).map((s) => `${count(s)} ${s}`).join(" · ");
  if (severe) {
    box.className = "verdict bad";
    box.append(h("span", { class: "big" }, "✖"), h("div", {},
      h("strong", {}, instruction ? "Hidden instructions for an AI found" : trojan ? "This code does not run the way it reads"
        : "Something is hiding in this text"), h("span", {}, summary)));
  } else if (minor) {
    box.className = "verdict warn";
    box.append(h("span", { class: "big" }, "⚠"), h("div", {},
      h("strong", {}, "Invisible characters, no hidden instructions"), h("span", {}, `${summary} · the clean tab removes them`)));
  } else {
    box.className = "verdict good";
    box.append(h("span", { class: "big" }, "✓"), h("div", {},
      h("strong", {}, "Nothing hidden"), h("span", {}, summary || "no invisible characters, smuggled messages or hidden text")));
  }
}

function cleanSummary(r, text, kind) {
  const total = Object.values(r.removed).reduce((a, b) => a + b, 0);
  const parts = [];
  if (total) parts.push(`${total} invisible character${total > 1 ? "s" : ""} removed (${Object.entries(r.removed).map(([k, v]) => `${v} ${k}`).join(", ")})`);
  if (r.removedElements) parts.push(`${r.removedElements} hidden element${r.removedElements > 1 ? "s" : ""} or comment${r.removedElements > 1 ? "s" : ""} dropped`);
  if (r.homoglyphsFixed) parts.push(`${r.homoglyphsFixed} lookalike letter${r.homoglyphsFixed > 1 ? "s" : ""} fixed`);
  if (state.doc?.hiddenCount) parts.push(`${state.doc.hiddenCount} hidden passage${state.doc.hiddenCount > 1 ? "s" : ""} of the document left out`);
  const again = scan(r.text, { kind }).findings.filter((f) => f.severity !== "info");
  const el = $("clean-summary");
  el.replaceChildren(parts.join(" · ") || "nothing to remove", " · ");
  if (!again.length) el.append(h("span", { class: "ok" }, "re-scan: clean ✓"), state.doc ? " · this is the text; Word's Inspect Document cleans the file itself" : "");
  else {
    const lookalikes = again.some((f) => f.rule === "homoglyph" || f.rule === "styled-letters") && !$("opt-homoglyphs").checked;
    el.append(h("span", { class: "still" }, `re-scan: ${again.length} left (${[...new Set(again.map((f) => f.rule))].join(", ")})` +
      (lookalikes ? ": tick “fix lookalike letters”" : "")));
  }
}

function render(result, text, kind, ms) {
  const has = text.length > 0;
  $("empty").hidden = has;
  $("verdict").hidden = !has;
  for (const id of ["tab-findings", "tab-reveal", "tab-clean"]) $(id).hidden = !has || id !== `tab-${state.tab}`;
  if (!has) {
    $("tab-findings").replaceChildren();
    $("stats").textContent = "";
    $("n-findings").textContent = "";
    return;
  }
  verdict(result);
  $("tab-findings").replaceChildren(...result.findings.map((f) => card(f, kind)));
  $("n-findings").textContent = result.findings.length || "";
  $("revealed").replaceChildren(revealed(text, kind));
  const r = clean(state.doc ? state.doc.visible : text,
    { kind, strict: $("opt-strict").checked, homoglyphs: $("opt-homoglyphs").checked, stripHtml: $("opt-strip").checked });
  state.cleaned = r.text;
  $("cleaned").textContent = r.text;
  cleanSummary(r, text, kind);
  const inv = result.invisible;
  $("stats").textContent = `${[...text].length.toLocaleString()} chars · ${inv.total - inv.legit} hidden` +
    (inv.legit ? ` (+${inv.legit} legit)` : "") + ` · read as ${kind} · ${ms.toFixed(1)} ms`;
}

function run() {
  const text = input.value;
  const t0 = performance.now();
  if (state.doc) {
    render(state.doc, text, "text", state.docMs);
    return;
  }
  const kind = currentKind(text);
  const result = scan(text, { kind });
  render(result, text, kind, performance.now() - t0);
  const auto = $("kind").options[0];
  auto.textContent = $("kind").value === "auto" && text ? `auto (${kind})` : "auto";
}

function schedule() {
  clearTimeout(state.timer);
  state.timer = setTimeout(run, input.value.length > 200000 ? 300 : 80);
}

// ── input: typing, samples, files ────────────────────────────────────────────

function setText(text, name = "") {
  closeDoc(false);
  state.name = name;
  input.value = text;
  run();
}

function closeDoc(rerun = true) {
  state.doc = null;
  input.readOnly = false;
  $("docbar").hidden = true;
  if (rerun) { input.value = ""; state.name = ""; run(); }
}

async function inflateRaw(data) {
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function decodeText(buf) {
  if (buf[0] === 0xff && buf[1] === 0xfe) return new TextDecoder("utf-16le").decode(buf.subarray(2));
  if (buf[0] === 0xfe && buf[1] === 0xff) return new TextDecoder("utf-16be").decode(buf.subarray(2));
  if (buf.subarray(0, 8192).includes(0)) return null;
  return new TextDecoder("utf-8").decode(buf);
}

async function openFile(file) {
  if (!file) return;
  if (file.size > 20 * 1024 * 1024) { setText(""); $("stats").textContent = `${file.name} is larger than 20 MB`; return; }
  const buf = new Uint8Array(await file.arrayBuffer());
  if (kindOf(file.name) === "docx") {
    const t0 = performance.now();
    try {
      const result = await scanDocx(buf, inflateRaw);
      state.doc = result;
      state.docMs = performance.now() - t0;
      state.name = file.name;
      input.value = result.text;
      input.readOnly = true;
      $("docname").textContent = file.name;
      $("docbar").hidden = false;
      run();
    } catch (e) {
      setText("");
      $("stats").textContent = `${file.name}: ${e.message}`;
    }
    return;
  }
  const text = decodeText(buf);
  if (text === null) { setText(""); $("stats").textContent = `${file.name} looks like a binary file`; return; }
  setText(text, file.name);
}

function selectTab(name) {
  state.tab = name;
  for (const b of document.querySelectorAll(".tabs button")) b.setAttribute("aria-selected", String(b.dataset.tab === name));
  run();
}

function flash(button, text) {
  const label = button.dataset.label || button.textContent;
  button.textContent = text;
  setTimeout(() => { button.textContent = label; }, 1400);
}

function init() {
  $("version").textContent = `v${VERSION}`;
  const select = $("sample");
  for (const s of SAMPLES) select.append(h("option", { value: s.id }, s.label));
  select.addEventListener("change", () => {
    const s = SAMPLES.find((x) => x.id === select.value);
    if (s) { $("kind").value = "auto"; setText(s.text, `sample.${{ html: "html", markdown: "md", code: "js", text: "txt" }[s.kind]}`); }
    select.value = "";
  });
  input.addEventListener("input", () => { if (!state.doc) { state.name = ""; schedule(); } });
  for (const id of ["kind", "opt-strip", "opt-homoglyphs", "opt-strict"]) $(id).addEventListener("change", run);
  $("open").addEventListener("click", () => $("file").click());
  $("file").addEventListener("change", (e) => { openFile(e.target.files[0]); e.target.value = ""; });
  $("clear").addEventListener("click", () => { closeDoc(); input.focus(); });
  $("doc-close").addEventListener("click", () => closeDoc());
  for (const b of document.querySelectorAll(".tabs button")) b.addEventListener("click", () => selectTab(b.dataset.tab));
  $("copy-clean").addEventListener("click", async (e) => {
    try { await navigator.clipboard.writeText(state.cleaned); flash(e.currentTarget, "copied ✓"); }
    catch { flash(e.currentTarget, "copy blocked"); }
  });
  $("dl-clean").addEventListener("click", () => {
    const name = state.name ? state.name.replace(/(\.[^.]+)?$/, (ext) => `.clean${state.doc ? ".txt" : ext || ".txt"}`) : "clean.txt";
    const a = h("a", { href: URL.createObjectURL(new Blob([state.cleaned], { type: "text/plain;charset=utf-8" })), download: name });
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  const panel = $("input-panel");
  panel.addEventListener("dragover", (e) => { e.preventDefault(); panel.classList.add("drop-active"); });
  panel.addEventListener("dragleave", () => panel.classList.remove("drop-active"));
  panel.addEventListener("drop", (e) => { e.preventDefault(); panel.classList.remove("drop-active"); openFile(e.dataTransfer.files[0]); });
  run();
}

init();
