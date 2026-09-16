const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

/* The Markdown export builds a table by hand. A cell containing "|" (httpx
   prints pipe-separated evidence) or a newline would silently break every row
   after it, so these lock the escaping in place. */
function loadDownloadNarrative() {
  const source = fs.readFileSync(path.join(__dirname, "..", "static", "app.js"), "utf8");
  const start = source.indexOf("function downloadNarrative()");
  assert.ok(start > -1, "downloadNarrative not found in app.js");
  const end = source.indexOf("\n}", start) + 2;
  const body = source.slice(start, end);

  let captured = null;
  let filename = null;
  const context = {
    state: { narrative: null },
    Blob: function (parts) { captured = parts.join(""); },
    URL: { createObjectURL: () => "blob:test", revokeObjectURL: () => {} },
    document: { createElement: () => ({ set href(v) {}, get href() { return "blob:test"; },
      set download(v) { filename = v; }, click() {} }) },
  };
  vm.createContext(context);
  vm.runInContext(body, context);
  return {
    run(narrative) {
      context.state.narrative = narrative;
      captured = null; filename = null;
      context.downloadNarrative();
      return { markdown: captured, filename };
    },
  };
}

const exporter = loadDownloadNarrative();

const BASE = {
  run_id: "abc-123",
  asset: "http://127.0.0.1:5005",
  phase: "web",
  phase_label: "Web application testing",
  model: "qwen3:1.7b",
  narrative: "Two paragraphs of prose.",
  tools: [{ tool: "gobuster", return_code: 0, findings: 2 }],
  findings: [],
};

function tableRows(markdown) {
  return markdown.split("\n").filter((line) => line.startsWith("| `"));
}

test("a pipe in the evidence does not break the table", () => {
  const { markdown } = exporter.run({ ...BASE, findings: [
    { path: "/", status: 200, size: null, source: "httpx",
      evidence: "SUCCESS | Meridian Freight | Flask:3.1.8,Python:3.11.16" },
  ]});
  const rows = tableRows(markdown);
  assert.strictEqual(rows.length, 1);
  // 5 columns means 6 unescaped delimiters.
  const unescaped = rows[0].split(/(?<!\\)\|/).length - 1;
  assert.strictEqual(unescaped, 6, `row has the wrong column count: ${rows[0]}`);
  assert.ok(rows[0].includes("\\|"), "the pipe should be escaped, not dropped");
});

test("a newline in a value is flattened rather than splitting the row", () => {
  const { markdown } = exporter.run({ ...BASE, findings: [
    { path: "/admin", status: 403, size: 10, source: "gobuster", note: "line one\nline two" },
  ]});
  const rows = tableRows(markdown);
  assert.strictEqual(rows.length, 1);
  assert.ok(rows[0].includes("line one line two"));
});

test("a redirect target is carried into the report", () => {
  const { markdown } = exporter.run({ ...BASE, findings: [
    { path: "/backups", status: 308, size: 247, source: "gobuster",
      note: "backup location", redirect: "http://127.0.0.1:5005/backups/" },
  ]});
  assert.ok(markdown.includes("redirects to http://127.0.0.1:5005/backups/"));
});

test("a missing status renders as an em dash, not the word undefined", () => {
  const { markdown } = exporter.run({ ...BASE, findings: [
    { path: "/x", status: null, size: null, source: "katana" },
  ]});
  assert.ok(!markdown.includes("undefined"));
  assert.ok(tableRows(markdown)[0].includes("| — |"));
});

test("tools that produced nothing are still listed", () => {
  const { markdown } = exporter.run({ ...BASE,
    tools: [{ tool: "nikto", return_code: 1, findings: 0 }] });
  assert.ok(markdown.includes("nikto (exit 1): 0 result(s)"));
});

test("the export is named for the run and states the model is local", () => {
  const { markdown, filename } = exporter.run(BASE);
  assert.strictEqual(filename, "hanzo-findings-abc-123.md");
  assert.ok(markdown.includes("Web application testing"));
  assert.ok(markdown.includes("written locally by qwen3:1.7b"));
  assert.ok(markdown.includes("not by itself proof of a vulnerability"));
});

test("a run with no narrative says so instead of leaving a blank section", () => {
  const { markdown } = exporter.run({ ...BASE, narrative: null });
  assert.ok(markdown.includes("_No narrative was generated._"));
});
