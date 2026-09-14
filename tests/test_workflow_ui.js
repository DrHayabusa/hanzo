"use strict";

// Run: node --test tests/test_workflow_ui.js. No browser, packages, or scans.
const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const ui = require("../static/app.js");

let nodes;
let requests;
let routes;
let originalSetTimeout;
function node(selector) {
  if (!nodes.has(selector)) {
    const classes = new Set();
    nodes.set(selector, {
      value: "", checked: false, disabled: false, textContent: "", innerHTML: "", style: {},
      classList: { add: (name) => classes.add(name), remove: (name) => classes.delete(name),
        toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name), contains: (name) => classes.has(name) },
    });
  }
  return nodes.get(selector);
}
function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}
function setupWorkflow(phase, target = "http://lab.invalid:8080", authorized = false) {
  node("#target").value = target;
  node("#workflowPhase").value = phase;
  node("#authorization").checked = authorized;
  node("#maxTools").value = "3";
}

beforeEach(() => {
  nodes = new Map(); requests = []; routes = {};
  ui.state.workflowRunning = false; ui.state.result = null; ui.state.providers = [];
  ui.state.llmConfigVersion = 0; ui.state.verifiedLlm = null;
  global.document = { querySelector: node, querySelectorAll: () => [] };
  originalSetTimeout = global.setTimeout;
  global.setTimeout = () => 0;
  global.fetch = async (path, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : undefined;
    requests.push({ path, body });
    if (routes[path]) return routes[path](body);
    if (path === "/api/redteam/workflows" && body) return response({ success: true, run_id: "test-evidence-id" }, 201);
    if (path === "/api/processes/list") return response({ active_processes: {} });
    return response({ runs: [] });
  };
});
afterEach(() => { delete global.document; delete global.fetch; global.setTimeout = originalSetTimeout; });

test("HTTP 200 application failure is rejected with its evidence payload", async () => {
  routes["/adapter"] = () => response({ success: false, error: "MCP tool unavailable", details: "test proof" });
  await assert.rejects(ui.api("/adapter"), (error) => error.message === "MCP tool unavailable" && error.data.details === "test proof");
});

test("a malformed success response is not treated as completed", async () => {
  routes["/adapter"] = () => ({ ok: true, status: 200, json: async () => { throw new Error("not JSON"); } });
  await assert.rejects(ui.api("/adapter"), /Invalid JSON response/);
});

test("MCP isError responses are failures even with HTTP 200", async () => {
  routes["/adapter"] = () => response({ isError: true, message: "MCP failed" });
  await assert.rejects(ui.api("/adapter"), /MCP failed/);
});

test("scanner outcomes distinguish no execution, failure, partial, and success", () => {
  const outcome = (tools) => ui.adapterOutcome("hexstrike_scan", { success: true, scan_results: { tools_executed: tools } }).status;
  assert.equal(outcome([]), "failed");
  assert.equal(outcome([{ success: false, status: "skipped" }]), "failed");
  assert.equal(outcome([{ success: true }, { success: false }]), "needs_review");
  assert.equal(outcome([{ success: true }, { success: true }]), "completed");
});

test("no-match classification is a valid completed outcome", () => {
  assert.equal(ui.adapterOutcome("claude_bughunter", { success: true, matched: false }).status, "completed");
});

test("CVE inputs are kept out of scanner-only phases", () => {
  assert.match(ui.workflowInputError("recon", "CVE-2021-44228"), /choose CVE/);
  assert.match(ui.workflowInputError("cve_triage", "http://lab.invalid"), /requires a CVE ID/);
  assert.equal(ui.workflowInputError("full", "CVE-2021-44228"), "");
  assert.equal(ui.workflowRequiresAuthorization("full", "CVE-2021-44228"), false);
  assert.equal(ui.workflowRequiresAuthorization("full", "http://lab.invalid"), true);
});

test("failed adapter payload is retained and persisted with failed status", async () => {
  setupWorkflow("full", undefined, true);
  routes["/api/intelligence/analyze-target"] = () => response({ success: false, error: "Profile failed", details: "failure evidence" });
  await ui.runAutomatedWorkflow();
  const saved = requests.find((item) => item.path === "/api/redteam/workflows").body;
  assert.equal(saved.status, "failed");
  assert.equal(saved.result.status, "failed");
  assert.equal(saved.result.steps[0].result.details, "failure evidence");
  assert.equal(ui.state.result.status, "failed");
  assert.ok(ui.state.result.completed_at);
  assert.equal(requests.some((item) => item.path.includes("smart-scan")), false);
  assert.equal(node("#runWorkflow").disabled, false);
  assert.equal(ui.state.workflowRunning, false);
});

test("partial smart scan stores needs_review rather than completed", async () => {
  setupWorkflow("recon", undefined, true);
  routes["/api/intelligence/analyze-target"] = () => response({ success: true });
  routes["/api/intelligence/smart-scan"] = () => response({ success: true, scan_results: { tools_executed: [{ tool: "a", success: true }, { tool: "b", success: false }] } });
  await ui.runAutomatedWorkflow();
  assert.equal(ui.state.result.status, "needs_review");
  assert.equal(requests.find((item) => item.path === "/api/redteam/workflows").body.status, "needs_review");
  assert.match(node("#resultJson").textContent, /needs_review/);
});

test("all scanners failing is not a successful assessment", async () => {
  setupWorkflow("recon", undefined, true);
  routes["/api/intelligence/analyze-target"] = () => response({ success: true });
  routes["/api/intelligence/smart-scan"] = () => response({ success: true, scan_results: { tools_executed: [{ tool: "a", success: false }] } });
  await ui.runAutomatedWorkflow();
  assert.equal(ui.state.result.status, "failed");
  assert.equal(ui.state.result.steps.length, 2);
  assert.equal(ui.state.result.steps[1].result.scan_results.tools_executed[0].tool, "a");
});

test("evidence-save failure is explicit without rewriting execution success", async () => {
  setupWorkflow("profile");
  routes["/api/intelligence/analyze-target"] = () => response({ success: true });
  routes["/api/redteam/workflows"] = () => response({ error: "Database unavailable" }, 503);
  await ui.runAutomatedWorkflow();
  assert.equal(ui.state.result.status, "needs_review");
  assert.equal(ui.state.result.execution_status, "completed");
  assert.equal(ui.state.result.evidence_status, "not_stored");
  assert.match(node("#resultSummary").innerHTML, /NOT STORED/);
  assert.equal(node("#copyResult").disabled, false);
});

test("no-match BugHunter run stores completed evidence", async () => {
  setupWorkflow("bughunter");
  routes["/api/redteam/bughunter/classify"] = () => response({ success: true, matched: false });
  await ui.runAutomatedWorkflow();
  assert.equal(ui.state.result.status, "completed");
  assert.match(ui.state.result.steps[0].message, /no high-confidence/);
});

test("Full CVE workflow only queries CVE intelligence without scan authorization", async () => {
  setupWorkflow("full", "cve-2021-44228");
  routes["/api/redteam/cve/triage"] = () => response({ success: true });
  await ui.runAutomatedWorkflow();
  assert.equal(ui.state.result.status, "completed");
  assert.equal(ui.state.result.steps.length, 1);
  assert.equal(ui.state.result.steps[0].adapter, "cve_mcp");
  assert.equal(requests.find((item) => item.path === "/api/redteam/cve/triage").body.cve_id, "CVE-2021-44228");
  assert.equal(requests.some((item) => item.path.includes("smart-scan")), false);
});

test("invalid phase/asset and missing authorization do not start requests", async () => {
  setupWorkflow("recon", "CVE-2021-44228", true);
  await ui.runAutomatedWorkflow();
  setupWorkflow("recon");
  await ui.runAutomatedWorkflow();
  assert.equal(requests.length, 0);
});

test("duplicate submissions cannot start a second workflow", async () => {
  setupWorkflow("profile");
  let resolve;
  routes["/api/intelligence/analyze-target"] = () => new Promise((done) => { resolve = done; });
  const pending = ui.runAutomatedWorkflow();
  await ui.runAutomatedWorkflow();
  assert.equal(requests.filter((item) => item.path.includes("analyze-target")).length, 1);
  resolve(response({ success: true }));
  await pending;
  assert.equal(ui.state.workflowRunning, false);
});

test("local readiness checks the selected model, not only the server default", async () => {
  node("#llmProvider").value = "ollama";
  node("#llmModel").value = "missing:7b";
  routes["/api/llm/status"] = () => response({ model: "qwen3:1.7b", model_available: true, models: ["qwen3:1.7b"] });
  await ui.loadLlmStatus();
  assert.equal(node("#chatSend").disabled, true);
  assert.match(node("#llmStatus").textContent, /missing:7b not downloaded/);
  assert.equal(ui.selectedModelAvailable(["qwen3:latest"], "qwen3"), true);
});

test("configured cloud provider is not shown as verified until a response succeeds", async () => {
  node("#llmProvider").value = "groq"; node("#llmModel").value = "model"; node("#llmApiKey").value = "temporary-test-key";
  await ui.loadLlmStatus();
  assert.equal(node("#llmDot").className, "offline");
  assert.equal(node("#chatSend").disabled, false);
  routes["/api/llm/chat"] = () => response({ success: true, model: "model", reply: "HANZO READY" });
  await ui.testLlm(); await ui.loadLlmStatus();
  assert.match(node("#llmStatus").textContent, /response verified/);
  ui.invalidateLlmVerification();
  assert.equal(node("#llmDot").className, "offline");
  assert.equal(ui.state.verifiedLlm, null);
});

test("cloud model test rejects an empty reply", async () => {
  node("#llmProvider").value = "groq"; node("#llmModel").value = "model";
  routes["/api/llm/chat"] = () => response({ success: true, model: "model", reply: "" });
  await ui.testLlm();
  assert.equal(ui.state.verifiedLlm, null);
  assert.match(node("#llmTestResult").textContent, /empty response/);
});

test("changing provider while local status is pending cannot overwrite new provider state", async () => {
  node("#llmProvider").value = "ollama"; node("#llmModel").value = "qwen3:1.7b";
  let resolve;
  routes["/api/llm/status"] = () => new Promise((done) => { resolve = done; });
  const pending = ui.loadLlmStatus();
  node("#llmProvider").value = "groq"; node("#llmModel").value = "cloud-model"; node("#llmApiKey").value = "test";
  ui.invalidateLlmVerification();
  resolve(response({ model: "qwen3:1.7b", models: ["qwen3:1.7b"], model_available: true }));
  await pending;
  assert.equal(node("#llmStatus").textContent, "Configured · not tested");
});
