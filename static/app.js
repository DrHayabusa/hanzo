const state = { health: null, processes: [], result: null, chat: [], llm: null, providers: [], integrations: [], lab: null, reports: [], exercises: [], selectedReport: null, workflowRunning: false, llmConfigVersion: 0, verifiedLlm: null };
const titles = { overview: "Overview", lab: "Lab network", assessment: "Test target", integrations: "MCP servers", tools: "Security tools", activity: "Running jobs", copilot: "AI assistant", exercises: "Lab exercises", reports: "Reports" };
const activeWorkflowPhases = new Set(["recon", "network_discovery", "network_pentest",
  "web", "api", "validate", "cloud_aws", "cloud_kubernetes", "cloud_container",
  "cloud_iac", "password", "binary", "forensics", "bugbounty_recon",
  "bugbounty_hunt", "full"]);
const stageCatalog = { groups: [], byId: new Map() };

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);

function showToast(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", error);
  toast.classList.add("show");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("show"), 3200);
}

function showView(id) {
  if (!titles[id]) id = "overview";
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === id));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === id));
  $("#pageTitle").textContent = titles[id];
  history.replaceState(null, "", `#${id}`);
  window.scrollTo(0, 0);
  if (id === "activity") loadProcesses();
  if (id === "copilot") loadLlmStatus();
  if (id === "integrations") loadIntegrations();
  if (id === "lab" && !state.lab) loadLab(false, true);
  if (id === "reports" || id === "overview") loadReports(true);
  if (id === "exercises") loadExercises();
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  let data;
  try { data = await response.json(); } catch { throw new Error(`Invalid JSON response (${response.status})`); }
  if (!response.ok || data?.success === false || data?.isError === true) {
    const error = new Error(data?.error || data?.message || `Request failed (${response.status})`);
    error.data = data;
    throw error;
  }
  return data;
}

function isCveTarget(target) { return /^CVE-\d{4}-\d{4,}$/i.test(String(target).trim()); }
function workflowRequiresAuthorization(phase, target) {
  return activeWorkflowPhases.has(phase) && !(phase === "full" && isCveTarget(target));
}
function workflowInputError(phase, target) {
  if (!String(target).trim()) return "Enter a website URL, hostname, IP address, or CVE ID";
  if (phase === "cve_triage" && !isCveTarget(target)) return "CVE intelligence requires a CVE ID, such as CVE-2021-44228";
  if (isCveTarget(target) && !["cve_triage", "full"].includes(phase)) return "For a CVE ID, choose CVE intelligence or the full assessment";
  return "";
}

function adapterOutcome(adapter, result) {
  if (!result || result.success === false || result.isError === true || ["failed", "error"].includes(result.status)) {
    return { status: "failed", message: result?.error || result?.message || `${adapter} failed` };
  }
  if (adapter === "hexstrike_scan") {
    const tools = result.scan_results?.tools_executed || [];
    const successful = tools.filter((tool) => tool.success === true && !["failed", "error", "skipped"].includes(tool.status)).length;
    if (!tools.length) return { status: "failed", message: "No scanner executed. Check installed tools and target compatibility." };
    if (!successful) return { status: "failed", message: `All ${tools.length} selected scanners failed or were skipped. Review their output.` };
    if (successful < tools.length) return { status: "needs_review", message: `${successful} of ${tools.length} scanners succeeded. Review failed or skipped tools.` };
  }
  if (adapter === "claude_bughunter" && result.matched === false) {
    return { status: "completed", message: result.message || "Classification completed; no high-confidence playbook matched." };
  }
  return { status: "completed", message: "" };
}

async function runWorkflowStep(workflow, adapter, path, body) {
  try {
    const result = await api(path, { method: "POST", body: JSON.stringify(body) });
    const outcome = adapterOutcome(adapter, result);
    workflow.steps.push({ adapter, ...outcome, result });
    if (outcome.status === "failed") throw new Error(outcome.message);
  } catch (error) {
    if (workflow.steps.at(-1)?.adapter !== adapter) {
      workflow.steps.push({ adapter, status: "failed", message: error.message, result: error.data || { error: error.message } });
    }
    throw error;
  }
}

function selectedModelAvailable(models, selected) {
  const name = String(selected || "").trim();
  return Boolean(name) && (models || []).some((model) => model === name || (!name.includes(":") && model === `${name}:latest`));
}

function formatUptime(seconds = 0) {
  const value = Math.max(0, Number(seconds));
  const hours = Math.floor(value / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m ${Math.floor(value % 60)}s`;
}

function renderHealth(data) {
  state.health = data;
  const displayName = data.agent_name || "Hanzo";
  $("#brandName").textContent = displayName.toUpperCase();
  document.title = "HANZO / Workspace";
  if (data.lab_cidr) $(".lab-chip b").textContent = data.lab_cidr;
  $("#statusDot").className = "online";
  $("#statusLabel").textContent = "Engine online";
  $("#engineStatus").textContent = "ONLINE";
  $("#engineStatus").style.color = "var(--green)";
  $("#engineMessage").textContent = data.version ? `version ${data.version}` : "API operational";
  $("#toolsOnline").textContent = data.total_tools_available ?? 0;
  $("#toolsRatio").textContent = `of ${data.total_tools_count ?? 0} detected`;
  $("#uptime").textContent = formatUptime(data.uptime);
  const total = Number(data.total_tools_count || 0);
  const available = Number(data.total_tools_available || 0);
  $("#coveragePercent").textContent = total ? `${Math.round((available / total) * 100)}% READY` : "0% READY";

  const categories = Object.entries(data.category_stats || {}).sort((a, b) => b[1].available - a[1].available);
  $("#categoryBars").innerHTML = categories.slice(0, 6).map(([name, stats]) => {
    const percent = stats.total ? Math.round((stats.available / stats.total) * 100) : 0;
    return `<div class="category-row"><label>${escapeHtml(name.replaceAll("_", " "))}</label><div class="bar"><i style="width:${percent}%"></i></div><span>${stats.available}/${stats.total}</span></div>`;
  }).join("") || '<p class="muted">No categories reported.</p>';

  const telemetry = data.telemetry || {};
  const system = telemetry.system_metrics || {};
  $("#cpuStat").textContent = `${Math.round(system.cpu_percent ?? telemetry.cpu_usage ?? 0)}%`;
  $("#memoryStat").textContent = `${Math.round(system.memory_percent ?? telemetry.memory_usage ?? 0)}%`;
  $("#commandStat").textContent = telemetry.commands_executed ?? telemetry.total_commands ?? 0;
  $("#lastUpdated").textContent = `Last heartbeat ${new Date().toLocaleTimeString()}`;
  renderToolMatrix();
}

function resourceValue(value) {
  return value ? escapeHtml(value) : "UNSPECIFIED";
}

function renderLab(data) {
  state.lab = data;
  $("#labName").textContent = data.name || "Detection Engineering Lab";
  $("#labCidr").textContent = data.cidr || "—";
  $("#networkCoreCidr").textContent = data.cidr || "—";
  $("#labNetworkMode").textContent = data.network_mode || "ISOLATED";
  $("#labHostPlatform").textContent = data.host?.platform || "—";
  $("#labHostCpu").textContent = data.host?.cpu || "—";
  $("#labHostMemory").textContent = data.host?.memory || "—";
  $("#labHostDisk").textContent = data.host?.disk || "—";
  $("#labNodes").innerHTML = (data.nodes || []).map((node) => `
    <article class="lab-node ${escapeHtml(node.status)}">
      <div class="node-top"><span class="node-icon">${escapeHtml(node.icon)}</span><span class="node-status"><i></i>${escapeHtml(node.status.replaceAll("_", " "))}</span></div>
      <h4>${escapeHtml(node.label)}</h4>
      <p>${escapeHtml(node.role)}</p>
      <div class="node-address"><span>ADDRESS</span><strong>${escapeHtml(node.ip || "CLOUD SERVICE")}${node.probe_port ? `:${escapeHtml(node.probe_port)}` : ""}</strong></div>
      <div class="node-spec"><span>${resourceValue(node.cpu)}</span><span>${resourceValue(node.memory)}</span><span>${resourceValue(node.disk)}</span></div>
    </article>`).join("");
  $("#labFlow").innerHTML = (data.flow || []).map((item) => `
    <div class="flow-step"><span>${escapeHtml(item.step)}</span><div><strong>${escapeHtml(item.label)}</strong><p>${escapeHtml(item.detail)}</p></div></div>`).join("");
  $("#labWarnings").innerHTML = (data.resource_guidance || []).map((item) => `<p><span>!</span>${escapeHtml(item)}</p>`).join("");
}

async function loadLab(probe = true, silent = false) {
  const button = $("#probeLab");
  if (button) { button.disabled = true; button.textContent = probe ? "Probing…" : "Loading…"; }
  try {
    const data = await api(`/api/lab/topology?probe=${probe ? "true" : "false"}`);
    renderLab(data);
    if (!silent) showToast("Lab service probes completed");
  } catch (error) {
    if (!silent) showToast(error.message, true);
  } finally {
    if (button) { button.disabled = false; button.textContent = "Probe configured services ⌁"; }
  }
}

function renderToolMatrix(filter = "") {
  if (!state.health) return;
  const statuses = state.health.tools_status || {};
  const categoryMap = {};
  Object.entries(state.health.category_stats || {}).forEach(([name]) => { categoryMap[name] = []; });

  // New Hanzo servers expose the complete category registry. Keep a compact
  // fallback for compatibility with an older upstream HexStrike worker.
  const fallbackGroups = {
    network: ["nmap", "masscan", "rustscan", "autorecon", "nbtscan", "arp-scan", "responder", "enum4linux", "enum4linux-ng", "rpcclient"],
    web_security: ["gobuster", "dirb", "nikto", "sqlmap", "ffuf", "feroxbuster", "dirsearch", "nuclei", "wpscan", "katana", "httpx", "wafw00f"],
    password: ["hydra", "john", "hashcat", "medusa", "patator", "ophcrack"],
    binary: ["gdb", "radare2", "binwalk", "ropgadget", "checksec", "objdump", "ghidra", "angr", "ropper"],
    cloud: ["prowler", "scout-suite", "trivy", "kube-hunter", "kube-bench", "checkov", "terrascan", "falco"],
    osint: ["amass", "subfinder", "fierce", "dnsenum", "theharvester", "sherlock", "recon-ng", "spiderfoot"]
  };
  const groups = state.health.tool_categories || fallbackGroups;
  const query = filter.trim().toLowerCase();
  const cards = Object.entries(groups).map(([category, tools]) => {
    const filtered = tools.filter((tool) => !query || tool.includes(query) || category.includes(query));
    if (!filtered.length) return "";
    const online = filtered.filter((tool) => statuses[tool]).length;
    return `<article class="tool-card"><div class="tool-card-head"><h3>${escapeHtml(category.replaceAll("_", " "))}</h3><span class="tool-count">${online}/${filtered.length} READY</span></div><div class="tool-list">${filtered.map((tool) => `<span class="tool-chip ${statuses[tool] ? "online" : ""}" title="${statuses[tool] ? "Executable found on worker PATH" : "Adapter exists; executable is not installed on this worker"}">${escapeHtml(tool)}</span>`).join("")}</div></article>`;
  }).join("");
  $("#toolMatrix").innerHTML = cards || '<div class="no-processes">No matching tools.</div>';
}

async function loadHealth(silent = false) {
  try {
    const data = await api("/health");
    renderHealth(data);
    await loadProcesses(true);
    if (!silent) showToast("Dashboard refreshed");
  } catch (error) {
    $("#statusDot").className = "offline";
    $("#statusLabel").textContent = "Engine offline";
    $("#engineStatus").textContent = "OFFLINE";
    $("#engineStatus").style.color = "var(--red)";
    $("#engineMessage").textContent = error.message;
    if (!silent) showToast(error.message, true);
  }
}

async function loadLlmStatus() {
  const providerId = $("#llmProvider")?.value || "ollama";
  const version = state.llmConfigVersion;
  const model = $("#llmModel").value.trim();
  const verified = state.verifiedLlm?.version === version;
  if (providerId !== "ollama") {
    const provider = state.providers.find((item) => item.id === providerId);
    const endpoint = $("#llmBaseUrl").value.trim();
    const keyReady = Boolean($("#llmApiKey").value.trim() || (provider?.server_key_configured && (providerId !== "compatible" || endpoint.replace(/\/$/, "") === String(provider.base_url || "").replace(/\/$/, ""))));
    const ready = keyReady && Boolean(model) && (providerId !== "compatible" || Boolean(endpoint));
    $("#llmDot").className = verified ? "online" : "offline";
    $("#llmStatus").textContent = verified ? `${model} · response verified` : (ready ? "Configured · not tested" : "API key, model, and endpoint required");
    $("#chatSend").disabled = !ready;
    return;
  }
  try {
    const data = await api("/api/llm/status");
    if (state.llmConfigVersion !== version || $("#llmProvider").value !== providerId) return;
    state.llm = data;
    const available = selectedModelAvailable(data.models, model);
    $("#llmDot").className = available ? "online" : "offline";
    $("#llmStatus").textContent = available ? `${model} · ${verified ? "response verified" : "installed · inference not tested"}` : (model ? `${model} not downloaded` : "Select a local model");
    $("#overviewAi").textContent = data.model_available ? "Model available" : "Default model missing";
    $("#chatSend").disabled = !available;
  } catch (error) {
    if (state.llmConfigVersion !== version || $("#llmProvider").value !== providerId) return;
    state.llm = null;
    $("#llmDot").className = "offline";
    $("#llmStatus").textContent = "Local AI offline";
    $("#overviewAi").textContent = "Offline";
    $("#chatSend").disabled = true;
  }
}

async function loadProviders() {
  try {
    const data = await api("/api/llm/providers");
    state.providers = data.providers || [];
    $("#llmProvider").innerHTML = state.providers.map((provider) => `<option value="${escapeHtml(provider.id)}">${escapeHtml(provider.label)}</option>`).join("");
    configureProvider("ollama");
  } catch (error) {
    showToast(`Could not load AI providers: ${error.message}`, true);
  }
}

function renderIntegrations(data) {
  state.integrations = data.integrations || [];
  const summary = data.summary || {};
  $("#hubTotal").textContent = summary.total ?? 0;
  $("#hubOnline").textContent = summary.ready ?? summary.online ?? 0;
  $("#hubInstalled").textContent = summary.source_cloned ?? 0;
  const core = state.integrations.filter((item) => ["hexstrike", "cve_mcp", "claude_bughunter"].includes(item.id));
  $("#overviewMcp").textContent = `${core.filter((item) => ["online", "ready"].includes(item.status)).length} / ${core.length} ready`;
  const TRANSPORTS = {
    native: "Embedded in this worker; its routes are called directly.",
    mcp_stdio: "Spoken to over stdio MCP: the process starts per call, no port is held.",
    mcp_sse: "Spoken to over SSE MCP at a configured URL.",
    cli: "Invoked as a command-line program on this worker.",
    http: "Reached over HTTP at a configured URL; deployed separately.",
  };
  const labels = { online: "online", ready: "ready", reachable: "TCP reachable", installed: "executable found", source_ready: "source cloned", needs_config: "needs setup", not_installed: "not installed", error: "error" };
  $("#integrationCards").innerHTML = state.integrations.map((item) => `
    <article class="integration-card">
      <div><span class="integration-kind">${escapeHtml(item.kind)}</span><h4>${escapeHtml(item.label)}</h4></div>
      <span class="integration-status ${escapeHtml(item.status)}">${escapeHtml(labels[item.status] || item.status)}</span>
      <p>${escapeHtml(item.role)}</p>
      <div class="adapter-proof ${item.execution_integrated ? "is-live" : ""}">${item.execution_integrated ? "CALLABLE FROM HANZO" : "SOURCE PINNED · EXTERNAL RUNTIME"}</div>
      <div class="integration-wiring">${escapeHtml(TRANSPORTS[item.kind] || item.kind)}</div>
      <div class="phase-list">${(item.phases || []).map((phase) => `<span>${escapeHtml(phase)}</span>`).join("")}</div>
      <small>${escapeHtml(item.message || item.endpoint || item.command || item.notes || "Run the integration installer")}</small>
      ${(item.tool_count || item.skill_count) ? `<div class="adapter-proof">${item.tool_count ? `${escapeHtml(item.tool_count)} MCP TOOLS` : ""}${item.skill_count ? `${escapeHtml(item.skill_count)} SKILLS` : ""}</div>` : ""}
      <a class="source-link" href="${escapeHtml(item.repo)}" target="_blank" rel="noreferrer">SOURCE ↗</a>
    </article>`).join("") || '<div class="no-processes">No integrations registered.</div>';
}

/* Counts come from the worker, never from this file, so the page cannot claim
   more than the host actually has. */
async function loadSystemStats(silent = true) {
  const band = $("#statBand");
  if (!band) return;
  try {
    const data = await api("/api/system/stats");
    const adapters = data.adapters || {};
    const stages = data.stages || {};
    const tiles = [
      { label: "Tool adapters ready", value: `${adapters.ready ?? 0}`, of: `of ${adapters.total ?? 0}`,
        ratio: (adapters.ready || 0) / Math.max(1, adapters.total || 1) },
      { label: "Distinct executables", value: `${adapters.executables ?? 0}`, of: "on PATH" },
      { label: "Engagement stages", value: `${stages.total ?? 0}`, of: `${stages.groups ?? 0} groups` },
      { label: "Wordlists discovered", value: `${(data.wordlists || {}).total ?? 0}`, of: "readable files" },
      { label: "Pinned source repos", value: `${(data.sources || {}).pinned_repositories ?? 0}`, of: "reviewed revisions" },
    ];
    band.innerHTML = tiles.map((tile) => `
      <div class="stat-tile">
        <span>${escapeHtml(tile.label)}</span>
        <strong>${escapeHtml(tile.value)}</strong>
        <small>${escapeHtml(tile.of)}</small>
        ${tile.ratio === undefined ? "" : `<div class="bar" role="img" aria-label="${Math.round(tile.ratio * 100)} percent ready"><i style="width:${Math.max(2, Math.round(tile.ratio * 100))}%"></i></div>`}
      </div>`).join("");
    $("#categoryReadiness").innerHTML = (adapters.by_category || []).map((group) => {
      const percent = Math.round((group.ready / Math.max(1, group.total)) * 100);
      return `<div class="category-row"><b>${escapeHtml(group.label)}</b>
        <div class="bar" role="img" aria-label="${percent} percent ready"><i style="width:${Math.max(2, percent)}%"></i></div>
        <span>${group.ready}/${group.total}</span></div>`;
    }).join("");
    $("#statsNote").textContent = data.note || "";
  } catch (error) {
    band.innerHTML = `<div class="empty-compact">Inventory unavailable: ${escapeHtml(error.message)}</div>`;
    if (!silent) showToast(error.message, true);
  }
}
async function loadIntegrations(silent = true) {
  loadSystemStats(true);
  let integrationError = null;
  try {
    const data = await api("/api/redteam/integrations?probe=true");
    renderIntegrations(data);
  } catch (error) {
    integrationError = error;
    if (!silent) showToast(error.message, true);
  }
  try {
    const llm = await api("/api/llm/status");
    $("#hubLlm").textContent = llm.model_available ? "READY" : "MODEL MISSING";
    $("#hubLlm").className = llm.model_available ? "good" : "warn";
    if (!silent && !integrationError) showToast("Integration status refreshed. Review each adapter's readiness.");
  } catch (error) {
    $("#hubLlm").textContent = "OFFLINE";
    $("#hubLlm").className = "bad";
    if (!silent) showToast(error.message, true);
  }
}

async function validateStack() {
  const button = $("#validateStack");
  button.disabled = true;
  button.textContent = "Validating…";
  try {
    const data = await api("/api/redteam/validate", { method: "POST", body: "{}" });
    renderIntegrations(data.integrations);
    $("#hubLlm").textContent = data.checks.local_llm_model_available ? "READY" : "DEGRADED";
    $("#hubLlm").className = data.checks.local_llm_model_available ? "good" : "warn";
    showToast(`Stack validation: ${data.status}`);
  } catch (error) { showToast(error.message, true); }
    finally { button.disabled = false; button.textContent = "Validate connections ↻"; }
}

function configureProvider(providerId) {
  const provider = state.providers.find((item) => item.id === providerId);
  if (!provider) return;
  $("#llmModel").value = provider.default_model || "";
  $("#llmBaseUrl").value = provider.base_url || "";
  $("#apiKeyRow").classList.toggle("hidden", !provider.requires_api_key);
  $("#baseUrlRow").classList.toggle("hidden", providerId !== "compatible");
  $("#providerDescription").textContent = providerId === "ollama"
    ? "Qwen analyzes results locally through Ollama. Prompts stay inside your lab."
    : "Hosted prompts leave your lab. Keys are held in page memory or the server environment. Provider quotas, pricing, and model availability vary.";
  $("#llmApiKey").value = "";
  invalidateLlmVerification();
}

function invalidateLlmVerification() {
  state.llmConfigVersion += 1;
  state.verifiedLlm = null;
  $("#llmTestResult").textContent = "Configured is not connected. Run a real model test.";
  loadLlmStatus();
}

function addChatMessage(role, content) {
  const item = document.createElement("div");
  item.className = `chat-message ${role}`;
  item.innerHTML = `<span>${role === "user" ? "YOU" : "HANZO AI"}</span><p>${escapeHtml(content)}</p>`;
  $("#chatMessages").append(item);
  $("#chatMessages").scrollTop = $("#chatMessages").scrollHeight;
}

async function sendChat(message) {
  if ($("#chatSend").disabled) return;
  const version = state.llmConfigVersion;
  addChatMessage("user", message);
  const history = state.chat.slice(-12);
  state.chat.push({ role: "user", content: message });
  $("#chatInput").value = "";
  $("#chatSend").disabled = true;
  $("#chatSend").textContent = "Thinking…";
  try {
    const body = {
      message,
      history,
      provider: $("#llmProvider").value,
      model: $("#llmModel").value.trim(),
    };
    if ($("#llmProvider").value !== "ollama") body.api_key = $("#llmApiKey").value;
    if ($("#llmProvider").value === "compatible") body.base_url = $("#llmBaseUrl").value.trim();
    if ($("#attachAssessment").checked && state.result) body.assessment = state.result;
    const data = await api("/api/llm/chat", { method: "POST", body: JSON.stringify(body) });
    if (!String(data.reply || "").trim()) throw new Error("The selected AI provider returned an empty response");
    if (version === state.llmConfigVersion) state.verifiedLlm = { version, model: data.model, provider: body.provider };
    state.chat.push({ role: "assistant", content: data.reply });
    addChatMessage("assistant", data.reply);
  } catch (error) {
    addChatMessage("assistant", `The selected AI provider could not respond: ${error.message}`);
    showToast(error.message, true);
  } finally {
    $("#chatSend").textContent = "Send →";
    loadLlmStatus();
  }
}

function updateWorkflowAuthorization() {
  const phase = $("#workflowPhase").value;
  const target = $("#target").value.trim();
  const active = workflowRequiresAuthorization(phase, target);
  $("#authorizationRow").classList.toggle("required", active);
  $("#workflowNote").textContent = active
    ? "This stage can invoke installed scanners. Confirm authorization, keep the asset in scope, and monitor Running jobs."
    : "This stage profiles, classifies, or queries CVE intelligence; no scanner process is launched.";
}

function markWorkflowStage(name) {
  $$(".workflow-rail span").forEach((item) => item.classList.toggle("active", item.dataset.stage === name));
}

async function runAutomatedWorkflow() {
  if (state.workflowRunning) return;
  const target = $("#target").value.trim();
  const phase = $("#workflowPhase").value;
  const authorized = $("#authorization").checked;
  const inputError = workflowInputError(phase, target);
  if (inputError) return showToast(inputError, true);
  if (workflowRequiresAuthorization(phase, target) && !authorized) return showToast("Confirm authorization before active execution", true);
  state.workflowRunning = true;
  state.result = null;
  $("#copyResult").disabled = true;

  $("#emptyResult").classList.add("hidden");
  $("#resultSummary").classList.add("hidden");
  $("#resultJson").classList.add("hidden");
  $("#loadingResult").classList.remove("hidden");
  $("#loadingText").textContent = `Running ${phaseName(phase).toLowerCase()}…`;
  $("#runWorkflow").disabled = true;
  const workflow = { asset: target, phase, started_at: new Date().toISOString(), steps: [] };
  let status = "completed";
  try {
    const cveTarget = isCveTarget(target);
    if (phase === "cve_triage" || (phase === "full" && cveTarget)) {
      markWorkflowStage("classify");
      await runWorkflowStep(workflow, "cve_mcp", "/api/redteam/cve/triage", { cve_id: target.toUpperCase(), depth: "quick" });
    } else {
      if (phase === "profile" || activeWorkflowPhases.has(phase)) {
        markWorkflowStage("profile");
        await runWorkflowStep(workflow, "hexstrike_profile", "/api/intelligence/analyze-target", { target, analysis_type: phase });
      }
      if (["bughunter", "full"].includes(phase)) {
        markWorkflowStage("classify");
        await runWorkflowStep(workflow, "claude_bughunter", "/api/redteam/bughunter/classify", { asset: target });
      }
      if (activeWorkflowPhases.has(phase)) {
        markWorkflowStage("execute");
        const objective = stageCatalog.byId.get(phase)?.objective || "comprehensive";
        await runWorkflowStep(workflow, "hexstrike_scan", "/api/intelligence/smart-scan", { target, objective, max_tools: Number($("#maxTools").value), authorization_confirmed: true });
      }
    }
    if (workflow.steps.some((step) => step.status === "needs_review")) status = "needs_review";
  } catch (error) {
    status = "failed";
    workflow.error = error.message;
  }
  workflow.completed_at = new Date().toISOString();
  workflow.status = status;
  workflow.execution_status = status;

  try {
    markWorkflowStage("evidence");
    const evidence = await api("/api/redteam/workflows", {
      method: "POST",
      body: JSON.stringify({ asset: target, phase, status, authorization_confirmed: authorized, result: workflow }),
    });
    if (!evidence.run_id) throw new Error("Evidence storage returned no report ID");
    workflow.evidence_id = evidence.run_id;
    workflow.evidence_status = "stored";
  } catch (error) {
    workflow.evidence_error = error.message;
    workflow.evidence_status = "not_stored";
    // Preserve execution truth while making incomplete evidence explicit.
    if (status !== "failed") status = "needs_review";
  }

  workflow.status = status;
  state.result = workflow;
  loadReports(true);
  renderWorkflowResult(workflow, status);
  if (status === "completed") {
    showToast(`${phaseName(phase)} completed`);
    loadProcesses(true);
  } else showToast(workflow.error || workflow.evidence_error || "Workflow needs review: inspect failed or skipped tools", true);
  $("#loadingResult").classList.add("hidden");
  $("#runWorkflow").disabled = false;
  $("#copyResult").disabled = false;
  state.workflowRunning = false;
}

function renderWorkflowResult(data, status) {
  $("#resultSummary").innerHTML = `<div><span>ASSET</span><strong>${escapeHtml(data.asset)}</strong></div><div><span>PHASE</span><strong>${escapeHtml(data.phase.replaceAll("_", " "))}</strong></div><div><span>RESULT</span><strong>${escapeHtml(status)} · ${escapeHtml(data.steps.length)} ADAPTERS</strong></div><div><span>EVIDENCE ID</span><strong>${escapeHtml(data.evidence_id || "NOT STORED")}</strong></div>`;
  $("#resultSummary").classList.remove("hidden");
  $("#resultJson").textContent = JSON.stringify(data, null, 2);
  $("#resultJson").classList.remove("hidden");
}

async function loadProcesses(silent = false) {
  try {
    const data = await api("/api/processes/list");
    const processes = Object.entries(data.active_processes || {}).map(([pid, info]) => ({ pid, ...info }));
    state.processes = processes;
    $("#activeTasks").textContent = processes.length;
    $("#processRows").innerHTML = processes.length ? processes.map((process) => `<div class="process-row"><span>${escapeHtml(process.pid)}</span><span title="${escapeHtml(process.command)}">${escapeHtml(String(process.command || "—").slice(0, 75))}</span><span class="running">● ${escapeHtml(process.status || "running")}</span><span>${escapeHtml(process.runtime_formatted || "—")}</span><span><button data-terminate="${escapeHtml(process.pid)}">TERMINATE</button></span></div>`).join("") : '<div class="no-processes">No active security processes.</div>';
  } catch (error) {
    if (!silent) showToast(error.message, true);
  }
}

async function terminateProcess(pid) {
  if (!confirm(`Terminate process ${pid}?`)) return;
  try {
    await api(`/api/processes/terminate/${encodeURIComponent(pid)}`, { method: "POST", body: "{}" });
    showToast(`Process ${pid} terminated`);
    loadProcesses(true);
  } catch (error) { showToast(error.message, true); }
}

function updateClock() {
  $("#clock").textContent = new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Dubai", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date()) + " GST";
}

if (typeof document !== "undefined") {
$$('.nav-item').forEach((item) => item.addEventListener("click", () => showView(item.dataset.view)));
$$('[data-open-view]').forEach((item) => item.addEventListener("click", () => showView(item.dataset.openView)));
$("#refreshButton").addEventListener("click", () => loadHealth());
$("#probeLab").addEventListener("click", () => loadLab(true));
$("#activityRefresh").addEventListener("click", () => loadProcesses());
$("#validateStack").addEventListener("click", validateStack);
$("#assessmentForm").addEventListener("submit", (event) => { event.preventDefault(); runAutomatedWorkflow(); });
$("#workflowPhase").addEventListener("change", updateWorkflowAuthorization);
$("#target").addEventListener("input", updateWorkflowAuthorization);
$("#openAutopilot").addEventListener("click", () => showView("assessment"));
$("#toolSearch").addEventListener("input", (event) => renderToolMatrix(event.target.value));
$("#copyResult").addEventListener("click", async () => {
  if (!state.result) return showToast("No result to copy", true);
  try { await navigator.clipboard.writeText(JSON.stringify(state.result, null, 2)); showToast("Result copied to clipboard"); }
  catch { showToast("Clipboard unavailable. Select the JSON evidence to copy it manually.", true); }
});
$("#processRows").addEventListener("click", (event) => {
  const button = event.target.closest("[data-terminate]");
  if (button) terminateProcess(button.dataset.terminate);
});
$("#chatForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const message = $("#chatInput").value.trim();
  if (message) sendChat(message);
});
$("#llmProvider").addEventListener("change", (event) => configureProvider(event.target.value));
$("#llmApiKey").addEventListener("input", invalidateLlmVerification);
$("#llmModel").addEventListener("input", invalidateLlmVerification);
$("#llmBaseUrl").addEventListener("input", invalidateLlmVerification);
$$('[data-prompt]').forEach((button) => button.addEventListener("click", () => {
  showView("copilot");
  $("#chatInput").value = button.dataset.prompt;
  $("#chatInput").focus();
}));

const initialView = location.hash.slice(1);
if (titles[initialView]) showView(initialView);
updateClock();
setInterval(updateClock, 1000);
loadHealth(true);
loadProviders();
loadIntegrations(true);
loadLab(false, true);
updateWorkflowAuthorization();
setInterval(() => loadHealth(true), 30000);
}
function downloadJson(value, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const link = document.createElement("a"); link.href = url; link.download = filename;
  document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
/* One source of proper names. Backend phase ids stay as they are; only the
   words the operator reads are spelled out in full. */
const PHASE_NAMES = {
  profile: "Target profiling",
  recon: "Reconnaissance",
  bughunter: "Vulnerability classification",
  cve_triage: "CVE intelligence",
  validate: "Vulnerability validation",
  full: "Full assessment",
  command: "Direct tool command",
  mcp: "MCP tool call",
};
function phaseName(value) {
  const key = String(value || "").toLowerCase();
  if (PHASE_NAMES[key]) return PHASE_NAMES[key];
  return String(value || "Assessment").replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
}
function reportLabel(run) { return phaseName(run.exercise_id || run.phase || "Assessment"); }
function statusBadge(status) {
  const safeClass = ["completed", "failed", "needs_review"].includes(status) ? status : "";
  return '<span class="status-badge ' + safeClass + '">' + escapeHtml(String(status || "unknown").replaceAll("_", " ")) + '</span>';
}
async function loadReports(silent = false) {
  try {
    const results = await Promise.all([api("/api/redteam/workflows?limit=30"), api("/api/lab/exercises/history?limit=30")]);
    state.reports = [...(results[0].runs || []), ...(results[1].runs || [])].sort((a,b) => String(b.created_at).localeCompare(String(a.created_at)));
    $("#reportCount").textContent = state.reports.length;
    $("#recentRuns").innerHTML = state.reports.slice(0,4).map((run) => '<div class="history-row"><div><strong>' + escapeHtml(reportLabel(run)) + '</strong><small>' + escapeHtml(run.target || run.asset) + '</small></div><div>' + statusBadge(run.status) + '</div><button class="text-button" data-report="' + escapeHtml(run.id) + '" aria-label="Open assessment evidence">View ↗</button></div>').join("") || '<div class="empty-compact">No assessments yet. Your first run will appear here.</div>';
    $("#reportList").innerHTML = state.reports.map((run) => '<article class="report-card"><div><h3>' + escapeHtml(reportLabel(run)) + '</h3><p>' + escapeHtml(run.target || run.asset) + '</p><small>' + escapeHtml(new Date(run.created_at).toLocaleString()) + ' · ' + escapeHtml(run.id) + '</small></div>' + statusBadge(run.status) + '<button class="secondary-button" data-report="' + escapeHtml(run.id) + '">View evidence →</button>' + (run.exercise_id ? '<a class="text-button" href="/api/lab/exercises/' + encodeURIComponent(run.id) + '/report?format=md">Markdown ↓</a>' : '<button class="text-button" data-delete-report="' + escapeHtml(run.id) + '">Delete ✕</button>') + '</article>').join("") || '<article class="panel empty-state"><strong>Your evidence starts here.</strong><p>Run an assessment or lab exercise to create the first report. No sample results are presented as live data.</p></article>';
  } catch (error) {
    $("#recentRuns").innerHTML = '<div class="empty-compact">History unavailable. Check the agent connection.</div>';
    $("#reportList").textContent = "Could not load history: " + error.message;
    if (!silent) showToast(error.message, true);
  }
}
function openReport(id) {
  const run = state.reports.find((item) => item.id === id);
  if (!run) return;
  state.selectedReport = run; state.narrative = null;
  $("#narrativeBlock").classList.add("hidden");
  showView("reports");
  $("#reportDetail").classList.remove("hidden");
  $("#reportDetailJson").textContent = JSON.stringify(run, null, 2);
  $("#reportDetail").scrollIntoView({ behavior: "smooth", block: "start" });
}
async function loadTelemetry() {
  try {
    const data = await api("/api/lab/telemetry/status");
    $("#overviewTelemetry").textContent = data.configured ? String(data.state).replaceAll("_", " ") : "Not configured";
    $("#telemetryDescription").textContent = data.configured ? data.endpoint + " · " + data.state + ". HEC delivery is not proof an alert fired." : "Optional. Set HANZO_SPLUNK_HEC_URL and HANZO_SPLUNK_HEC_TOKEN on Kali. Local evidence works without Splunk.";
    $("#testTelemetry").disabled = !data.configured;
  } catch (error) { $("#telemetryDescription").textContent = error.message; $("#overviewTelemetry").textContent = "Unavailable"; }
}
async function loadExercises() {
  try {
    const data = await api("/api/lab/exercises");
    state.exercises = data.exercises || [];
    $("#exerciseTarget").value = data.configured_target;
    $("#companionLink").href = data.configured_target;
    const selection = $("#exerciseSelect").value;
    $("#exerciseSelect").innerHTML = state.exercises.map((item) => '<option value="' + escapeHtml(item.id) + '">' + escapeHtml(item.name) + '</option>').join("");
    if (state.exercises.some((item) => item.id === selection)) $("#exerciseSelect").value = selection;
    describeExercise(); loadTelemetry();
  } catch (error) { $("#exerciseDescription").textContent = error.message; showToast(error.message, true); }
}
function describeExercise() {
  const item = state.exercises.find((item) => item.id === $("#exerciseSelect").value);
  $("#exerciseDescription").innerHTML = item ? escapeHtml(item.description) + '<small>' + escapeHtml(item.request_count) + ' exercise requests + one identity check · ' + escapeHtml((item.expected_events || []).join(", ")) + '</small>' : "";
}
async function runLabExercise() {
  if (!$("#exerciseAuthorization").checked) return showToast("Confirm lab authorization first", true);
  $("#runExercise").disabled = true; $("#exerciseStatus").textContent = "RUNNING";
  $("#exerciseResult").className = "loading-state"; $("#exerciseResult").textContent = "Calling your configured lab companion…";
  try {
    const run = await api("/api/lab/exercises/run", { method: "POST", body: JSON.stringify({exercise_id: $("#exerciseSelect").value, target: $("#exerciseTarget").value, authorization_confirmed: true}) });
    state.result = run;
    $("#exerciseStatus").textContent = run.status.replaceAll("_", " ").toUpperCase();
    $("#exerciseResult").className = "";
    $("#exerciseResult").innerHTML = (run.error ? '<p class="bad">' + escapeHtml(run.error) + '</p>' : '') +
      (run.checks || []).map((check) => '<div class="evidence-check"><strong>' + escapeHtml(check.name) + '<span class="' + (check.passed ? 'good' : 'bad') + '">' + (check.passed ? 'Observed' : 'Review') + '</span></strong><p>Expected event: ' + escapeHtml(check.expected_events.join(", ")) + '</p></div>').join("") +
      '<p class="correlation">' + escapeHtml(run.correlation_id) + '</p><pre>' + escapeHtml(run.splunk_query) + '</pre><p class="form-note">HEC: ' + escapeHtml(run.telemetry.status) + '. Exercise completion describes the expected training behavior, not a secure target. Verify indexing and detection in Splunk.</p><a class="text-button" href="/api/lab/exercises/' + encodeURIComponent(run.id) + '/report?format=md">Download Markdown report ↓</a>';
    loadReports(true); loadTelemetry();
    showToast("Lab exercise: " + run.status, run.status !== "completed");
  } catch (error) { $("#exerciseStatus").textContent = "FAILED"; $("#exerciseResult").className = "empty-state"; $("#exerciseResult").textContent = error.message; showToast(error.message, true); }
  finally { $("#runExercise").disabled = false; }
}
async function testLlm() {
  const button = $("#testLlm"); button.disabled = true;
  const version = state.llmConfigVersion;
  $("#llmTestResult").textContent = "Testing a real model response…";
  const body = { message: "Connectivity check. Reply with HANZO READY.", provider: $("#llmProvider").value, model: $("#llmModel").value.trim() };
  if (body.provider !== "ollama") body.api_key = $("#llmApiKey").value;
  if (body.provider === "compatible") body.base_url = $("#llmBaseUrl").value.trim();
  try {
    const data = await api("/api/llm/chat", {method:"POST", body:JSON.stringify(body)});
    if (!String(data.reply || "").trim()) throw new Error("The selected AI provider returned an empty response");
    if (state.llmConfigVersion !== version) return;
    state.verifiedLlm = { version, model: data.model, provider: body.provider };
    $("#llmTestResult").textContent = "Connected · " + data.model + " · " + data.reply;
    $("#llmStatus").textContent = data.model + " · response verified"; $("#llmDot").className = "online";
    showToast("Model response verified");
  } catch (error) {
    if (state.llmConfigVersion !== version) return;
    state.verifiedLlm = null;
    $("#llmTestResult").textContent = error.message; $("#llmDot").className = "offline"; $("#llmStatus").textContent = "Connection test failed";
  }
  finally { button.disabled = false; }
}
if (typeof document !== "undefined") {
$("#quickForm").addEventListener("submit", (event) => { event.preventDefault(); $("#target").value = $("#quickTarget").value.trim(); updateWorkflowAuthorization(); showView("assessment"); $("#target").focus(); });
$(".brand").addEventListener("click", (event) => { event.preventDefault(); showView("overview"); });
$("#checkTarget").addEventListener("click", () => checkTargetReadiness());
async function checkTargetReadiness() {
  const target = $("#target").value.trim();
  const note = $("#preflightResult");
  if (!target) { note.textContent = "Enter a target first."; return; }
  const button = $("#checkTarget");
  button.disabled = true;
  note.textContent = "Checking the target and this worker's adapters…";
  try {
    const data = await api("/api/assessment/preflight", { method: "POST", body: JSON.stringify({ target, stage: $("#workflowPhase").value }) });
    const parts = [];
    parts.push(data.valid ? `Accepted as ${data.kind}.` : `Rejected: ${data.error}`);
    if (data.reachability && data.reachability.checked) parts.push(data.reachability.detail);
    if (data.readiness && data.readiness.applicable) {
      parts.push(data.readiness.detail);
      if (data.readiness.ready.length) parts.push(`Installed for this stage: ${data.readiness.ready.join(", ")}.`);
      if (data.readiness.missing.length) parts.push(`Not installed: ${data.readiness.missing.join(", ")}.`);
    } else if (data.readiness) { parts.push(data.readiness.detail); }
    parts.push(data.ready_to_run ? "Pre-flight passed; reachability is not a guarantee a scanner will succeed." : `Blocked: ${data.message}`);
    note.textContent = parts.join(" ");
  } catch (error) { note.textContent = `Pre-flight failed: ${error.message}`; }
  finally { button.disabled = false; }
}
$("#refreshReports").addEventListener("click", () => loadReports());
$("#reportPurge").addEventListener("click", () => purgeReports());
$("#refreshStats")?.addEventListener("click", () => loadSystemStats(false));
$("#writeNarrative").addEventListener("click", () => writeNarrative());
$("#downloadNarrative").addEventListener("click", () => downloadNarrative());
/* Findings are extracted by the worker; the model only narrates them. Both the
   prose and the facts it was given are shown, so a reader can check it. */
async function writeNarrative() {
  const run = state.selectedReport;
  if (!run) return showToast("Open a report first", true);
  const button = $("#writeNarrative");
  const block = $("#narrativeBlock");
  button.disabled = true;
  block.classList.remove("hidden");
  $("#narrativeStatus").textContent = "Extracting findings, then asking the local model to write them up…";
  $("#narrativeText").textContent = "";
  $("#narrativeFindings").innerHTML = "";
  try {
    const data = await api("/api/reports/narrative", { method: "POST", body: JSON.stringify({ run_id: run.id }) });
    state.narrative = data;
    const counts = data.counts || {};
    const sources = Object.entries(counts.by_source || {}).map(([k, v]) => `${v} from ${k}`).join(", ");
    $("#narrativeStatus").textContent = [
      data.message || "",
      `${counts.total ?? 0} observation(s)${sources ? ` (${sources})` : ""}, ${counts.noteworthy ?? 0} noteworthy.`,
      data.model ? `Written by ${data.model} running locally.` : "",
    ].filter(Boolean).join(" ");
    $("#narrativeText").textContent = data.narrative || "";
    if ((data.unverified_paths || []).length) {
      const warning = document.createElement("p");
      warning.className = "narrative-warning";
      warning.textContent = `Not supported by the findings: ${data.unverified_paths.join(", ")}`;
      $("#narrativeText").append(warning);
    }
    $("#narrativeFindings").innerHTML = (data.findings || []).map((item) => `
      <div class="finding-row">
        <code>${escapeHtml(item.path)}</code>
        <span>${item.status === null || item.status === undefined ? "—" : escapeHtml(String(item.status))}</span>
        <span>${item.size === null || item.size === undefined ? "" : escapeHtml(String(item.size)) + " B"}</span>
        <small>${escapeHtml(item.note || item.evidence || "")}</small>
        <em>${escapeHtml(item.source || "")}</em>
      </div>`).join("") || '<div class="empty-compact">No findings were extracted from this run.</div>';
    $("#downloadNarrative").disabled = !data.narrative && !(data.findings || []).length;
  } catch (error) {
    $("#narrativeStatus").textContent = `Could not write the report: ${error.message}`;
  } finally { button.disabled = false; }
}
function downloadNarrative() {
  const data = state.narrative;
  if (!data) return;
  // A cell value may contain "|" (httpx prints pipe-separated evidence) or a
  // newline; either would break the table, so escape both.
  const cell = (value) => String(value ?? "").replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ").trim();
  const rows = (data.findings || []).map((item) => {
    const detail = [item.note, item.evidence, item.redirect ? `redirects to ${item.redirect}` : ""]
      .filter(Boolean).join("; ");
    return `| \`${cell(item.path)}\` | ${item.status ?? "—"} | ${item.size ?? ""} | ${cell(detail)} | ${cell(item.source)} |`;
  }).join("\n");
  const markdown = [
    `# Findings — ${data.asset || ""}`,
    "", `Stage: ${data.phase_label || data.phase || ""}`,
    `Report ID: ${data.run_id}`,
    data.model ? `Narrative written locally by ${data.model} from the extracted findings below.` : "",
    "", "## Summary", "", data.narrative || "_No narrative was generated._",
    "", "## Observations", "",
    "| Path | Status | Size | Note | Found by |", "| --- | --- | --- | --- | --- |", rows,
    "", "## Tools that ran", "",
    ...(data.tools || []).map((t) => `- ${t.tool} (exit ${t.return_code}): ${t.findings} result(s)`),
    "", "_Observations are parsed from real tool output. A listed path is what the tool reported; it is not by itself proof of a vulnerability._",
  ].filter((line) => line !== undefined).join("\n");
  const blob = new Blob([markdown], { type: "text/markdown" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `hanzo-findings-${data.run_id}.md`;
  link.click();
  URL.revokeObjectURL(link.href);
}
document.addEventListener("click", (event) => { const button = event.target.closest("[data-report]"); if (button) openReport(button.dataset.report); });
document.addEventListener("click", (event) => { const button = event.target.closest("[data-delete-report]"); if (button) deleteReport(button.dataset.deleteReport, button); });
async function deleteReport(id, button) {
  const run = state.reports.find((item) => item.id === id);
  const label = run ? reportLabel(run) + " · " + (run.target || run.asset || id) : id;
  if (!window.confirm("Permanently delete this report?\n\n" + label + "\n\nThis cannot be undone.")) return;
  if (button) button.disabled = true;
  try {
    await api("/api/redteam/workflows/" + encodeURIComponent(id), { method: "DELETE" });
    if (state.selectedReport && state.selectedReport.id === id) { state.selectedReport = null; $("#reportDetail").classList.add("hidden"); }
    showToast("Report deleted.");
    await loadReports(true);
  } catch (error) { showToast(error.message, true); if (button) button.disabled = false; }
}
async function purgeReports() {
  const keepField = $("#reportKeepLatest");
  const keep = Math.max(0, Number(keepField && keepField.value) || 0);
  const deletable = state.reports.filter((run) => !run.exercise_id).length;
  if (!deletable) { showToast("There are no stored reports to delete.", true); return; }
  const removing = Math.max(0, deletable - keep);
  if (!removing) { showToast("Nothing to delete: the retention count covers every stored report."); return; }
  if (!window.confirm("Permanently delete " + removing + " of " + deletable + " stored report(s), keeping the newest " + keep + "?\n\nThis cannot be undone.")) return;
  const button = $("#reportPurge");
  if (button) button.disabled = true;
  try {
    const result = await api("/api/redteam/workflows/purge", { method: "POST", body: JSON.stringify({ keep_latest: keep }) });
    showToast(result.message || "Reports deleted.");
    await loadReports(true);
  } catch (error) { showToast(error.message, true); }
  finally { if (button) button.disabled = false; }
}
$("#downloadReport").addEventListener("click", () => { if (state.selectedReport) downloadJson(state.selectedReport, "hanzo-" + state.selectedReport.id + ".json"); });
$("#exerciseSelect").addEventListener("change", describeExercise);
$("#exerciseForm").addEventListener("submit", (event) => { event.preventDefault(); runLabExercise(); });
$("#testLlm").addEventListener("click", testLlm);
$("#testTelemetry").addEventListener("click", async () => {
  $("#testTelemetry").disabled = true;
  try { const data = await api("/api/lab/telemetry/test", {method:"POST", body:"{}"}); showToast("HEC accepted probe: " + data.correlation_id); }
  catch (error) { showToast(error.message, true); }
  finally { loadTelemetry(); }
});
/* The stage menu is built from the worker's catalog so the console, the
   pre-flight check and the evidence store cannot drift apart. */
async function loadStages() {
  const select = $("#workflowPhase");
  if (!select) return;
  const previous = select.value;
  try {
    const data = await api("/api/assessment/stages");
    stageCatalog.groups = data.groups || [];
    stageCatalog.byId = new Map();
    activeWorkflowPhases.clear();
    const fragment = document.createDocumentFragment();
    stageCatalog.groups.forEach((group) => {
      const optgroup = document.createElement("optgroup");
      optgroup.label = group.label;
      (group.stages || []).forEach((stage) => {
        stageCatalog.byId.set(stage.id, stage);
        if (stage.executes) activeWorkflowPhases.add(stage.id);
        const option = document.createElement("option");
        option.value = stage.id;
        const ready = stage.readiness || {};
        option.textContent = ready.applicable
          ? `${stage.label} (${ready.ready.length}/${ready.ready.length + ready.missing.length} ready)`
          : stage.label;
        if (ready.applicable && !ready.ready.length) option.dataset.unavailable = "true";
        optgroup.append(option);
      });
      fragment.append(optgroup);
    });
    select.replaceChildren(fragment);
    select.value = stageCatalog.byId.has(previous) ? previous : "profile";
    describeStage();
  } catch (error) {
    $("#preflightResult").textContent = `Stage catalog unavailable: ${error.message}. The listed stages may be incomplete.`;
  }
}
function describeStage() {
  const stage = stageCatalog.byId.get($("#workflowPhase").value);
  const note = $("#stageDescription");
  if (!note) return;
  if (!stage) { note.textContent = ""; return; }
  const ready = stage.readiness || {};
  const parts = [stage.description];
  if (!stage.executes) parts.push("Non-executing: no scanner is launched and no authorization is needed.");
  else if (ready.applicable) {
    parts.push(ready.detail);
    if (ready.ready.length) parts.push(`Installed: ${ready.ready.join(", ")}.`);
    if (ready.missing.length) parts.push(`Not installed: ${ready.missing.join(", ")}.`);
  }
  note.textContent = parts.join(" ");
}
$("#workflowPhase").addEventListener("change", describeStage);
window.addEventListener("hashchange", () => showView(location.hash.slice(1)));
loadStages();
loadReports(true);
loadTelemetry();
}

// Dependency-free regression tests import the same code used by the browser.
if (typeof module !== "undefined" && module.exports) {
  module.exports = { state, api, adapterOutcome, workflowInputError, workflowRequiresAuthorization, selectedModelAvailable, runAutomatedWorkflow, loadLlmStatus, invalidateLlmVerification, testLlm };
}
