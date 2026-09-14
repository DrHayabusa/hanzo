/* Only trusted, server-configured MCP connections are selectable here. */
(() => {
  const host = document.getElementById("integrations");
  if (!host) return;
  const panel = document.createElement("article");
  panel.className = "panel optional-mcp-panel";
  panel.innerHTML = `<div class="panel-head"><div><span class="section-index">EXTERNAL MCP BRIDGE</span><h3>Your MCP servers</h3></div><button id="optionalRefresh" class="secondary-button">Refresh inventory</button></div>
    <p class="section-explainer">Connect trusted stdio, SSE, or Streamable HTTP servers through your private <code>HANZO_MCP_CONFIG</code> file. Discovery is separate from permission to execute: only exact server-side allowlisted tools can run.</p>
    <p id="optionalMessage" class="form-note" role="status">Loading configuration…</p>
    <div class="assessment-grid"><form id="optionalForm" class="scan-form">
      <label for="optionalServer">MCP server</label><select id="optionalServer"></select>
      <button id="optionalProbe" type="button" class="secondary-button">Connect &amp; discover tools ↗</button>
      <label for="optionalTool">Allowlisted tool</label><select id="optionalTool"></select>
      <p id="optionalDescription" class="form-note"></p>
      <details><summary>Tool input schema</summary><pre id="optionalSchema">{}</pre></details>
      <label for="optionalArguments">Arguments (JSON object)</label><textarea id="optionalArguments" rows="5" spellcheck="false">{}</textarea>
      <label class="check-row"><input id="optionalConfirm" type="checkbox" required><span>I reviewed these arguments and authorize this tool on my lab assets.</span></label>
      <button id="optionalRun" class="primary-button" type="submit">Run selected MCP tool →</button>
    </form><div><h3>Protocol &amp; execution evidence</h3><pre id="optionalResult">No connection attempted. Your lab services are not probed automatically.</pre></div></div>`;
  host.appendChild(panel);
  const el = (id) => document.getElementById(id);
  let servers = [], busy = false;
  const current = () => servers.find((server) => server.id === el("optionalServer").value);
  const output = (value) => { el("optionalResult").textContent = JSON.stringify(value, null, 2).slice(0, 270000); };
  const options = (select, entries, empty) => {
    select.replaceChildren();
    for (const [value, label] of entries.length ? entries : [["", empty]]) {
      const option = document.createElement("option"); option.value = value; option.textContent = label; select.appendChild(option);
    }
  };
  const detail = () => {
    const tool = (current()?.tool_details || []).find((item) => item.name === el("optionalTool").value);
    el("optionalDescription").textContent = tool?.description || "Probe this server to discover its tools and input schemas.";
    el("optionalSchema").textContent = JSON.stringify(tool?.inputSchema || {}, null, 2);
    el("optionalConfirm").checked = false;
    el("optionalRun").disabled = busy || !tool;
  };
  const selectServer = () => {
    const server = current();
    const allowed = (server?.tool_details || []).filter((tool) => tool.allowlisted);
    options(el("optionalTool"), allowed.map((tool) => [tool.name, tool.name]), "No discovered allowlisted tools");
    el("optionalProbe").disabled = busy || !server;
    el("optionalMessage").textContent = server ? `${server.name}: ${server.status} — ${server.message || "Not yet checked"}` : "No optional servers configured. Follow docs/OPTIONAL_MCP.md; core CVE and BugHunter remain available above.";
    el("optionalArguments").value = "{}"; detail();
  };
  const refresh = async () => {
    try {
      const data = await api("/api/mcp/optional"); servers = data.servers || [];
      options(el("optionalServer"), servers.map((server) => [server.id, `${server.name} · ${server.transport}`]), "No servers configured");
      selectServer();
    } catch (error) { el("optionalMessage").textContent = error.message; }
  };
  el("optionalRefresh").addEventListener("click", refresh);
  el("optionalServer").addEventListener("change", selectServer);
  el("optionalTool").addEventListener("change", () => { el("optionalArguments").value = "{}"; detail(); });
  el("optionalArguments").addEventListener("input", () => { el("optionalConfirm").checked = false; });
  el("optionalProbe").addEventListener("click", async () => {
    if (busy || !current()) return;
    const id = current().id; busy = true; el("optionalProbe").disabled = true;
    try {
      const result = await api(`/api/mcp/optional/${encodeURIComponent(id)}/probe`, {method:"POST", body:JSON.stringify({})});
      servers = servers.map((server) => server.id === id ? result : server); output(result);
    } catch (error) { output({error:error.message}); }
    finally { busy = false; selectServer(); }
  });
  el("optionalForm").addEventListener("submit", async (event) => {
    event.preventDefault(); if (busy || !current() || !el("optionalConfirm").checked || !el("optionalTool").value) return;
    let args;
    try { args = JSON.parse(el("optionalArguments").value); if (!args || Array.isArray(args) || typeof args !== "object") throw new Error("Arguments must be a JSON object"); }
    catch (error) { output({error:error.message}); return; }
    busy = true; el("optionalRun").disabled = true;
    try {
      const result = await api(`/api/mcp/optional/${encodeURIComponent(current().id)}/call`, {method:"POST", body:JSON.stringify({tool:el("optionalTool").value, arguments:args, authorization_confirmed:true})});
      output(result); showToast(result.success ? "MCP tool returned — review evidence" : "MCP tool reported failure");
    } catch (error) { output({error:error.message, result:error.data || error.result || error.payload}); }
    finally { busy = false; detail(); }
  });
  refresh();
})();
