/* A schema-driven launcher for the worker's existing HexStrike tool routes. */
(function (global) {
  "use strict";
  const DISPLAY_LIMIT = 120000;
  const validEndpoint = (value) => /^\/api\/tools\/[A-Za-z0-9_/-]+$/.test(String(value || ""));
  const failedResponse = (value) => Boolean(value && (value.success === false || value.isError === true || value.error || ["failed", "error"].includes(value.status)));
  const fieldType = (field) => String(field.type || "str").toLowerCase();
  const isBoolean = (field) => ["bool", "boolean"].includes(fieldType(field));
  const isJson = (field) => ["object", "array", "json", "dict", "list"].includes(fieldType(field));
  /* Fields that name a file of terms: offer the lists this worker really has. */
  const isWordlist = (field) => !isBoolean(field) && !isJson(field) && /wordlist|word_list|userlist|passlist/i.test(String(field.name || ""));
  const WORDLIST_OPTION_LIMIT = 500;
  const baseName = (value) => String(value || "").split("/").pop().toLowerCase();
  const readable = (bytes) => (bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`);
  const readinessMark = (command) => (command.installed === false ? " · not installed"
    : command.installed === true ? " · ready" : " · runtime check");

  function fieldValue(field, input) {
    if (isBoolean(field)) return Boolean(input.checked);
    const raw = String(input.value ?? "");
    if (!raw.trim()) {
      if (field.required) throw new Error(`${field.name} is required`);
      return undefined;
    }
    if (["int", "integer", "number", "float"].includes(fieldType(field))) {
      const value = Number(raw);
      if (!Number.isFinite(value) || (["int", "integer"].includes(fieldType(field)) && !Number.isInteger(value))) throw new Error(`${field.name} must be a valid ${fieldType(field)}`);
      if (field.minimum !== undefined && value < field.minimum) throw new Error(`${field.name} must be at least ${field.minimum}`);
      if (field.maximum !== undefined && value > field.maximum) throw new Error(`${field.name} must be at most ${field.maximum}`);
      return value;
    }
    if (isJson(field)) {
      let value;
      try { value = JSON.parse(raw); } catch { throw new Error(`${field.name} must contain valid JSON`); }
      if (["object", "dict"].includes(fieldType(field)) && (!value || typeof value !== "object" || Array.isArray(value))) throw new Error(`${field.name} must be a JSON object`);
      if (["array", "list"].includes(fieldType(field)) && !Array.isArray(value)) throw new Error(`${field.name} must be a JSON array`);
      return value;
    }
    return raw;
  }

  function buildPayload(fields, inputs) {
    const result = Object.create(null);
    fields.forEach((field, index) => {
      if (!field.name || ["__proto__", "constructor", "prototype", "authorization_confirmed"].includes(field.name)) return;
      const value = fieldValue(field, inputs[index]);
      if (value !== undefined) result[field.name] = value;
    });
    result.authorization_confirmed = true;
    return result;
  }

  async function request(fetcher, path, options = {}) {
    const response = await fetcher(path, { ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
    const raw = await response.text();
    let data;
    try { data = JSON.parse(raw); }
    catch {
      const error = new Error(`Worker returned non-JSON output (HTTP ${response.status})`);
      error.data = { raw_response: raw }; throw error;
    }
    if (!response.ok || failedResponse(data)) {
      const error = new Error(data?.error || data?.message || `Tool request failed (HTTP ${response.status})`);
      error.data = data; throw error;
    }
    return data;
  }

  class ArsenalLauncher {
    constructor(doc, fetcher) {
      this.doc = doc; this.fetcher = fetcher; this.categories = []; this.fields = []; this.inputs = [];
      this.command = null; this.busy = false; this.lastResult = null; this.nodes = {};
      this.wordlists = []; this.wordlistCatalog = null;
    }
    /* Wordlists are ranked so the closest match to the adapter default comes first. */
    wordlistChoices(field) {
      const wanted = baseName(field.default);
      const groups = { wordlist: "web", userlist: "usernames", passlist: "passwords" };
      const key = Object.keys(groups).find((name) => String(field.name || "").toLowerCase().includes(name));
      const preferred = key ? groups[key] : "web";
      const score = (item) => (baseName(item.path) === wanted ? 0 : item.group === preferred ? 1 : 2);
      return this.wordlists.slice().sort((a, b) => score(a) - score(b) || a.path.localeCompare(b.path)).slice(0, WORDLIST_OPTION_LIMIT);
    }
    knownWordlist(value) {
      return Boolean(value) && this.wordlists.some((item) => item.path === value);
    }
    element(tag, text, id, className) {
      const element = this.doc.createElement(tag);
      if (text !== undefined) element.textContent = text;
      if (id) { element.id = id; this.nodes[id] = element; }
      if (className) element.className = className;
      return element;
    }
    label(text, input) {
      const label = this.element("label", text); label.htmlFor = input.id; label.append(input); return label;
    }
    mount() {
      const matrix = this.doc.querySelector("#toolMatrix");
      if (!matrix || this.doc.querySelector("#arsenalLauncher")) return;
      const panel = this.element("article", undefined, "arsenalLauncher", "panel scan-form");
      panel.style.marginBottom = "22px";
      const heading = this.element("div", undefined, undefined, "panel-head");
      heading.append(this.element("h3", "HexStrike command launcher"));
      const reload = this.element("button", "Refresh catalog ↻", "arsenalRefresh", "text-button");
      reload.type = "button"; reload.addEventListener("click", () => this.load()); heading.append(reload); panel.append(heading);
      panel.append(this.element("p", "Every adapter this worker exposes is in one list, grouped by category. Filter by name, category or description, review the arguments, then confirm your authorized scope. These are the worker’s real API routes; an executable that is absent is not marked ready.", undefined, "form-note"));
      const form = this.element("form", undefined, "arsenalForm");
      const search = this.element("input", undefined, "arsenalSearch");
      search.type = "search"; search.placeholder = "Filter tools by name, category or description";
      search.autocomplete = "off";
      form.append(this.label("Find a tool", search));
      const row = this.element("div", undefined, undefined, "form-row");
      const category = this.element("select", undefined, "arsenalCategory");
      const command = this.element("select", undefined, "arsenalCommand");
      row.append(this.label("Category", category), this.label("Tool", command)); form.append(row);
      search.addEventListener("input", () => this.selectCategory());
      form.append(this.element("p", "Loading the worker catalog…", "arsenalDescription", "form-note"));
      form.append(this.element("p", "", "arsenalReadiness", "form-note"));
      form.append(this.element("div", undefined, "arsenalFields", "provider-form"));
      form.append(this.element("h4", "Review the exact request"));
      const preview = this.element("pre", "Select a command.", "arsenalPreview");
      preview.style.whiteSpace = "pre-wrap"; preview.style.overflowWrap = "anywhere"; preview.style.maxHeight = "280px"; preview.style.overflow = "auto";
      form.append(preview);
      const checkbox = this.element("input", undefined, "arsenalAuthorization"); checkbox.type = "checkbox";
      const confirmation = this.element("label", undefined, undefined, "check-row");
      confirmation.append(checkbox, this.element("span", "I reviewed the target, scope, and arguments above. I own or am explicitly authorized to test these assets and accept the effects of this command.")); form.append(confirmation);
      const run = this.element("button", "Run selected command →", "arsenalRun", "primary-button"); run.type = "submit"; run.disabled = true; form.append(run);
      const jobs = this.element("a", "Monitor or stop scanner processes in Running jobs ↗", undefined, "text-button"); jobs.href = "#activity"; form.append(jobs);
      const status = this.element("p", "No command executed.", "arsenalStatus", "form-note"); status.setAttribute("role", "status"); form.append(status);
      const output = this.element("pre", "", "arsenalResult"); output.style.whiteSpace = "pre-wrap"; output.style.overflowWrap = "anywhere"; output.style.maxHeight = "500px"; output.style.overflow = "auto"; form.append(output);
      const download = this.element("button", "Download command evidence ↓", "arsenalDownload", "text-button"); download.type = "button"; download.disabled = true; form.append(download);
      category.addEventListener("change", () => this.selectCategory()); command.addEventListener("change", () => this.selectCommand());
      checkbox.addEventListener("change", () => this.updateRunButton());
      form.addEventListener("submit", (event) => { event.preventDefault(); this.execute(); });
      download.addEventListener("click", () => this.download());
      panel.append(form); matrix.before(panel); this.load();
    }
    async load() {
      if (this.busy) return;
      this.nodes.arsenalRefresh.disabled = true; this.nodes.arsenalRun.disabled = true;
      this.nodes.arsenalAuthorization.checked = false;
      try {
        const catalog = await request(this.fetcher, "/api/arsenal/catalog");
        this.categories = (catalog.categories || []).filter((category) => Array.isArray(category.commands));
        await this.loadWordlists();
        this.nodes.arsenalCategory.replaceChildren();
        const total = this.categories.reduce((sum, item) => sum + item.commands.length, 0);
        const readyTotal = this.categories.reduce((sum, item) => sum + item.commands.filter((c) => c.installed === true).length, 0);
        const every = this.element("option", `All categories (${readyTotal}/${total} ready)`);
        every.value = "__all__"; this.nodes.arsenalCategory.append(every);
        this.categories.forEach((category) => {
          const ready = category.commands.filter((command) => command.installed === true).length;
          const option = this.element("option", `${category.label || category.id} (${ready}/${category.commands.length} ready)`); option.value = category.id; this.nodes.arsenalCategory.append(option);
        });
        this.nodes.arsenalCategory.value = "__all__";
        this.selectCategory();
      } catch (error) {
        this.command = null; this.nodes.arsenalDescription.textContent = `Catalog unavailable: ${error.message}`; this.nodes.arsenalStatus.textContent = "No command executed. Refresh the catalog after restoring the worker.";
      } finally { this.nodes.arsenalRefresh.disabled = false; }
    }
    /* A missing wordlist catalog must never block the launcher; the field stays free text. */
    async loadWordlists() {
      try {
        const catalog = await request(this.fetcher, "/api/arsenal/wordlists");
        this.wordlistCatalog = catalog;
        this.wordlists = (catalog.groups || []).flatMap((group) => (group.wordlists || [])
          .map((item) => ({ ...item, group: group.id, groupLabel: group.label })));
      } catch { this.wordlistCatalog = null; this.wordlists = []; }
    }
    /* One dropdown reaches every adapter: categories become option groups, and
       the filter narrows by name, category or description. */
    visibleCategories() {
      const selected = this.nodes.arsenalCategory.value;
      const needle = String(this.nodes.arsenalSearch?.value || "").trim().toLowerCase();
      const chosen = selected === "__all__" ? this.categories
        : this.categories.filter((item) => item.id === selected);
      if (!needle) return chosen.map((item) => ({ ...item, commands: item.commands.slice() }));
      return chosen
        .map((item) => ({
          ...item,
          commands: item.commands.filter((command) => [command.id, command.label, command.tool,
            command.description, item.label, item.id]
            .some((value) => String(value || "").toLowerCase().includes(needle))),
        }))
        .filter((item) => item.commands.length);
    }
    selectCategory() {
      const previous = this.nodes.arsenalCommand.value;
      const groups = this.visibleCategories();
      this.nodes.arsenalCommand.replaceChildren();
      let flat = [];
      groups.forEach((category) => {
        const optgroup = this.doc.createElement("optgroup");
        const ready = category.commands.filter((command) => command.installed === true).length;
        optgroup.label = `${category.label || category.id} — ${ready}/${category.commands.length} ready`;
        category.commands.forEach((command) => {
          const option = this.element("option", `${command.label || command.id}${readinessMark(command)}`);
          option.value = command.id; optgroup.append(option); flat.push(command);
        });
        this.nodes.arsenalCommand.append(optgroup);
      });
      this.nodes.arsenalCommand.disabled = flat.length === 0;
      if (!flat.length) {
        const none = this.element("option", "No tool matches this filter"); none.value = "";
        this.nodes.arsenalCommand.append(none);
      } else if (flat.some((command) => command.id === previous)) {
        this.nodes.arsenalCommand.value = previous;
      } else {
        const runnable = flat.find((command) => command.installed === true) || flat[0];
        this.nodes.arsenalCommand.value = runnable.id;
      }
      this.selectCommand();
    }
    selectCommand() {
      const wanted = this.nodes.arsenalCommand.value;
      this.command = this.categories.flatMap((item) => item.commands).find((item) => item.id === wanted) || null;
      this.fields = this.command?.fields || []; this.inputs = [];
      this.nodes.arsenalFields.replaceChildren();
      this.nodes.arsenalDescription.textContent = this.command?.description || (this.command ? this.command.endpoint : "No commands registered.");
      this.nodes.arsenalReadiness.textContent = !this.command ? "" : this.command.installed === false ? `${this.command.tool || this.command.label} is not installed on this worker. Install its dependencies on Kali, then refresh.` : this.command.installed === true ? "Executable detected. Review required credentials and arguments; detection is not a full functional test." : "Runtime readiness is not verified. Review the command and worker setup before execution.";
      this.fields.forEach((field, index) => {
        const input = this.element(isJson(field) ? "textarea" : "input", undefined, `arsenalField${index}`);
        if (isBoolean(field)) { input.type = "checkbox"; input.checked = field.default === true; }
        else {
          input.type = ["int", "integer", "number", "float"].includes(fieldType(field)) ? "number" : "text";
          if (input.type === "number") input.step = ["int", "integer"].includes(fieldType(field)) ? "1" : "any";
          input.value = field.default == null ? "" : (isJson(field) && typeof field.default !== "string" ? JSON.stringify(field.default, null, 2) : String(field.default));
          input.required = Boolean(field.required); input.autocomplete = "off";
        }
        const label = this.label(`${field.name}${field.required ? " (required)" : ""} · ${field.type || "text"}`, input);
        if (isBoolean(field)) label.className = "check-row";
        if (isWordlist(field)) this.attachWordlists(field, input, label, index);
        input.addEventListener("input", () => this.updatePreview()); input.addEventListener("change", () => this.updatePreview());
        this.inputs.push(input); this.nodes.arsenalFields.append(label);
      });
      this.updatePreview();
    }
    /* Offer the lists that exist, keep any custom path typable, and never leave a
       default pointing at a file this worker does not have. */
    attachWordlists(field, input, label, index) {
      const note = this.element("p", "", undefined, "form-note");
      if (!this.wordlists.length) {
        note.textContent = this.wordlistCatalog
          ? "No wordlist found on this worker. Install one (bash scripts/install_wordlists.sh) or type an absolute path; the adapter default may not exist here."
          : "Wordlist catalog unavailable. Type an absolute path to a wordlist on the worker.";
        label.append(note);
        return;
      }
      const listId = `arsenalWordlistOptions${index}`;
      const datalist = this.element("datalist");
      datalist.id = listId;
      this.wordlistChoices(field).forEach((item) => {
        const option = this.element("option");
        option.value = item.path;
        option.label = `${item.name} · ${item.groupLabel} · ${readable(item.bytes)}`;
        datalist.append(option);
      });
      if (input.setAttribute) input.setAttribute("list", listId);
      const original = input.value;
      if (!this.knownWordlist(original)) {
        const replacement = this.wordlistChoices(field)[0];
        if (replacement) {
          input.value = replacement.path;
          note.textContent = original
            ? `The adapter default ${original} is not present on this worker. HANZO selected ${replacement.name}; pick another from the list or type any path.`
            : `Choose one of ${this.wordlists.length} discovered wordlists, or type any path on the worker.`;
        }
      } else {
        note.textContent = `Selected from ${this.wordlists.length} discovered wordlists. You can also type any path on the worker.`;
      }
      label.append(datalist, note);
    }
    updatePreview() {
      this.nodes.arsenalAuthorization.checked = false;
      try {
        if (!this.command || !validEndpoint(this.command.endpoint)) throw new Error("Select a valid catalog command.");
        this.payload = buildPayload(this.fields, this.inputs); this.inputError = null;
        this.nodes.arsenalPreview.textContent = `POST ${this.command.endpoint}\n${JSON.stringify(this.payload, null, 2)}`;
      } catch (error) { this.payload = null; this.inputError = error.message; this.nodes.arsenalPreview.textContent = error.message; }
      this.updateRunButton();
    }
    updateRunButton() {
      this.nodes.arsenalRun.disabled = this.busy || !this.command || this.command.installed === false || !this.payload || !this.nodes.arsenalAuthorization.checked;
    }
    async execute() {
      if (this.busy) return;
      if (!this.nodes.arsenalAuthorization.checked) { this.nodes.arsenalStatus.textContent = "Review the request and confirm your authorized scope before execution."; return; }
      if (!this.command || !validEndpoint(this.command.endpoint)) { this.nodes.arsenalStatus.textContent = "Choose a valid catalog command."; return; }
      if (this.command.installed === false) { this.nodes.arsenalStatus.textContent = "This executable is missing. Install it and refresh the catalog first."; return; }
      let payload;
      try { payload = buildPayload(this.fields, this.inputs); }
      catch (error) { this.nodes.arsenalStatus.textContent = error.message; return; }
      const selected = this.command;
      this.busy = true; this.updateRunButton();
      [this.nodes.arsenalCategory, this.nodes.arsenalCommand, this.nodes.arsenalRefresh, this.nodes.arsenalAuthorization, ...this.inputs].forEach((input) => { input.disabled = true; });
      this.nodes.arsenalStatus.textContent = `Running ${selected.label || selected.id}. Review active processes in Running jobs.`;
      this.nodes.arsenalResult.textContent = "Waiting for worker output…";
      const evidence = { command_id: selected.id, command: selected.label, endpoint: selected.endpoint, started_at: new Date().toISOString() };
      try {
        evidence.response = await request(this.fetcher, selected.endpoint, { method: "POST", body: JSON.stringify(payload) });
        evidence.status = "completed";
        this.nodes.arsenalStatus.textContent = `${selected.label || selected.id}: response received. Inspect the output; command completion is not a security verdict.`;
      } catch (error) {
        evidence.status = "failed"; evidence.error = error.message; evidence.response = error.data || { error: error.message };
        this.nodes.arsenalStatus.textContent = `${selected.label || selected.id} failed: ${error.message}`;
      } finally {
        evidence.completed_at = new Date().toISOString(); this.lastResult = evidence;
        try {
          const saved = await request(this.fetcher, "/api/redteam/workflows", {method:"POST", body:JSON.stringify({
            asset:String(payload.target || payload.url || payload.base_url || payload.domain || payload.file_path || payload.binary || selected.id),
            phase:"command", status:evidence.status, authorization_confirmed:true, result:evidence,
          })});
          evidence.evidence_id = saved.id || saved.run_id;
        } catch (error) {
          evidence.evidence_error = "Local evidence could not be saved. Download this response before leaving the page.";
          this.nodes.arsenalStatus.textContent += ` ${evidence.evidence_error}`;
        }
        const output = JSON.stringify(evidence, null, 2);
        this.nodes.arsenalResult.textContent = output.length > DISPLAY_LIMIT ? `${output.slice(0, DISPLAY_LIMIT)}\n\n[Display truncated. Download command evidence for the full response.]` : output;
        this.nodes.arsenalDownload.disabled = false;
        this.busy = false;
        [this.nodes.arsenalCategory, this.nodes.arsenalCommand, this.nodes.arsenalRefresh, this.nodes.arsenalAuthorization, ...this.inputs].forEach((input) => { input.disabled = false; });
        this.nodes.arsenalAuthorization.checked = false; this.updateRunButton();
      }
    }
    download() {
      if (!this.lastResult) return;
      const url = global.URL.createObjectURL(new Blob([JSON.stringify(this.lastResult, null, 2)], { type: "application/json" }));
      const link = this.element("a"); link.href = url; link.download = `hanzo-command-${String(this.lastResult.command_id).replace(/[^a-z0-9_-]/gi, "-")}.json`;
      this.doc.body.append(link); link.click(); link.remove(); global.setTimeout(() => global.URL.revokeObjectURL(url), 1000);
    }
  }
  if (typeof module !== "undefined" && module.exports) module.exports = { ArsenalLauncher, buildPayload, fieldValue, validEndpoint, failedResponse, request, DISPLAY_LIMIT };
  else if (global.document) { const launcher = new ArsenalLauncher(global.document, global.fetch.bind(global)); launcher.mount(); }
})(typeof window !== "undefined" ? window : globalThis);
