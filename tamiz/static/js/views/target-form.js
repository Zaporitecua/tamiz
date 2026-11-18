// Create or edit a target (administrators only).

import { get, post, put } from "../api.js";
import { go, state } from "../app.js";
import { $, $$, formValues, html, mount } from "../dom.js";
import { t } from "../i18n.js";
import { busy, codeBlock, copyButton, showFormErrors, toast } from "../ui.js";

const SECRET_FIELDS = [
  ["password", "password", "ssh"],
  ["private_key", "textarea", "ssh"],
  ["passphrase", "password", "ssh"],
  ["sudo_password", "password", "ssh"],
  ["jump_password", "password", "ssh"],
];

export async function render(root, [id]) {
  const editing = Boolean(id);
  const [target, groups, meta] = await Promise.all([
    editing ? get(`targets/${id}`) : Promise.resolve(null),
    get("groups"),
    state.meta ? Promise.resolve(state.meta) : get("meta"),
  ]);
  const presets = Object.fromEntries(meta.presets.map((p) => [p.key, p]));
  const initial = target || blank(presets.nginx);
  draw(root, initial, groups, presets, editing);
}

function blank(preset) {
  return {
    name: "", environment: "", description: "", platform: preset.key, transport: preset.transport,
    conn: { port: 22, ...(preset.conn || {}) }, layout: { ...preset.layout }, commands: { timeout: 60, ...preset.commands },
    logs: { ...preset.logs }, entry_files: preset.entry_files || [], import_paths: [],
    require_review: false, enabled: true, group_ids: [], secret_keys: [],
  };
}

function seg(name, value, options) {
  return html`<div class="segmented" role="radiogroup">${options.map(([v, label]) => html`
    <label><input type="radio" name="${name}" value="${v}" ${v === value ? "checked" : ""}><span>${label}</span></label>`)}</div>`;
}

function field(label, input, hint, attrs = "") {
  return html`<div class="field" ${attrs}><label>${label}</label>${input}${hint ? html`<span class="hint">${hint}</span>` : ""}</div>`;
}

function draw(root, x, groups, presets, editing) {
  const c = x.conn || {};
  const l = x.layout || {};
  const cmd = x.commands || {};
  const logs = x.logs || {};
  const jump = c.jump || {};
  const has = new Set(x.secret_keys || []);
  const secretInput = (key, type) => {
    const ph = has.has(key) ? t("tform.secret_saved") : "";
    const input = type === "textarea"
      ? html`<textarea class="textarea mono" name="secret.${key}" rows="4" placeholder="${ph}" autocomplete="off" spellcheck="false"></textarea>`
      : html`<input class="input" type="password" name="secret.${key}" placeholder="${ph}" autocomplete="new-password">`;
    return html`${input}${has.has(key) ? html`<label class="check"><input type="checkbox" data-clear="${key}"> ${t("tform.secret_clear")}</label>` : ""}`;
  };

  mount(root, html`
    <div class="crumbs"><a href="#/targets">${t("nav.targets")}</a>${editing ? html` / <a href="#/targets/${x.id}">${x.name}</a>` : ""}</div>
    <div class="page-head"><div><h1>${editing ? t("tform.edit_title", { name: x.name }) : t("target.new")}</h1>
      <p>${t("tform.intro")}</p></div></div>
    <form id="tform" class="panel" novalidate>
      <fieldset class="fieldset">
        <legend>${t("tform.identity")}</legend>
        <div class="form-grid">
          ${field(t("target.name"), html`<input class="input" name="name" value="${x.name}" required maxlength="64">`, t("tform.name_hint"))}
          ${field(t("target.environment"), html`<input class="input" name="environment" value="${x.environment}" maxlength="40" list="envs">
            <datalist id="envs"><option value="prod"><option value="stage"><option value="dev"><option value="lab"></datalist>`)}
          ${field(t("target.description"), html`<input class="input" name="description" value="${x.description}" maxlength="500">`, "", 'class="field span-2"')}
          ${field(t("target.platform"), html`<select class="select" name="platform" id="platform">
            ${Object.values(presets).map((p) => html`<option value="${p.key}" ${p.key === x.platform ? "selected" : ""}>${p.label}</option>`)}
          </select>`, t("tform.platform_hint"))}
          <div class="field"><span class="label">${t("tform.options")}</span>
            <label class="check"><input type="checkbox" name="enabled" ${x.enabled ? "checked" : ""}> ${t("tform.enabled")}</label>
            <label class="check"><input type="checkbox" name="require_review" ${x.require_review ? "checked" : ""}> ${t("tform.require_review")}</label>
          </div>
        </div>
      </fieldset>

      <fieldset class="fieldset">
        <legend>${t("tform.connection")}</legend>
        <p>${t("tform.connection_intro")}</p>
        <div class="field" data-field="transport">${seg("transport", x.transport, [
          ["ssh", t("transport.ssh")], ["docker", t("transport.docker")], ["local", t("transport.local")], ["export", t("transport.export")]])}</div>

        ${x.secret_unreadable ? html`<p class="notice error section">${t("tform.secret_unreadable")}</p>` : ""}
        <div data-for="ssh" class="form-grid section">
          ${field(t("tform.host"), html`<input class="input mono" name="conn.host" value="${c.host || ""}" placeholder="10.0.0.12">`)}
          <div class="form-grid">
            ${field(t("tform.port"), html`<input class="input mono" name="conn.port" data-type="number" value="${c.port || 22}" inputmode="numeric">`)}
            ${field(t("tform.username"), html`<input class="input mono" name="conn.username" value="${c.username || ""}" placeholder="tamiz">`)}
          </div>
          ${field(t("tform.key_file"), html`<input class="input mono" name="conn.key_file" value="${c.key_file || ""}" placeholder="waf_ed25519">`, t("tform.key_file_hint"))}
          ${field(t("tform.private_key"), secretInput("private_key", "textarea"), t("tform.private_key_hint"))}
          ${field(t("tform.passphrase"), secretInput("passphrase", "password"))}
          ${field(t("tform.password"), secretInput("password", "password"), t("tform.password_hint"))}
          <details class="span-2" ${jump.host ? "open" : ""}><summary>${t("tform.jump")}</summary>
            <div class="form-grid section">
              ${field(t("tform.host"), html`<input class="input mono" name="conn.jump.host" value="${jump.host || ""}" placeholder="bastion.example.org">`)}
              ${field(t("tform.port"), html`<input class="input mono" name="conn.jump.port" data-type="number" value="${jump.port || 22}">`)}
              ${field(t("tform.username"), html`<input class="input mono" name="conn.jump.username" value="${jump.username || ""}">`, t("tform.jump_user_hint"))}
              ${field(t("tform.key_file"), html`<input class="input mono" name="conn.jump.key_file" value="${jump.key_file || ""}">`, t("tform.jump_key_hint"))}
              ${field(t("tform.password"), secretInput("jump_password", "password"))}
            </div>
          </details>
        </div>

        <div data-for="docker" class="form-grid section">
          ${field(t("tform.container"), html`<input class="input mono" name="conn.container" value="${c.container || ""}" placeholder="waf">`)}
          ${field(t("tform.exec_user"), html`<input class="input mono" name="conn.exec_user" value="${c.exec_user || ""}" placeholder="root">`, t("tform.exec_user_hint"))}
          ${field(t("tform.docker_host"), html`<input class="input mono" name="conn.docker_host" value="${c.docker_host || ""}" placeholder="unix:///var/run/docker.sock">`, t("tform.docker_host_hint"), 'class="field span-2"')}
          <div class="notice warn span-2">${t("tform.docker_warning")}</div>
        </div>

        <div data-for="local" class="section"><div class="notice">${t("tform.local_note")}</div></div>
        <div data-for="export" class="section"><div class="notice">${t("tform.export_note")}</div></div>
      </fieldset>

      <fieldset class="fieldset">
        <legend>${t("tform.files")}</legend>
        <p>${t("tform.files_intro")}</p>
        <div class="field" data-field="layout.mode">${seg("layout.mode", l.mode || "per_group", [
          ["per_group", t("layout.per_group")], ["shared", t("layout.shared")]])}
          <span class="hint" id="layout-hint"></span></div>
        <div class="form-grid section">
          ${field(t("tform.before"), html`<input class="input mono" name="layout.before" value="${l.before || ""}">`, "", 'class="field span-2"')}
          ${field(t("tform.after"), html`<input class="input mono" name="layout.after" value="${l.after || ""}">`, "", 'class="field span-2"')}
          <label class="check span-2" data-for-layout="per_group"><input type="checkbox" name="layout.mkdirs" ${l.mkdirs ? "checked" : ""}> ${t("tform.mkdirs")}</label>
        </div>
        <div class="section" id="path-preview"></div>
        <div class="section" id="snippet"></div>
      </fieldset>

      <fieldset class="fieldset" data-hide-for="export">
        <legend>${t("tform.commands")}</legend>
        <p>${t("tform.commands_intro")}</p>
        <div class="form-grid">
          ${field(t("tform.validate"), html`<input class="input mono" name="commands.validate" value="${cmd.validate || ""}" placeholder="nginx -t">`, t("tform.validate_hint"))}
          ${field(t("tform.reload"), html`<input class="input mono" name="commands.reload" value="${cmd.reload || ""}" placeholder="nginx -s reload">`, t("tform.reload_hint"))}
          ${field(t("tform.discover"), html`<input class="input mono" name="commands.discover" value="${cmd.discover || ""}" placeholder="nginx -T">`, t("tform.discover_hint"))}
          ${field(t("tform.timeout"), html`<input class="input mono" name="commands.timeout" data-type="number" value="${cmd.timeout || 60}">`)}
          <div class="field span-2" data-field="commands.sudo_mode"><span class="label">${t("tform.sudo_mode")}</span>
            ${seg("commands.sudo_mode", cmd.sudo_mode || "none", [["none", t("sudo.none")], ["commands", t("sudo.commands")], ["all", t("sudo.all")]])}
            <span class="hint" id="sudo-hint"></span></div>
          <div data-for="ssh" class="span-2 form-grid">
            ${field(t("tform.sudo_password"), secretInput("sudo_password", "password"), t("tform.sudo_password_hint"))}
            ${field(t("tform.prefix"), html`<input class="input mono" name="commands.command_prefix" value="${cmd.command_prefix || ""}" placeholder="docker exec waf">`, t("tform.prefix_hint"))}
          </div>
        </div>
        <div class="section" id="sudoers"></div>
      </fieldset>

      <fieldset class="fieldset" data-hide-for="export">
        <legend>${t("tform.logs")}</legend>
        <p>${t("tform.logs_intro")}</p>
        <div class="form-grid">
          ${field(t("tform.audit_log"), html`<input class="input mono" name="logs.audit_log" value="${logs.audit_log || ""}" placeholder="/var/log/modsec_audit.log">`, t("tform.audit_log_hint"))}
          ${field(t("tform.error_log"), html`<input class="input mono" name="logs.error_log" value="${logs.error_log || ""}" placeholder="/var/log/nginx/error.log">`)}
        </div>
      </fieldset>

      <fieldset class="fieldset">
        <legend>${t("tform.advanced")}</legend>
        <div class="form-grid">
          ${field(t("tform.entry_files"), html`<textarea class="textarea mono" name="entry_files" data-type="lines" rows="3" placeholder="/etc/nginx/modsec/main.conf">${(x.entry_files || []).join("\n")}</textarea>`, t("tform.entry_files_hint"))}
          ${field(t("tform.import_paths"), html`<textarea class="textarea mono" name="import_paths" data-type="lines" rows="3" placeholder="/etc/nginx/modsec/custom/*.conf">${(x.import_paths || []).join("\n")}</textarea>`, t("tform.import_paths_hint"))}
          ${field(t("tform.include_base"), html`<select class="select" name="commands.include_base">
              <option value="file" ${cmd.include_base !== "server_root" ? "selected" : ""}>${t("tform.include_base_file")}</option>
              <option value="server_root" ${cmd.include_base === "server_root" ? "selected" : ""}>${t("tform.include_base_root")}</option></select>`)}
          ${field(t("tform.server_root"), html`<input class="input mono" name="commands.server_root" value="${cmd.server_root || ""}" placeholder="/etc/httpd">`)}
        </div>
      </fieldset>

      <fieldset class="fieldset">
        <legend>${t("nav.groups")}</legend>
        <p>${t("tform.groups_intro")}</p>
        ${groups.length ? html`<div class="row">${groups.map((g) => html`<label class="check"><input type="checkbox" data-group="${g.id}" ${x.group_ids.includes(g.id) ? "checked" : ""}> ${g.name} <span class="faint mono">${g.id_ranges}</span></label>`)}</div>`
          : html`<p class="faint">${t("tform.no_groups")}</p>`}
      </fieldset>

      <div class="form-actions">
        <a class="btn" href="${editing ? "#/targets/" + x.id : "#/targets"}">${t("common.cancel")}</a>
        <button class="btn btn-primary" type="submit">${editing ? t("common.save") : t("target.create")}</button>
      </div>
    </form>`);

  const form = $("#tform", root);
  const refresh = () => {
    const v = formValues(form);
    $$("[data-for]", form).forEach((el) => { el.hidden = el.dataset.for !== v.transport; });
    $$("[data-hide-for]", form).forEach((el) => { el.hidden = el.dataset.hideFor === v.transport; });
    $$("[data-for-layout]", form).forEach((el) => { el.hidden = el.dataset.forLayout !== v.layout.mode; });
    $("#layout-hint", form).textContent = t("layout." + v.layout.mode + "_hint");
    $("#sudo-hint", form).textContent = t("sudo." + v.commands.sudo_mode + "_hint");
    previewPaths(form, v);
    snippet(form, v, presets);
    sudoers(form, v);
  };
  form.addEventListener("input", refresh);
  form.addEventListener("change", (ev) => {
    if (ev.target.id === "platform" && !editing) {
      const p = presets[ev.target.value];
      const fill = { "layout.before": p.layout.before, "layout.after": p.layout.after,
        "commands.validate": p.commands.validate, "commands.reload": p.commands.reload,
        "commands.discover": p.commands.discover, "logs.audit_log": p.logs.audit_log, "logs.error_log": p.logs.error_log,
        "conn.container": (p.conn || {}).container || "", "conn.exec_user": (p.conn || {}).exec_user || "" };
      for (const [k, val] of Object.entries(fill)) { const el = form.elements[k]; if (el) el.value = val ?? ""; }
      for (const [k, val] of [["transport", p.transport], ["layout.mode", p.layout.mode], ["commands.sudo_mode", p.commands.sudo_mode]]) {
        const r = form.querySelector(`[name="${k}"][value="${val}"]`); if (r) r.checked = true;
      }
      form.elements["layout.mkdirs"].checked = Boolean(p.layout.mkdirs);
      form.elements.entry_files.value = (p.entry_files || []).join("\n");
    }
    refresh();
  });
  refresh();

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const v = formValues(form);
    const secret = {};
    for (const [key] of SECRET_FIELDS) {
      const val = (v.secret || {})[key];
      if (val) secret[key] = val;
    }
    $$("[data-clear]:checked", form).forEach((el) => { secret[el.dataset.clear] = null; });
    delete v.secret;
    if (Object.keys(secret).length) v.secret = secret;
    v.group_ids = $$("[data-group]:checked", form).map((el) => Number(el.dataset.group));
    if (v.conn && v.conn.jump && !v.conn.jump.host) delete v.conn.jump;
    await busy($("button[type=submit]", form), async () => {
      try {
        const saved = editing ? await put(`targets/${x.id}`, v) : await post("targets", v);
        toast(editing ? t("tform.saved") : t("tform.created"));
        go(`/targets/${saved.id}`);
      } catch (e) {
        showFormErrors(form, e);
      }
    });
  });
}

function previewPaths(form, v) {
  const el = $("#path-preview", form);
  if (v.layout.mode !== "per_group" || !v.layout.before) { el.innerHTML = ""; return; }
  const ex = (tpl, p) => tpl.replace("{group}", "shop").replace("{block}", "012").replace("{placement}", p);
  mount(el, html`<div class="code-title">${t("tform.example_paths")}</div>
    <pre class="code">${ex(v.layout.before, "before")}\n${ex(v.layout.after || "", "after")}</pre>`);
}

function snippet(form, v, presets) {
  const el = $("#snippet", form);
  const p = presets[v.platform];
  if (!p || !p.include_snippet) { el.innerHTML = ""; return; }
  mount(el, html`<div class="code-title"><span>${t("tform.include_snippet")}</span>${copyButton(p.include_snippet)}</div>
    ${codeBlock(p.include_snippet)}<p class="hint faint">${t("tform.include_snippet_hint")}</p>`);
}

function sudoers(form, v) {
  const el = $("#sudoers", form);
  const mode = v.commands.sudo_mode;
  if (v.transport !== "ssh" || mode === "none") { el.innerHTML = ""; return; }
  const user = (v.conn && v.conn.username) || "tamiz";
  const cmds = [v.commands.validate, v.commands.reload, v.commands.discover].filter(Boolean);
  for (const k of ["audit_log", "error_log"]) {
    if (v.logs[k] && v.logs[k].startsWith("/")) cmds.push(`tail -c * -- ${v.logs[k]}`);
  }
  if (mode === "all") cmds.push("sh");
  cmds.push("true");
  const line = `${user} ALL=(root) NOPASSWD: ${cmds.map((c) => {
    const [bin, ...rest] = c.split(" ");
    const dir = ["tail", "sh", "true", "docker", "kubectl"].includes(bin) ? "/usr/bin" : "/usr/sbin";
    return [bin.startsWith("/") ? bin : `${dir}/${bin}`, ...rest].join(" ");
  }).join(", ")}`;
  mount(el, html`<div class="code-title"><span>${t("tform.sudoers")}</span>${copyButton(line)}</div>
    <pre class="code wrap">${line}</pre><p class="hint faint">${t("tform.sudoers_hint")}</p>`);
}
