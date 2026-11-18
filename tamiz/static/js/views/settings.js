// Settings: workspace preferences, users, API tokens, account, data.

import { del, download, get, patch, post, put } from "../api.js";
import { can, go, state } from "../app.js";
import { $, $$, formValues, html, icon, mount, on } from "../dom.js";
import { t } from "../i18n.js";
import { busy, confirmDialog, copyButton, modal, showFormErrors, timeTag, toast, toastError } from "../ui.js";

export async function render(root, [tab]) {
  const tabs = ["workspace", "tokens", "account", "data", "about"];
  if (can("admin")) tabs.splice(1, 0, "users");
  tab = tabs.includes(tab) ? tab : "workspace";
  mount(root, html`
    <div class="page-head"><div><h1>${t("nav.settings")}</h1></div></div>
    <nav class="tabs">${tabs.map((x) => html`<a href="#/settings/${x}" aria-selected="${x === tab}">${t("stab." + x)}</a>`)}</nav>
    <div id="pane"></div>`);
  const pane = $("#pane", root);
  await ({ workspace, users, tokens, account, data, about })[tab](pane);
}

async function workspace(pane) {
  const s = await get("settings");
  const ro = !can("admin");
  mount(pane, html`<form id="ws" class="panel" novalidate>
    <fieldset class="fieldset"><legend>${t("set.ids")}</legend><p>${t("set.ids_intro")}</p>
      <div class="form-grid">
        <div class="field" data-field="id_range_start"><label>${t("set.range_start")}</label><input class="input mono" name="id_range_start" data-type="number" value="${s.id_range_start}"></div>
        <div class="field" data-field="id_range_end"><label>${t("set.range_end")}</label><input class="input mono" name="id_range_end" data-type="number" value="${s.id_range_end}"></div>
        <div class="field" data-field="block_size"><label>${t("set.block_size")}</label><input class="input mono" name="block_size" data-type="number" value="${s.block_size}">
          <span class="hint">${t("set.block_size_hint")}</span></div>
      </div></fieldset>
    <fieldset class="fieldset"><legend>${t("set.render")}</legend>
      <div class="field" data-field="render_style"><div class="segmented">
        <label><input type="radio" name="render_style" value="crs" ${s.render_style === "crs" ? "checked" : ""}><span>${t("set.style_crs")}</span></label>
        <label><input type="radio" name="render_style" value="compact" ${s.render_style === "compact" ? "checked" : ""}><span>${t("set.style_compact")}</span></label></div>
        <span class="hint">${t("set.render_hint")}</span></div></fieldset>
    <fieldset class="fieldset"><legend>${t("set.policy")}</legend>
      <div class="stack">
        <label class="check"><input type="checkbox" name="require_reason" ${s.require_reason ? "checked" : ""}> ${t("set.require_reason")}</label>
        <label class="check"><input type="checkbox" name="default_reload" ${s.default_reload ? "checked" : ""}> ${t("set.default_reload")}</label>
        <label class="check"><input type="checkbox" name="review_self_approve" ${s.review_self_approve ? "checked" : ""}> ${t("set.self_approve")}</label>
        <div class="field" data-field="expiry_warning_days"><label>${t("set.expiry_days")}</label><input class="input mono" name="expiry_warning_days" data-type="number" value="${s.expiry_warning_days}"></div>
      </div></fieldset>
    ${ro ? html`<p class="faint">${t("set.admin_only")}</p>` : html`<div class="form-actions"><button class="btn btn-primary" type="submit">${t("common.save")}</button></div>`}
  </form>`);
  const form = $("#ws", pane);
  if (ro) $$("input", form).forEach((i) => { i.disabled = true; });
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    await busy($("button[type=submit]", form), async () => {
      try { await put("settings", formValues(form)); toast(t("set.saved")); } catch (e) { showFormErrors(form, e); }
    });
  });
}

async function users(pane) {
  const list = await get("users");
  mount(pane, html`
    <div class="section-head"><div><h2>${t("users.title")}</h2><p>${t("users.intro")}</p></div>
      ${state.mode === "local" ? html`<button class="btn btn-primary" data-action="new-user">${icon("plus")} ${t("users.new")}</button>` : ""}</div>
    <div class="table-wrap"><table class="table"><thead><tr><th>${t("users.name")}</th><th>${t("users.role")}</th><th>${t("users.source")}</th><th>${t("users.last_login")}</th><th></th></tr></thead>
      <tbody>${list.map((u) => html`<tr class="${u.disabled ? "disabled" : ""}"><td><div class="cell-main">${u.username}</div><div class="cell-sub">${u.display_name}</div></td>
        <td>${t("role." + u.role)}${u.disabled ? html` <span class="tag">${t("users.disabled")}</span>` : ""}</td><td>${u.source}</td>
        <td>${u.last_login_at ? timeTag(u.last_login_at) : html`<span class="faint">${t("common.never")}</span>`}</td>
        <td class="actions"><button class="btn btn-sm" data-edit-user="${u.id}">${t("common.edit")}</button></td></tr>`)}</tbody></table></div>
    <div class="notice section">${t("users.roles_help")}</div>`);

  const roleSelect = (value) => html`<select class="select" name="role">${["viewer", "editor", "admin"].map((r) => html`<option value="${r}" ${r === value ? "selected" : ""}>${t("role." + r)}</option>`)}</select>`;
  on(pane, "click", "[data-action=new-user]", () => modal({
    title: t("users.new"),
    body: html`<form id="uf" class="stack"><div class="field" data-field="username"><label>${t("login.username")}</label><input class="input" name="username"></div>
      <div class="field"><label>${t("users.display")}</label><input class="input" name="display_name"></div>
      <div class="field" data-field="role"><label>${t("users.role")}</label>${roleSelect("viewer")}</div>
      <div class="field" data-field="password"><label>${t("login.password")}</label><input class="input" type="password" name="password" autocomplete="new-password"><span class="hint">${t("setup.password_hint")}</span></div></form>`,
    actions: [{ label: t("common.cancel") }, { label: t("users.create"), kind: "primary", onClick: async (d) => {
      const f = $("#uf", d);
      try {
        await post("users", Object.fromEntries(new FormData(f)));
      } catch (e) { showFormErrors(f, e); return false; }
      toast(t("users.created"));
      go("/settings/users");
    } }],
  }));
  on(pane, "click", "[data-edit-user]", (ev, b) => {
    const u = list.find((x) => String(x.id) === b.dataset.editUser);
    modal({
      title: u.username,
      body: html`<form id="uf" class="stack">
        <div class="field"><label>${t("users.display")}</label><input class="input" name="display_name" value="${u.display_name}"></div>
        <div class="field" data-field="role"><label>${t("users.role")}</label>${roleSelect(u.role)}</div>
        <label class="check"><input type="checkbox" name="disabled" ${u.disabled ? "checked" : ""}> ${t("users.disable")}</label>
        ${u.source === "local" ? html`<div class="field" data-field="password"><label>${t("users.new_password")}</label><input class="input" type="password" name="password" autocomplete="new-password"><span class="hint">${t("users.new_password_hint")}</span></div>` : ""}
        </form>`,
      actions: [
        { label: t("common.delete"), kind: "danger", onClick: async () => {
          if (!await confirmDialog(t("users.delete"), t("users.delete_confirm", { name: u.username }), { danger: true })) return false;
          await del(`users/${u.id}`); toast(t("users.deleted")); go("/settings/users");
        } },
        { label: t("common.cancel") },
        { label: t("common.save"), kind: "primary", onClick: async (d) => {
          const f = $("#uf", d);
          const body = { display_name: f.elements.display_name.value, role: f.elements.role.value, disabled: f.elements.disabled.checked };
          if (f.elements.password && f.elements.password.value) body.password = f.elements.password.value;
          try { await patch(`users/${u.id}`, body); } catch (e) { showFormErrors(f, e); return false; }
          toast(t("users.saved")); go("/settings/users");
        } },
      ],
    });
  });
}

async function tokens(pane) {
  const list = state.user.id ? await get("tokens") : [];
  mount(pane, html`
    <div class="section-head"><div><h2>${t("tok.title")}</h2><p>${t("tok.intro")}</p></div>
      ${state.user.id ? html`<button class="btn btn-primary" data-action="new-token">${icon("plus")} ${t("tok.new")}</button>` : ""}</div>
    ${list.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>${t("tok.name")}</th><th>${t("tok.prefix")}</th><th>${t("tok.created")}</th><th>${t("tok.used")}</th><th>${t("tok.expires")}</th><th></th></tr></thead>
      <tbody>${list.map((k) => html`<tr><td>${k.name}</td><td class="mono">tmz_${k.prefix}_…</td><td>${timeTag(k.created_at)}</td>
        <td>${k.last_used_at ? timeTag(k.last_used_at) : html`<span class="faint">${t("common.never")}</span>`}</td><td>${k.expires_at ? k.expires_at.slice(0, 10) : t("tok.no_expiry")}</td>
        <td class="actions"><button class="btn btn-sm btn-danger" data-revoke="${k.id}">${t("tok.revoke")}</button></td></tr>`)}</tbody></table></div>`
      : html`<p class="muted">${state.user.id ? t("tok.none") : t("tok.need_user")}</p>`}
    <h3 class="section">${t("tok.usage")}</h3>
    <pre class="code wrap">curl -H "Authorization: Bearer tmz_..." ${location.origin}${location.pathname}api/dashboard</pre>`);
  on(pane, "click", "[data-action=new-token]", () => modal({
    title: t("tok.new"),
    body: html`<form id="kf" class="stack"><div class="field"><label>${t("tok.name")}</label><input class="input" name="name" placeholder="ci-pipeline"></div>
      <div class="field"><label>${t("tok.days")}</label><input class="input mono" name="days" data-type="number" placeholder="90"><span class="hint">${t("tok.days_hint")}</span></div></form>`,
    actions: [{ label: t("common.cancel") }, { label: t("tok.create"), kind: "primary", onClick: async (d) => {
      const f = $("#kf", d);
      const r = await post("tokens", { name: f.elements.name.value, days: f.elements.days.value ? Number(f.elements.days.value) : null });
      modal({ title: t("tok.created_title"),
        body: html`<p>${t("tok.copy_now")}</p><div class="copyable"><pre class="code wrap token-reveal">${r.token}</pre>${copyButton(r.token)}</div>`,
        actions: [{ label: t("common.done"), kind: "primary" }], onClose: () => go("/settings/tokens") });
    } }],
  }));
  on(pane, "click", "[data-revoke]", async (ev, b) => {
    if (!await confirmDialog(t("tok.revoke"), t("tok.revoke_confirm"), { danger: true })) return;
    try { await del(`tokens/${b.dataset.revoke}`); go("/settings/tokens"); } catch (e) { toastError(e); }
  });
}

async function account(pane) {
  if (state.mode !== "local" || !state.user.id) {
    mount(pane, html`<p class="muted">${t("acct.external", { mode: state.mode })}</p>`);
    return;
  }
  mount(pane, html`<form id="pf" class="panel stack" novalidate>
    <h2>${t("acct.password")}</h2>
    <div class="field"><label>${t("acct.current")}</label><input class="input" type="password" name="current" autocomplete="current-password"></div>
    <div class="field" data-field="new"><label>${t("acct.new")}</label><input class="input" type="password" name="new" autocomplete="new-password"><span class="hint">${t("setup.password_hint")}</span></div>
    <div class="form-actions"><button class="btn btn-primary" type="submit">${t("acct.change")}</button></div></form>`);
  const f = $("#pf", pane);
  f.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    await busy($("button", f), async () => {
      try {
        await post("auth/password", { current: f.elements.current.value, new: f.elements.new.value });
        toast(t("acct.changed"));
        location.reload();
      } catch (e) { showFormErrors(f, e); }
    });
  });
}

async function data(pane) {
  mount(pane, html`
    <section class="panel"><h2>${t("data.export")}</h2><p>${t("data.export_text")}</p>
      <button class="btn" data-action="export">${icon("download")} ${t("data.export_btn")}</button></section>
    ${can("editor") ? html`<section class="panel"><h2>${t("data.import")}</h2><p>${t("data.import_text")}</p>
      <div class="row"><input type="file" id="jf" accept="application/json,.json">
      <label class="check"><input type="checkbox" id="keep"> ${t("data.keep_ids")}</label>
      <button class="btn" data-action="import">${icon("import")} ${t("data.import_btn")}</button></div></section>` : ""}
    <section class="panel"><h2>${t("data.backup")}</h2><p>${t("data.backup_text")}</p></section>`);
  on(pane, "click", "[data-action=export]", (ev, b) => busy(b, () => download("io/export", "tamiz-export.json").catch(toastError)));
  on(pane, "click", "[data-action=import]", async (ev, b) => {
    const file = $("#jf", pane).files[0];
    if (!file) { toast(t("data.choose_file"), "warn"); return; }
    await busy(b, async () => {
      try {
        const body = JSON.parse(await file.text());
        body.keep_ids = $("#keep", pane).checked;
        const r = await post("io/import", body);
        toast(t("data.imported", r));
      } catch (e) { toastError(e); }
    });
  });
}

async function about(pane) {
  mount(pane, html`<dl class="kv panel">
    <dt>${t("about.version")}</dt><dd class="mono">${state.version}</dd>
    <dt>${t("about.auth")}</dt><dd>${t("auth_mode." + state.mode)}</dd>
    <dt>${t("about.user")}</dt><dd>${state.user.username} (${t("role." + state.user.role)})</dd>
    <dt>${t("about.api")}</dt><dd><a href="api/docs" target="_blank" rel="noopener">api/docs</a></dd>
    <dt>${t("about.license")}</dt><dd>Apache-2.0</dd>
    <dt>${t("about.fonts")}</dt><dd>Atkinson Hyperlegible Next / Mono (SIL OFL 1.1)</dd>
  </dl>`);
}
