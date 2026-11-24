// Group detail: its exclusions, where it is deployed, and ID renumbering.

import { del, get, post } from "../api.js";
import { can, go } from "../app.js";
import { $, html, icon, mount, on } from "../dom.js";
import { what, whereHtml } from "../describe.js";
import { t } from "../i18n.js";
import { busy, confirmDialog, emptyState, toast, toastError, worstLevel } from "../ui.js";
import { groupDialog } from "./groups.js";

export async function render(root, [id]) {
  const [groups, targets, items] = await Promise.all([get("groups"), get("targets"), get(`exclusions?group_id=${id}`)]);
  const g = groups.find((x) => String(x.id) === id);
  if (!g) { mount(root, emptyState(t("app.not_found"), "")); return; }
  const tname = Object.fromEntries(targets.map((x) => [x.id, x.name]));
  const outside = items.filter((e) => e.lint.some((i) => i.code === "rule_id_outside_group" || i.code === "rule_id_reserved"));

  mount(root, html`
    <div class="crumbs"><a href="#/groups">${t("nav.groups")}</a></div>
    <div class="page-head">
      <div><h1>${g.name}</h1>
        <p><span class="mono">${g.slug}</span> <span class="faint">${t("groups.ids")}:</span> <span class="mono">${g.id_ranges}</span>
          ${g.description ? html`<br>${g.description}` : ""}</p></div>
      <div class="page-actions">
        ${can("editor") ? html`<button type="button" class="btn" data-action="edit">${icon("edit")} ${t("common.edit")}</button>
          <a class="btn btn-primary" href="#/exclusions/new?group=${g.id}">${icon("plus")} ${t("excl.new")}</a>` : ""}
      </div>
    </div>

    <section>
      <div class="section-head"><h2>${t("group.deployed_on")}</h2></div>
      <p>${g.target_ids.length ? g.target_ids.map((i, n) => html`${n ? ", " : ""}<a href="#/targets/${i}">${tname[i]}</a>`) : html`<span class="muted">${t("groups.not_deployed_long")}</span>`}</p>
    </section>

    <section class="section">
      <div class="section-head"><h2>${t("nav.exclusions")}</h2><span class="faint">${t("groups.used", { used: g.ids_used, cap: g.ids_capacity })}</span></div>
      ${items.length ? html`<div class="table-wrap"><table class="table">
        <thead><tr><th>${t("excl.rule_id")}</th><th>${t("excl.what")}</th><th>${t("excl.where")}</th><th>${t("common.state")}</th></tr></thead>
        <tbody>${items.map((e) => html`<tr class="clickable${e.enabled ? "" : " disabled"}" data-id="${e.id}">
          <td class="id">${e.rule_id ?? "—"}</td>
          <td><div class="cell-main">${what(e)}</div>${e.reason ? html`<div class="cell-sub">${e.reason}</div>` : ""}</td>
          <td>${whereHtml(e)}</td>
          <td>${e.enabled ? (worstLevel(e.lint) === "error" ? html`<span class="tag error">${t("lint.has_errors")}</span>` : t("common.enabled")) : t("common.disabled")}</td></tr>`)}</tbody></table></div>`
        : emptyState(t("group.empty_title"), t("group.empty_text"), can("editor") ? html`<a class="btn btn-primary" href="#/exclusions/new?group=${g.id}">${t("excl.new")}</a>` : "")}
    </section>

    <section class="section">
      <div class="section-head"><div><h2>${t("renumber.title")}</h2><p>${t("renumber.intro")}</p></div>
        <button type="button" class="btn" data-action="plan">${t("renumber.preview")}</button></div>
      ${outside.length ? html`<div class="notice warn">${t("renumber.outside", { n: outside.length })}</div>` : ""}
      <div id="renumber"></div>
    </section>

    ${can("editor") && !items.length ? html`<section class="section"><button type="button" class="btn btn-danger" data-action="delete">${icon("trash")} ${t("groups.delete")}</button></section>` : ""}`);

  on(root, "click", "tr.clickable", (ev, tr) => go(`/exclusions/${tr.dataset.id}`));
  on(root, "click", "[data-action=edit]", () => groupDialog(g, targets));
  on(root, "click", "[data-action=plan]", async (ev, b) => {
    await busy(b, async () => {
      const p = await get(`groups/${g.id}/renumber`);
      const box = $("#renumber", root);
      if (!p.changes.length) { mount(box, html`<p class="muted">${t("renumber.nothing")}</p>`); return; }
      mount(box, html`
        <div class="table-wrap"><table class="table"><thead><tr><th>${t("renumber.old")}</th><th>${t("renumber.new")}</th><th>${t("eform.reason")}</th></tr></thead>
        <tbody>${p.changes.map((c) => html`<tr><td class="id">${c.old}</td><td class="id">${c.new > 0 ? c.new : t("renumber.new_block")}</td><td>${c.reason}</td></tr>`)}</tbody></table></div>
        ${p.blocks_to_release.length ? html`<p class="hint">${t("renumber.release", { blocks: p.blocks_to_release.join(", ") })}</p>` : ""}
        <p class="notice section">${t("renumber.after")}</p>
        ${can("editor") ? html`<div class="form-actions"><button type="button" class="btn btn-primary" data-action="renumber">${t("renumber.apply", { n: p.changes.length })}</button></div>` : ""}`);
    });
  });
  on(root, "click", "[data-action=renumber]", async (ev, b) => {
    await busy(b, async () => {
      try {
        const r = await post(`groups/${g.id}/renumber`, {});
        toast(t("renumber.done", { n: r.changed }));
        go(`/groups/${g.id}`);
      } catch (e) { toastError(e); }
    });
  });
  on(root, "click", "[data-action=delete]", async () => {
    if (!await confirmDialog(t("groups.delete"), t("groups.delete_confirm", { name: g.name }), { danger: true, confirm: t("common.delete") })) return;
    try { await del(`groups/${g.id}`); toast(t("groups.deleted")); go("/groups"); } catch (e) { toastError(e); }
  });
}
