// Groups list. A group is usually one application or site; it owns a block
// of rule IDs and is deployed to one or more targets.

import { get, patch, post } from "../api.js";
import { can, go } from "../app.js";
import { $, $$, html, icon, mount, on } from "../dom.js";
import { t } from "../i18n.js";
import { emptyState, modal, toast } from "../ui.js";

export async function render(root) {
  const [groups, targets] = await Promise.all([get("groups"), get("targets")]);
  const tname = Object.fromEntries(targets.map((x) => [x.id, x.name]));
  mount(root, html`
    <div class="page-head">
      <div><h1>${t("nav.groups")}</h1><p>${t("groups.intro")}</p></div>
      <div class="page-actions">${can("editor") ? html`<button class="btn btn-primary" data-action="new">${icon("plus")} ${t("groups.new")}</button>` : ""}</div>
    </div>
    ${groups.length ? html`<div class="table-wrap"><table class="table">
      <thead><tr><th>${t("groups.name")}</th><th>${t("groups.ids")}</th><th>${t("groups.usage")}</th><th>${t("nav.exclusions")}</th><th>${t("nav.targets")}</th></tr></thead>
      <tbody>${groups.map((g) => html`<tr class="clickable" data-id="${g.id}">
        <td><div class="cell-main">${g.name}</div><div class="cell-sub mono">${g.slug}</div></td>
        <td class="mono">${g.id_ranges}</td>
        <td><div class="meter" title="${g.ids_used} / ${g.ids_capacity}"><i data-fill="${g.ids_capacity ? Math.min(100, (100 * g.ids_used) / g.ids_capacity).toFixed(1) : 0}"></i></div>
          <div class="cell-sub">${t("groups.used", { used: g.ids_used, cap: g.ids_capacity })}</div></td>
        <td>${g.enabled_count}${g.exclusion_count !== g.enabled_count ? html` <span class="faint">(${t("groups.disabled_n", { n: g.exclusion_count - g.enabled_count })})</span>` : ""}</td>
        <td>${g.target_ids.length ? g.target_ids.map((i) => tname[i]).join(", ") : html`<span class="faint">${t("groups.not_deployed")}</span>`}</td>
      </tr>`)}</tbody></table></div>`
      : emptyState(t("groups.empty_title"), t("groups.empty_text"),
          can("editor") ? html`<button class="btn btn-primary" data-action="new">${icon("plus")} ${t("groups.new")}</button>` : "")}`);

  on(root, "click", "tr.clickable", (ev, tr) => go(`/groups/${tr.dataset.id}`));
  on(root, "click", "[data-action=new]", () => groupDialog(null, targets));
}

export function groupDialog(group, targets) {
  const g = group || { name: "", slug: "", description: "", target_ids: [] };
  modal({
    title: group ? t("groups.edit") : t("groups.new"),
    body: html`<form id="gform" class="stack" novalidate>
      <div class="field" data-field="name"><label for="gname">${t("groups.name")}</label>
        <input class="input" id="gname" name="name" value="${g.name}" required maxlength="80"><span class="hint">${t("groups.name_hint")}</span></div>
      <div class="field" data-field="slug"><label for="gslug">${t("groups.slug")}</label>
        <input class="input mono" id="gslug" name="slug" value="${g.slug}" maxlength="48" pattern="[a-z0-9][a-z0-9-]*" placeholder="${t("groups.slug_auto")}">
        <span class="hint">${t("groups.slug_hint")}</span></div>
      <div class="field"><label for="gdesc">${t("groups.description")}</label>
        <input class="input" id="gdesc" name="description" value="${g.description}" maxlength="300"></div>
      ${targets.length ? html`<div class="field"><span class="label">${t("groups.deploy_to")}</span>
        <div class="row">${targets.map((x) => html`<label class="check"><input type="checkbox" value="${x.id}" ${g.target_ids.includes(x.id) ? "checked" : ""}> ${x.name}</label>`)}</div></div>` : ""}
      ${group ? "" : html`<p class="hint faint">${t("groups.block_note")}</p>`}
    </form>`,
    actions: [{ label: t("common.cancel") }, {
      label: group ? t("common.save") : t("groups.create"), kind: "primary",
      onClick: async (d) => {
        const f = $("#gform", d);
        const body = {
          name: f.elements.name.value.trim(), description: f.elements.description.value.trim(),
          target_ids: $$("input[type=checkbox]:checked", f).map((i) => Number(i.value)),
        };
        if (f.elements.slug.value.trim()) body.slug = f.elements.slug.value.trim();
        const saved = group ? await patch(`groups/${group.id}`, body) : await post("groups", body);
        toast(group ? t("groups.saved") : t("groups.created", { ranges: saved.id_ranges }));
        go(`/groups/${saved.id}`);
      },
    }],
  });
}
