// Exclusions list with filters.

import { get, patch } from "../api.js";
import { can } from "../app.js";
import { $, html, icon, mount, on } from "../dom.js";
import { what, whereHtml } from "../describe.js";
import { t } from "../i18n.js";
import { emptyState, lintList, toast, toastError, worstLevel } from "../ui.js";

export async function render(root) {
  const [items, groups] = await Promise.all([get("exclusions"), get("groups")]);
  const gname = Object.fromEntries(groups.map((g) => [g.id, g.name]));
  const params = new URLSearchParams(location.hash.split("?")[1] || "");

  mount(root, html`
    <div class="page-head">
      <div><h1>${t("nav.exclusions")}</h1><p>${t("excl.intro")}</p></div>
      <div class="page-actions">
        ${can("editor") ? html`<a class="btn" href="#/analyzer">${icon("analyzer")} ${t("excl.from_logs")}</a>
          <a class="btn btn-primary" href="#/exclusions/new">${icon("plus")} ${t("excl.new")}</a>` : ""}
      </div>
    </div>
    ${items.length ? html`
      <div class="toolbar">
        <input class="input grow" type="search" id="q" placeholder="${t("excl.search")}" value="${params.get("q") || ""}">
        <select class="select" id="g"><option value="">${t("excl.all_groups")}</option>
          ${groups.map((g) => html`<option value="${g.id}" ${params.get("group") === String(g.id) ? "selected" : ""}>${g.name}</option>`)}</select>
        <select class="select" id="s"><option value="">${t("excl.all_scopes")}</option>
          <option value="conditional">${t("scope.conditional")}</option><option value="global">${t("scope.global")}</option><option value="raw">${t("scope.raw")}</option></select>
        <label class="check"><input type="checkbox" id="p"> ${t("excl.problems_only")}</label>
      </div>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>${t("excl.rule_id")}</th><th>${t("excl.what")}</th><th>${t("excl.where")}</th><th>${t("excl.group")}</th><th>${t("excl.on")}</th></tr></thead>
        <tbody id="rows"></tbody>
      </table></div>
      <p class="faint section" id="count"></p>`
      : emptyState(t("excl.empty_title"), t("excl.empty_text"),
          can("editor") ? html`<a class="btn btn-primary" href="#/exclusions/new">${icon("plus")} ${t("excl.new")}</a>` : "")}`);
  if (!items.length) return;

  const draw = () => {
    const q = $("#q", root).value.trim().toLowerCase();
    const g = $("#g", root).value;
    const s = $("#s", root).value;
    const p = $("#p", root).checked;
    const shown = items.filter((e) => {
      if (g && String(e.group_id) !== g) return false;
      if (s && e.scope !== s) return false;
      if (p && !["error", "warning"].includes(worstLevel(e.lint))) return false;
      if (!q) return true;
      const hay = [e.rule_id, e.reason, e.reference, ...(e.selectors || []), ...(e.variables || []),
        ...(e.conditions || []).map((c) => c.value), e.raw_text, gname[e.group_id]].join(" ").toLowerCase();
      return hay.includes(q);
    });
    mount($("#rows", root), shown.map((e) => {
      const level = worstLevel(e.lint);
      return html`<tr class="clickable${e.enabled ? "" : " disabled"}" data-id="${e.id}" data-level="${level || ""}">
        <td class="id">${e.rule_id ?? html`<span class="faint">—</span>`}</td>
        <td><div class="cell-main">${what(e)}</div>
          <div class="tags">${html`<span class="tag ${e.scope}">${t("scope." + e.scope)}</span>`}${e.verbatim ? html`<span class="tag">${t("excl.imported")}</span>` : ""}
          ${e.expires_at ? html`<span class="tag steel">${t("excl.expires", { date: e.expires_at.slice(0, 10) })}</span>` : ""}</div>
          ${e.reason ? html`<div class="cell-sub">${e.reason}</div>` : ""}
          ${level === "error" || level === "warning" ? lintList(e.lint.filter((i) => i.level !== "info")) : ""}</td>
        <td>${whereHtml(e)}</td>
        <td>${gname[e.group_id] || ""}</td>
        <td>${can("editor") ? html`<label class="check"><input type="checkbox" data-toggle="${e.id}" ${e.enabled ? "checked" : ""} aria-label="${t("excl.on")}"></label>` : (e.enabled ? t("common.yes") : t("common.no"))}</td>
      </tr>`;
    }));
    $("#count", root).textContent = t("excl.count", { shown: shown.length, total: items.length });
  };
  ["#q", "#g", "#s", "#p"].forEach((sel) => $(sel, root).addEventListener("input", draw));
  draw();

  on(root, "click", "tr.clickable", (ev, tr) => {
    if (ev.target.closest("input, label, a, button")) return;
    location.hash = `#/exclusions/${tr.dataset.id}`;
  });
  on(root, "change", "[data-toggle]", async (ev, box) => {
    const id = Number(box.dataset.toggle);
    try {
      const saved = await patch(`exclusions/${id}`, { enabled: box.checked });
      const item = items.find((e) => e.id === id);
      Object.assign(item, { ...saved, lint: item.lint });
      toast(box.checked ? t("excl.enabled_toast") : t("excl.disabled_toast"));
      draw();
    } catch (e) {
      box.checked = !box.checked;
      toastError(e);
    }
  });
}
