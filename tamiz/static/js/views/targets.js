// Targets list.

import { get, post } from "../api.js";
import { can } from "../app.js";
import { $, html, icon, mount, on } from "../dom.js";
import { t } from "../i18n.js";
import { busy, emptyState, stateRim, targetStatus, timeTag, toastError } from "../ui.js";

export async function render(root) {
  const [targets, groups] = await Promise.all([get("targets"), get("groups")]);
  const names = Object.fromEntries(groups.map((g) => [g.id, g.name]));
  mount(root, html`
    <div class="page-head">
      <div><h1>${t("nav.targets")}</h1><p>${t("targets.intro")}</p></div>
      <div class="page-actions">
        ${can("admin") ? html`<a class="btn btn-primary" href="#/targets/new">${icon("plus")} ${t("target.new")}</a>` : ""}
      </div>
    </div>
    ${targets.length ? html`
      <div class="table-wrap"><table class="table">
        <thead><tr><th>${t("target.name")}</th><th>${t("common.state")}</th><th>${t("target.connection")}</th>
          <th>${t("nav.groups")}</th><th>${t("targets.last_check")}</th><th></th></tr></thead>
        <tbody>${targets.map((x) => row(x, names))}</tbody>
      </table></div>`
      : emptyState(t("targets.empty_title"), t("targets.empty_text"),
          can("admin") ? html`<a class="btn btn-primary" href="#/targets/new">${icon("plus")} ${t("target.new")}</a>` : "")}`);

  on(root, "click", "tr.clickable", (ev, tr) => {
    if (ev.target.closest("button, a")) return;
    location.hash = `#/targets/${tr.dataset.id}`;
  });
  on(root, "click", "[data-check]", async (ev, btn) => {
    const id = btn.dataset.check;
    await busy(btn, async () => {
      try {
        const plan = await post(`targets/${id}/check`, {});
        const x = targets.find((y) => String(y.id) === id);
        x.last_status = plan.summary;
        x.last_check_error = null;
        x.last_check_at = new Date().toISOString();
      } catch (e) {
        toastError(e);
        const x = targets.find((y) => String(y.id) === id);
        x.last_check_error = e.message;
      }
      const x = targets.find((y) => String(y.id) === id);
      $(`tr[data-id="${id}"]`, root).outerHTML = String(row(x, names));
    });
  });
}

function where(x) {
  const c = x.conn || {};
  if (x.transport === "ssh") return `${c.username || "?"}@${c.host || "?"}${c.port && c.port !== 22 ? ":" + c.port : ""}`;
  if (x.transport === "docker") return c.container || "";
  return t("transport." + x.transport);
}

function row(x, names) {
  const st = targetStatus(x);
  const n = (x.last_status && x.last_status.changes) || 0;
  return html`<tr class="clickable${x.enabled ? "" : " disabled"}" data-id="${x.id}">
    <td><div class="cell-main">${x.name}</div><div class="cell-sub">${[x.environment, x.description].filter(Boolean).join(", ")}</div></td>
    <td>${stateRim(st === "disabled" ? "skipped" : st, t("tstate." + st, { n }))}
      ${x.last_check_error ? html`<div class="cell-sub">${x.last_check_error}</div>` : ""}</td>
    <td><div class="mono">${where(x)}</div><div class="cell-sub">${t("transport." + x.transport)}</div></td>
    <td>${x.group_ids.length ? x.group_ids.map((g) => names[g]).filter(Boolean).join(", ") : html`<span class="faint">${t("common.none")}</span>`}</td>
    <td>${x.last_check_at ? timeTag(x.last_check_at) : html`<span class="faint">${t("common.never")}</span>`}</td>
    <td class="actions">${x.enabled ? html`<button type="button" class="btn btn-sm" data-check="${x.id}">${icon("refresh")} ${t("target.check")}</button>` : ""}</td>
  </tr>`;
}
