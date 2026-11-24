// Global history: every change, apply, import and login.

import { get } from "../api.js";
import { $, debounce, html, mount, on } from "../dom.js";
import { historyText } from "../describe.js";
import { t } from "../i18n.js";
import { timeTag } from "../ui.js";

const LINKS = { target: "targets", exclusion: "exclusions", group: "groups" };

export async function render(root) {
  mount(root, html`
    <div class="page-head"><div><h1>${t("nav.history")}</h1><p>${t("hist.intro")}</p></div></div>
    <div class="toolbar">
      <input class="input grow" type="search" id="q" placeholder="${t("hist.search")}">
      <select class="select" id="e"><option value="">${t("hist.all")}</option>
        <option value="target">${t("nav.targets")}</option><option value="exclusion">${t("nav.exclusions")}</option>
        <option value="group">${t("nav.groups")}</option><option value="user">${t("hist.users")}</option></select>
    </div>
    <ul class="activity" id="list"></ul>
    <div class="section"><button type="button" class="btn" id="more" hidden>${t("hist.more")}</button></div>`);

  let lastId = null;
  const load = async (append) => {
    const q = $("#q", root).value.trim();
    const e = $("#e", root).value;
    const params = new URLSearchParams({ limit: "60" });
    if (q) params.set("q", q);
    if (e) params.set("entity", e);
    if (append && lastId) params.set("before", String(lastId));
    const rows = await get(`history?${params}`);
    const items = rows.map((h) => html`<li><span>${timeTag(h.at)}</span><span>
      <span class="who">${h.actor}</span> ${t("action." + h.action)}
      ${h.entity && h.entity_id && LINKS[h.entity] ? html` <a href="#/${LINKS[h.entity]}/${h.entity_id}">${t("hist.open")}</a>` : ""}
      ${historyText(h) ? html`<br><span class="${h.ok ? "muted" : "bad"}">${historyText(h)}</span>` : ""}</span></li>`);
    const list = $("#list", root);
    if (append) list.insertAdjacentHTML("beforeend", items.map(String).join(""));
    else mount(list, items.length ? items : html`<li class="muted">${t("hist.empty")}</li>`);
    lastId = rows.length ? rows[rows.length - 1].id : lastId;
    $("#more", root).hidden = rows.length < 60;
  };
  $("#q", root).addEventListener("input", debounce(() => load(false), 300));
  $("#e", root).addEventListener("change", () => load(false));
  on(root, "click", "#more", () => load(true));
  await load(false);
}
