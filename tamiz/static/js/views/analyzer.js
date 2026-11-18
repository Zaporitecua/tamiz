// Log analyzer: read a target's ModSecurity log (or a pasted one), group the
// matches, and turn false positives into exclusion drafts.

import { get, post } from "../api.js";
import { can, go } from "../app.js";
import { $, $$, html, icon, mount, on } from "../dom.js";
import { condition } from "../describe.js";
import { t } from "../i18n.js";
import { busy, emptyState, toast, toastError } from "../ui.js";

let last = null;   // keep the last result while navigating to the form and back

export async function render(root) {
  // Reading a server's logs needs the editor role; viewers can paste a log.
  const targets = (can("editor") ? await get("targets") : []).filter((x) => x.transport !== "export" && x.enabled
    && ((x.logs || {}).audit_log || (x.logs || {}).error_log));
  mount(root, html`
    <div class="page-head"><div><h1>${t("nav.analyzer")}</h1><p>${t("an.intro")}</p></div></div>
    <form id="aform" class="panel" novalidate>
      <div class="field"><span class="label">${t("an.source")}</span>
        <div class="segmented" role="radiogroup">
          <label><input type="radio" name="mode" value="target" ${targets.length ? "checked" : "disabled"}><span>${t("an.from_target")}</span></label>
          <label><input type="radio" name="mode" value="paste" ${targets.length ? "" : "checked"}><span>${t("an.paste")}</span></label>
        </div></div>
      <div class="form-grid section" data-mode="target">
        <div class="field"><label for="tg">${t("an.target")}</label>
          <select class="select" id="tg">${targets.map((x) => html`<option value="${x.id}">${x.name}</option>`)}</select></div>
        <div class="field"><label for="src">${t("an.log")}</label>
          <select class="select" id="src"><option value="audit_log">${t("an.audit_log")}</option><option value="error_log">${t("an.error_log")}</option></select></div>
        <div class="field"><label for="bytes">${t("an.size")}</label>
          <select class="select" id="bytes"><option value="1048576">1 MB</option><option value="5242880" selected>5 MB</option><option value="20971520">20 MB</option></select>
          <span class="hint">${t("an.size_hint")}</span></div>
      </div>
      <div class="section" data-mode="paste">
        <div class="field"><label for="txt">${t("an.paste_label")}</label>
          <textarea class="textarea mono" id="txt" rows="8" spellcheck="false" placeholder="---ICmPEb5c---A--"></textarea>
          <span class="hint">${t("an.formats")}</span></div>
        <div class="field section"><label for="file">${t("an.file")}</label><input type="file" id="file" accept=".log,.txt,.json,text/plain"></div>
      </div>
      <p class="hint faint section">${t("an.privacy")}</p>
      <div class="form-actions"><button class="btn btn-primary" type="submit">${icon("analyzer")} ${t("an.run")}</button></div>
    </form>
    <div id="results" class="section"></div>`);

  const form = $("#aform", root);
  const sync = () => {
    const mode = form.querySelector("[name=mode]:checked").value;
    $$("[data-mode]", form).forEach((el) => { el.hidden = el.dataset.mode !== mode; });
  };
  form.addEventListener("change", sync);
  sync();
  $("#file", form).addEventListener("change", async (ev) => {
    const f = ev.target.files[0];
    if (!f) return;
    if (f.size > 20 * 1024 * 1024) { toast(t("an.too_big"), "error"); return; }
    $("#txt", form).value = await f.text();
  });
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    await busy($("button[type=submit]", form), async () => {
      try {
        const mode = form.querySelector("[name=mode]:checked").value;
        last = mode === "target"
          ? await post(`targets/${$("#tg", form).value}/analyze`, { source: $("#src", form).value, bytes: Number($("#bytes", form).value) })
          : await post("analyze", { text: $("#txt", form).value });
        results($("#results", root), last);
      } catch (e) { toastError(e); }
    });
  });
  if (last) results($("#results", root), last);
}

function results(box, r) {
  if (!r.transactions) {
    mount(box, emptyState(t("an.nothing_title"), t("an.nothing_text")));
    return;
  }
  const scoring = r.scoring_rules.map((s) => `${s.rule_id} (${s.count})`).join(", ");
  mount(box, html`
    <div class="section-head"><div><h2>${t("an.findings", { n: r.findings.length })}</h2>
      <p>${t("an.summary", { tx: r.transactions, blocked: r.blocked, formats: r.formats.join(", ") || "?" })}</p></div>
      ${can("editor") ? html`<button class="btn" data-action="merge" disabled>${t("an.merge")}</button>` : ""}</div>
    ${scoring ? html`<div class="notice">${t("an.scoring", { rules: scoring })}</div>` : ""}
    <div class="section">${r.findings.length ? r.findings.map((f, i) => finding(f, i)) : html`<p class="muted">${t("an.only_scoring")}</p>`}</div>`);

  on(box, "click", "[data-create]", (ev, b) => openDraft([r.findings[Number(b.dataset.create)]]));
  on(box, "change", "[data-pick]", () => {
    const picked = $$("[data-pick]:checked", box);
    const btn = $("[data-action=merge]", box);
    if (btn) btn.disabled = picked.length < 2;
  });
  on(box, "click", "[data-action=merge]", () => {
    const picked = $$("[data-pick]:checked", box).map((c) => r.findings[Number(c.dataset.pick)]);
    // Only findings on the same path and the same variable can share one
    // exclusion; otherwise the result would exclude more than what was seen.
    const key = (f) => JSON.stringify([f.suggestion.conditions, f.suggestion.action, f.suggestion.variables]);
    if (new Set(picked.map(key)).size > 1) { toast(t("an.merge_mismatch"), "warn", 6000); return; }
    openDraft(picked);
  });
}

function finding(f, i) {
  const s = f.suggestion;
  return html`<article class="finding${f.covered_by.length ? " covered" : ""}">
    <div>
      <h3><span class="id">${f.rule_id}</span> ${f.msg || ""} ${f.category ? html`<span class="tag">${f.category}</span>` : ""}</h3>
      <div class="where">${f.host ? html`${f.host} ` : ""}${f.path}${f.variable ? html` <span class="faint">→</span> ${f.variable}` : ""}</div>
      ${f.paths.length > 1 || f.wildcard ? html`<div class="cell-sub">${t("an.paths_seen")}: <span class="mono">${f.paths.join("  ")}</span></div>` : ""}
      <div class="cell-sub">${f.methods.join(", ")}</div>
    </div>
    <div class="counts"><b>${f.count}</b>${t("an.hits")}<br><span class="${f.blocked ? "" : "faint"}">${t("an.blocked_n", { n: f.blocked })}</span></div>
    ${f.samples.length ? html`<details class="samples"><summary>${t("an.samples")}</summary><pre class="code wrap">${f.samples.join("\n")}</pre></details>` : ""}
    <div class="actions">
      ${f.covered_by.length ? html`<span class="tag ok">${t("an.covered", { ids: f.covered_by.map((x) => "#" + x).join(", ") })}</span>` : ""}
      <span class="faint">${t("an.suggestion")}: ${t("action_kind." + s.action)}${s.variables.length ? ` ${s.variables.join(", ")}` : ""}, ${s.conditions.map(condition).join(` ${t("describe.and")} `)}</span>
      ${can("editor") ? html`<label class="check"><input type="checkbox" data-pick="${i}"> ${t("an.select")}</label>
        <button class="btn btn-sm btn-primary" data-create="${i}">${icon("plus")} ${t("an.create")}</button>` : ""}
    </div>
  </article>`;
}

function openDraft(findings) {
  const base = structuredClone(findings[0].suggestion);
  const selectors = [...new Set(findings.flatMap((f) => f.suggestion.selectors))];
  const variables = [...new Set(findings.flatMap((f) => f.suggestion.variables))];
  const allTarget = findings.every((f) => f.suggestion.action === "remove_target");
  const draft = { ...base, selectors, variables: allTarget ? variables : [],
    action: allTarget ? "remove_target" : "remove_rule", origin: "analyzer",
    reason: findings.length > 1 ? t("an.merged_reason", { n: findings.length }) : base.reason };
  sessionStorage.setItem("tamiz.draft", JSON.stringify(draft));
  go("/exclusions/new?from=analyzer");
}
