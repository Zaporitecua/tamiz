// Create or edit an exclusion, with a live preview of the SecLang Tamiz will
// write and the linter's findings.

import { del, get, post, put } from "../api.js";
import { can, go, state } from "../app.js";
import { $, $$, debounce, html, icon, mount, on } from "../dom.js";
import { t } from "../i18n.js";
import { busy, codeBlock, confirmDialog, highlightSecLang, lintList, showFormErrors, toast, toastError } from "../ui.js";

const DEFAULT = {
  scope: "conditional", action: "remove_target", selector_type: "id", selectors: [], variables: [],
  engine_mode: "DetectionOnly", conditions: [{ variable: "REQUEST_FILENAME", operator: "beginsWith", value: "", negate: false, transforms: [] }],
  phase: null, log: false, extra_actions: [], raw_text: "", placement: "before", reason: "", reference: "",
  expires_at: "", enabled: true,
};

export async function render(root, [id]) {
  const editing = Boolean(id);
  const groups = await get("groups");
  let ex;
  if (editing) {
    ex = await get(`exclusions/${id}`);
  } else {
    ex = structuredClone(DEFAULT);
    const q = new URLSearchParams(location.hash.split("?")[1] || "");
    const draft = sessionStorage.getItem("tamiz.draft");
    if (q.get("from") && draft) {
      Object.assign(ex, JSON.parse(draft));
      sessionStorage.removeItem("tamiz.draft");
    }
    ex.group_id = ex.group_id || Number(q.get("group")) || (groups[0] && groups[0].id);
  }
  if (!groups.length) {
    mount(root, html`<div class="page-head"><div><h1>${t("excl.new")}</h1></div></div>
      <div class="empty"><h3>${t("eform.need_group")}</h3><p>${t("eform.need_group_text")}</p>
      <a class="btn btn-primary" href="#/groups">${t("groups.new")}</a></div>`);
    return;
  }
  draw(root, ex, groups, editing);
}

function opOptions(selected) {
  const ops = (state.meta && state.meta.operators) || ["beginsWith", "streq", "endsWith", "contains", "rx", "within", "ipMatch", "pm", "eq"];
  return ops.map((o) => html`<option value="${o}" title="@${o}" ${o === selected ? "selected" : ""}>${t("op_word." + o)}</option>`);
}

function condRow(c, i) {
  return html`<div class="cond" data-cond="${i}">
    <div class="neg"><label title="${t("eform.negate")}"><input type="checkbox" data-k="negate" ${c.negate ? "checked" : ""}><span>!</span></label></div>
    <div class="field" data-field="conditions.${i}.variable"><input class="input mono" data-k="variable" value="${c.variable}" list="vars" aria-label="${t("eform.variable")}"></div>
    <div class="field" data-field="conditions.${i}.operator"><select class="select" data-k="operator" aria-label="${t("eform.operator")}">${opOptions(c.operator)}</select></div>
    <div class="field" data-field="conditions.${i}.value"><input class="input mono" data-k="value" value="${c.value}" aria-label="${t("eform.value")}" placeholder="/api/login"></div>
    <button type="button" class="btn btn-quiet btn-icon" data-remove-cond="${i}" aria-label="${t("eform.remove_condition")}">${icon("x")}</button>
    <input type="hidden" data-k="transforms" value="${(c.transforms || []).join(",")}">
  </div>`;
}

function sharedTransforms(conds) {
  const all = (conds || []).map((c) => (c.transforms || []).join(","));
  return all.length && all.every((x) => x === all[0]) ? all[0] : "";
}

function chips(name, values, placeholder) {
  return html`<div class="listbox" data-chips="${name}">
    ${values.map((v) => html`<span class="chip" data-v="${v}">${v}<button type="button" aria-label="${t("common.remove")}">×</button></span>`)}
    <input placeholder="${placeholder}" aria-label="${placeholder}"></div>`;
}

function seg(name, value, options) {
  return html`<div class="segmented" role="radiogroup">${options.map(([v, label]) => html`
    <label><input type="radio" name="${name}" value="${v}" ${v === value ? "checked" : ""}><span>${label}</span></label>`)}</div>`;
}

function draw(root, ex, groups, editing) {
  const readonly = !can("editor");
  mount(root, html`
    <div class="crumbs"><a href="#/exclusions">${t("nav.exclusions")}</a></div>
    <div class="page-head"><div>
      <h1>${editing ? t("eform.edit_title", { id: ex.id }) : t("excl.new")}</h1>
      <p>${editing && ex.rule_id ? html`${t("eform.rule_id")} <span class="id">${ex.rule_id}</span>` : t("eform.intro")}</p></div></div>
    <div class="split form-split">
      <form id="eform" class="panel" novalidate>
        <datalist id="vars">${((state.meta && state.meta.variables) || []).map((v) => html`<option value="${v}">`)}</datalist>
        ${ex.verbatim ? html`<div class="notice"><p><strong>${t("eform.verbatim_title")}</strong></p><p>${t("eform.verbatim_text")}</p></div>` : ""}

        <fieldset class="fieldset">
          <legend>${t("eform.where_title")}</legend>
          <div class="form-grid">
            <div class="field" data-field="group_id"><label for="group">${t("excl.group")}</label>
              <select class="select" id="group" name="group_id">${groups.map((g) => html`<option value="${g.id}" ${g.id === ex.group_id ? "selected" : ""}>${g.name}</option>`)}</select></div>
            <div class="field"><span class="label">${t("excl.on")}</span>
              <label class="check"><input type="checkbox" name="enabled" ${ex.enabled ? "checked" : ""}> ${t("eform.enabled")}</label></div>
          </div>
          <div class="field section" data-field="scope"><span class="label">${t("eform.scope")}</span>
            ${seg("scope", ex.scope, [["conditional", t("scope.conditional_long")], ["global", t("scope.global_long")], ["raw", t("scope.raw_long")]])}
            <span class="hint" id="scope-hint"></span></div>
        </fieldset>

        <fieldset class="fieldset" data-scope="conditional">
          <legend>${t("eform.conditions")}</legend>
          <p>${t("eform.conditions_intro")}</p>
          <div class="conditions" id="conds" data-field="conditions">${ex.conditions.map((c, i) => html`${i ? html`<div class="cond-join">${t("describe.and")}</div>` : ""}${condRow(c, i)}`)}</div>
          <button type="button" class="btn btn-sm section" data-action="add-cond">${icon("plus")} ${t("eform.add_condition")}</button>
        </fieldset>

        <fieldset class="fieldset" data-scope="conditional global">
          <legend>${t("eform.what_title")}</legend>
          <div class="field" data-field="action">
            ${seg("action", ex.action, [["remove_target", t("action_kind.remove_target")], ["remove_rule", t("action_kind.remove_rule")], ["engine_mode", t("action_kind.engine_mode")]])}
            <span class="hint" id="action-hint"></span></div>
          <div class="form-grid section" data-action-not="engine_mode">
            <div class="field" data-field="selector_type"><span class="label">${t("eform.selector_type")}</span>
              ${seg("selector_type", ex.selector_type || "id", [["id", t("selector.id")], ["tag", t("selector.tag")]])}</div>
            <div class="field span-2" data-field="selectors"><label>${t("eform.selectors")}</label>
              ${chips("selectors", ex.selectors || [], t("eform.selectors_ph"))}
              <span class="hint">${t("eform.selectors_hint")}</span></div>
            <div class="field span-2" data-field="variables" data-action-only="remove_target"><label>${t("eform.variables")}</label>
              ${chips("variables", ex.variables || [], "ARGS:password")}
              <span class="hint">${t("eform.variables_hint")}</span></div>
          </div>
          <div class="field section" data-action-only="engine_mode" data-field="engine_mode"><label>${t("eform.engine_mode")}</label>
            <select class="select" name="engine_mode">${["DetectionOnly", "Off"].map((m) => html`<option ${m === ex.engine_mode ? "selected" : ""}>${m}</option>`)}</select></div>
        </fieldset>

        <fieldset class="fieldset" data-scope="raw">
          <legend>${t("eform.raw_title")}</legend>
          <p>${t("eform.raw_intro")}</p>
          <div class="field" data-field="raw_text"><textarea class="textarea mono" name="raw_text" rows="8" spellcheck="false">${ex.raw_text || ""}</textarea></div>
          <div class="field section" data-field="placement"><span class="label">${t("eform.placement")}</span>
            ${seg("placement", ex.placement || "before", [["before", t("placement.before")], ["after", t("placement.after")]])}</div>
        </fieldset>

        <fieldset class="fieldset">
          <legend>${t("eform.why_title")}</legend>
          <div class="form-grid">
            <div class="field span-2" data-field="reason"><label for="reason">${t("eform.reason")}</label>
              <input class="input" id="reason" name="reason" value="${ex.reason || ""}" maxlength="500" placeholder="${t("eform.reason_ph")}"></div>
            <div class="field" data-field="reference"><label for="ref">${t("eform.reference")}</label>
              <input class="input" id="ref" name="reference" value="${ex.reference || ""}" maxlength="300" placeholder="OPS-1234"></div>
            <div class="field" data-field="expires_at"><label for="exp">${t("eform.expires")}</label>
              <input class="input" id="exp" type="date" name="expires_at" value="${(ex.expires_at || "").slice(0, 10)}">
              <span class="hint">${t("eform.expires_hint")}</span></div>
          </div>
        </fieldset>

        <details class="fieldset" data-scope="conditional"><summary>${t("eform.advanced")}</summary>
          <div class="form-grid section">
            <div class="field" data-field="phase"><label for="phase">${t("eform.phase")}</label>
              <select class="select" id="phase" name="phase"><option value="">${t("eform.phase_auto")}</option>
                <option value="1" ${ex.phase === 1 ? "selected" : ""}>1 (${t("eform.phase1")})</option>
                <option value="2" ${ex.phase === 2 ? "selected" : ""}>2 (${t("eform.phase2")})</option></select></div>
            <div class="field"><span class="label">${t("eform.logging")}</span>
              <label class="check"><input type="checkbox" name="log" ${ex.log ? "checked" : ""}> ${t("eform.log")}</label></div>
            <div class="field span-2"><label for="tr">${t("eform.transforms")}</label>
              <input class="input mono" id="tr" placeholder="lowercase" value="${sharedTransforms(ex.conditions)}">
              <span class="hint">${t("eform.transforms_hint")}</span></div>
          </div>
        </details>

        ${readonly ? "" : html`<div class="form-actions">
          ${editing ? html`<button type="button" class="btn btn-danger" data-action="delete">${icon("trash")} ${t("common.delete")}</button>` : ""}
          <a class="btn" href="#/exclusions">${t("common.cancel")}</a>
          <button class="btn btn-primary" type="submit">${editing ? t("common.save") : t("eform.create")}</button></div>`}
      </form>
      <aside class="preview-pane sticky">
        <div><div class="code-title"><span>${t("eform.preview")}</span><span id="placement" class="faint"></span></div>
          <pre class="code" id="preview"></pre></div>
        <div id="errors"></div>
        <div id="lint"></div>
        ${ex.verbatim ? html`<div>${codeBlock(ex.source_text, { title: t("eform.original_text") })}</div>` : ""}
      </aside>
    </div>`);

  const form = $("#eform", root);
  if (readonly) $$("input, select, textarea, button", form).forEach((el) => { el.disabled = true; });

  // ---------------------------------------------------------- read state --
  const chipValues = (name) => $$(`[data-chips="${name}"] .chip`, form).map((c) => c.dataset.v);
  const read = () => {
    const v = {};
    v.scope = form.querySelector("[name=scope]:checked").value;
    v.group_id = Number(form.elements.group_id.value);
    v.enabled = form.elements.enabled.checked;
    v.action = form.querySelector("[name=action]:checked")?.value || "remove_rule";
    v.selector_type = form.querySelector("[name=selector_type]:checked")?.value || "id";
    v.selectors = chipValues("selectors");
    v.variables = v.action === "remove_target" ? chipValues("variables") : [];
    v.engine_mode = v.action === "engine_mode" ? form.elements.engine_mode.value : null;
    v.conditions = $$("[data-cond]", form).map((row) => ({
      variable: $("[data-k=variable]", row).value.trim(),
      operator: $("[data-k=operator]", row).value,
      value: $("[data-k=value]", row).value,
      negate: $("[data-k=negate]", row).checked,
      transforms: $("[data-k=transforms]", row).value.split(",").filter(Boolean),
    }));
    v.phase = form.elements.phase.value ? Number(form.elements.phase.value) : null;
    v.log = form.elements.log.checked;
    v.extra_actions = ex.extra_actions || [];
    v.raw_text = form.elements.raw_text.value;
    v.placement = form.querySelector("[name=placement]:checked")?.value || "before";
    v.reason = form.elements.reason.value.trim();
    v.reference = form.elements.reference.value.trim();
    v.expires_at = form.elements.expires_at.value || null;
    if (v.scope !== "conditional") v.conditions = [];
    if (v.action === "engine_mode") { v.selectors = []; v.selector_type = null; }
    if (ex.id) v.id = ex.id;
    return v;
  };

  const visibility = () => {
    const v = read();
    $$("[data-scope]", form).forEach((el) => { el.hidden = !el.dataset.scope.split(" ").includes(v.scope); });
    const engine = $('[name=action][value="engine_mode"]', form).closest("label");
    engine.hidden = v.scope !== "conditional";
    if (v.scope === "global" && v.action === "engine_mode") $('[name=action][value="remove_rule"]', form).checked = true;
    const action = read().action;
    $$("[data-action-only]", form).forEach((el) => { el.hidden = el.dataset.actionOnly !== action; });
    $$("[data-action-not]", form).forEach((el) => { el.hidden = el.dataset.actionNot === action; });
    $("#scope-hint", form).textContent = t("scope." + v.scope + "_hint");
    $("#action-hint", form).textContent = t("action_kind." + action + "_hint");
  };

  const preview = debounce(async () => {
    try {
      const r = await post("exclusions/preview", read());
      $("#preview", root).innerHTML = String(highlightSecLang(r.rendered || t("eform.preview_incomplete")));
      $("#placement", root).textContent = t("eform.placement_note", {
        placement: t("placement." + r.placement), phase: r.phase ? t("eform.in_phase", { n: r.phase }) : "" });
      mount($("#errors", root), r.errors.length ? html`<div class="notice error">${lintList(r.errors)}</div>` : "");
      mount($("#lint", root), r.lint.length ? html`<h3>${t("eform.lint_title")}</h3>${lintList(r.lint)}` : "");
    } catch { /* preview is best effort */ }
  }, 250);

  const refresh = () => { visibility(); preview(); };
  $("#tr", form).addEventListener("input", (e) => {
    const value = e.target.value.split(/[\s,]+/).filter(Boolean).join(",");
    $$("[data-k=transforms]", form).forEach((h) => { h.value = value; });
  });
  form.addEventListener("input", refresh);
  form.addEventListener("change", refresh);
  refresh();

  // ---------------------------------------------------------- conditions --
  const redrawConds = (conds) => {
    mount($("#conds", form), conds.map((c, i) => html`${i ? html`<div class="cond-join">${t("describe.and")}</div>` : ""}${condRow(c, i)}`));
    refresh();
  };
  on(form, "click", "[data-action=add-cond]", () => {
    const conds = read().conditions;
    conds.push({ variable: conds.length ? "REQUEST_METHOD" : "REQUEST_FILENAME", operator: conds.length ? "streq" : "beginsWith", value: "", negate: false });
    redrawConds(conds);
  });
  on(form, "click", "[data-remove-cond]", (ev, b) => {
    const conds = read().conditions;
    conds.splice(Number(b.dataset.removeCond), 1);
    redrawConds(conds.length ? conds : [structuredClone(DEFAULT.conditions[0])]);
  });

  // ----------------------------------------------------------------- chips --
  const addChips = (box, text) => {
    const input = $("input", box);
    for (const v of text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)) {
      if ($$(".chip", box).some((c) => c.dataset.v === v)) continue;
      const span = document.createElement("span");
      span.className = "chip";
      span.dataset.v = v;
      span.textContent = v;
      const x = document.createElement("button");
      x.type = "button";
      x.textContent = "×";
      x.setAttribute("aria-label", t("common.remove"));
      span.appendChild(x);
      box.insertBefore(span, input);
    }
    input.value = "";
    refresh();
  };
  on(form, "keydown", "[data-chips] input", (ev, input) => {
    const box = input.closest("[data-chips]");
    if (["Enter", ",", " ", "Tab"].includes(ev.key) && input.value.trim()) {
      ev.preventDefault();
      addChips(box, input.value);
    } else if (ev.key === "Backspace" && !input.value) {
      const last = $$(".chip", box).pop();
      if (last) { last.remove(); refresh(); }
    }
  });
  on(form, "paste", "[data-chips] input", (ev, input) => {
    ev.preventDefault();
    addChips(input.closest("[data-chips]"), ev.clipboardData.getData("text"));
  });
  on(form, "focusout", "[data-chips] input", (ev, input) => {
    if (input.value.trim()) addChips(input.closest("[data-chips]"), input.value);
  });
  on(form, "click", ".chip button", (ev, b) => { b.closest(".chip").remove(); refresh(); });
  on(form, "click", "[data-chips]", (ev, box) => { if (ev.target === box) $("input", box).focus(); });

  // ------------------------------------------------------------------ save --
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const v = read();
    await busy($("button[type=submit]", form), async () => {
      try {
        const saved = ex.id ? await put(`exclusions/${ex.id}`, v) : await post("exclusions", { ...v, origin: ex.origin || "ui" });
        toast(ex.id ? t("eform.saved") : t("eform.created", { id: saved.rule_id || saved.id }));
        go(`/exclusions/${saved.id}`);
      } catch (e) {
        showFormErrors(form, e);
      }
    });
  });
  on(form, "click", "[data-action=delete]", async () => {
    if (!await confirmDialog(t("eform.delete_title"), t("eform.delete_confirm"), { danger: true, confirm: t("common.delete") })) return;
    try {
      await del(`exclusions/${ex.id}`);
      toast(t("eform.deleted"));
      go("/exclusions");
    } catch (e) { toastError(e); }
  });
}
