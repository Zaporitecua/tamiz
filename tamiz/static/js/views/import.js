// Import exclusions that already exist on a server (or in pasted text).

import { get, post } from "../api.js";
import { can, go } from "../app.js";
import { $, $$, html, icon, mount, on } from "../dom.js";
import { t, tCode } from "../i18n.js";
import { busy, codeBlock, emptyState, toast, toastError } from "../ui.js";

export async function render(root) {
  if (!can("editor")) { mount(root, emptyState(t("imp.title"), t("common.need_editor"))); return; }
  const [targets, groups] = await Promise.all([get("targets"), get("groups")]);
  const remote = targets.filter((x) => x.transport !== "export");
  mount(root, html`
    <div class="page-head"><div><h1>${t("imp.title")}</h1><p>${t("imp.intro")}</p></div></div>
    <div class="panel">
      <div class="field"><span class="label">${t("an.source")}</span>
        <div class="segmented"><label><input type="radio" name="mode" value="target" ${remote.length ? "checked" : "disabled"}><span>${t("imp.from_target")}</span></label>
          <label><input type="radio" name="mode" value="paste" ${remote.length ? "" : "checked"}><span>${t("an.paste")}</span></label></div></div>
      <div class="form-grid section" data-mode="target">
        <div class="field"><label for="tg">${t("an.target")}</label>
          <select class="select" id="tg"><option value="">${t("imp.choose_target")}</option>${remote.map((x) => html`<option value="${x.id}">${x.name}</option>`)}</select>
          <span class="hint">${t("imp.paths_hint")}</span></div>
        <div class="field"><label for="file">${t("imp.file")}</label><select class="select" id="file" disabled></select></div>
      </div>
      <div class="section" data-mode="paste">
        <div class="field"><label for="txt">${t("imp.paste_label")}</label><textarea class="textarea mono" id="txt" rows="8" spellcheck="false"></textarea></div>
      </div>
      <div class="form-actions"><button class="btn btn-primary" data-action="scan">${t("imp.scan")}</button></div>
    </div>
    <div id="scan" class="section"></div>`);

  const sync = () => {
    const mode = root.querySelector("[name=mode]:checked").value;
    $$("[data-mode]", root).forEach((el) => { el.hidden = el.dataset.mode !== mode; });
  };
  root.addEventListener("change", (ev) => { if (ev.target.name === "mode") sync(); });
  sync();

  $("#tg", root).addEventListener("change", async (ev) => {
    const sel = $("#file", root);
    sel.disabled = true;
    mount(sel, "");
    if (!ev.target.value) return;
    try {
      const r = await get(`targets/${ev.target.value}/import`);
      mount(sel, r.files.length ? r.files.map((f) => html`<option>${f}</option>`) : html`<option value="">${t("imp.no_files")}</option>`);
      sel.disabled = !r.files.length;
      if (!r.patterns.length) toast(t("imp.no_patterns"), "warn", 7000);
    } catch (e) { toastError(e); }
  });

  let scanState = null;
  on(root, "click", "[data-action=scan]", async (ev, b) => {
    await busy(b, async () => {
      try {
        const mode = root.querySelector("[name=mode]:checked").value;
        if (mode === "target") {
          const tid = $("#tg", root).value;
          const path = $("#file", root).value;
          if (!tid || !path) { toast(t("imp.choose_file"), "warn"); return; }
          const r = await post(`targets/${tid}/import/scan`, { path });
          scanState = { ...r, target_id: Number(tid), path };
        } else {
          const text = $("#txt", root).value;
          const r = await post("import/scan", { text });
          scanState = { ...r, text };
        }
        drawScan($("#scan", root), scanState, groups);
      } catch (e) { toastError(e); }
    });
  });

  on(root, "click", "[data-action=commit]", async (ev, b) => {
    const box = $("#scan", root);
    const items = $$(".proposal", box).filter((p) => $("[data-k=sel]", p).checked).map((p) => {
      const g = $("[data-k=group]", p).value;
      return {
        key: p.dataset.key,
        group_id: g.startsWith("new:") ? null : Number(g),
        new_group: g.startsWith("new:") ? g.slice(4) : undefined,
        as_raw: $("[data-k=raw]", p)?.checked || false,
        placement: $("[data-k=placement]", p)?.value,
      };
    });
    if (!items.length) { toast(t("imp.nothing_selected"), "warn"); return; }
    const renumber = $("#renumber", box).checked;
    const retire = $("#retire", box)?.checked || false;
    await busy(b, async () => {
      try {
        let r;
        if (scanState.target_id) {
          r = await post(`targets/${scanState.target_id}/import/commit`, {
            path: scanState.path, file_hash: scanState.file_hash, items, renumber, retire });
        } else {
          r = await post("import/commit", { text: scanState.text, items, renumber });
        }
        toast(t("imp.done", { n: r.created.length }));
        if (retire && scanState.target_id) go(`/targets/${scanState.target_id}/changes`);
        else go("/exclusions");
      } catch (e) { toastError(e); }
    });
  });
}

function groupSelect(p, groups) {
  const existing = groups.find((g) => g.slug === p.group_hint);
  return html`<select class="select" data-k="group">
    ${existing ? "" : html`<option value="new:${p.group_hint}">${t("imp.new_group", { name: p.group_hint })}</option>`}
    ${groups.map((g) => html`<option value="${g.id}" ${existing && existing.id === g.id ? "selected" : ""}>${g.name}</option>`)}
  </select>`;
}

function drawScan(box, s, groups) {
  const props = s.proposals;
  if (!props.length) { mount(box, emptyState(t("imp.empty_title"), t("imp.empty_text"))); return; }
  const excl = props.filter((p) => p.kind === "exclusion").length;
  mount(box, html`
    <div class="section-head"><div><h2>${t("imp.found", { n: excl, other: props.length - excl })}</h2>
      <p>${s.path ? html`<span class="mono">${s.path}</span>` : ""}</p></div></div>
    ${s.errors.length ? html`<div class="notice error">${s.errors.map((e) => html`<p>${tCode("perr." + e.code, e)} (${t("imp.line", { n: e.line })})</p>`)}</div>` : ""}
    ${s.warnings.length ? html`<div class="notice warn">${s.warnings.map((e) => html`<p>${tCode("perr." + e.code, e)} (${t("imp.line", { n: e.line })})</p>`)}</div>` : ""}
    <div class="table-wrap">${props.map((p) => html`
      <div class="proposal" data-key="${p.key}">
        <input type="checkbox" data-k="sel" ${p.selected ? "checked" : ""} aria-label="${t("imp.select")}">
        <div class="stack">
          <div class="row"><span class="faint">${t("imp.line", { n: p.line })}</span>
            ${p.kind === "exclusion" ? (p.structured ? html`<span class="tag ok">${t("imp.recognised")}</span>` : html`<span class="tag">${t("imp.as_raw")}</span> <span class="faint">${tCode("raw_reason." + (p.raw_reason || "").replace(/^(action|operator)_.*/, "$1"), { detail: p.raw_reason })}</span>`)
              : html`<span class="tag">${t("imp.not_exclusion")}</span>`}
            ${p.duplicate_of ? html`<span class="tag steel">${t("imp.duplicate", { id: p.duplicate_of })}</span>` : ""}
            ${p.id_conflicts.length ? html`<span class="tag error">${t("imp.id_conflict", { ids: p.id_conflicts.join(", ") })}</span>` : ""}</div>
          ${p.comment ? html`<div class="cell-sub">${p.comment}</div>` : ""}
          ${codeBlock(p.text)}
        </div>
        <div class="stack">
          <div class="field"><label>${t("excl.group")}</label>${groupSelect(p, groups)}</div>
          ${p.structured ? html`<label class="check"><input type="checkbox" data-k="raw"> ${t("imp.keep_raw")}</label>` : html`
            <div class="field"><label>${t("eform.placement")}</label><select class="select" data-k="placement">
              <option value="before" ${p.placement === "before" ? "selected" : ""}>${t("placement.before")}</option>
              <option value="after" ${p.placement === "after" ? "selected" : ""}>${t("placement.after")}</option></select></div>`}
        </div>
      </div>`)}</div>
    <div class="panel section">
      <label class="check"><input type="checkbox" id="renumber" checked> ${t("imp.renumber")}</label>
      <p class="hint faint">${t("imp.renumber_hint")}</p>
      ${s.target_id && s.can_retire ? html`<label class="check section"><input type="checkbox" id="retire" checked> ${t("imp.retire")}</label>
        <p class="hint faint">${t("imp.retire_hint")}</p>` : ""}
      <div class="form-actions"><button class="btn btn-primary" data-action="commit">${icon("import")} ${t("imp.commit")}</button></div>
    </div>`);
}
