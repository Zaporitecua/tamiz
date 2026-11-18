// Target detail: pending changes and apply, load order, files and groups,
// diagnosis, configuration and history.

import { del, download, get, post, put } from "../api.js";
import { can, go } from "../app.js";
import { $, $$, html, icon, mount, on } from "../dom.js";
import { applySummary, historyText } from "../describe.js";
import { t, tCode } from "../i18n.js";
import {
  busy, codeBlock, confirmDialog, copyButton, diffBlock, emptyState, errorText, modal,
  stateRim, targetStatus, timeTag, toast, toastError,
} from "../ui.js";

const TABS = ["changes", "order", "files", "diagnose", "config", "history"];

export async function render(root, [id, tab]) {
  tab = TABS.includes(tab) ? tab : "changes";
  const [target, groups] = await Promise.all([get(`targets/${id}`), get("groups")]);
  const st = targetStatus(target);
  mount(root, html`
    <div class="crumbs"><a href="#/targets">${t("nav.targets")}</a></div>
    <div class="page-head">
      <div><h1>${target.name}</h1>
        <p>${stateRim(st === "disabled" ? "skipped" : st, t("tstate." + st, { n: (target.last_status || {}).changes || 0 }))}
          <span class="faint">${[target.environment, t("transport." + target.transport), target.description].filter(Boolean).join(", ")}</span></p></div>
      <div class="page-actions">
        ${can("admin") ? html`<a class="btn" href="#/targets/${id}/edit">${icon("edit")} ${t("common.edit")}</a>` : ""}
      </div>
    </div>
    <nav class="tabs" role="tablist">
      ${TABS.filter((x) => x !== "diagnose" || can("admin")).map((x) =>
        html`<a href="#/targets/${id}/${x}" role="tab" aria-selected="${x === tab}">${t("ttab." + x)}</a>`)}
    </nav>
    <div id="tab"></div>`);
  const pane = $("#tab", root);
  const views = { changes, order, files, diagnose, config, history };
  await views[tab](pane, target, groups);
}

// ----------------------------------------------------------------- changes --
async function changes(pane, target) {
  let force = new Set();
  const isExport = target.transport === "export";

  async function load(btn) {
    const run = async () => {
      try {
        const plan = await post(`targets/${target.id}/check`, { force: [...force] });
        drawPlan(plan);
      } catch (e) {
        mount(pane, html`<div class="notice error"><p><strong>${t("plan.check_failed")}</strong></p><p>${errorText(e)}</p>
          ${e.code === "host_key_mismatch" ? html`<p>${t("plan.host_key_help", e.params)}</p>` : ""}</div>
          <p class="section"><button class="btn" data-action="recheck">${icon("refresh")} ${t("plan.retry")}</button></p>`);
      }
    };
    if (btn) await busy(btn, run); else await run();
  }

  function drawPlan(plan) {
    const s = plan.summary;
    const changed = plan.ops.filter((o) => o.action !== "none");
    const unchanged = plan.ops.filter((o) => o.action === "none");
    const pendingReview = (target.reviews || []).find((r) => r.status === "pending" && r.plan_hash === s.hash);
    const approved = (target.reviews || []).find((r) => r.status === "approved" && r.plan_hash === s.hash);
    mount(pane, html`
      <div class="plan-bar">
        <div><div class="summary">${stateRim(s.status, t("plan.status_" + s.status, { n: s.changes }))}</div>
          ${target.last_check_at ? html`<div class="cell-sub">${t("plan.checked")} ${timeTag(new Date().toISOString())}</div>` : ""}</div>
        <div class="row">
          <button class="btn" data-action="recheck">${icon("refresh")} ${t("target.check")}</button>
          ${actions(s, isExport, pendingReview, approved)}
        </div>
      </div>
      ${plan.warnings.length ? html`<div class="notice warn">${plan.warnings.map((w) => html`<p>${tCode("pwarn." + w.code, w)}</p>`)}</div>` : ""}
      ${target.require_review && s.status === "pending" ? reviewBox(pendingReview, approved) : ""}
      ${changed.length ? changed.map((o) => fileOp(o)) : html`<p class="muted">${t("plan.nothing")}</p>`}
      ${unchanged.length ? html`<details class="section"><summary>${t("plan.unchanged", { n: unchanged.length })}</summary>
        <div class="section">${unchanged.map((o) => fileOp(o))}</div></details>` : ""}
    `);
    pane.dataset.hash = s.hash;
  }

  function actions(s, exp, pendingReview, approved) {
    if (!can("editor") || s.status !== "pending") return "";
    if (exp) {
      return html`<button class="btn" data-action="bundle">${icon("download")} ${t("plan.bundle")}</button>
        <button class="btn btn-primary" data-action="mark">${icon("check")} ${t("plan.mark_deployed")}</button>`;
    }
    if (target.require_review && !approved) {
      return pendingReview ? "" : html`<button class="btn btn-primary" data-action="request-review">${t("review.request")}</button>`;
    }
    return html`<label class="check"><input type="checkbox" id="reload" checked> ${t("plan.reload")}</label>
      <button class="btn btn-primary" data-action="apply" ${approved ? html`data-review="${approved.id}"` : ""}>${icon("apply")} ${t("plan.apply")}</button>`;
  }

  function reviewBox(pendingReview, approved) {
    if (approved) return html`<div class="notice ok">${t("review.approved_by", { who: approved.decided_by })}</div>`;
    if (!pendingReview) return html`<div class="notice">${t("review.needed")}</div>`;
    return html`<div class="notice"><p>${t("review.waiting", { who: pendingReview.requested_by })}</p>
      ${pendingReview.note ? html`<p>“${pendingReview.note}”</p>` : ""}
      ${can("editor") ? html`<div class="row"><button class="btn btn-sm btn-primary" data-review-decide="approve" data-id="${pendingReview.id}">${t("review.approve")}</button>
        <button class="btn btn-sm btn-danger" data-review-decide="reject" data-id="${pendingReview.id}">${t("review.reject")}</button></div>` : ""}</div>`;
  }

  function fileOp(o) {
    const blocked = o.action === "blocked";
    const forceable = o.blocked.length && o.blocked.every((b) => b === "drift" || b === "foreign");
    return html`<article class="file-op${blocked ? " blocked" : ""}">
      <header>
        <span class="mono">${o.path}</span>
        <span class="row">${stateRim(o.action === "none" ? "in_sync" : o.action, t("op." + o.action))}
          ${o.forced ? html`<span class="tag error">${t("plan.forced")}</span>` : ""}
          ${forceable && can("editor") ? html`<button class="btn btn-sm btn-danger" data-force="${o.path}">${o.forced ? t("plan.unforce") : t("plan.force")}</button>` : ""}</span>
      </header>
      <div class="units">
        ${o.units.map((u) => html`<div class="row">${stateRim(u.state, t("ustate." + u.state))}
          <span>${u.group.startsWith("tamiz-keep") ? t("plan.keep_file") : html`<a href="#/groups">${u.group_name || u.group}</a>`}</span>
          ${u.placement ? html`<span class="faint">${t("placement." + u.placement)}</span>` : ""}
          ${u.count ? html`<span class="faint">${t("plan.n_exclusions", { n: u.count })}</span>` : ""}</div>`)}
        ${o.blocked.map((b) => html`<div class="notice error">${tCode("blocked." + b.split(":")[0], { detail: b })}</div>`)}
        ${o.retirements.length ? html`<div class="notice">${t("plan.retirement")}</div>` : ""}
      </div>
      ${o.diff ? diffBlock(o.diff) : ""}
    </article>`;
  }

  // ------------------------------------------------------------ handlers --
  on(pane, "click", "[data-action=recheck]", (ev, b) => load(b));
  on(pane, "click", "[data-force]", (ev, b) => {
    const p = b.dataset.force;
    if (force.has(p)) force.delete(p); else force.add(p);
    load(b);
  });
  on(pane, "click", "[data-action=apply]", async (ev, b) => {
    const reload = $("#reload", pane)?.checked ?? true;
    const ok = await confirmDialog(t("plan.apply_confirm_title", { name: target.name }),
      reload ? t("plan.apply_confirm") : t("plan.apply_confirm_noreload"), { confirm: t("plan.apply") });
    if (!ok) return;
    await busy(b, async () => {
      try {
        const res = await post(`targets/${target.id}/apply`, {
          plan_hash: pane.dataset.hash, reload, force: [...force],
          review_id: b.dataset.review ? Number(b.dataset.review) : undefined,
        });
        showApplyResult(res);
        force = new Set();
        await load();
      } catch (e) { toastError(e); }
    });
  });
  on(pane, "click", "[data-action=bundle]", async (ev, b) => {
    await busy(b, () => download(`targets/${target.id}/bundle`, "tamiz.zip").catch(toastError));
  });
  on(pane, "click", "[data-action=mark]", async (ev, b) => {
    const ok = await confirmDialog(t("plan.mark_title"), t("plan.mark_confirm"), { confirm: t("plan.mark_deployed") });
    if (!ok) return;
    await busy(b, async () => {
      try {
        await post(`targets/${target.id}/mark-deployed`, { plan_hash: pane.dataset.hash });
        toast(t("plan.marked"));
        await load();
      } catch (e) { toastError(e); }
    });
  });
  on(pane, "click", "[data-action=request-review]", () => {
    modal({
      title: t("review.request"),
      body: html`<div class="field"><label for="rnote">${t("review.note")}</label><textarea class="textarea" id="rnote" rows="3"></textarea>
        <span class="hint">${t("review.note_hint")}</span></div>`,
      actions: [{ label: t("common.cancel") }, {
        label: t("review.request"), kind: "primary", onClick: async (d) => {
          await post(`targets/${target.id}/reviews`, { plan_hash: pane.dataset.hash, note: $("#rnote", d).value });
          toast(t("review.requested"));
          go(`/targets/${target.id}/changes`);
        },
      }],
    });
  });
  on(pane, "click", "[data-review-decide]", async (ev, b) => {
    await busy(b, async () => {
      try {
        await post(`targets/${target.id}/reviews/${b.dataset.id}/${b.dataset.reviewDecide}`, {});
        toast(t("review.decided_" + b.dataset.reviewDecide));
        go(`/targets/${target.id}/changes`);
      } catch (e) { toastError(e); }
    });
  });

  mount(pane, html`<div class="loading">${t("plan.checking", { name: target.name })}</div>`);
  if (!target.enabled) {
    mount(pane, html`<div class="notice">${t("plan.disabled")}</div>`);
    return;
  }
  await load();
}

export function showApplyResult(res) {
  modal({
    title: t("apply.result_" + res.status),
    wide: true,
    body: html`<p>${applySummary(res.summary_code, res.summary_params, res.summary)}</p>${stepsList(res.steps)}`,
    actions: [{ label: t("common.close"), kind: "primary" }],
  });
  if (res.status === "ok") toast(t("apply.done"));
}

export function stepsList(steps) {
  return html`<ol class="steps">${steps.map((s) => html`
    <li class="${s.status}">
      <div class="step-name">${t("step." + s.name)} ${s.status !== "ok" ? html`<span class="tag ${s.status === "failed" ? "error" : ""}">${t("state." + s.status)}</span>` : ""}</div>
      ${s.detail ? html`<div class="step-detail">${tCode("sdetail." + s.detail, { detail: s.detail })}</div>` : ""}
      ${stepData(s)}
      ${s.commands.map((c) => html`<details class="cmd"><summary>$ ${c.command} <span class="${c.exit_code ? "" : "faint"}">(${t("apply.exit", { code: c.exit_code })}, ${c.duration_ms} ms)</span></summary>
        <pre class="code wrap">${[c.stdout, c.stderr].filter(Boolean).join("\n") || t("apply.no_output")}</pre></details>`)}
    </li>`)}</ol>`;
}

function stepData(s) {
  const d = s.data || {};
  if (s.name === "permissions" && d.paths) {
    return html`<ul>${d.paths.map((p) => html`<li><span class="mono">${p.path}</span>: ${t("perm." + p.problem)} ${p.detail ? html`<span class="faint">(${p.detail})</span>` : ""}</li>`)}</ul>`;
  }
  if (s.name === "verify") {
    const parts = [];
    if (d.rules_loaded) {
      const r = d.rules_loaded;
      const sum = (a) => a.reduce((x, y) => x + y, 0);
      if (r.before) parts.push(html`<li>${t("verify.rules", { before: sum(r.before), after: sum(r.after), exp: r.expected_delta, obs: r.observed_delta })}</li>`);
    }
    if (d.load_order && d.load_order.checks) {
      for (const c of d.load_order.checks) {
        parts.push(html`<li>${stateRim(c.status, t("lo." + c.status))} <span class="mono">${c.path}</span></li>`);
      }
    } else if (d.load_order && d.load_order.skipped) {
      parts.push(html`<li class="faint">${t("verify.no_load_order")}</li>`);
    }
    if (d.selinux && d.selinux.enabled) {
      for (const [p, f] of Object.entries(d.selinux.files || {})) {
        parts.push(html`<li>${stateRim(f.status === "ok" ? "ok" : "error", t("selinux." + f.status))} <span class="mono">${p}</span> <span class="faint">${f.label}</span></li>`);
      }
    }
    return parts.length ? html`<ul class="plain">${parts}</ul>` : "";
  }
  if (s.name === "write" && d.selinux) {
    return html`<div class="cell-sub">${d.selinux.map((x) => html`<div>SELinux ${x.status}: <span class="mono">${x.path}</span> ${x.label}</div>`)}</div>`;
  }
  return "";
}

// ---------------------------------------------------------------- order ----
async function order(pane, target) {
  mount(pane, html`<div class="loading">${t("order.loading")}</div>`);
  let report;
  try {
    report = await get(`targets/${target.id}/load-order`);
  } catch (e) {
    mount(pane, html`<div class="notice error">${errorText(e)}</div>`);
    return;
  }
  if (!report.entries.length) {
    mount(pane, html`<div class="notice warn">${report.notes.map((n) => html`<p>${tCode("lonote." + n.code, n)}</p>`)}</div>
      <p class="muted section">${t("order.how")}</p>`);
    return;
  }
  // Collapse runs of CRS rule files into one woven band.
  const bands = [];
  for (const e of report.entries) {
    const last = bands[bands.length - 1];
    if (e.role === "crs_rules" && last && last.role === "crs_rules" && last.depth === e.depth) {
      last.count++; last.lastOrder = e.order; last.lastPath = e.path; continue;
    }
    bands.push({ ...e, count: 1, lastOrder: e.order, lastPath: e.path });
  }
  const checks = Object.fromEntries(report.checks.map((c) => [c.path, c]));
  const base = (p) => p.split("/").pop();
  const dir = (p) => p.slice(0, p.length - base(p).length);
  mount(pane, html`
    <div class="section-head"><div><h2>${t("order.title")}</h2><p>${t("order.intro", { source: t("lsource." + report.source) })}</p></div>
      <button class="btn" data-action="reload-order">${icon("refresh")} ${t("order.refresh")}</button></div>
    <div class="stack-wrap">
      <ol class="sieves">${bands.map((b) => {
        const chk = checks[b.path];
        const wrong = chk && chk.status !== "ok";
        const cls = ["sieve", `depth-${Math.min(b.depth, 3)}`];
        if (b.role === "crs_rules") cls.push("crs");
        if (b.role === "crs_before" || b.role === "crs_after") cls.push("crs-slot");
        if (b.role === "managed") cls.push("managed");
        if (wrong) cls.push("wrong");
        if (!b.exists) cls.push("missing");
        const ord = b.count > 1 ? `${b.order}–${b.lastOrder}` : `${b.order}`;
        const label = b.role === "crs_rules" && b.count > 1
          ? html`${t("order.crs_band", { n: b.count })}<br><span class="faint mono">${base(b.path)} … ${base(b.lastPath)}</span>`
          : html`<span class="faint">${dir(b.path)}</span><b>${base(b.path)}</b>`;
        const why = b.role === "managed"
          ? (chk ? t("lo." + chk.status) + (b.group ? ` (${b.group.startsWith("tamiz-keep") ? t("plan.keep_file") : b.group})` : "") : "")
          : t("lrole." + b.role);
        return html`<li class="${cls.join(" ")}"><span class="ord">${ord}</span><span class="path">${label}</span><span class="why">${why}</span></li>`;
      })}</ol>
      <aside class="stack-legend">
        <p>${t("order.legend_intro")}</p>
        <dl>
          <dt class="managed"></dt><dd>${t("order.legend_managed")}</dd>
          <dt class="crs"></dt><dd>${t("order.legend_crs")}</dd>
          <dt></dt><dd>${t("order.legend_other")}</dd>
          <dt class="wrong"></dt><dd>${t("order.legend_wrong")}</dd>
        </dl>
        ${report.notes.length ? html`<div class="notice warn section">${report.notes.map((n) => html`<p>${tCode("lonote." + n.code, n)}</p>`)}</div>` : ""}
        ${report.checks.filter((c) => c.status !== "ok").length ? html`<div class="notice error section"><p>${t("order.problems")}</p>
          <p>${t("order.problems_help")}</p></div>` : ""}
      </aside>
    </div>`);
  on(pane, "click", "[data-action=reload-order]", () => order(pane, target));
}

// ---------------------------------------------------------------- files ----
async function files(pane, target, groups) {
  const assigned = new Set(target.group_ids);
  mount(pane, html`
    <section>
      <div class="section-head"><div><h2>${t("files.groups")}</h2><p>${t("files.groups_intro")}</p></div></div>
      ${groups.length ? html`<form id="gform" class="row">${groups.map((g) => html`<label class="check">
          <input type="checkbox" value="${g.id}" ${assigned.has(g.id) ? "checked" : ""} ${can("editor") ? "" : "disabled"}>
          ${g.name} <span class="faint">(${t("plan.n_exclusions", { n: g.enabled_count })})</span></label>`)}
        ${can("editor") ? html`<button class="btn btn-sm" type="submit">${t("common.save")}</button>` : ""}</form>`
        : emptyState(t("files.no_groups"), t("files.no_groups_text"), html`<a class="btn" href="#/groups">${t("nav.groups")}</a>`)}
    </section>
    <section class="section">
      <div class="section-head"><div><h2>${t("files.managed")}</h2><p>${t("files.managed_intro")}</p></div></div>
      ${target.managed_files.length ? html`<div class="table-wrap"><table class="table">
        <thead><tr><th>${t("files.path")}</th><th>${t("files.group")}</th><th>${t("files.placement")}</th><th>${t("common.state")}</th><th>${t("files.applied")}</th></tr></thead>
        <tbody>${target.managed_files.map((f) => html`<tr><td class="mono">${f.path}</td>
          <td>${f.group_slug.startsWith("tamiz-keep") ? html`<span class="faint">${t("plan.keep_file")}</span>` : f.group_slug}</td>
          <td>${t("placement." + f.placement)}</td><td>${f.remote_state ? stateRim(f.remote_state, t("ustate." + f.remote_state)) : ""}</td>
          <td>${timeTag(f.last_applied_at)}</td></tr>`)}</tbody></table></div>`
        : html`<p class="muted">${t("files.none")}</p>`}
    </section>
    ${target.retirements.length ? html`<section class="section">
      <div class="section-head"><div><h2>${t("files.retirements")}</h2><p>${t("files.retirements_intro")}</p></div></div>
      <div class="table-wrap"><table class="table"><thead><tr><th>${t("files.path")}</th><th>${t("common.state")}</th><th>${t("common.when")}</th><th></th></tr></thead>
      <tbody>${target.retirements.map((r) => html`<tr><td class="mono">${r.path}</td><td>${stateRim(r.status, t("rstate." + r.status))}</td>
        <td>${timeTag(r.created_at)} <span class="faint">${r.created_by}</span></td>
        <td class="actions">${r.status === "pending" && can("editor") ? html`<button class="btn btn-sm" data-cancel-ret="${r.id}">${t("common.cancel")}</button>` : ""}</td></tr>`)}
      </tbody></table></div></section>` : ""}`);

  const form = $("#gform", pane);
  if (form) form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const ids = $$("input:checked", form).map((i) => Number(i.value));
    await busy($("button", form), async () => {
      try {
        await put(`targets/${target.id}/groups`, { group_ids: ids });
        toast(t("files.groups_saved"));
      } catch (e) { toastError(e); }
    });
  });
  on(pane, "click", "[data-cancel-ret]", async (ev, b) => {
    try {
      await del(`targets/${target.id}/retirements/${b.dataset.cancelRet}`);
      go(`/targets/${target.id}/files`);
    } catch (e) { toastError(e); }
  });
}

// ------------------------------------------------------------- diagnose ----
async function diagnose(pane, target) {
  mount(pane, html`<div class="section-head"><div><h2>${t("diag.title")}</h2><p>${t("diag.intro")}</p></div>
    <button class="btn btn-primary" data-action="diag">${icon("stethoscope")} ${t("diag.run")}</button></div><div id="diag-out"></div>`);
  on(pane, "click", "[data-action=diag]", async (ev, b) => {
    await busy(b, async () => {
      try {
        const r = await post(`targets/${target.id}/diagnose`, {});
        const out = $("#diag-out", pane);
        mount(out, html`
          ${r.host ? html`<dl class="kv panel"><dt>${t("diag.user")}</dt><dd class="mono">${r.host.user} (uid ${r.host.uid})</dd>
            <dt>${t("diag.os")}</dt><dd>${r.host.os || ""} <span class="faint">${r.host.kernel || ""}</span></dd>
            <dt>SELinux</dt><dd>${r.host.selinux}</dd>
            <dt>${t("diag.tools")}</dt><dd class="mono">${Object.keys(r.host).filter((k) => k.startsWith("cmd.")).map((k) => k.slice(4)).join(", ")}</dd></dl>` : ""}
          <ol class="steps section">${r.steps.map((s) => html`<li class="${s.status}">
            <div class="step-name">${t("dstep." + s.name)} ${s.status !== "ok" ? html`<span class="tag ${s.status === "failed" ? "error" : ""}">${t("state." + s.status)}</span>` : ""}</div>
            ${s.detail ? html`<div class="step-detail">${tCode("sdetail." + s.detail, { detail: s.detail })}</div>` : ""}
            ${s.name === "directories" ? html`<ul>${(s.data || []).map((d) => html`<li><span class="mono">${d.path}</span>: ${d.state === "exists" ? (d.writable ? t("diag.writable") : t("diag.not_writable")) : t("diag.missing")} <span class="faint">${d.owner}</span></li>`)}</ul>` : ""}
            ${s.name === "selinux" && s.data && s.data.mislabeled.length ? html`<pre class="code wrap">${s.data.mislabeled.join("\n")}</pre>
              <p class="step-detail">${t("diag.restorecon_help")}</p>` : ""}
            ${s.command ? html`<details class="cmd"><summary>$ ${s.command.command}</summary><pre class="code wrap">${[s.command.stdout, s.command.stderr].filter(Boolean).join("\n")}</pre></details>` : ""}
          </li>`)}</ol>`);
      } catch (e) { toastError(e); }
    });
  });
}

// --------------------------------------------------------------- config ----
async function config(pane, target, groups) {
  const c = target.conn || {};
  const cmd = target.commands || {};
  const hk = target.host_key_fingerprint || {};
  mount(pane, html`
    <div class="split">
      <section>
        <h2>${t("config.summary")}</h2>
        <dl class="kv section">
          <dt>${t("target.platform")}</dt><dd>${target.platform}</dd>
          <dt>${t("target.connection")}</dt><dd class="mono">${target.transport === "ssh" ? `${c.username}@${c.host}:${c.port}` : target.transport === "docker" ? c.container : t("transport." + target.transport)}</dd>
          ${c.jump ? html`<dt>${t("tform.jump")}</dt><dd class="mono">${c.jump.username || c.username}@${c.jump.host}</dd>` : ""}
          <dt>${t("tform.files")}</dt><dd>${t("layout." + target.layout.mode)}<br><span class="mono">${target.layout.before}</span><br><span class="mono">${target.layout.after}</span></dd>
          <dt>${t("tform.validate")}</dt><dd class="mono">${cmd.validate || "—"}</dd>
          <dt>${t("tform.reload")}</dt><dd class="mono">${cmd.reload || "—"}</dd>
          <dt>${t("tform.sudo_mode")}</dt><dd>${t("sudo." + cmd.sudo_mode)}</dd>
          <dt>${t("tform.audit_log")}</dt><dd class="mono">${target.logs.audit_log || "—"}</dd>
          <dt>${t("tform.require_review")}</dt><dd>${target.require_review ? t("common.yes") : t("common.no")}</dd>
          ${Object.keys(hk).length ? html`<dt>${t("config.host_key")}</dt><dd class="mono">${Object.entries(hk).map(([k, v]) => html`${k}: ${v}<br>`)}</dd>` : ""}
        </dl>
        ${can("admin") && Object.keys(hk).length ? html`<button class="btn btn-sm" data-action="reset-key">${t("config.reset_key")}</button>` : ""}
        ${can("editor") && target.transport !== "export" ? html`<div class="row section">
          <button class="btn" data-run="validate">${t("config.run_validate")}</button>
          <button class="btn" data-run="reload">${t("config.run_reload")}</button></div>` : ""}
      </section>
      <section>
        ${target.include_snippet ? html`<div class="code-title"><span>${t("tform.include_snippet")}</span>${copyButton(target.include_snippet)}</div>${codeBlock(target.include_snippet)}` : ""}
        ${can("admin") ? html`<div class="section"><button class="btn btn-danger" data-action="delete">${icon("trash")} ${t("config.delete")}</button>
          <p class="hint faint">${t("config.delete_hint")}</p></div>` : ""}
      </section>
    </div>`);
  on(pane, "click", "[data-run]", async (ev, b) => {
    await busy(b, async () => {
      try {
        const r = await post(`targets/${target.id}/run/${b.dataset.run}`, {});
        modal({ title: `$ ${r.command}`, wide: true,
          body: html`<p>${t("apply.exit", { code: r.exit_code })}</p><pre class="code wrap">${[r.stdout, r.stderr].filter(Boolean).join("\n") || t("apply.no_output")}</pre>`,
          actions: [{ label: t("common.close"), kind: "primary" }] });
      } catch (e) { toastError(e); }
    });
  });
  on(pane, "click", "[data-action=reset-key]", async () => {
    if (!await confirmDialog(t("config.reset_key"), t("config.reset_key_confirm"), { danger: true })) return;
    await post(`targets/${target.id}/host-key/reset`, {});
    toast(t("config.key_reset"));
    go(`/targets/${target.id}/config`);
  });
  on(pane, "click", "[data-action=delete]", async () => {
    if (!await confirmDialog(t("config.delete"), t("config.delete_confirm", { name: target.name }), { danger: true, confirm: t("common.delete") })) return;
    try {
      await del(`targets/${target.id}`);
      toast(t("config.deleted"));
      go("/targets");
    } catch (e) { toastError(e); }
  });
}

// -------------------------------------------------------------- history ----
async function history(pane, target) {
  const events = await get(`history?entity=target&entity_id=${target.id}&limit=50`);
  mount(pane, html`
    <section><h2>${t("history.applies")}</h2>
      ${target.applies.length ? html`<div class="table-wrap section"><table class="table">
        <thead><tr><th>${t("common.when")}</th><th>${t("common.who")}</th><th>${t("common.state")}</th><th>${t("history.summary")}</th></tr></thead>
        <tbody>${target.applies.map((a) => html`<tr class="clickable" data-apply="${a.id}"><td>${timeTag(a.started_at)}</td><td>${a.actor}</td>
          <td>${stateRim(a.status, t("astate." + a.status))}</td><td>${applySummary(a.summary_code, a.summary_params, a.summary)}</td></tr>`)}</tbody></table></div>`
        : html`<p class="muted">${t("history.no_applies")}</p>`}
    </section>
    <section class="section"><h2>${t("history.events")}</h2>
      <ul class="activity section">${events.map((h) => html`<li><span>${timeTag(h.at)}</span>
        <span><span class="who">${h.actor}</span> ${t("action." + h.action)}${historyText(h) ? html`: <span class="${h.ok ? "" : "bad"}">${historyText(h)}</span>` : ""}</span></li>`)}</ul>
    </section>`);
  on(pane, "click", "[data-apply]", async (ev, tr) => {
    const a = await get(`applies/${tr.dataset.apply}`);
    const { dialog } = modal({
      title: t("history.apply_title", { id: a.id }), wide: true,
      body: html`<p>${applySummary(a.summary_code, a.summary_params, a.summary)}</p>${stepsList(a.steps)}
        ${a.snapshots.length ? html`<h3 class="section">${t("history.snapshots")}</h3><ul>${a.snapshots.map((s) => html`<li>
          <a href="#" data-snapshot="${s.id}" class="mono">${s.path}</a> ${s.existed ? "" : html`<span class="faint">(${t("history.did_not_exist")})</span>`}</li>`)}</ul>` : ""}`,
      actions: [{ label: t("common.close"), kind: "primary" }],
    });
    on(dialog, "click", "[data-snapshot]", async (e, link) => {
      e.preventDefault();
      const snap = await get(`snapshots/${link.dataset.snapshot}`);
      modal({ title: snap.path, wide: true, body: codeBlock(snap.content || ""),
              actions: [{ label: t("common.close"), kind: "primary" }] });
    });
  });
}
