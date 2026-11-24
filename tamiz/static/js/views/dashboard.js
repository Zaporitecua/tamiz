// Dashboard: one sentence that says how the WAFs are doing, the targets at a
// glance, what needs attention and recent activity.

import { get, post } from "../api.js";
import { can } from "../app.js";
import { $, html, icon, mount, on } from "../dom.js";
import { historyText } from "../describe.js";
import { t, tIssue } from "../i18n.js";
import { busy, stateRim, targetStatus, timeTag, toast } from "../ui.js";

export async function render(root) {
  const data = await get("dashboard");
  draw(root, data);
}

function sentence(targets) {
  const active = targets.filter((x) => x.enabled);
  const by = {};
  for (const x of active) {
    const s = targetStatus(x);
    by[s] = (by[s] || 0) + 1;
  }
  if (!active.length) return { head: t("dash.no_targets_head"), sub: "" };
  const ok = by.in_sync || 0;
  const head = ok === active.length
    ? html`<span class="ok">${t("dash.all_in_sync", { n: ok })}</span>`
    : html`${t("dash.some_in_sync", { ok, total: active.length })}`;
  const bits = [];
  if (by.pending) bits.push(t("dash.n_pending", { n: by.pending }));
  if (by.blocked) bits.push(t("dash.n_blocked", { n: by.blocked }));
  if (by.error) bits.push(t("dash.n_error", { n: by.error }));
  if (by.never) bits.push(t("dash.n_never", { n: by.never }));
  return { head, sub: bits.join(". ") + (bits.length ? "." : "") };
}

function draw(root, data) {
  const s = sentence(data.targets);
  const c = data.counts;
  const attention = [
    ...data.reviews.map((r) => html`<li class="warning"><a href="#/targets/${r.target_id}/changes">${t("dash.review_waiting", { target: r.target_name, who: r.requested_by })}</a></li>`),
    ...data.findings.slice(0, 12).map((f) => html`<li class="${f.level}"><a href="#/exclusions/${f.exclusion_id}">#${f.exclusion_id}</a> ${tIssue(f)}</li>`),
  ];
  mount(root, html`
    <div class="page-head">
      <div>
        <h1 class="hero-line">${s.head}</h1>
        <p class="hero-sub">${s.sub} ${t("dash.counts", { exclusions: c.enabled, groups: c.groups })}</p>
      </div>
      <div class="page-actions">
        ${data.targets.length ? html`<button type="button" class="btn" data-action="check-all">${icon("refresh")} ${t("dash.check_all")}</button>` : ""}
        ${can("editor") ? html`<a class="btn btn-primary" href="#/exclusions/new">${icon("plus")} ${t("excl.new")}</a>` : ""}
      </div>
    </div>

    ${data.targets.length ? html`
      <div class="target-strip">
        ${data.targets.map((x) => cell(x))}
      </div>` : onboarding()}

    <div class="split section">
      <section>
        <div class="section-head"><h2>${t("dash.attention")}</h2></div>
        ${attention.length ? html`<ul class="lint">${attention}</ul>` : html`<p class="muted">${t("dash.nothing_to_review")}</p>`}
        ${data.lint.info ? html`<p class="faint">${t("dash.info_count", { n: data.lint.info })}</p>` : ""}
      </section>
      <section>
        <div class="section-head"><h2>${t("dash.activity")}</h2><a href="#/history">${t("dash.all_history")}</a></div>
        ${data.recent.length ? html`<ul class="activity">${data.recent.map((h) => html`
          <li><span>${timeTag(h.at)}</span><span><span class="who">${h.actor}</span> ${t("action." + h.action)}${historyText(h) ? html`: <span class="${h.ok ? "" : "bad"}">${historyText(h)}</span>` : ""}</span></li>`)}</ul>`
          : html`<p class="muted">${t("dash.no_activity")}</p>`}
      </section>
    </div>`);

  on(root, "click", "[data-action=check-all]", async (ev, btn) => {
    await busy(btn, async () => {
      let failures = 0;
      for (const x of data.targets.filter((y) => y.enabled)) {
        const el = $(`[data-target="${x.id}"] .status`, root);
        if (el) el.innerHTML = String(stateRim("running", t("dash.checking")));
        try {
          const plan = await post(`targets/${x.id}/check`, {});
          x.last_status = plan.summary;
          x.last_check_error = null;
        } catch (e) {
          failures++;
          x.last_check_error = e.message;
        }
        x.last_check_at = new Date().toISOString();
        const cellEl = $(`[data-target="${x.id}"]`, root);
        if (cellEl) cellEl.outerHTML = String(cell(x));
      }
      const s2 = sentence(data.targets);
      mount($(".hero-line", root), s2.head);
      toast(failures ? t("dash.check_done_errors", { n: failures }) : t("dash.check_done"), failures ? "warn" : "ok");
    });
  });
}

function cell(x) {
  const st = targetStatus(x);
  const pending = x.last_status && x.last_status.changes;
  return html`<a class="target-cell" href="#/targets/${x.id}" data-target="${x.id}" data-state="${st}">
    <span class="name">${x.name}</span>
    <span class="status">${stateRim(st === "disabled" ? "skipped" : st, t("tstate." + st, { n: pending || 0 }))}</span>
    <span class="meta">${[x.environment, t("transport." + x.transport)].filter(Boolean).join(", ")}${x.last_check_at ? html`, ${t("dash.checked")} ${timeTag(x.last_check_at)}` : ""}</span>
  </a>`;
}

function onboarding() {
  return html`<section class="panel">
    <h2>${t("onb.title")}</h2>
    <p class="muted">${t("onb.text")}</p>
    <ol class="steps">
      <li><div class="step-name">${t("onb.s1")}</div><div class="step-detail">${t("onb.s1_text")}</div></li>
      <li><div class="step-name">${t("onb.s2")}</div><div class="step-detail">${t("onb.s2_text")}</div></li>
      <li><div class="step-name">${t("onb.s3")}</div><div class="step-detail">${t("onb.s3_text")}</div></li>
      <li><div class="step-name">${t("onb.s4")}</div><div class="step-detail">${t("onb.s4_text")}</div></li>
    </ol>
    ${can("admin") ? html`<a class="btn btn-primary" href="#/targets/new">${icon("plus")} ${t("target.new")}</a>` : ""}
  </section>`;
}
