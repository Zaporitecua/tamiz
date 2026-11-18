// Shared UI pieces: toasts, dialogs, error display, state rims, dates,
// SecLang highlighting and diffs.

import { $, $$, applyDynamic, esc, html, icon, raw } from "./dom.js";
import { lang, t, tIssue, tError } from "./i18n.js";

// ----------------------------------------------------------------- toasts --
export function toast(message, kind = "ok", ms = 4200) {
  const box = document.getElementById("toasts");
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = message;
  box.appendChild(el);
  setTimeout(() => el.remove(), ms);
}

export function errorText(err) {
  if (!err) return "";
  if (err.code) return tError(err.code, err.params, err.message);
  return String(err.message || err);
}

export function toastError(err) {
  toast(errorText(err), "error", 7000);
}

// ---------------------------------------------------------------- dialogs --
// modal({title, body, actions, wide}) -> {dialog, close}. `body` is html.
// Each action: {label, kind: "primary"|"danger"|"", value, onClick}. If
// onClick returns false (or a promise resolving to false) the dialog stays.
export function modal({ title, body, actions = [], wide = false, onClose }) {
  const d = document.createElement("dialog");
  d.className = "modal" + (wide ? " wide" : "");
  d.innerHTML = String(html`
    <div class="modal-head"><h2>${title}</h2>
      <button class="btn btn-quiet btn-icon" data-close aria-label="${t("common.close")}">${icon("x")}</button>
    </div>
    <div class="modal-body">${body}</div>
    ${actions.length ? html`<div class="modal-foot">${actions.map((a, i) =>
      html`<button class="btn ${a.kind ? "btn-" + a.kind : ""}" data-i="${i}">${a.label}</button>`)}</div>` : ""}
  `);
  document.body.appendChild(d);
  applyDynamic(d);
  const close = (value) => { d.close(value ?? ""); };
  d.addEventListener("close", () => { onClose && onClose(d.returnValue); d.remove(); });
  d.addEventListener("click", async (ev) => {
    if (ev.target === d || ev.target.closest("[data-close]")) return close("");
    const b = ev.target.closest("[data-i]");
    if (!b) return;
    const a = actions[Number(b.dataset.i)];
    if (a.onClick) {
      b.classList.add("busy");
      try {
        const r = await a.onClick(d);
        if (r === false) return;
      } catch (e) {
        toastError(e);
        return;
      } finally {
        b.classList.remove("busy");
      }
    }
    close(a.value ?? "ok");
  });
  d.showModal();
  return { dialog: d, close };
}

export function confirmDialog(title, message, { danger = false, confirm = t("common.confirm") } = {}) {
  return new Promise((resolve) => {
    modal({
      title, body: html`<p>${message}</p>`,
      actions: [{ label: t("common.cancel"), value: "no" },
                { label: confirm, kind: danger ? "danger" : "primary", value: "yes" }],
      onClose: (v) => resolve(v === "yes"),
    });
  });
}

// Run an async action while a button shows it is busy.
export async function busy(button, fn) {
  if (!button) return fn();
  button.classList.add("busy");
  button.disabled = true;
  try { return await fn(); } finally { button.classList.remove("busy"); button.disabled = false; }
}

// Show API validation issues next to the matching fields of a form.
export function showFormErrors(form, err) {
  $$(".field.invalid", form).forEach((f) => f.classList.remove("invalid"));
  $$(".field .error", form).forEach((e) => e.remove());
  const leftovers = [];
  for (const issue of (err && err.issues) || []) {
    const name = issue.field;
    const input = name && (form.querySelector(`[name="${CSS.escape(name)}"]`)
      || form.querySelector(`[data-field="${CSS.escape(name)}"]`)
      || form.querySelector(`[data-field="${CSS.escape(name.split(".")[0])}"]`));
    const msg = tIssue(issue);
    const field = input && input.closest(".field");
    if (field) {
      field.classList.add("invalid");
      const p = document.createElement("div");
      p.className = "error";
      p.textContent = msg;
      field.appendChild(p);
    } else {
      leftovers.push(msg);
    }
  }
  const first = form.querySelector(".field.invalid");
  if (first) first.scrollIntoView({ block: "center", behavior: "smooth" });
  if (leftovers.length || !(err && err.issues && err.issues.length)) {
    toast(leftovers.length ? leftovers.join("; ") : errorText(err), "error", 7000);
  }
}

// ----------------------------------------------------------------- states --
const STATE_CLASS = {
  in_sync: "ok", ok: "ok", approved: "ok", applied: "ok", done: "ok",
  pending: "pending", create: "pending", update: "pending", delete: "pending", retire: "pending", running: "pending",
  ok_with_warnings: "warn", warning: "warn", unknown: "idle", stale: "idle", gone: "idle", skipped: "idle",
  drift: "error", foreign: "error", blocked: "error", error: "error", failed: "error",
  rolled_back: "warn", rollback_failed: "error", reload_failed: "error", rejected: "error",
  not_loaded: "error", wrong_position: "error", loaded_twice: "warn", never: "idle", cancelled: "idle",
};

export function stateRim(state, label) {
  const cls = STATE_CLASS[state] || "idle";
  return html`<span class="state ${cls}">${label ?? t("state." + state)}</span>`;
}

export function targetStatus(target) {
  if (!target.enabled) return "disabled";
  if (target.last_check_error) return "error";
  if (!target.last_status) return "never";
  return target.last_status.status;
}

// ------------------------------------------------------------------ dates --
export function fmtDate(iso, { relative = true } = {}) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const diff = (Date.now() - d.getTime()) / 1000;
  if (relative && diff >= 0 && diff < 7 * 86400) {
    const rtf = new Intl.RelativeTimeFormat(lang(), { numeric: "auto" });
    if (diff < 60) return rtf.format(-Math.round(diff), "second");
    if (diff < 3600) return rtf.format(-Math.round(diff / 60), "minute");
    if (diff < 86400) return rtf.format(-Math.round(diff / 3600), "hour");
    return rtf.format(-Math.round(diff / 86400), "day");
  }
  return d.toLocaleString(lang(), { dateStyle: "medium", timeStyle: "short" });
}

export function timeTag(iso) {
  if (!iso) return "";
  return html`<time datetime="${iso}" title="${new Date(iso).toLocaleString(lang())}">${fmtDate(iso)}</time>`;
}

// --------------------------------------------------------- SecLang colour --
const DIRECTIVE_RE = /^(\s*)(Sec[A-Za-z]+|Include(?:Optional)?)(\b.*)$/;

export function highlightSecLang(text) {
  const out = [];
  for (const line of String(text || "").split("\n")) {
    if (/^\s*#/.test(line)) { out.push(`<span class="c">${esc(line)}</span>`); continue; }
    const m = line.match(DIRECTIVE_RE);
    let rest = m ? m[3] : line;
    let lead = m ? `${esc(m[1])}<span class="d">${esc(m[2])}</span>` : "";
    rest = esc(rest)
      .replace(/(\b(?:REQUEST|ARGS|REMOTE|QUERY|RESPONSE|TX|FILES|XML|SERVER|MATCHED|REQBODY)[A-Z_]*(?::[^\s"|,;\\]+)?)/g, '<span class="v">$1</span>')
      .replace(/(!?@[a-zA-Z]+)/g, '<span class="o">$1</span>')
      .replace(/\b(id:)(\d+)/g, '$1<span class="n">$2</span>')
      .replace(/(ctl:[a-zA-Z]+=)/g, '<span class="k">$1</span>');
    out.push(lead + rest);
  }
  return raw(out.join("\n"));
}

export function codeBlock(text, { title, wrap = false } = {}) {
  return html`${title ? html`<div class="code-title">${title}</div>` : ""}<pre class="code${wrap ? " wrap" : ""}">${highlightSecLang(text)}</pre>`;
}

export function diffBlock(diff) {
  if (!diff) return "";
  const lines = diff.split("\n").map((l) => {
    let cls = "";
    if (l.startsWith("+++") || l.startsWith("---")) cls = "meta";
    else if (l.startsWith("@@")) cls = "hunk";
    else if (l.startsWith("+")) cls = "add";
    else if (l.startsWith("-")) cls = "del";
    return `<div class="${cls}">${esc(l) || " "}</div>`;
  });
  return raw(`<div class="diff">${lines.join("")}</div>`);
}

export function copyButton(text) {
  return html`<button class="btn btn-quiet btn-icon" data-copy="${text}" title="${t("common.copy")}" aria-label="${t("common.copy")}">${icon("copy")}</button>`;
}

document.addEventListener("click", async (ev) => {
  const b = ev.target.closest("[data-copy]");
  if (!b) return;
  try {
    await navigator.clipboard.writeText(b.dataset.copy);
    toast(t("common.copied"));
  } catch {
    toast(t("common.copy_failed"), "warn");
  }
});

export function emptyState(title, text, action) {
  return html`<div class="empty"><h3>${title}</h3><p>${text}</p>${action || ""}</div>`;
}

export function lintList(items) {
  if (!items || !items.length) return "";
  return html`<ul class="lint">${items.map((i) => html`<li class="${i.level}">${tIssue(i)}</li>`)}</ul>`;
}

export function worstLevel(items) {
  const order = { error: 3, warning: 2, info: 1 };
  let best = null;
  for (const i of items || []) if (!best || order[i.level] > order[best]) best = i.level;
  return best;
}
