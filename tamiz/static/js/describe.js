// Plain-language summaries of an exclusion ("what" it excludes and "where").

import { html } from "./dom.js";
import { t } from "./i18n.js";

const MAX = 4;

function list(items) {
  const shown = items.slice(0, MAX).join(", ");
  return items.length > MAX ? `${shown} ${t("describe.and_more", { n: items.length - MAX })}` : shown;
}

export function what(e) {
  if (e.scope === "raw") return t("describe.raw", { placement: t("placement." + e.placement) });
  if (e.action === "engine_mode") return t("describe.engine", { mode: e.engine_mode });
  const sel = list(e.selectors || []);
  const byTag = e.selector_type === "tag";
  if (e.action === "remove_target") {
    return t(byTag ? "describe.remove_target_tag" : "describe.remove_target", { vars: list(e.variables || []), sel });
  }
  return t(byTag ? "describe.remove_rule_tag" : "describe.remove_rule", { sel });
}

export function condition(c) {
  const op = t("op_word." + c.operator);
  return `${c.variable} ${c.negate ? t("describe.not") + " " : ""}${op} ${c.value}`.trim();
}

export function where(e) {
  if (e.scope === "global") return t("describe.everywhere");
  if (e.scope === "raw") return (e.raw_text || "").split("\n").find((l) => l.trim() && !l.trim().startsWith("#")) || "";
  return (e.conditions || []).map(condition).join(` ${t("describe.and")} `);
}

// One line describing a history entry, in the interface language. Falls back
// to the English summary the server stored.
export function historyText(h) {
  const d = h.detail || {};
  switch (h.action) {
    case "apply":
      return d.code ? `${d.target}: ${applySummary(d.code, d.params, h.summary)}` : h.summary;
    case "login":
    case "login_failed":
      return d.ip ? t("hist.from_ip", { ip: d.ip }) : h.summary;
    case "exclusion_created":
    case "exclusion_updated":
    case "exclusion_deleted":
      if (!d.exclusion) return h.summary;
      return `#${h.entity_id}${d.exclusion.rule_id ? " [" + d.exclusion.rule_id + "]" : ""} ${what(d.exclusion)}${
        d.exclusion.scope === "conditional" ? ", " + where(d.exclusion) : ""}`;
    case "mark_deployed":
      return `${d.target}: ${t("hist.files_n", { n: d.files })}`;
    case "validate":
    case "reload":
      return d.target ? `${d.target}: ${t("apply.exit", { code: d.exit_code })}` : h.summary;
    default:
      return d.name ? d.name + (d.ranges ? ` (${d.ranges})` : "") : h.summary;
  }
}

export function applySummary(code, params, fallback) {
  const key = "asum." + code;
  const text = t(key, params || {});
  return text === key ? (fallback || "") : text;
}

// The same as where(), as HTML: variables and values in code style, the
// operator in words.
export function whereHtml(e) {
  if (e.scope !== "conditional") return html`<span class="muted">${where(e)}</span>`;
  return (e.conditions || []).map((c, i) => html`${i ? html` ${t("describe.and")} ` : ""}<span class="cond-code">${c.variable}</span>
    ${c.negate ? t("describe.not") + " " : ""}${t("op_word." + c.operator)} <span class="cond-code">${c.value}</span>`);
}
