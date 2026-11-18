// Tiny DOM helpers. No framework: views build HTML strings with `html`,
// which escapes every interpolated value unless it is wrapped in `raw()`.

class Raw {
  constructor(s) { this.s = s; }
  toString() { return this.s; }
}

export const raw = (s) => new Raw(String(s ?? ""));

export function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function part(v) {
  if (v === null || v === undefined || v === false) return "";
  if (v instanceof Raw) return v.s;
  if (Array.isArray(v)) return v.map(part).join("");
  return esc(v);
}

// html`<p>${userText}</p>` -> Raw with userText escaped.
export function html(strings, ...values) {
  let out = strings[0];
  values.forEach((v, i) => { out += part(v) + strings[i + 1]; });
  return new Raw(out);
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

// Inline styles are blocked by the Content-Security-Policy, so values such
// as a meter's fill are carried in data attributes and applied here.
export function applyDynamic(root) {
  $$("[data-fill]", root).forEach((n) => n.style.setProperty("--fill", `${n.dataset.fill}%`));
}

export function mount(el, content) {
  el.innerHTML = part(content);
  applyDynamic(el);
  return el;
}

// Event delegation: on(root, "click", "[data-action=save]", (ev, el) => ...)
export function on(root, type, selector, fn) {
  root.addEventListener(type, (ev) => {
    const el = ev.target.closest(selector);
    if (el && root.contains(el)) fn(ev, el);
  });
}

export function icon(name) {
  return raw(`<svg aria-hidden="true" focusable="false"><use href="#i-${name}"/></svg>`);
}

// Collect a form into an object. Names with dots build nested objects
// ("conn.host" -> {conn: {host}}). Checkboxes become booleans; fields with
// data-type="number" become numbers; data-type="lines" become arrays.
export function formValues(form) {
  const out = {};
  for (const el of form.elements) {
    if (!el.name || el.disabled) continue;
    let value;
    if (el.type === "checkbox") value = el.checked;
    else if (el.type === "radio") { if (!el.checked) continue; value = el.value; }
    else value = el.value;
    if (el.dataset.type === "number") value = value === "" ? null : Number(value);
    if (el.dataset.type === "lines") value = value.split("\n").map((s) => s.trim()).filter(Boolean);
    const keys = el.name.split(".");
    let cur = out;
    keys.slice(0, -1).forEach((k) => { cur = cur[k] ??= {}; });
    cur[keys[keys.length - 1]] = value;
  }
  return out;
}

export function debounce(fn, ms = 300) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}
