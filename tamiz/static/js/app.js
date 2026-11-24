// Application shell: authentication state, navigation rail, hash router.

import { get, post } from "./api.js";
import { $, $$, html, icon, mount, on } from "./dom.js";
import { lang, setLang, t } from "./i18n.js";
import { errorText, toast } from "./ui.js";

export const state = { user: null, mode: "local", version: "", meta: null };

const ROUTES = [
  [/^\/$/, "dashboard"],
  [/^\/targets$/, "targets"],
  [/^\/targets\/new$/, "target-form"],
  [/^\/targets\/(\d+)\/edit$/, "target-form"],
  [/^\/targets\/(\d+)(?:\/(\w+))?$/, "target"],
  [/^\/exclusions$/, "exclusions"],
  [/^\/exclusions\/new$/, "exclusion-form"],
  [/^\/exclusions\/(\d+)$/, "exclusion-form"],
  [/^\/groups$/, "groups"],
  [/^\/groups\/(\d+)$/, "group"],
  [/^\/analyzer$/, "analyzer"],
  [/^\/import$/, "import"],
  [/^\/history$/, "history"],
  [/^\/settings(?:\/(\w+))?$/, "settings"],
];

const NAV = [
  ["/", "dashboard", "nav.dashboard"],
  ["/targets", "targets", "nav.targets"],
  ["/exclusions", "exclusions", "nav.exclusions"],
  ["/groups", "groups", "nav.groups"],
  ["/analyzer", "analyzer", "nav.analyzer"],
  ["/import", "import", "nav.import"],
  ["/history", "history", "nav.history"],
];

export function can(role) {
  const rank = { viewer: 0, editor: 1, admin: 2 };
  return state.user && rank[state.user.role] >= rank[role];
}

export function go(path) {
  if (location.hash === "#" + path) route();
  else location.hash = "#" + path;
}

export function parseQuery() {
  const q = location.hash.split("?")[1] || "";
  return Object.fromEntries(new URLSearchParams(q));
}

// ------------------------------------------------------------------ theme --
// Dark is the default; only "light" is stored as a choice.
function currentTheme() {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function applyTheme() {
  let theme = "dark";
  try { theme = localStorage.getItem("tamiz.theme") === "light" ? "light" : "dark"; } catch { /* storage blocked */ }
  if (theme === "light") document.documentElement.dataset.theme = "light";
  else delete document.documentElement.dataset.theme;
}

// The button shows where it takes you: a sun in the dark theme, a moon in the light one.
function themeIcon() {
  return icon(currentTheme() === "dark" ? "sun" : "moon");
}

function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  try { localStorage.setItem("tamiz.theme", next); } catch { /* storage blocked: only this page */ }
  if (next === "light") document.documentElement.dataset.theme = "light";
  else delete document.documentElement.dataset.theme;
  $$("[data-action=theme]").forEach((b) => { b.innerHTML = String(themeIcon()); });
}

// ------------------------------------------------------------------ shell --
function shell() {
  const app = $("#app");
  app.className = "";
  const user = state.user;
  mount(app, html`
    <div class="shell">
      <aside class="rail">
        <a class="brand" href="#/"><span class="sieve-mark" aria-hidden="true"></span><span class="brand-name">tamiz</span></a>
        <nav class="nav" aria-label="${t("nav.label")}">
          ${NAV.map(([path, ic, key]) => html`<a href="#${path}" data-path="${path}">${icon(ic)}<span>${t(key)}</span></a>`)}
          <div class="nav-sep"></div>
          <a href="#/settings" data-path="/settings">${icon("settings")}<span>${t("nav.settings")}</span></a>
        </nav>
        <div class="rail-foot">
          <div class="rail-user"><span><strong>${user.display_name || user.username}</strong><br>${t("role." + user.role)}</span>
            ${state.mode === "local" ? html`<button type="button" class="btn btn-quiet btn-icon" data-action="logout" title="${t("nav.logout")}" aria-label="${t("nav.logout")}">${icon("logout")}</button>` : ""}
          </div>
          <div class="rail-tools">
            <button type="button" class="btn btn-quiet btn-sm" data-action="theme" aria-label="${t("nav.theme")}">${themeIcon()}</button>
            <button type="button" class="btn btn-quiet btn-sm" data-action="lang">${lang() === "es" ? "English" : "Español"}</button>
          </div>
          <span class="faint">v${state.version}</span>
        </div>
      </aside>
      <main class="main" id="main">
        ${state.mode === "none" ? html`<div class="banner">${t("app.no_auth_banner")}</div>` : ""}
        <div class="page" id="page"></div>
      </main>
    </div>`);
}

function highlightNav(path) {
  document.querySelectorAll(".nav a").forEach((a) => {
    const p = a.dataset.path;
    const active = p === "/" ? path === "/" : path === p || path.startsWith(p + "/");
    if (active) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
}

let routeToken = 0;

async function route() {
  if (!state.user) return;
  const path = (location.hash.replace(/^#/, "") || "/").split("?")[0];
  const old = $("#page");
  if (!old) return;
  // Views attach delegated listeners to their root (dom.js `on`). A fresh
  // element per navigation drops the previous view's listeners; reusing the
  // same one piled them up, and one click ran an action once per earlier visit.
  const page = old.cloneNode(false);
  old.replaceWith(page);
  highlightNav(path);
  for (const [re, name] of ROUTES) {
    const m = path.match(re);
    if (!m) continue;
    const token = ++routeToken;
    page.innerHTML = `<div class="loading">${t("common.loading")}</div>`;
    try {
      const mod = await import(`./views/${name}.js`);
      if (token !== routeToken) return;
      await mod.render(page, m.slice(1), { isCurrent: () => token === routeToken });
      if (token === routeToken) $("#main").scrollTo?.(0, 0);
    } catch (e) {
      if (token !== routeToken) return;
      console.error(e);
      mount(page, html`<div class="notice error"><p><strong>${t("app.view_error")}</strong></p><p>${errorText(e)}</p></div>`);
    }
    document.title = `${page.querySelector("h1")?.textContent || "Tamiz"} | Tamiz`;
    return;
  }
  mount(page, html`<div class="empty"><h3>${t("app.not_found")}</h3><a class="btn" href="#/">${t("nav.dashboard")}</a></div>`);
}

// -------------------------------------------------------------------- boot --
async function boot() {
  applyTheme();
  document.documentElement.lang = lang();
  let status;
  try {
    status = await get("auth/status");
  } catch (e) {
    mount($("#app"), html`<div class="auth-page"><div class="notice error">${errorText(e)}</div></div>`);
    return;
  }
  state.mode = status.mode;
  state.version = status.version;
  state.user = status.user;
  if (!state.user) {
    const mod = await import("./views/login.js");
    mod.render($("#app"), status);
    return;
  }
  try { state.meta = await get("meta"); } catch { state.meta = null; }
  shell();
  route();
}

window.addEventListener("hashchange", route);
window.addEventListener("tamiz:unauthenticated", () => {
  if (state.user) { state.user = null; toast(t("app.session_expired"), "warn"); boot(); }
});
document.addEventListener("DOMContentLoaded", () => {
  on(document.body, "click", "[data-action=logout]", async () => {
    await post("auth/logout");
    state.user = null;
    location.hash = "#/";
    boot();
  });
  on(document.body, "click", "[data-action=theme]", toggleTheme);
  on(document.body, "click", "[data-action=lang]", () => {
    setLang(lang() === "es" ? "en" : "es");
    document.documentElement.lang = lang();
    shell();
    route();
  });
  boot();
});

export { boot, route };
