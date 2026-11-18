// Login and first-run setup (creating the first administrator).

import { post } from "../api.js";
import { $, formValues, html, mount } from "../dom.js";
import { t } from "../i18n.js";
import { busy, errorText } from "../ui.js";

export function render(root, status) {
  root.className = "";
  if (status.setup_needed) return setup(root);
  if (status.mode === "proxy") {
    mount(root, html`<div class="auth-page"><div class="auth-card">
      ${brand()}<h1>${t("login.proxy_title")}</h1><p>${t("login.proxy_text")}</p></div></div>`);
    return;
  }
  mount(root, html`
    <div class="auth-page"><div class="auth-card">
      ${brand()}
      <h1>${t("login.title")}</h1>
      <p>${t("login.subtitle")}</p>
      <form id="login" novalidate>
        <div class="field"><label for="u">${t("login.username")}</label>
          <input class="input" id="u" name="username" autocomplete="username" required autofocus></div>
        <div class="field"><label for="p">${t("login.password")}</label>
          <input class="input" id="p" name="password" type="password" autocomplete="current-password" required></div>
        <div class="error-box" aria-live="polite"></div>
        <button class="btn btn-primary" type="submit">${t("login.submit")}</button>
      </form>
    </div></div>`);
  const form = $("#login", root);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = form;
    const box = $(".error-box", form);
    box.innerHTML = "";
    await busy($("button", form), async () => {
      try {
        await post("auth/login", formValues(f));
        location.reload();
      } catch (e) {
        mount(box, html`<div class="notice error">${errorText(e)}</div>`);
      }
    });
  });
}

function brand() {
  return html`<div class="brand"><span class="sieve-mark" aria-hidden="true"></span><span class="brand-name">tamiz</span></div>`;
}

function setup(root) {
  mount(root, html`
    <div class="auth-page"><div class="auth-card">
      ${brand()}
      <h1>${t("setup.title")}</h1>
      <p>${t("setup.text")}</p>
      <form id="setup" novalidate>
        <div class="field"><label for="c">${t("setup.code")}</label>
          <input class="input mono" id="c" name="code" required autocomplete="off" placeholder="abcd-ef01-2345-6789">
          <span class="hint">${t("setup.code_hint")}</span></div>
        <div class="field"><label for="u">${t("login.username")}</label>
          <input class="input" id="u" name="username" required autocomplete="username"></div>
        <div class="field"><label for="p">${t("login.password")}</label>
          <input class="input" id="p" name="password" type="password" required autocomplete="new-password" minlength="10">
          <span class="hint">${t("setup.password_hint")}</span></div>
        <div class="error-box" aria-live="polite"></div>
        <button class="btn btn-primary" type="submit">${t("setup.submit")}</button>
      </form>
    </div></div>`);
  const form = $("#setup", root);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const box = $(".error-box", form);
    box.innerHTML = "";
    await busy($("button", form), async () => {
      try {
        await post("auth/setup", formValues(form));
        location.reload();
      } catch (e) {
        mount(box, html`<div class="notice error">${errorText(e)}</div>`);
      }
    });
  });
}
