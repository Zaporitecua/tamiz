// HTTP client for the Tamiz API. URLs are relative so Tamiz works behind a
// reverse proxy under any path prefix (e.g. https://host/tamiz/).

export class ApiError extends Error {
  constructor(status, body) {
    super((body && body.message) || `HTTP ${status}`);
    this.status = status;
    this.code = (body && body.error) || "http_" + status;
    this.params = (body && body.params) || {};
    this.issues = (body && body.issues) || [];
  }
}

export async function api(path, { method = "GET", body, signal } = {}) {
  const headers = { "X-Tamiz": "1", Accept: "application/json" };
  const opts = { method, headers, credentials: "same-origin", signal };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch("api/" + path.replace(/^\//, ""), opts);
  } catch (e) {
    throw new ApiError(0, { error: "network", message: e.message });
  }
  const type = res.headers.get("content-type") || "";
  const data = type.includes("json") ? await res.json() : await res.blob();
  if (res.status === 401 && !path.startsWith("auth/")) {
    window.dispatchEvent(new CustomEvent("tamiz:unauthenticated"));
  }
  if (!res.ok) throw new ApiError(res.status, type.includes("json") ? data : null);
  return data;
}

export const get = (p, o) => api(p, o);
export const post = (p, body = {}) => api(p, { method: "POST", body });
export const put = (p, body = {}) => api(p, { method: "PUT", body });
export const patch = (p, body = {}) => api(p, { method: "PATCH", body });
export const del = (p) => api(p, { method: "DELETE" });

// Download a file returned by the API (zip bundles, JSON exports).
export async function download(path, fallbackName) {
  const res = await fetch("api/" + path, { headers: { "X-Tamiz": "1" }, credentials: "same-origin" });
  if (!res.ok) {
    let body = null;
    try { body = await res.json(); } catch { /* not JSON */ }
    throw new ApiError(res.status, body);
  }
  const blob = await res.blob();
  const cd = res.headers.get("content-disposition") || "";
  const m = cd.match(/filename="([^"]+)"/);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = (m && m[1]) || fallbackName;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
