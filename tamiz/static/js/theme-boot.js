// Loaded as a classic, blocking script in <head> so a saved light theme is
// applied before the first paint (dark is the default in tokens.css). It is a
// file and not an inline script because the CSP forbids inline scripts.
try {
  if (localStorage.getItem("tamiz.theme") === "light") document.documentElement.dataset.theme = "light";
} catch { /* storage blocked: stay dark */ }
