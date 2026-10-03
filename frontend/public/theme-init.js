// Runs before first paint so there is no flash of the wrong theme. Kept as a separate file because
// the page's Content-Security-Policy does not allow inline scripts.
(function () {
  var pref = "system";
  try { pref = localStorage.getItem("asm-theme") || "system"; } catch { /* storage blocked: follow the system */ }
  var light = pref === "light" || (pref === "system" && window.matchMedia("(prefers-color-scheme: light)").matches);
  document.documentElement.setAttribute("data-theme", light ? "light" : "dark");
})();
