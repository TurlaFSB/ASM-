// Theme preference: "light" | "dark" | "system". Stored per browser; "system" follows the OS live.
const KEY = "asm-theme";
const query = () => window.matchMedia("(prefers-color-scheme: light)");

export function getThemePref() {
  try { return localStorage.getItem(KEY) || "system"; } catch { return "system"; }
}

export function applyTheme(pref = getThemePref()) {
  const light = pref === "light" || (pref === "system" && query().matches);
  document.documentElement.setAttribute("data-theme", light ? "light" : "dark");
}

export function setThemePref(pref) {
  try { localStorage.setItem(KEY, pref); } catch { /* private mode: the choice lasts until reload */ }
  applyTheme(pref);
}

export function watchSystemTheme() {
  query().addEventListener("change", () => { if (getThemePref() === "system") applyTheme("system"); });
}

// For SVG/canvas attributes that cannot use CSS variables (chart axes and grids).
export function fgAlpha(alpha) {
  const fg = getComputedStyle(document.documentElement).getPropertyValue("--fg").trim() || "255 255 255";
  return `rgb(${fg} / ${alpha})`;
}
