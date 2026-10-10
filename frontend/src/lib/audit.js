export function label(action) {
  const t = String(action || "").replace(/_/g, " ");
  return t.charAt(0).toUpperCase() + t.slice(1);
}

export function summarize(detail) {
  if (!detail || typeof detail !== "object") return "";
  return Object.entries(detail)
    .filter(([, v]) => v !== null && v !== undefined && typeof v !== "object")
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`)
    .join(", ");
}
