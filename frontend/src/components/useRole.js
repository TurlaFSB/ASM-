import { useEffect, useState } from "react";
import { getMe } from "../api";

let cached = null;   // one /auth/me call per page load

// "admin" | "viewer" | null while loading. Viewers see everything but cannot change anything.
export default function useRole() {
  const [role, setRole] = useState(cached);
  useEffect(() => {
    if (cached) return;
    let live = true;
    getMe().then(r => { cached = r.data.role || "admin"; if (live) setRole(cached); }).catch(() => {});
    return () => { live = false; };
  }, []);
  return role;
}
