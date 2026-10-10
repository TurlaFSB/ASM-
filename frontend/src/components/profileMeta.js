import { Zap, Gauge, Radar } from "lucide-react";

// Used until GET /scans/profiles answers (and if it fails), so the picker is never empty.
export const FALLBACK_PROFILES = [
  { name: "quick", label: "Quick", estimate: "~2-3 min", description: "Fast triage: top 100 ports, CVE match, high/critical only." },
  { name: "standard", label: "Standard", estimate: "~3-12 min", description: "Balanced: top 1000 ports, TLS, screenshots, short directory discovery." },
  { name: "deep", label: "Deep", estimate: "~20+ min", description: "Exhaustive: all ports, large wordlist, long nuclei budget." },
];

export const PROFILE_ICONS = { quick: Zap, standard: Gauge, deep: Radar };
export const PROFILE_COLORS = { quick: "var(--green)", standard: "var(--blue)", deep: "var(--accent)" };
