// Scroll-linked polish that needs no changes in the page components.
//
//  1. data-scrolled on <html>: the sticky page header shows its hairline only once content scrolls under it.
//  2. Scroll reveal: rows and cards that START below the fold fade up once, the first time they scroll
//     into view. Anything already on screen when it appears is left alone, so there is no load-in
//     animation and no flash. Skipped entirely under prefers-reduced-motion.

const REVEAL_SELECTOR = "tbody tr, .stat-card, .vuln-stat, .form-card, .recent-scans, .alert-card, .schedule-card, .scan-card";

export function initMotion() {
  if (typeof window === "undefined") return;
  const root = document.documentElement;

  let ticking = false;
  const onScroll = () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      root.dataset.scrolled = String(window.scrollY > 4);
      ticking = false;
    });
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce || !("IntersectionObserver" in window)) return;

  const checked = new WeakSet();
  const io = new IntersectionObserver((entries) => {
    let order = 0;
    for (const entry of entries) {
      const el = entry.target;
      if (!checked.has(el)) {
        checked.add(el);
        if (entry.isIntersecting) { io.unobserve(el); continue; }   // visible on arrival: never animate
        el.classList.add("reveal", "reveal-pending");                 // below the fold: wait for it
        continue;
      }
      if (entry.isIntersecting) {
        el.style.transitionDelay = `${Math.min(order++ * 28, 140)}ms`;   // gentle stagger within one batch
        el.classList.remove("reveal-pending");
        io.unobserve(el);
        setTimeout(() => { el.classList.remove("reveal"); el.style.transitionDelay = ""; }, 600);
      }
    }
  }, { rootMargin: "0px 0px -4% 0px", threshold: 0.01 });

  const watch = (el) => { if (!checked.has(el)) io.observe(el); };
  const scan = (node) => {
    if (node.nodeType !== 1) return;
    if (node.matches(REVEAL_SELECTOR)) watch(node);
    node.querySelectorAll(REVEAL_SELECTOR).forEach(watch);
  };
  const unwatch = (node) => {
    if (node.nodeType !== 1) return;
    io.unobserve(node);
    node.querySelectorAll(REVEAL_SELECTOR).forEach((el) => io.unobserve(el));
  };

  new MutationObserver((mutations) => {
    for (const m of mutations) {
      m.addedNodes.forEach(scan);
      m.removedNodes.forEach(unwatch);
    }
  }).observe(document.body, { childList: true, subtree: true });
  scan(document.body);
}
