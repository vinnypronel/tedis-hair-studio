// include.js — smooth cross-page fades (vanilla JS)

(function () {
  // On initial load: fade in
  document.addEventListener("DOMContentLoaded", function () {
    document.body.classList.add("fade-in");
  });

  // If the page was restored from bfcache (back/forward), ensure it's visible
  window.addEventListener("pageshow", function (e) {
    if (e.persisted) {
      document.body.classList.remove("fade-out");
      document.body.classList.add("fade-in");
    }
  });

  // Intercept internal nav links and fade out before leaving
  function shouldIntercept(a) {
    const href = a.getAttribute("href") || "";
    if (!href) return false;
    if (href.startsWith("#")) return false;                 // in-page anchors
    if (href.startsWith("mailto:") || href.startsWith("tel:")) return false;
    if (a.hasAttribute("download") || a.target === "_blank") return false;

    try {
      const url = new URL(a.href, window.location.href);
      return url.origin === window.location.origin;         // only internal links
    } catch {
      return false;
    }
  }

  document.addEventListener("click", function (e) {
    const a = e.target.closest("a[href]");
    if (!a || !shouldIntercept(a)) return;

    e.preventDefault();
    document.documentElement.classList.add("is-transitioning");
    document.body.classList.remove("fade-in");
    document.body.classList.add("fade-out");

    // Navigate after the fade-out finishes (match CSS duration)
    setTimeout(function () {
      window.location.href = a.href;
    }, 260);
  }, { capture: true });
})();
