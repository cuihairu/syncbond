// Browser-language auto-redirect for the SyncBond docs site.
//
// Loaded synchronously from <head> so the decision happens before first
// paint. Three rules keep it from ever fighting the visitor:
//
//   1. Only the two locale *home* pages redirect. A deep link such as
//      /syncbond/zh/design/merge must keep working regardless of the
//      browser language, so anything below a home is left alone.
//   2. An explicit choice always wins. Clicking a link to a locale root
//      (the VitePress language switcher or a Home nav link) records the
//      preference in localStorage; browser detection is ignored from
//      then on, across sessions.
//   3. No signal, no redirect. If the browser reports no language at
//      all, the visitor stays where they landed.
//
// Detection considers only the *primary* language (navigator.languages[0],
// falling back to navigator.language): a user whose list is ['en-US',
// 'zh-CN'] prefers English and must not be bounced to the Chinese pages.
(function () {
  'use strict';

  var STORAGE_KEY = 'sbLang';
  // Keep in step with `base` in .vitepress/config.mts.
  var EN_HOME = '/syncbond/';
  var ZH_HOME = '/syncbond/zh/';

  function homeLocale(pathname) {
    // Accept the trailing-slash, bare and index.html forms of each home so a
    // redirected visitor always lands on one canonical home URL.
    if (pathname === EN_HOME || pathname === '/syncbond' || pathname === '/syncbond/index.html') return 'en';
    if (pathname === ZH_HOME || pathname === '/syncbond/zh' || pathname === '/syncbond/zh/index.html') return 'zh';
    return null;
  }

  function detectedLocale() {
    var primary = '';
    if (typeof navigator === 'object' && navigator) {
      primary = String(
        (navigator.languages && navigator.languages.length && navigator.languages[0]) ||
          navigator.language ||
          ''
      );
    }
    if (!primary) return null;
    return /^zh([-_]|$)/i.test(primary) ? 'zh' : 'en';
  }

  function storedLocale() {
    try {
      var value = localStorage.getItem(STORAGE_KEY);
      return value === 'zh' || value === 'en' ? value : null;
    } catch (e) {
      // Storage blocked (private mode, disabled storage): detection still
      // works per load, the choice just is not sticky.
      return null;
    }
  }

  function remember(locale) {
    try {
      localStorage.setItem(STORAGE_KEY, locale);
    } catch (e) {
      // Storage blocked: the manual switch still navigates, it just is
      // not sticky across visits.
    }
  }

  var home = homeLocale(location.pathname);
  if (home) {
    var target = storedLocale() || detectedLocale();
    if (target && target !== home) {
      location.replace(target === 'zh' ? ZH_HOME : EN_HOME);
    }
  }

  // The VitePress language switcher and each locale's Home/Overview links
  // are plain anchors pointing at a locale root. Recording such clicks as
  // an explicit preference is what lets a manual switch outlive detection.
  // Capture phase, so VitePress's own click handling cannot swallow it.
  document.addEventListener(
    'click',
    function (event) {
      var node = event.target;
      while (node && node.nodeType === 1 && node.tagName !== 'A') node = node.parentNode;
      if (!node || node.nodeType !== 1) return;
      var href = node.getAttribute('href');
      var picked =
        href === EN_HOME || href === '/syncbond' || href === '/syncbond/index.html'
          ? 'en'
          : href === ZH_HOME || href === '/syncbond/zh' || href === '/syncbond/zh/index.html'
            ? 'zh'
            : null;
      if (picked) remember(picked);
    },
    true
  );
})();
