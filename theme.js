/* Applies the saved theme before the page paints. Dark is the default. */
(function () {
  var root = document.documentElement;
  function apply(t) {
    t = t === 'light' ? 'light' : 'dark';
    root.setAttribute('data-theme', t);
    var m = document.querySelector('meta[name="theme-color"]');
    if (m) m.setAttribute('content', t === 'light' ? '#f4f6fb' : '#10131a');
    var s = document.querySelector('meta[name="apple-mobile-web-app-status-bar-style"]');
    if (s) s.setAttribute('content', t === 'light' ? 'default' : 'black-translucent');
    return t;
  }
  var saved = 'dark';
  try { saved = localStorage.getItem('signhub-theme') || 'dark'; } catch (_) {}
  apply(saved);
  window.SignHubTheme = {
    get: function () { return root.getAttribute('data-theme'); },
    set: function (t) {
      t = apply(t);
      try { localStorage.setItem('signhub-theme', t); } catch (_) {}
      return t;
    }
  };
})();
