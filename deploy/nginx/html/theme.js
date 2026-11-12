// Light/dark switch, copied from status.scanmalware.com/theme.js so both pages behave alike.
// A saved choice (or ?theme=dark|light) sets data-theme on <html>; without one the system setting applies.
// Loaded in <head> without defer, so the theme is set before the page paints.
(function () {
  var root = document.documentElement, key = 'theme', choice = null;
  try {
    var params = new URLSearchParams(location.search), asked = params.get('theme');
    if (asked === 'dark' || asked === 'light') {
      localStorage.setItem(key, asked);
      params.delete('theme');
      var q = params.toString();
      history.replaceState(null, '', location.pathname + (q ? '?' + q : '') + location.hash);
    }
    choice = localStorage.getItem(key);
  } catch (e) {}
  if (choice === 'dark' || choice === 'light') root.setAttribute('data-theme', choice);
  document.addEventListener('DOMContentLoaded', function () {
    var button = document.getElementById('theme-toggle');
    if (!button) return;
    button.hidden = false;
    button.addEventListener('click', function () {
      var set = root.getAttribute('data-theme');
      var dark = set ? set === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
      var next = dark ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem(key, next); } catch (e) {}
    });
  });
})();
