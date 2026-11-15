/* SignHub gate: content is only available inside the installed web app,
   unless the visitor scrolls to the bottom and chooses "Continue on the web". */
(function () {
  var standalone = window.navigator.standalone === true ||
    (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);
  if (standalone) return;
  try { if (sessionStorage.getItem('signhub-web') === '1') return; } catch (_) {}

  var root = document.documentElement;
  root.classList.add('gated');

  var ios = /iPhone|iPad|iPod/.test(navigator.userAgent) ||
    (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

  var hero = ios
    ? '<img src="icon.png" width="84" height="84" alt="" class="gate-icon">' +
      '<h1>Install SignHub</h1>' +
      '<p>SignHub works best as a web app. Install it once and open it from your Home Screen.</p>' +
      '<a class="btn primary block" href="Install/SignHub_WebApp.mobileconfig">Install web app</a>' +
      '<ol class="gate-steps">' +
        '<li>Tap <b>Install web app</b> and choose <b>Allow</b>.</li>' +
        '<li>Open <b>Settings</b>, tap <b>Profile Downloaded</b>, then <b>Install</b>.</li>' +
        '<li>Open <b>SignHub</b> from your Home Screen.</li>' +
      '</ol>' +
      '<details class="fold"><summary>Or add it manually</summary><div class="fold-body">' +
        '<p class="hint" style="margin:0">In Safari, tap the <b>Share</b> button, choose <b>Add to Home Screen</b>, then open SignHub from your Home Screen.</p>' +
      '</div></details>'
    : '<img src="icon.png" width="84" height="84" alt="" class="gate-icon">' +
      '<h1>SignHub</h1>' +
      '<p>SignHub is made for iPhone and iPad. Open this page in Safari on your iOS device to install it.</p>';

  var about =
    '<h2>About SignHub</h2>' +
    '<p>SignHub is a simple web interface for signing and installing iOS apps. Upload an IPA, add your own signing certificate and provisioning profile, and get an install link for your iPhone or iPad.</p>' +
    '<p>The site also has ready-to-use certificates and a DNS profile that helps keep your sideloaded apps from being revoked.</p>' +
    '<h3>How it works</h3>' +
    '<ol><li>Choose your IPA file or paste a direct link.</li>' +
    '<li>Add your certificate, its password and your provisioning profile.</li>' +
    '<li>Tap <b>Sign IPA</b>, then open the install link in Safari.</li></ol>' +
    '<h3>Open source</h3>' +
    '<p>SignHub is open source. You can read the code on <a href="https://github.com/suleyman13900/SignHub" target="_blank" rel="noopener">GitHub</a>.</p>' +
    '<button type="button" id="gate-continue" class="gate-continue">Continue on the web</button>';

  function build() {
    var g = document.createElement('div');
    g.id = 'gate';
    g.innerHTML = '<section class="gate-hero">' + hero + '</section>' +
                  '<section class="gate-about">' + about + '</section>';
    document.body.appendChild(g);
    document.getElementById('gate-continue').addEventListener('click', function () {
      try { sessionStorage.setItem('signhub-web', '1'); } catch (_) {}
      root.classList.remove('gated');
      g.remove();
      window.scrollTo(0, 0);
    });
  }
  if (document.body) build(); else document.addEventListener('DOMContentLoaded', build);
})();
