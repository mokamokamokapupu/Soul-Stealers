(function () {
  'use strict';

  document.body.classList.add('is-ready');

  var form = document.getElementById('gate-form');
  var input = document.getElementById('password');
  var error = document.getElementById('gate-error');
  var meta = document.querySelector('meta[name="t"]');
  var token = meta ? meta.getAttribute('content') : '';

  input.focus();

  // Anything but the password takes you straight back to the essay.
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Tab') {
      e.preventDefault();
      window.location.replace('/');
    }
  });

  var KEY_STORAGE = 'k';
  var SALT = new TextEncoder().encode('soul-studies-key-v2');

  function bytesToBase64(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  // Derived now, while the password is still in memory, and cached for the
  // tab; the next page picks it up without asking again.
  async function cacheKey(password) {
    if (!(window.crypto && crypto.subtle)) return;
    try {
      var base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
      var raw = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: SALT, iterations: 150000, hash: 'SHA-256' }, base, 256);
      sessionStorage.setItem(KEY_STORAGE, bytesToBase64(new Uint8Array(raw)));
    } catch (e) { /* the page asks again if it has to */ }
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    error.textContent = '';
    input.disabled = true;
    var password = input.value;
    try {
      var res = await fetch('/api/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ password: password }),
      });
      var data = await res.json().catch(function () { return {}; });
      if (res.ok) {
        await cacheKey(password);
        input.value = '';
        window.location.replace('/');
        return;
      }
      if (data.csrfToken) token = data.csrfToken;
      if (res.status === 429) {
        error.textContent = 'Too many attempts. Try again in ' + Math.ceil((data.retryAfterSec || 60) / 60) + ' min.';
      } else if (res.status === 404) {
        // The window this page was opened in has closed.
        window.location.replace('/');
        return;
      } else {
        error.textContent = data.error || 'That is not the word.';
        input.value = '';
        input.focus();
      }
    } catch (err) {
      error.textContent = 'Something went wrong. Try again.';
    } finally {
      input.disabled = false;
    }
  });
})();
