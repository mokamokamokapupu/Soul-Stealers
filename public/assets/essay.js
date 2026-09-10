(function () {
  'use strict';

  var body = document.body;
  var hasApp = document.querySelectorAll('.view').length > 2;

  // Set directly, not on a frame callback: a background tab never gets one,
  // and the page is invisible until this lands.
  function ready() {
    body.classList.add('is-ready');
  }

  // ---------------------------------------------------------------------
  // Section tabs, scroll reveals, progress rail
  // ---------------------------------------------------------------------

  var tabs = Array.prototype.slice.call(document.querySelectorAll('.pub-tab'));
  var panels = Array.prototype.slice.call(document.querySelectorAll('.pub-panel'));
  var tabsBar = document.getElementById('pub-tabs');

  function activateTab(name) {
    tabs.forEach(function (t) {
      var on = t.dataset.tab === name;
      t.classList.toggle('is-active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    panels.forEach(function (p) {
      var on = p.dataset.panel === name;
      p.classList.toggle('is-active', on);
      if (on) p.querySelectorAll('[data-reveal]').forEach(function (el) { el.classList.add('in-view'); });
    });
    if (tabsBar && tabsBar.getBoundingClientRect().top < 0) {
      tabsBar.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }
  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () { activateTab(tab.dataset.tab); });
  });

  var revealEls = document.querySelectorAll('[data-reveal]');
  if (revealEls.length && 'IntersectionObserver' in window) {
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('in-view');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });
    revealEls.forEach(function (el) { observer.observe(el); });
  } else {
    revealEls.forEach(function (el) { el.classList.add('in-view'); });
  }

  var progressFill = document.getElementById('progress-fill');
  function updateProgress() {
    var doc = document.documentElement;
    var height = doc.scrollHeight - doc.clientHeight;
    var pct = height > 0 ? Math.min(1, Math.max(0, (doc.scrollTop || document.body.scrollTop) / height)) : 0;
    if (progressFill) progressFill.style.transform = 'scaleX(' + pct + ')';
  }
  window.addEventListener('scroll', updateProgress, { passive: true });
  updateProgress();

  // Everything below only matters before there is a session; once the rest of
  // the page is present it owns the views and this file steps back.
  if (hasApp) { ready(); return; }

  // ---------------------------------------------------------------------
  // Entry
  // ---------------------------------------------------------------------

  var gateView = document.getElementById('view-gate');
  var essayView = document.getElementById('view-essay');
  var gateForm = document.getElementById('gate-form');
  var gateInput = document.getElementById('password');
  var gateError = document.getElementById('gate-error');
  var gateCard = document.getElementById('gate-card');

  function show(name) {
    essayView.classList.toggle('active', name === 'essay');
    gateView.classList.toggle('active', name === 'gate');
    body.dataset.view = name;
    if (name === 'gate') {
      gateInput.value = '';
      gateError.textContent = '';
      gateInput.focus();
    }
  }

  var KEYS = ['q', 'w', 'e', 'i', 'o', 'p'];
  var held = Object.create(null);
  var fired = false;

  function typingIn(el) {
    if (!el) return false;
    return el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable;
  }

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Tab' && body.dataset.view === 'gate') {
      e.preventDefault();
      show('essay');
      return;
    }
    var k = e.key ? e.key.toLowerCase() : '';
    if (KEYS.indexOf(k) === -1) return;
    if (typingIn(e.target)) {
      if (held[k]) e.preventDefault();
      return;
    }
    held[k] = true;
    if (!fired && body.dataset.view === 'essay' && KEYS.every(function (x) { return held[x]; })) {
      fired = true;
      e.preventDefault();
      show('gate');
    }
  });
  document.addEventListener('keyup', function (e) {
    var k = e.key ? e.key.toLowerCase() : '';
    if (KEYS.indexOf(k) !== -1) delete held[k];
    if (!KEYS.every(function (x) { return held[x]; })) fired = false;
  });
  window.addEventListener('blur', function () { held = Object.create(null); fired = false; });

  // The key is derived here, while the password is still in memory, and cached
  // for the tab. The page reloads straight after, and picks it back up.
  var ROOM_KEY_STORAGE = 'ss_room_key_v1';
  var PBKDF2_SALT = new TextEncoder().encode('soul-studies-key-v2');
  var PBKDF2_ITERATIONS = 150000;

  function bytesToBase64(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  async function cacheRoomKey(password) {
    if (!(window.crypto && window.crypto.subtle)) return;
    try {
      var baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
      var raw = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: PBKDF2_SALT, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        baseKey,
        256
      );
      sessionStorage.setItem(ROOM_KEY_STORAGE, bytesToBase64(new Uint8Array(raw)));
    } catch (e) { /* the unlock prompt covers it */ }
  }

  var csrfToken = null;

  gateForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    gateError.textContent = '';
    gateInput.disabled = true;
    var password = gateInput.value;
    try {
      if (!csrfToken) {
        var s = await fetch('/api/session', { credentials: 'same-origin' });
        csrfToken = (await s.json()).csrfToken;
      }
      var res = await fetch('/api/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ password: password }),
      });
      var data = await res.json();
      if (res.ok) {
        await cacheRoomKey(password);
        gateInput.value = '';
        if (gateCard) gateCard.classList.add('is-leaving');
        // Reload rather than swap views: the rest of the page is only sent to
        // a session that has already passed this point.
        window.location.replace('/setup');
        return;
      }
      csrfToken = null;
      if (res.status === 429) {
        gateError.textContent = 'Too many attempts. Try again in ' + Math.ceil((data.retryAfterSec || 60) / 60) + ' min.';
      } else {
        gateError.textContent = data.error || 'That is not the word.';
        gateInput.value = '';
        gateInput.focus();
      }
    } catch (err) {
      gateError.textContent = 'Something went wrong. Try again.';
    } finally {
      gateInput.disabled = false;
    }
  });

  show(document.body.dataset.view === 'gate' ? 'gate' : 'essay');
  ready();
})();
