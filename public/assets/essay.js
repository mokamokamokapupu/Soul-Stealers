(function () {
  'use strict';

  var body = document.body;
  body.classList.add('is-ready');

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
    var pct = height > 0 ? Math.min(1, Math.max(0, (doc.scrollTop || body.scrollTop) / height)) : 0;
    if (progressFill) progressFill.style.transform = 'scaleX(' + pct + ')';
  }
  window.addEventListener('scroll', updateProgress, { passive: true });
  updateProgress();

  if (document.querySelectorAll('.view').length > 1) return;

  var expected = '{{E}}';
  if (!expected || expected.charAt(0) === '{' || !(window.crypto && crypto.subtle)) return;

  var held = Object.create(null);
  var last = '';
  var busy = false;

  function hex(buf) {
    var out = '';
    new Uint8Array(buf).forEach(function (b) { out += (b < 16 ? '0' : '') + b.toString(16); });
    return out;
  }

  function digest(text) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)).then(hex);
  }

  async function consider() {
    var chord = Object.keys(held).sort().join('');
    if (chord.length < 3 || chord === last || busy) return;
    last = chord;
    busy = true;
    try {
      if (await digest(chord + '|a') !== expected) return;
      var proof = await digest(chord + '|b');
      await fetch('/', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ p: proof }),
      });
      window.location.replace('/');
    } catch (e) {
      /* stay put */
    } finally {
      busy = false;
    }
  }

  function keyOf(e) {
    return e.key && e.key.length === 1 ? e.key.toLowerCase() : '';
  }

  document.addEventListener('keydown', function (e) {
    var k = keyOf(e);
    if (!k || e.repeat) return;
    held[k] = true;
    consider();
  });
  document.addEventListener('keyup', function (e) {
    var k = keyOf(e);
    if (k) delete held[k];
    last = '';
  });
  window.addEventListener('blur', function () {
    held = Object.create(null);
    last = '';
  });
})();
