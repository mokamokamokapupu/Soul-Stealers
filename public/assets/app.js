(function () {
  'use strict';

  // ---------------------------------------------------------------------
  // View routing
  // ---------------------------------------------------------------------
  // Four views live in the DOM at all times; only one is ever visible.
  // Switching views is a pure client-side state change — no window.location,
  // no <a href> navigation, no reloads. The URL bar always stays on "/".
  //
  // IMPORTANT: this file makes zero authorization decisions on its own.
  // Every view transition below is triggered either by the user (e.g.
  // clicking the discreet entry mark) or by a successful response from a
  // server API call. The server independently re-checks the session stage
  // on every single API request (see server.js) — nothing here "unlocks"
  // anything. If someone hand-edits the DOM or calls showView('chat')
  // themselves, the chat view will render, but /api/chat/messages and
  // /api/chat/send will still return 403 with no data, exactly as if the
  // gate had never been passed.
  // ---------------------------------------------------------------------

  var VIEWS = ['essay', 'gate', 'setup', 'chat'];
  var currentView = 'essay';

  function showView(name) {
    if (VIEWS.indexOf(name) === -1) name = 'essay';
    VIEWS.forEach(function (v) {
      var el = document.getElementById('view-' + v);
      if (el) el.classList.toggle('active', v === name);
    });
    document.body.dataset.view = name;
    var wasChat = currentView === 'chat';
    currentView = name;

    if (name === 'chat') {
      startChatPolling();
    } else if (wasChat) {
      stopChatPolling();
    }
    if (name === 'gate') {
      var pw = document.getElementById('password');
      if (pw) pw.focus();
    } else if (name === 'setup') {
      var un = document.getElementById('username');
      if (un) un.focus();
    }
  }

  // ---------------------------------------------------------------------
  // Shared session/CSRF state, refreshed from /api/session as needed.
  // The frontend never decides who is authorized — it only mirrors
  // whatever the server's session bootstrap says, purely for UI purposes.
  // ---------------------------------------------------------------------

  var csrfToken = null;
  var myUsername = null;

  function applySessionData(data) {
    csrfToken = data.csrfToken || csrfToken;
    if (data.username) myUsername = data.username;
  }

  // ---------------------------------------------------------------------
  // Initial routing on load / refresh — this is the ONLY place that maps
  // the current stage + entry path to a starting view. The path a user
  // landed on (e.g. a bookmark to /chat) is treated as a *hint*, never a
  // grant: it's clamped down to whatever the server says the session is
  // actually allowed to see. The URL is then normalized back to "/".
  // ---------------------------------------------------------------------

  var PATH_HINT = { '/': 'essay', '/portal': 'gate', '/setup': 'setup', '/chat': 'chat' };
  var STAGE_MAX = { none: 'gate', password_ok: 'setup', active: 'chat' };

  async function bootstrapRouting() {
    var hinted = PATH_HINT[window.location.pathname] || 'essay';

    var data;
    try {
      var res = await fetch('/api/session', { credentials: 'same-origin' });
      data = await res.json();
    } catch (e) {
      data = { stage: 'none' };
    }
    applySessionData(data);

    var maxAllowed = STAGE_MAX[data.stage] || 'gate';
    var hintedIdx = VIEWS.indexOf(hinted);
    var maxIdx = VIEWS.indexOf(maxAllowed);
    var startView = VIEWS[Math.min(hintedIdx, maxIdx)];

    // Refresh from any path always normalizes the visible URL back to "/",
    // per the SPA requirement — the browser bar never shows /portal, /setup,
    // or /chat even though those paths still serve this same shell so old
    // links/bookmarks keep working.
    if (window.location.pathname !== '/') {
      window.history.replaceState(null, '', '/');
    }

    if (startView === 'chat') {
      myUsername = data.username;
      whoNameEl.textContent = myUsername || '—';
      myAvatarEl.src = avatarUrl(myUsername);
    }

    showView(startView);
    ready();
  }

  // ---------------------------------------------------------------------
  // Page fade-in (was site.js)
  // ---------------------------------------------------------------------

  function ready() {
    document.body.classList.add('is-ready');
  }

  // ---------------------------------------------------------------------
  // Gate view (was portal.js)
  // ---------------------------------------------------------------------

  var gateForm = document.getElementById('gate-form');
  var gateInput = document.getElementById('password');
  var gateError = document.getElementById('gate-error');
  var gateSubmit = document.getElementById('gate-submit');
  var gateCard = document.getElementById('gate-card');
  var gateBack = document.getElementById('gate-back');

  function setGateError(msg) { gateError.textContent = msg || ''; }

  gateBack.addEventListener('click', function () {
    setGateError('');
    gateInput.value = '';
    showView('essay');
  });

  gateForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    setGateError('');
    gateSubmit.disabled = true;
    try {
      var res = await fetch('/api/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ password: gateInput.value }),
      });
      var data = await res.json();
      if (res.ok) {
        applySessionData(data);
        gateSubmit.textContent = 'Entering…';
        gateCard.classList.add('is-leaving');
        setTimeout(function () {
          gateCard.classList.remove('is-leaving');
          gateSubmit.textContent = 'Enter';
          gateSubmit.disabled = false;
          gateInput.value = '';
          showView('setup');
        }, 280);
        return;
      } else if (res.status === 429) {
        setGateError('Too many attempts. Try again in ' + Math.ceil((data.retryAfterSec || 60) / 60) + ' min.');
      } else {
        setGateError(data.error || 'That is not the word.');
        gateInput.value = '';
        gateInput.focus();
      }
    } catch (err) {
      setGateError('Something went wrong. Try again.');
    } finally {
      if (!gateCard.classList.contains('is-leaving')) gateSubmit.disabled = false;
    }
  });

  // ---------------------------------------------------------------------
  // Setup view (was setup.js)
  // ---------------------------------------------------------------------

  var setupForm = document.getElementById('setup-form');
  var setupInput = document.getElementById('username');
  var setupError = document.getElementById('setup-error');
  var setupSubmit = document.getElementById('setup-submit');
  var setupCard = document.getElementById('setup-card');

  function setSetupError(msg) { setupError.textContent = msg || ''; }

  setupForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    setSetupError('');
    setupSubmit.disabled = true;
    try {
      var res = await fetch('/api/username', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ username: setupInput.value.trim() }),
      });
      var data = await res.json();
      if (res.ok) {
        applySessionData(data);
        myUsername = data.username;
        setupSubmit.textContent = 'Entering…';
        setupCard.classList.add('is-leaving');
        setTimeout(function () {
          setupCard.classList.remove('is-leaving');
          setupSubmit.textContent = 'Continue';
          setupSubmit.disabled = false;
          setupInput.value = '';
          whoNameEl.textContent = myUsername;
          myAvatarEl.src = avatarUrl(myUsername);
          showView('chat');
        }, 280);
        return;
      } else {
        setSetupError(data.error || 'Could not use that name.');
      }
    } catch (err) {
      setSetupError('Something went wrong. Try again.');
    } finally {
      if (!setupCard.classList.contains('is-leaving')) setupSubmit.disabled = false;
    }
  });

  // ---------------------------------------------------------------------
  // Chat view (was chat.js)
  // ---------------------------------------------------------------------

  var messagesEl = document.getElementById('messages');
  var composer = document.getElementById('composer');
  var msgInput = document.getElementById('msg-input');
  var whoNameEl = document.getElementById('who-name');
  var logoutBtn = document.getElementById('logout-btn');
  var myAvatarEl = document.getElementById('my-avatar');
  var avatarInput = document.getElementById('avatar-input');
  var avatarStatusEl = document.getElementById('avatar-status');

  var since = 0;
  var pollTimer = null;

  var NEAR_BOTTOM_PX = 80;

  function isNearBottom() {
    return messagesEl.scrollTop + messagesEl.clientHeight >= messagesEl.scrollHeight - NEAR_BOTTOM_PX;
  }

  function scrollToBottom() {
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function avatarUrl(username) {
    return '/api/avatar/' + encodeURIComponent(username || '');
  }

  function fmtTime(ts) {
    var d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function renderMessages(list) {
    if (list.length === 0) return;
    var wasEmpty = messagesEl.querySelector('.empty-state');
    if (wasEmpty) wasEmpty.remove();

    var stickToBottom = isNearBottom();

    list.forEach(function (m) {
      var wrap = document.createElement('div');
      wrap.className = 'msg' + (m.username === myUsername ? ' self' : '');

      var avatar = document.createElement('img');
      avatar.className = 'avatar';
      avatar.alt = '';
      avatar.src = avatarUrl(m.username);
      avatar.loading = 'lazy';

      var body = document.createElement('div');
      body.className = 'body';

      var meta = document.createElement('div');
      meta.className = 'meta';
      var nameSpan = document.createElement('span');
      nameSpan.className = 'name';
      nameSpan.textContent = m.username; // textContent — never innerHTML — no HTML injection possible
      meta.appendChild(nameSpan);
      meta.appendChild(document.createTextNode(' · ' + fmtTime(m.ts)));

      var text = document.createElement('div');
      text.className = 'text';
      text.textContent = m.text; // safe: rendered as plain text, not parsed as HTML

      body.appendChild(meta);
      body.appendChild(text);
      wrap.appendChild(avatar);
      wrap.appendChild(body);
      messagesEl.appendChild(wrap);
      since = Math.max(since, m.ts);
    });

    if (stickToBottom) scrollToBottom();
  }

  async function poll() {
    try {
      var res = await fetch('/api/chat/messages?since=' + since, { credentials: 'same-origin' });
      if (res.status === 403) {
        // Session lapsed server-side — the frontend just reflects that by
        // dropping back to the gate; it never itself decided access was OK.
        stopChatPolling();
        showView('gate');
        return;
      }
      var data = await res.json();
      renderMessages(data.messages || []);
    } catch (e) { /* transient network hiccup — next poll will retry */ }
  }

  function startChatPolling() {
    if (pollTimer) return;
    since = 0;
    messagesEl.innerHTML = '<p class="empty-state">It\'s quiet. Say something.</p>';
    poll().then(scrollToBottom);
    pollTimer = setInterval(poll, 1800);
  }

  function stopChatPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  composer.addEventListener('submit', async function (e) {
    e.preventDefault();
    var text = msgInput.value.trim();
    if (!text) return;
    msgInput.value = '';
    try {
      var res = await fetch('/api/chat/send', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ text: text }),
      });
      if (res.status === 403) { showView('gate'); return; }
      if (res.ok) { await poll(); scrollToBottom(); }
    } catch (e) { msgInput.value = text; }
  });

  function setAvatarStatus(msg, isError) {
    avatarStatusEl.textContent = msg || '';
    avatarStatusEl.classList.toggle('is-error', !!isError);
  }

  var MAX_AVATAR_CLIENT_BYTES = 3 * 1024 * 1024;
  var ALLOWED_AVATAR_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

  avatarInput.addEventListener('change', async function () {
    var file = avatarInput.files && avatarInput.files[0];
    if (!file) return;

    if (ALLOWED_AVATAR_TYPES.indexOf(file.type) === -1) {
      setAvatarStatus('Use a JPEG, PNG, or WebP image.', true);
      avatarInput.value = '';
      return;
    }
    if (file.size > MAX_AVATAR_CLIENT_BYTES) {
      setAvatarStatus('Image is too large (3MB max).', true);
      avatarInput.value = '';
      return;
    }

    setAvatarStatus('Uploading…');
    try {
      var res = await fetch('/api/avatar', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': file.type, 'X-CSRF-Token': csrfToken },
        body: file,
      });
      var data = await res.json();
      if (res.ok) {
        myAvatarEl.src = data.avatarUrl;
        setAvatarStatus('Profile picture updated.');
        setTimeout(function () { setAvatarStatus(''); }, 2500);
      } else {
        setAvatarStatus(data.error || 'Could not upload that image.', true);
      }
    } catch (e) {
      setAvatarStatus('Something went wrong. Try again.', true);
    } finally {
      avatarInput.value = '';
    }
  });

  logoutBtn.addEventListener('click', async function () {
    try {
      await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
    } catch (e) { /* best effort */ }
    stopChatPolling();
    myUsername = null;
    csrfToken = null;
    // Re-bootstrap to pick up a fresh session/CSRF token, then land on essay.
    var res = await fetch('/api/session', { credentials: 'same-origin' }).catch(function () { return null; });
    if (res) {
      try { applySessionData(await res.json()); } catch (e) { /* ignore */ }
    }
    showView('essay');
  });

  // ---------------------------------------------------------------------
  // Essay interactivity: scroll-reveal, discreet entry mark, section index
  // nav with active-section highlighting, and scroll-progress rail.
  // ---------------------------------------------------------------------

  var threshold = document.getElementById('threshold-mark');
  threshold.addEventListener('click', function () {
    setGateError('');
    showView('gate');
  });

  var essaySections = document.querySelectorAll('.essay section');
  if (essaySections.length && 'IntersectionObserver' in window) {
    var revealObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('in-view');
            revealObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15, rootMargin: '0px 0px -60px 0px' }
    );
    essaySections.forEach(function (s) { revealObserver.observe(s); });
  } else if (essaySections.length) {
    essaySections.forEach(function (s) { s.classList.add('in-view'); });
  }

  // Index nav: click a dot to smooth-scroll to its section; highlight the
  // dot matching whichever tradition section is currently in view.
  var indexNav = document.getElementById('index-nav');
  var indexDots = Array.prototype.slice.call(document.querySelectorAll('.index-dot'));
  indexDots.forEach(function (dot) {
    dot.addEventListener('click', function () {
      var target = document.getElementById(dot.dataset.target);
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  });

  var accentSections = Array.prototype.slice.call(document.querySelectorAll('.essay section[data-accent]'));
  if (accentSections.length && 'IntersectionObserver' in window) {
    var navObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          var dot = indexNav.querySelector('[data-target="' + entry.target.id + '"]');
          if (!dot) return;
          if (entry.isIntersecting) {
            indexDots.forEach(function (d) { d.classList.remove('is-active'); });
            dot.classList.add('is-active');
          }
        });
      },
      { threshold: 0.5 }
    );
    accentSections.forEach(function (s) { navObserver.observe(s); });
  }

  // Scroll-progress rail across the whole page.
  var progressFill = document.getElementById('progress-fill');
  function updateProgress() {
    var doc = document.documentElement;
    var scrollTop = doc.scrollTop || document.body.scrollTop;
    var height = doc.scrollHeight - doc.clientHeight;
    var pct = height > 0 ? Math.min(1, Math.max(0, scrollTop / height)) : 0;
    progressFill.style.transform = 'scaleX(' + pct + ')';
  }
  window.addEventListener('scroll', updateProgress, { passive: true });
  updateProgress();

  // A small, playful interactive touch on the hero sigil — click cycles an
  // accent hue. Purely decorative, no navigation.
  var heroSigil = document.getElementById('hero-sigil');
  var SIGIL_HUES = ['greek', 'dualism', 'abrahamic', 'dharmic', 'secular', ''];
  var sigilHueIdx = 0;
  heroSigil.style.cursor = 'pointer';
  heroSigil.addEventListener('click', function () {
    sigilHueIdx = (sigilHueIdx + 1) % SIGIL_HUES.length;
    var hue = SIGIL_HUES[sigilHueIdx];
    if (hue) {
      heroSigil.setAttribute('data-accent', hue);
    } else {
      heroSigil.removeAttribute('data-accent');
    }
  });

  // ---------------------------------------------------------------------
  // Go
  // ---------------------------------------------------------------------

  bootstrapRouting();
})();
