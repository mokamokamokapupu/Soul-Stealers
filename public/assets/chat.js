(function () {
  'use strict';

  var messagesEl = document.getElementById('messages');
  var composer = document.getElementById('composer');
  var input = document.getElementById('msg-input');
  var whoNameEl = document.getElementById('who-name');
  var logoutBtn = document.getElementById('logout-btn');
  var myAvatarEl = document.getElementById('my-avatar');
  var avatarInput = document.getElementById('avatar-input');
  var avatarStatusEl = document.getElementById('avatar-status');

  var csrfToken = null;
  var myUsername = null;
  var since = 0;
  var pollTimer = null;

  // How close to the bottom (in px) counts as "already at the bottom" —
  // if the user is within this, new messages auto-scroll them down; if
  // they've scrolled further up than this to read history, they're left
  // alone.
  var NEAR_BOTTOM_PX = 80;

  function isNearBottom() {
    return messagesEl.scrollTop + messagesEl.clientHeight >= messagesEl.scrollHeight - NEAR_BOTTOM_PX;
  }

  function scrollToBottom() {
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function avatarUrl(username) {
    return '/api/avatar/' + encodeURIComponent(username);
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
      if (res.status === 403) { window.location.href = '/portal'; return; }
      var data = await res.json();
      renderMessages(data.messages || []);
    } catch (e) { /* transient network hiccup — next poll will retry */ }
  }

  composer.addEventListener('submit', async function (e) {
    e.preventDefault();
    var text = input.value.trim();
    if (!text) return;
    input.value = '';
    try {
      var res = await fetch('/api/chat/send', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ text: text }),
      });
      if (res.status === 403) { window.location.href = '/portal'; return; }
      if (res.ok) { await poll(); scrollToBottom(); }
    } catch (e) { /* leave text lost silently is bad — restore it */ input.value = text; }
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

    // Client-side checks are convenience only — the server independently
    // sniffs the real file bytes and enforces the size limit regardless of
    // what's declared here.
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
    await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
    clearInterval(pollTimer);
    window.location.href = '/';
  });

  async function bootstrap() {
    var res = await fetch('/api/session', { credentials: 'same-origin' });
    var data = await res.json();
    if (data.stage !== 'active') {
      window.location.href = data.stage === 'password_ok' ? '/setup' : '/portal';
      return;
    }
    csrfToken = data.csrfToken;
    myUsername = data.username;
    whoNameEl.textContent = myUsername;
    myAvatarEl.src = avatarUrl(myUsername);
    await poll();
    scrollToBottom();
    pollTimer = setInterval(poll, 1800);
  }

  bootstrap();
})();
