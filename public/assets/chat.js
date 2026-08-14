(function () {
  'use strict';

  var messagesEl = document.getElementById('messages');
  var composer = document.getElementById('composer');
  var input = document.getElementById('msg-input');
  var whoNameEl = document.getElementById('who-name');
  var logoutBtn = document.getElementById('logout-btn');

  var csrfToken = null;
  var myUsername = null;
  var since = 0;
  var pollTimer = null;

  function fmtTime(ts) {
    var d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function renderMessages(list) {
    if (list.length === 0) return;
    var wasEmpty = messagesEl.querySelector('.empty-state');
    if (wasEmpty) wasEmpty.remove();

    var atBottom = messagesEl.scrollTop + messagesEl.clientHeight >= messagesEl.scrollHeight - 40;

    list.forEach(function (m) {
      var wrap = document.createElement('div');
      wrap.className = 'msg' + (m.username === myUsername ? ' self' : '');

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

      wrap.appendChild(meta);
      wrap.appendChild(text);
      messagesEl.appendChild(wrap);
      since = Math.max(since, m.ts);
    });

    if (atBottom) messagesEl.scrollTop = messagesEl.scrollHeight;
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
      if (res.ok) { await poll(); }
    } catch (e) { /* leave text lost silently is bad — restore it */ input.value = text; }
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
    await poll();
    pollTimer = setInterval(poll, 1800);
  }

  bootstrap();
})();
