(function () {
  'use strict';

  // ---------------------------------------------------------------------
  // View routing — six views live in the DOM; only one is visible. All
  // authorization decisions happen server-side on every API call; this
  // file only mirrors what the server says (see server.js).
  // ---------------------------------------------------------------------

  var VIEWS = ['essay', 'gate', 'setup', 'chat', 'gpt', 'games'];
  var currentView = 'essay';

  function showView(name) {
    if (VIEWS.indexOf(name) === -1) name = 'essay';
    VIEWS.forEach(function (v) {
      var el = document.getElementById('view-' + v);
      if (el) el.classList.toggle('active', v === name);
    });
    document.body.dataset.view = name;
    var wasChat = currentView === 'chat';
    var wasGames = currentView === 'games';
    currentView = name;
    applyUiScale();

    if (name === 'chat') {
      startChatPolling();
    } else if (wasChat) {
      stopChatPolling();
    }
    if (wasGames && name !== 'games') leaveGames();
    if (name === 'games') enterGames();
    setKeepalive(name === 'gpt' || name === 'games');

    if (name === 'gate') {
      gateInput.value = '';
      setGateError('');
      gateInput.focus();
    } else if (name === 'setup') {
      setupInput.value = '';
      setSetupError('');
      setupInput.focus();
    } else if (name === 'gpt') {
      var gi = document.getElementById('gpt-input');
      if (gi) gi.focus();
    }
  }

  var keepaliveTimer = null;
  function setKeepalive(on) {
    if (on && !keepaliveTimer) {
      keepaliveTimer = setInterval(function () {
        fetch('/api/session', { credentials: 'same-origin' }).catch(function () { /* transient */ });
      }, 45000);
    } else if (!on && keepaliveTimer) {
      clearInterval(keepaliveTimer);
      keepaliveTimer = null;
    }
  }

  // ---------------------------------------------------------------------
  // Shared session/CSRF state
  // ---------------------------------------------------------------------

  var csrfToken = null;
  var myUsername = null;
  var myRoom = null;

  var ROOM_LABELS = { overwatch: 'Overwatch', meowmeow: 'meowmeow' };

  function applySessionData(data) {
    csrfToken = data.csrfToken || csrfToken;
    if (data.username) myUsername = data.username;
    if (data.room) myRoom = data.room;
  }

  function updateRoomTag() {
    if (!roomTagEl) return;
    roomTagEl.textContent = myRoom ? (ROOM_LABELS[myRoom] || myRoom) : '';
  }

  // ---------------------------------------------------------------------
  // Chat content encryption. The server stores and relays chat text as an
  // opaque blob — it never sees plaintext. The AES-GCM key is derived
  // (PBKDF2) from the site password, which every room member already
  // knows; the fixed salt is fine because all secrecy is in the password.
  // ---------------------------------------------------------------------

  var ROOM_KEY_STORAGE = 'ss_room_key_v1';
  var PBKDF2_SALT = new TextEncoder().encode('soul-studies-chat-room-v1');
  var PBKDF2_ITERATIONS = 150000;
  var roomKey = null;
  var cryptoAvailable = !!(window.crypto && window.crypto.subtle);

  function bytesToBase64(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function base64ToBytes(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  async function deriveRoomKey(password) {
    var enc = new TextEncoder().encode(password);
    var baseKey = await crypto.subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: PBKDF2_SALT, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async function setRoomKey(password) {
    roomKey = await deriveRoomKey(password);
    try {
      var raw = await crypto.subtle.exportKey('raw', roomKey);
      sessionStorage.setItem(ROOM_KEY_STORAGE, bytesToBase64(new Uint8Array(raw)));
    } catch (e) { /* private mode — key won't survive a refresh */ }
  }

  async function loadCachedRoomKey() {
    var b64;
    try { b64 = sessionStorage.getItem(ROOM_KEY_STORAGE); } catch (e) { return null; }
    if (!b64) return null;
    try {
      return await crypto.subtle.importKey('raw', base64ToBytes(b64), 'AES-GCM', true, ['encrypt', 'decrypt']);
    } catch (e) { return null; }
  }

  function clearRoomKey() {
    roomKey = null;
    try { sessionStorage.removeItem(ROOM_KEY_STORAGE); } catch (e) { /* ignore */ }
  }

  async function encryptText(plaintext) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var data = new TextEncoder().encode(plaintext);
    var cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, roomKey, data);
    var combined = new Uint8Array(iv.length + cipherBuf.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(cipherBuf), iv.length);
    return bytesToBase64(combined);
  }

  async function decryptText(b64) {
    if (!roomKey || typeof b64 !== 'string') return null;
    try {
      var combined = base64ToBytes(b64);
      if (combined.length < 13) return null;
      var iv = combined.slice(0, 12);
      var data = combined.slice(12);
      var plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, roomKey, data);
      return new TextDecoder().decode(plainBuf);
    } catch (e) {
      return null;
    }
  }

  // ---------------------------------------------------------------------
  // Initial routing — the landed-on path is a hint, never a grant: it is
  // clamped to whatever stage the server reports, then the URL is
  // normalized back to "/".
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

    if (window.location.pathname !== '/') {
      window.history.replaceState(null, '', '/');
    }

    if (startView === 'chat') {
      myUsername = data.username;
      whoNameEl.textContent = myUsername || '—';
      myAvatarEl.src = avatarUrl(myUsername);
      updateRoomTag();
      if (cryptoAvailable) roomKey = await loadCachedRoomKey();
      setUnlockVisible(cryptoAvailable && !roomKey);
    }

    showView(startView);
    ready();
  }

  function ready() {
    document.body.classList.add('is-ready');
  }

  // ---------------------------------------------------------------------
  // Gate view
  // ---------------------------------------------------------------------

  var gateForm = document.getElementById('gate-form');
  var gateInput = document.getElementById('password');
  var gateError = document.getElementById('gate-error');
  var gateCard = document.querySelector('.minimal-gate');

  function setGateError(msg) { gateError.textContent = msg || ''; }

  gateForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    setGateError('');
    gateInput.disabled = true;
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
        // Derive the room encryption key while the password is in memory —
        // it is never sent anywhere for this purpose.
        if (cryptoAvailable) {
          try { await setRoomKey(gateInput.value); } catch (e2) { /* unlock prompt will cover it */ }
        }
        gateCard.classList.add('is-leaving');
        setTimeout(function () {
          gateCard.classList.remove('is-leaving');
          gateInput.disabled = false;
          gateInput.value = '';
          showView('setup');
        }, 220);
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
      if (!gateCard.classList.contains('is-leaving')) gateInput.disabled = false;
    }
  });

  // ---------------------------------------------------------------------
  // Setup view
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
          updateRoomTag();
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
  // Chat view
  // ---------------------------------------------------------------------

  var messagesEl = document.getElementById('messages');
  var composer = document.getElementById('composer');
  var msgInput = document.getElementById('msg-input');
  var sendBtn = document.getElementById('send-btn');
  var whoNameEl = document.getElementById('who-name');
  var roomTagEl = document.getElementById('room-tag');
  var logoutBtn = document.getElementById('logout-btn');
  var myAvatarEl = document.getElementById('my-avatar');
  var avatarInput = document.getElementById('avatar-input');
  var avatarStatusEl = document.getElementById('avatar-status');
  var chatStatusEl = document.getElementById('chat-status');

  var imageBtnInput = document.getElementById('image-input');
  var emojiBtn = document.getElementById('emoji-btn');
  var emojiPopover = document.getElementById('emoji-popover');

  var replyPreviewEl = document.getElementById('reply-preview');
  var replyPreviewNameEl = document.getElementById('reply-preview-name');
  var replyPreviewTextEl = document.getElementById('reply-preview-text');
  var replyPreviewCancelBtn = document.getElementById('reply-preview-cancel');

  var unlockOverlay = document.getElementById('unlock-overlay');
  var unlockForm = document.getElementById('unlock-form');
  var unlockInput = document.getElementById('unlock-password');
  var unlockError = document.getElementById('unlock-error');

  var since = 0;
  var pollTimer = null;
  var pollInFlight = false;
  var renderedIds = Object.create(null);
  var lastAuthor = null; // who sent the most recently rendered message, for grouping
  var replyingTo = null;

  var NEAR_BOTTOM_PX = 80;

  function isNearBottom() {
    return messagesEl.scrollTop + messagesEl.clientHeight >= messagesEl.scrollHeight - NEAR_BOTTOM_PX;
  }

  function scrollToBottom(smooth) {
    if (smooth && 'scrollTo' in messagesEl) {
      messagesEl.scrollTo({ top: messagesEl.scrollHeight, behavior: 'smooth' });
    } else {
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }
  }

  function avatarUrl(username) {
    return '/api/avatar/' + encodeURIComponent(username || '');
  }

  function chatImageUrl(imageId) {
    return '/api/chat-image/' + encodeURIComponent(imageId || '');
  }

  function fmtTime(ts) {
    var d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function truncate(str, n) {
    if (str.length <= n) return str;
    return str.slice(0, n - 1) + '…';
  }

  function setReplyPreviewVisible(visible) {
    replyPreviewEl.hidden = !visible;
    replyPreviewEl.classList.toggle('is-open', visible);
  }

  function startReply(id, username, previewText) {
    replyingTo = { id: id, username: username, preview: previewText };
    replyPreviewNameEl.textContent = username;
    replyPreviewTextEl.textContent = previewText;
    setReplyPreviewVisible(true);
    msgInput.focus();
  }

  function cancelReply() {
    replyingTo = null;
    setReplyPreviewVisible(false);
  }

  replyPreviewCancelBtn.addEventListener('click', cancelReply);

  var EMOJI_SET = ['😀','😄','😁','😂','🤣','😊','🙂','😉','😍','🥰','😘','😎','🤔','🙄','😴',
    '😭','😢','😅','😳','😱','🥺','😡','🤯','🤗','🤩','😇','🙃','😬','😏','🫠',
    '👍','👎','👏','🙌','🙏','🤝','💪','✌️','🤞','👋',
    '❤️','🧡','💛','💚','💙','💜','🖤','🤍','💔','💯',
    '🔥','✨','🎉','🎊','💡','⭐','🌟','☀️','🌙','🌈',
    '🐱','🐶','🦋','🌸','🍀','☕','🍕','🎵','📚','🧠'];

  var emojiPopulated = false;
  function populateEmojiPicker() {
    if (emojiPopulated) return;
    emojiPopulated = true;
    EMOJI_SET.forEach(function (emoji) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'emoji-option';
      btn.textContent = emoji;
      btn.addEventListener('click', function () {
        insertAtCursor(msgInput, emoji);
      });
      emojiPopover.appendChild(btn);
    });
  }

  function insertAtCursor(input, str) {
    var start = input.selectionStart != null ? input.selectionStart : input.value.length;
    var end = input.selectionEnd != null ? input.selectionEnd : input.value.length;
    input.value = input.value.slice(0, start) + str + input.value.slice(end);
    var pos = start + str.length;
    input.focus();
    if (input.setSelectionRange) input.setSelectionRange(pos, pos);
  }

  function setEmojiPopoverOpen(open) {
    populateEmojiPicker();
    emojiPopover.hidden = !open;
    emojiBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    emojiBtn.classList.toggle('is-active', open);
  }

  emojiBtn.addEventListener('click', function (e) {
    e.stopPropagation();
    setEmojiPopoverOpen(emojiPopover.hidden);
  });
  document.addEventListener('click', function (e) {
    if (!emojiPopover.hidden && !emojiPopover.contains(e.target) && e.target !== emojiBtn) {
      setEmojiPopoverOpen(false);
    }
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !emojiPopover.hidden) setEmojiPopoverOpen(false);
  });

  function setUnlockVisible(visible) {
    unlockOverlay.hidden = !visible;
    if (visible) setTimeout(function () { unlockInput.focus(); }, 50);
  }

  unlockForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    unlockError.textContent = '';
    var candidate = unlockInput.value;
    unlockInput.disabled = true;
    try {
      var candidateKey = await deriveRoomKey(candidate);
      // Verify against a message already on screen when one exists; with an
      // empty room there is nothing to check against, so accept.
      var probe = messagesEl.querySelector('.msg[data-cipher]');
      var ok = true;
      if (probe) {
        var savedKey = roomKey;
        roomKey = candidateKey;
        var decrypted = await decryptText(probe.getAttribute('data-cipher'));
        ok = decrypted !== null;
        roomKey = savedKey;
      }
      if (!ok) {
        unlockError.textContent = 'That doesn\'t look right — try again.';
        unlockInput.value = '';
        unlockInput.disabled = false;
        unlockInput.focus();
        return;
      }
      roomKey = candidateKey;
      try {
        var raw = await crypto.subtle.exportKey('raw', roomKey);
        sessionStorage.setItem(ROOM_KEY_STORAGE, bytesToBase64(new Uint8Array(raw)));
      } catch (err) { /* key still works for this tab */ }
      unlockInput.value = '';
      unlockInput.disabled = false;
      setUnlockVisible(false);
      messagesEl.innerHTML = '';
      renderedIds = Object.create(null);
      lastAuthor = null;
      since = 0;
      await poll();
      scrollToBottom();
    } catch (err) {
      unlockError.textContent = 'Something went wrong. Try again.';
      unlockInput.disabled = false;
    }
  });

  async function buildReplyQuoteEl(replyTo) {
    var quote = document.createElement('button');
    quote.type = 'button';
    quote.className = 'msg-quote';
    var quoteName = document.createElement('span');
    quoteName.className = 'msg-quote-name';
    quoteName.textContent = replyTo.username;
    var quoteText = document.createElement('span');
    quoteText.className = 'msg-quote-text';
    if (replyTo.type === 'image') {
      quoteText.textContent = '📷 Photo';
    } else if (cryptoAvailable) {
      var decrypted = await decryptText(replyTo.cipher);
      quoteText.textContent = decrypted === null ? '🔒 message' : truncate(decrypted, 80);
    } else {
      quoteText.textContent = truncate(replyTo.cipher || '', 80);
    }
    quote.appendChild(quoteName);
    quote.appendChild(quoteText);
    quote.addEventListener('click', function () {
      var target = messagesEl.querySelector('[data-msg-id="' + CSS.escape(replyTo.id) + '"]');
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        target.classList.add('is-highlighted');
        setTimeout(function () { target.classList.remove('is-highlighted'); }, 1200);
      }
    });
    return quote;
  }

  async function renderOne(m) {
    if (renderedIds[m.id]) { since = Math.max(since, m.ts); return; }
    renderedIds[m.id] = true;

    // Consecutive messages from the same person render as one stream: no
    // repeated avatar or name, just the bubble, aligned under the first.
    var grouped = lastAuthor !== null && m.username === lastAuthor;

    var wrap = document.createElement('div');
    wrap.className = 'msg msg-enter' + (m.username === myUsername ? ' self' : '') + (grouped ? ' grouped' : '');
    wrap.dataset.msgId = m.id;

    var lead;
    if (grouped) {
      lead = document.createElement('div');
      lead.className = 'avatar-spacer';
    } else {
      lead = document.createElement('img');
      lead.className = 'avatar';
      lead.alt = '';
      lead.src = avatarUrl(m.username);
      lead.loading = 'lazy';
    }

    var body = document.createElement('div');
    body.className = 'body';

    if (!grouped) {
      var meta = document.createElement('div');
      meta.className = 'meta';
      var nameSpan = document.createElement('span');
      nameSpan.className = 'name';
      nameSpan.textContent = m.username; // textContent — never innerHTML
      meta.appendChild(nameSpan);
      meta.appendChild(document.createTextNode(' · ' + fmtTime(m.ts)));
      body.appendChild(meta);
    }

    if (m.replyTo) {
      body.appendChild(await buildReplyQuoteEl(m.replyTo));
    }

    var previewForReply;

    if (m.type === 'image') {
      var figure = document.createElement('button');
      figure.type = 'button';
      figure.className = 'msg-image-btn';
      var img = document.createElement('img');
      img.className = 'msg-image';
      img.alt = m.username + ' sent an image';
      img.loading = 'lazy';
      img.src = chatImageUrl(m.imageId);
      figure.appendChild(img);
      figure.addEventListener('click', function () { openLightbox(img.src); });
      body.appendChild(figure);
      previewForReply = '📷 Photo';
    } else {
      var text = document.createElement('div');
      text.className = 'text';
      var plain = m.text;
      if (cryptoAvailable) {
        var decrypted = await decryptText(m.text);
        plain = decrypted === null ? null : decrypted;
        wrap.setAttribute('data-cipher', m.text);
      }
      text.textContent = plain === null ? '🔒 Unable to decrypt this message' : plain;
      if (plain === null) text.classList.add('is-locked');
      body.appendChild(text);
      previewForReply = plain === null ? '🔒 message' : plain;
    }

    var actions = document.createElement('div');
    actions.className = 'msg-actions';
    var replyBtn = document.createElement('button');
    replyBtn.type = 'button';
    replyBtn.className = 'msg-action-btn';
    replyBtn.textContent = '↩ Reply';
    replyBtn.addEventListener('click', function () { startReply(m.id, m.username, truncate(previewForReply, 80)); });
    actions.appendChild(replyBtn);
    body.appendChild(actions);

    wrap.appendChild(lead);
    wrap.appendChild(body);
    messagesEl.appendChild(wrap);
    lastAuthor = m.username;
    since = Math.max(since, m.ts);

    requestAnimationFrame(function () {
      requestAnimationFrame(function () { wrap.classList.add('msg-enter-active'); });
    });
    setTimeout(function () { wrap.classList.remove('msg-enter', 'msg-enter-active'); }, 500);
  }

  async function renderMessages(list) {
    if (list.length === 0) return;
    var wasEmpty = messagesEl.querySelector('.empty-state');
    if (wasEmpty) wasEmpty.remove();

    var stickToBottom = isNearBottom();
    for (var i = 0; i < list.length; i++) {
      await renderOne(list[i]);
    }
    if (stickToBottom) scrollToBottom(true);
  }

  function openLightbox(src) {
    var overlay = document.createElement('div');
    overlay.className = 'lightbox';
    var img = document.createElement('img');
    img.src = src;
    overlay.appendChild(img);
    overlay.addEventListener('click', function () { overlay.remove(); });
    document.addEventListener('keydown', function esc(e) {
      if (e.key === 'Escape') { overlay.remove(); document.removeEventListener('keydown', esc); }
    });
    document.body.appendChild(overlay);
    requestAnimationFrame(function () { overlay.classList.add('is-open'); });
  }

  async function poll() {
    if (pollInFlight) return;
    pollInFlight = true;
    try {
      var res = await fetch('/api/chat/messages?since=' + since, { credentials: 'same-origin' });
      if (res.status === 403) {
        stopChatPolling();
        showView('gate');
        return;
      }
      var data = await res.json();
      await renderMessages(data.messages || []);
    } catch (e) { /* transient — next poll retries */ }
    finally { pollInFlight = false; }
  }

  function startChatPolling() {
    if (pollTimer) return;
    since = 0;
    renderedIds = Object.create(null);
    lastAuthor = null;
    messagesEl.innerHTML = '<p class="empty-state">It\'s quiet. Say something.</p>';
    poll().then(function () { scrollToBottom(false); });
    pollTimer = setInterval(poll, 1800);
  }

  function stopChatPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  function setChatStatus(msg, isError) {
    if (!chatStatusEl) return;
    chatStatusEl.textContent = msg || '';
    chatStatusEl.classList.toggle('is-error', !!isError);
  }

  composer.addEventListener('submit', async function (e) {
    e.preventDefault();
    var text = msgInput.value.trim();
    if (!text) return;
    if (cryptoAvailable && !roomKey) { setUnlockVisible(true); return; }

    msgInput.value = '';
    sendBtn.disabled = true;
    sendBtn.classList.add('is-sending');
    var pendingReplyTo = replyingTo ? replyingTo.id : undefined;
    cancelReply();

    try {
      var payloadText = cryptoAvailable ? await encryptText(text) : text;
      var res = await fetch('/api/chat/send', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ text: payloadText, replyTo: pendingReplyTo }),
      });
      if (res.status === 403) { showView('gate'); return; }
      var data = await res.json();
      if (res.ok && data.message) {
        // Render straight from the send response; the id-based dedup in
        // renderOne covers the interval poll picking it up again.
        await renderMessages([data.message]);
        scrollToBottom(true);
      } else if (!res.ok) {
        setChatStatus(data.error || 'Could not send that message.', true);
        setTimeout(function () { setChatStatus(''); }, 3000);
      }
    } catch (err) {
      msgInput.value = text;
    } finally {
      sendBtn.disabled = false;
      sendBtn.classList.remove('is-sending');
    }
  });

  imageBtnInput.addEventListener('change', async function () {
    var file = imageBtnInput.files && imageBtnInput.files[0];
    if (!file) return;
    var allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowed.indexOf(file.type) === -1) {
      setChatStatus('Use a JPEG, PNG, or WebP image.', true);
      imageBtnInput.value = '';
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setChatStatus('Image is too large (5MB max).', true);
      imageBtnInput.value = '';
      return;
    }

    var pendingReplyTo = replyingTo ? replyingTo.id : undefined;
    cancelReply();
    setChatStatus('Sending image…');
    try {
      var url = '/api/chat/image' + (pendingReplyTo ? '?replyTo=' + encodeURIComponent(pendingReplyTo) : '');
      var res = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': file.type, 'X-CSRF-Token': csrfToken },
        body: file,
      });
      if (res.status === 403) { showView('gate'); return; }
      var data = await res.json();
      if (res.ok && data.message) {
        await renderMessages([data.message]);
        scrollToBottom(true);
        setChatStatus('');
      } else {
        setChatStatus(data.error || 'Could not send that image.', true);
        setTimeout(function () { setChatStatus(''); }, 3000);
      }
    } catch (e2) {
      setChatStatus('Something went wrong. Try again.', true);
    } finally {
      imageBtnInput.value = '';
    }
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
    } catch (e2) {
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
    myRoom = null;
    csrfToken = null;
    clearRoomKey();
    cancelReply();
    updateRoomTag();
    var res = await fetch('/api/session', { credentials: 'same-origin' }).catch(function () { return null; });
    if (res) {
      try { applySessionData(await res.json()); } catch (e) { /* ignore */ }
    }
    resetGpt();
    lastSubmitted = { snake: 0, tetris: 0, mines: 0, cookie: 0 };
    showView('essay');
  });

  // ---------------------------------------------------------------------
  // Appearance settings: interface scale + color skins, persisted locally
  // and applied only in the private views.
  // ---------------------------------------------------------------------

  var SCALE_KEY = 'ss_ui_scale';
  var SKIN_KEY = 'ss_chat_skin';
  var SKINS = ['', 'abyss', 'plum', 'crimson', 'paper'];
  var uiScale = 1;
  var chatSkin = '';
  try {
    var savedScale = parseFloat(localStorage.getItem(SCALE_KEY));
    if (savedScale >= 0.8 && savedScale <= 1.3) uiScale = savedScale;
    var savedSkin = localStorage.getItem(SKIN_KEY);
    if (SKINS.indexOf(savedSkin) > 0) chatSkin = savedSkin;
  } catch (e) { /* private mode */ }

  var settingsBtn = document.getElementById('chat-settings-btn');
  var settingsPanel = document.getElementById('chat-settings');
  var scaleInput = document.getElementById('ui-scale');
  var scaleValue = document.getElementById('ui-scale-value');
  var skinButtons = Array.prototype.slice.call(document.querySelectorAll('.skin-swatch'));

  function applyUiScale() {
    var scaled = currentView === 'chat' || currentView === 'gpt' || currentView === 'games';
    document.documentElement.style.fontSize = (scaled && uiScale !== 1) ? (uiScale * 100) + '%' : '';
  }

  function applySkin() {
    if (chatSkin) {
      document.body.dataset.chatSkin = chatSkin;
    } else {
      delete document.body.dataset.chatSkin;
    }
    skinButtons.forEach(function (b) {
      b.classList.toggle('is-active', (b.dataset.skin || '') === chatSkin);
    });
  }

  settingsBtn.addEventListener('click', function () {
    var open = settingsPanel.hidden;
    settingsPanel.hidden = !open;
    settingsBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    settingsBtn.classList.toggle('is-active', open);
  });

  scaleInput.value = String(uiScale);
  scaleValue.textContent = Math.round(uiScale * 100) + '%';
  scaleInput.addEventListener('input', function () {
    uiScale = parseFloat(scaleInput.value) || 1;
    scaleValue.textContent = Math.round(uiScale * 100) + '%';
    try { localStorage.setItem(SCALE_KEY, String(uiScale)); } catch (e) { /* ignore */ }
    applyUiScale();
  });

  skinButtons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      chatSkin = btn.dataset.skin || '';
      try { localStorage.setItem(SKIN_KEY, chatSkin); } catch (e) { /* ignore */ }
      applySkin();
    });
  });
  applySkin();

  // ---------------------------------------------------------------------
  // Assistant view (G+P+T)
  // ---------------------------------------------------------------------

  var gptMessagesEl = document.getElementById('gpt-messages');
  var gptForm = document.getElementById('gpt-form');
  var gptInput = document.getElementById('gpt-input');
  var gptSend = document.getElementById('gpt-send');
  var gptFallback = document.getElementById('gpt-fallback');
  var gptBack = document.getElementById('gpt-back');
  var gptClear = document.getElementById('gpt-clear');
  var GPT_EMPTY_HTML = '<p class="empty-state">Ask anything. This conversation lives only in this tab and is never stored.</p>';
  var gptHistory = [];
  var gptBusy = false;

  function addGptBubble(role, text, pending) {
    var empty = gptMessagesEl.querySelector('.empty-state');
    if (empty) empty.remove();
    var el = document.createElement('div');
    el.className = 'gpt-msg ' + role + (pending ? ' pending' : '');
    el.textContent = text;
    gptMessagesEl.appendChild(el);
    gptMessagesEl.scrollTop = gptMessagesEl.scrollHeight;
    return el;
  }

  function resetGpt() {
    gptHistory = [];
    gptMessagesEl.innerHTML = GPT_EMPTY_HTML;
    gptFallback.hidden = true;
  }

  gptClear.addEventListener('click', resetGpt);
  gptBack.addEventListener('click', function () { showView('chat'); });

  gptForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    if (gptBusy) return;
    var text = gptInput.value.trim();
    if (!text) return;
    gptInput.value = '';
    gptFallback.hidden = true;
    gptHistory.push({ role: 'user', content: text });
    addGptBubble('user', text);
    var pendingEl = addGptBubble('assistant', '…', true);
    gptBusy = true;
    gptSend.disabled = true;
    try {
      var res = await fetch('/api/gpt', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({
          messages: gptHistory.slice(-12).map(function (m) {
            return { role: m.role, content: m.content.slice(0, 6000) };
          }),
        }),
      });
      if (res.status === 403) { showView('gate'); return; }
      var data = await res.json();
      if (res.ok && data.reply) {
        pendingEl.classList.remove('pending');
        pendingEl.textContent = data.reply;
        gptHistory.push({ role: 'assistant', content: data.reply });
      } else {
        pendingEl.remove();
        gptHistory.pop();
        gptInput.value = text;
        gptFallback.hidden = false;
      }
    } catch (err) {
      pendingEl.remove();
      gptHistory.pop();
      gptInput.value = text;
      gptFallback.hidden = false;
    } finally {
      gptBusy = false;
      gptSend.disabled = false;
      gptInput.focus();
      gptMessagesEl.scrollTop = gptMessagesEl.scrollHeight;
    }
  });

  // ---------------------------------------------------------------------
  // Arcade shared: tabs, leaderboard, score submission
  // ---------------------------------------------------------------------

  var gamesWho = document.getElementById('games-who');
  var gamesBack = document.getElementById('games-back');
  var gameTabs = Array.prototype.slice.call(document.querySelectorAll('.game-tab'));
  var lbGameLabel = document.getElementById('lb-game-label');
  var lbPodium = document.getElementById('lb-podium');
  var lbRest = document.getElementById('lb-rest');
  var lbEmpty = document.getElementById('lb-empty');
  var GAME_LABELS = { snake: 'Snake', tetris: 'Tetris', mines: 'Minesweeper', cookie: 'Cookie Clicker' };
  var activeGame = 'snake';
  var lastScores = {};
  var lastSubmitted = { snake: 0, tetris: 0, mines: 0, cookie: 0 };

  gamesBack.addEventListener('click', function () { showView('chat'); });

  function fmtScore(n) {
    if (n >= 1e9) return (n / 1e9).toFixed(1) + 'b';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'm';
    if (n >= 1e4) return Math.round(n / 1e3) + 'k';
    return String(Math.floor(n));
  }

  function isMe(name) {
    return myUsername && name && name.toLowerCase() === myUsername.toLowerCase();
  }

  function renderLeaderboard(scores) {
    lastScores = scores || {};
    renderActiveLb();
  }

  function renderActiveLb() {
    lbGameLabel.textContent = GAME_LABELS[activeGame] || activeGame;
    var list = lastScores[activeGame] || [];
    lbPodium.innerHTML = '';
    lbRest.innerHTML = '';
    lbEmpty.hidden = list.length > 0;

    [1, 0, 2].forEach(function (idx) {
      if (!list[idx]) return;
      var row = list[idx];
      var card = document.createElement('div');
      card.className = 'podium-card rank-' + (idx + 1) + (isMe(row.username) ? ' is-me' : '');
      var medal = document.createElement('span');
      medal.className = 'podium-medal';
      medal.textContent = ['🥇', '🥈', '🥉'][idx];
      var img = document.createElement('img');
      img.className = 'podium-avatar';
      img.alt = '';
      img.src = avatarUrl(row.username);
      var name = document.createElement('span');
      name.className = 'podium-name';
      name.textContent = row.username;
      var val = document.createElement('b');
      val.className = 'podium-score';
      val.textContent = fmtScore(row.score);
      card.appendChild(medal);
      card.appendChild(img);
      card.appendChild(name);
      card.appendChild(val);
      lbPodium.appendChild(card);
    });

    list.slice(3, 10).forEach(function (row, i) {
      var li = document.createElement('li');
      if (isMe(row.username)) li.classList.add('is-me');
      var rank = document.createElement('span');
      rank.className = 'lb-rank';
      rank.textContent = String(i + 4);
      var name = document.createElement('span');
      name.className = 'lb-name';
      name.textContent = row.username;
      var val = document.createElement('b');
      val.textContent = fmtScore(row.score);
      li.appendChild(rank);
      li.appendChild(name);
      li.appendChild(val);
      lbRest.appendChild(li);
    });
  }

  async function fetchLeaderboard() {
    try {
      var res = await fetch('/api/games/scores', { credentials: 'same-origin' });
      if (!res.ok) return;
      var data = await res.json();
      renderLeaderboard(data.scores);
    } catch (e) { /* stays as-is */ }
  }

  async function submitScore(game, score) {
    score = Math.floor(score);
    if (!(score > 0) || score <= lastSubmitted[game]) return;
    lastSubmitted[game] = score;
    try {
      var res = await fetch('/api/games/score', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ game: game, score: score }),
      });
      if (res.ok) {
        var data = await res.json();
        if (data.scores) renderLeaderboard(data.scores);
      }
    } catch (e) { /* resubmits on the next event */ }
  }

  function setActiveGame(name) {
    if (activeGame !== name) {
      stopSnake(true);
      stopTetris(true);
      stopMines();
    }
    activeGame = name;
    gameTabs.forEach(function (t) { t.classList.toggle('is-active', t.dataset.game === name); });
    ['snake', 'tetris', 'mines', 'cookie'].forEach(function (g) {
      document.getElementById('stage-' + g).hidden = g !== name;
    });
    renderActiveLb();
  }

  gameTabs.forEach(function (tab) {
    tab.addEventListener('click', function () { setActiveGame(tab.dataset.game); });
  });

  function enterGames() {
    gamesWho.textContent = myUsername || '—';
    loadCookieState();
    startCookieLoop();
    loadTetrisCfg();
    if (!minesBuilt) newMines();
    fetchLeaderboard();
  }

  function leaveGames() {
    stopSnake(true);
    stopTetris(true);
    stopMines();
    submitScore('cookie', cookie.total);
    stopCookieLoop();
  }

  // ---------------------------------------------------------------------
  // Snake — speed and apple count are adjustable, Google-style
  // ---------------------------------------------------------------------

  var snakeCanvas = document.getElementById('snake-canvas');
  var snakeCtx = snakeCanvas.getContext('2d');
  var snakeOverlay = document.getElementById('snake-overlay');
  var snakeMsg = document.getElementById('snake-msg');
  var snakeStartBtn = document.getElementById('snake-start');
  var snakeScoreEl = document.getElementById('snake-score');
  var snakeBestEl = document.getElementById('snake-best');
  var SNAKE_CELLS = 19;
  var SNAKE_PX = 20;
  var SNAKE_HINT = 'arrows or WASD · eat, grow, don\'t die';
  var SNAKE_SPEEDS = { slow: 170, normal: 125, fast: 85 };
  var SNAKE_OPTS_KEY = 'ss_snake_opts';
  var snakeOpts = { speed: 'normal', apples: 1 };
  try {
    var savedSnake = JSON.parse(localStorage.getItem(SNAKE_OPTS_KEY) || '{}');
    if (SNAKE_SPEEDS[savedSnake.speed]) snakeOpts.speed = savedSnake.speed;
    if ([1, 3, 5].indexOf(savedSnake.apples) !== -1) snakeOpts.apples = savedSnake.apples;
  } catch (e) { /* defaults */ }
  var snake = null;
  var snakeTimer = null;
  var snakeBest = 0;

  function saveSnakeOpts() {
    try { localStorage.setItem(SNAKE_OPTS_KEY, JSON.stringify(snakeOpts)); } catch (e) { /* ignore */ }
  }

  function refreshSnakeOptButtons() {
    document.querySelectorAll('#snake-speed button').forEach(function (b) {
      b.classList.toggle('is-active', b.dataset.speed === snakeOpts.speed);
    });
    document.querySelectorAll('#snake-apples button').forEach(function (b) {
      b.classList.toggle('is-active', Number(b.dataset.apples) === snakeOpts.apples);
    });
  }

  document.querySelectorAll('#snake-speed button').forEach(function (b) {
    b.addEventListener('click', function () {
      snakeOpts.speed = b.dataset.speed;
      saveSnakeOpts();
      refreshSnakeOptButtons();
      if (snake) snake.delay = SNAKE_SPEEDS[snakeOpts.speed];
    });
  });
  document.querySelectorAll('#snake-apples button').forEach(function (b) {
    b.addEventListener('click', function () {
      snakeOpts.apples = Number(b.dataset.apples);
      saveSnakeOpts();
      refreshSnakeOptButtons();
      if (snake) {
        while (snake.foods.length < snakeOpts.apples) snake.foods.push(snakeSpawnFood(snake));
        snake.foods.length = Math.min(snake.foods.length, snakeOpts.apples);
        drawSnake();
      }
    });
  });
  refreshSnakeOptButtons();

  function snakeSpawnFood(s) {
    while (true) {
      var p = {
        x: Math.floor(Math.random() * SNAKE_CELLS),
        y: Math.floor(Math.random() * SNAKE_CELLS),
      };
      var clash = s.body.some(function (b) { return b.x === p.x && b.y === p.y; }) ||
        s.foods.some(function (f) { return f.x === p.x && f.y === p.y; });
      if (!clash) return p;
    }
  }

  function themeColor(name, fallback) {
    var v = getComputedStyle(document.body).getPropertyValue(name).trim();
    return v || fallback;
  }

  function drawSnake() {
    snakeCtx.clearRect(0, 0, snakeCanvas.width, snakeCanvas.height);
    if (!snake) return;
    var accent = themeColor('--verdigris', '#6f8f76');
    var bright = themeColor('--verdigris-bright', '#93b89a');
    snakeCtx.fillStyle = themeColor('--danger', '#a65b4b');
    snake.foods.forEach(function (f) {
      snakeCtx.beginPath();
      snakeCtx.arc(f.x * SNAKE_PX + 10, f.y * SNAKE_PX + 10, 7, 0, Math.PI * 2);
      snakeCtx.fill();
    });
    snake.body.forEach(function (b, i) {
      snakeCtx.fillStyle = i === 0 ? bright : accent;
      snakeCtx.fillRect(b.x * SNAKE_PX + 1, b.y * SNAKE_PX + 1, SNAKE_PX - 2, SNAKE_PX - 2);
    });
  }

  function startSnake() {
    snake = {
      body: [{ x: 9, y: 9 }, { x: 8, y: 9 }, { x: 7, y: 9 }],
      dir: { x: 1, y: 0 },
      nextDir: { x: 1, y: 0 },
      score: 0,
      foods: [],
      delay: SNAKE_SPEEDS[snakeOpts.speed],
    };
    for (var i = 0; i < snakeOpts.apples; i++) snake.foods.push(snakeSpawnFood(snake));
    snakeScoreEl.textContent = '0';
    snakeOverlay.hidden = true;
    drawSnake();
    snakeTimer = setTimeout(snakeTick, snake.delay);
  }

  function snakeTick() {
    snakeTimer = null;
    if (!snake) return;
    snake.dir = snake.nextDir;
    var head = { x: snake.body[0].x + snake.dir.x, y: snake.body[0].y + snake.dir.y };
    var hitWall = head.x < 0 || head.y < 0 || head.x >= SNAKE_CELLS || head.y >= SNAKE_CELLS;
    var hitSelf = snake.body.some(function (b) { return b.x === head.x && b.y === head.y; });
    if (hitWall || hitSelf) { endSnake(); return; }
    snake.body.unshift(head);
    var ate = -1;
    for (var i = 0; i < snake.foods.length; i++) {
      if (snake.foods[i].x === head.x && snake.foods[i].y === head.y) { ate = i; break; }
    }
    if (ate !== -1) {
      snake.score += 10;
      snakeScoreEl.textContent = String(snake.score);
      snake.foods[ate] = snakeSpawnFood(snake);
      if (snake.delay > 65) snake.delay -= 2;
    } else {
      snake.body.pop();
    }
    drawSnake();
    snakeTimer = setTimeout(snakeTick, snake.delay);
  }

  function endSnake() {
    if (snakeTimer) { clearTimeout(snakeTimer); snakeTimer = null; }
    var finalScore = snake ? snake.score : 0;
    snake = null;
    if (finalScore > snakeBest) {
      snakeBest = finalScore;
      snakeBestEl.textContent = String(finalScore);
    }
    snakeMsg.textContent = 'game over · score ' + finalScore;
    snakeStartBtn.textContent = 'play again';
    snakeOverlay.hidden = false;
    submitScore('snake', finalScore);
  }

  function stopSnake(abandon) {
    if (snakeTimer) { clearTimeout(snakeTimer); snakeTimer = null; }
    if (!snake) return;
    if (abandon && snake.score > 0) submitScore('snake', snake.score);
    snake = null;
    snakeMsg.textContent = SNAKE_HINT;
    snakeStartBtn.textContent = 'play';
    snakeOverlay.hidden = false;
  }

  snakeStartBtn.addEventListener('click', startSnake);

  var SNAKE_DIRS = {
    arrowup: { x: 0, y: -1 }, w: { x: 0, y: -1 },
    arrowdown: { x: 0, y: 1 }, s: { x: 0, y: 1 },
    arrowleft: { x: -1, y: 0 }, a: { x: -1, y: 0 },
    arrowright: { x: 1, y: 0 }, d: { x: 1, y: 0 },
  };

  // ---------------------------------------------------------------------
  // Tetris — guideline-style: SRS kicks, 7-bag with 5-piece preview, hold,
  // ghost piece, DAS/ARR handling, lock delay with move resets, T-spins,
  // back-to-back and combo scoring. Keybinds are per-username.
  // ---------------------------------------------------------------------

  var tetrisCanvas = document.getElementById('tetris-canvas');
  var tetrisCtx = tetrisCanvas.getContext('2d');
  var tHoldCanvas = document.getElementById('t-hold');
  var tHoldCtx = tHoldCanvas.getContext('2d');
  var tNextCanvas = document.getElementById('t-next');
  var tNextCtx = tNextCanvas.getContext('2d');
  var tetrisOverlay = document.getElementById('tetris-overlay');
  var tetrisMsg = document.getElementById('tetris-msg');
  var tetrisStartBtn = document.getElementById('tetris-start');
  var tetrisScoreEl = document.getElementById('tetris-score');
  var tetrisLinesEl = document.getElementById('tetris-lines');
  var tetrisLevelEl = document.getElementById('tetris-level');
  var tetrisComboEl = document.getElementById('tetris-combo');
  var tetrisB2bEl = document.getElementById('tetris-b2b');
  var tetrisActionEl = document.getElementById('tetris-action');
  var tetrisKeysBtn = document.getElementById('tetris-keys-btn');
  var tetrisKeypanel = document.getElementById('tetris-keypanel');
  var tBindsEl = document.getElementById('t-binds');
  var tKeysUserEl = document.getElementById('t-keys-user');
  var tDasInput = document.getElementById('t-das');
  var tDasVal = document.getElementById('t-das-val');
  var tArrInput = document.getElementById('t-arr');
  var tArrVal = document.getElementById('t-arr-val');

  var T_COLS = 10;
  var T_ROWS = 20;
  var T_PX = 24;
  var T_LOCK_MS = 500;
  var T_LOCK_RESETS = 15;

  var T_DEFS = {
    I: { color: '#41c6d8', size: 4, cells: [[0, 1], [1, 1], [2, 1], [3, 1]] },
    J: { color: '#5b7de0', size: 3, cells: [[0, 0], [0, 1], [1, 1], [2, 1]] },
    L: { color: '#e09b4a', size: 3, cells: [[2, 0], [0, 1], [1, 1], [2, 1]] },
    O: { color: '#e8d24b', size: 2, cells: [[0, 0], [1, 0], [0, 1], [1, 1]] },
    S: { color: '#5fd875', size: 3, cells: [[1, 0], [2, 0], [0, 1], [1, 1]] },
    T: { color: '#b45fd8', size: 3, cells: [[1, 0], [0, 1], [1, 1], [2, 1]] },
    Z: { color: '#e05b5b', size: 3, cells: [[0, 0], [1, 0], [1, 1], [2, 1]] },
  };

  function rotateCells(cells, size) {
    return cells.map(function (c) { return [size - 1 - c[1], c[0]]; });
  }

  var T_SHAPES = {};
  Object.keys(T_DEFS).forEach(function (t) {
    var rots = [T_DEFS[t].cells];
    for (var i = 1; i < 4; i++) rots.push(rotateCells(rots[i - 1], T_DEFS[t].size));
    T_SHAPES[t] = rots;
  });

  // SRS kick tables, already converted to screen coordinates (y grows down).
  var KICKS_JLSTZ = {
    '0>1': [[0, 0], [-1, 0], [-1, -1], [0, 2], [-1, 2]],
    '1>0': [[0, 0], [1, 0], [1, 1], [0, -2], [1, -2]],
    '1>2': [[0, 0], [1, 0], [1, 1], [0, -2], [1, -2]],
    '2>1': [[0, 0], [-1, 0], [-1, -1], [0, 2], [-1, 2]],
    '2>3': [[0, 0], [1, 0], [1, -1], [0, 2], [1, 2]],
    '3>2': [[0, 0], [-1, 0], [-1, 1], [0, -2], [-1, -2]],
    '3>0': [[0, 0], [-1, 0], [-1, 1], [0, -2], [-1, -2]],
    '0>3': [[0, 0], [1, 0], [1, -1], [0, 2], [1, 2]],
  };
  var KICKS_I = {
    '0>1': [[0, 0], [-2, 0], [1, 0], [-2, 1], [1, -2]],
    '1>0': [[0, 0], [2, 0], [-1, 0], [2, -1], [-1, 2]],
    '1>2': [[0, 0], [-1, 0], [2, 0], [-1, -2], [2, 1]],
    '2>1': [[0, 0], [1, 0], [-2, 0], [1, 2], [-2, -1]],
    '2>3': [[0, 0], [2, 0], [-1, 0], [2, -1], [-1, 2]],
    '3>2': [[0, 0], [-2, 0], [1, 0], [-2, 1], [1, -2]],
    '3>0': [[0, 0], [1, 0], [-2, 0], [1, 2], [-2, -1]],
    '0>3': [[0, 0], [-1, 0], [2, 0], [-1, -2], [2, 1]],
  };
  var KICKS_180 = [[0, 0], [0, -1], [0, 1], [1, 0], [-1, 0]];

  var T_ACTIONS = [
    ['left', 'move left'],
    ['right', 'move right'],
    ['soft', 'soft drop'],
    ['hard', 'hard drop'],
    ['cw', 'rotate cw'],
    ['ccw', 'rotate ccw'],
    ['r180', 'rotate 180°'],
    ['hold', 'hold'],
  ];
  var T_DEFAULT_BINDS = {
    left: 'ArrowLeft', right: 'ArrowRight', soft: 'ArrowDown', hard: 'Space',
    cw: 'ArrowUp', ccw: 'KeyZ', r180: 'KeyA', hold: 'CapsLock',
  };
  var tCfg = { binds: Object.assign({}, T_DEFAULT_BINDS), das: 170, arr: 33 };
  var bindCapture = null;

  function tetrisCfgKey() {
    return 'ss_tetris_cfg_' + (myRoom || '') + '_' + (myUsername || '').toLowerCase();
  }

  function loadTetrisCfg() {
    tCfg = { binds: Object.assign({}, T_DEFAULT_BINDS), das: 170, arr: 33 };
    try {
      var raw = localStorage.getItem(tetrisCfgKey());
      if (raw) {
        var p = JSON.parse(raw);
        if (p && typeof p === 'object') {
          if (p.binds && typeof p.binds === 'object') {
            T_ACTIONS.forEach(function (a) {
              if (typeof p.binds[a[0]] === 'string') tCfg.binds[a[0]] = p.binds[a[0]];
            });
          }
          if (p.das >= 67 && p.das <= 300) tCfg.das = p.das;
          if (p.arr >= 0 && p.arr <= 83) tCfg.arr = p.arr;
        }
      }
    } catch (e) { /* defaults */ }
    tKeysUserEl.textContent = myUsername || '';
    buildBindRows();
    refreshTuning();
  }

  function saveTetrisCfg() {
    try { localStorage.setItem(tetrisCfgKey(), JSON.stringify(tCfg)); } catch (e) { /* ignore */ }
  }

  function keyLabel(code) {
    var map = {
      ArrowLeft: '←', ArrowRight: '→', ArrowUp: '↑', ArrowDown: '↓',
      Space: 'space', CapsLock: 'caps', ShiftLeft: 'l-shift', ShiftRight: 'r-shift',
      ControlLeft: 'l-ctrl', ControlRight: 'r-ctrl', Enter: 'enter', Backspace: 'bksp',
    };
    if (map[code]) return map[code];
    if (/^Key[A-Z]$/.test(code)) return code.slice(3);
    if (/^Digit[0-9]$/.test(code)) return code.slice(5);
    return code.toLowerCase();
  }

  function buildBindRows() {
    tBindsEl.innerHTML = '';
    T_ACTIONS.forEach(function (a) {
      var row = document.createElement('div');
      row.className = 'bind-row';
      var label = document.createElement('span');
      label.textContent = a[1];
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'bind-btn';
      btn.dataset.action = a[0];
      btn.textContent = keyLabel(tCfg.binds[a[0]]);
      btn.addEventListener('click', function () {
        if (bindCapture) {
          var prev = tBindsEl.querySelector('.bind-btn.is-listening');
          if (prev) {
            prev.classList.remove('is-listening');
            prev.textContent = keyLabel(tCfg.binds[prev.dataset.action]);
          }
        }
        bindCapture = a[0];
        btn.classList.add('is-listening');
        btn.textContent = 'press a key…';
      });
      row.appendChild(label);
      row.appendChild(btn);
      tBindsEl.appendChild(row);
    });
  }

  function refreshTuning() {
    tDasInput.value = String(tCfg.das);
    tArrInput.value = String(tCfg.arr);
    tDasVal.textContent = tCfg.das + 'ms';
    tArrVal.textContent = tCfg.arr + 'ms';
  }

  tDasInput.addEventListener('input', function () {
    tCfg.das = Number(tDasInput.value);
    tDasVal.textContent = tCfg.das + 'ms';
    saveTetrisCfg();
  });
  tArrInput.addEventListener('input', function () {
    tCfg.arr = Number(tArrInput.value);
    tArrVal.textContent = tCfg.arr + 'ms';
    saveTetrisCfg();
  });

  tetrisKeysBtn.addEventListener('click', function () {
    tetrisKeypanel.hidden = !tetrisKeypanel.hidden;
    tetrisKeysBtn.classList.toggle('is-active', !tetrisKeypanel.hidden);
  });

  var tetris = null;
  var tetrisRaf = null;
  var tetrisLastTs = 0;

  function tCollide(x, y, rot) {
    var cells = T_SHAPES[tetris.piece.type][rot];
    for (var i = 0; i < cells.length; i++) {
      var bx = x + cells[i][0];
      var by = y + cells[i][1];
      if (bx < 0 || bx >= T_COLS || by >= T_ROWS) return true;
      if (by >= 0 && tetris.grid[by][bx]) return true;
    }
    return false;
  }

  function tResetLock() {
    if (tetris.lockResets < T_LOCK_RESETS) {
      tetris.lockAcc = 0;
      tetris.lockResets++;
    }
  }

  function tTryShift(dx) {
    var p = tetris.piece;
    if (tCollide(p.x + dx, p.y, p.rot)) return false;
    p.x += dx;
    tetris.lastMoveRotation = false;
    if (tCollide(p.x, p.y + 1, p.rot)) tResetLock();
    return true;
  }

  function tRotate(delta) {
    var p = tetris.piece;
    if (p.type === 'O') return;
    var newRot = (p.rot + delta + 4) % 4;
    var kicks = delta === 2
      ? KICKS_180
      : (p.type === 'I' ? KICKS_I : KICKS_JLSTZ)[p.rot + '>' + newRot];
    for (var i = 0; i < kicks.length; i++) {
      var kx = kicks[i][0];
      var ky = kicks[i][1];
      if (!tCollide(p.x + kx, p.y + ky, newRot)) {
        p.x += kx;
        p.y += ky;
        p.rot = newRot;
        tetris.lastMoveRotation = true;
        tetris.lastKickIndex = i;
        if (tCollide(p.x, p.y + 1, p.rot)) tResetLock();
        return;
      }
    }
  }

  function tRefillQueue() {
    while (tetris.queue.length < 6) {
      if (!tetris.bag.length) {
        tetris.bag = ['I', 'J', 'L', 'O', 'S', 'T', 'Z'];
        for (var i = tetris.bag.length - 1; i > 0; i--) {
          var j = Math.floor(Math.random() * (i + 1));
          var tmp = tetris.bag[i]; tetris.bag[i] = tetris.bag[j]; tetris.bag[j] = tmp;
        }
      }
      tetris.queue.push(tetris.bag.pop());
    }
  }

  function tSpawn(type) {
    tetris.piece = { type: type, rot: 0, x: type === 'O' ? 4 : 3, y: -1 };
    tetris.gravAcc = 0;
    tetris.lockAcc = 0;
    tetris.lockResets = 0;
    tetris.lastMoveRotation = false;
    if (tCollide(tetris.piece.x, tetris.piece.y, 0)) {
      endTetris();
      return false;
    }
    return true;
  }

  function tSpawnFromQueue() {
    var type = tetris.queue.shift();
    tRefillQueue();
    drawTNext();
    return tSpawn(type);
  }

  function tHoldPiece() {
    if (tetris.holdUsed) return;
    tetris.holdUsed = true;
    var cur = tetris.piece.type;
    if (tetris.hold) {
      var h = tetris.hold;
      tetris.hold = cur;
      tSpawn(h);
    } else {
      tetris.hold = cur;
      tSpawnFromQueue();
    }
    drawTHold();
  }

  function tGravityDelay() {
    var l = tetris.level - 1;
    return Math.max(Math.pow(0.8 - l * 0.007, l) * 1000, 16);
  }

  function tGhostY() {
    var p = tetris.piece;
    var y = p.y;
    while (!tCollide(p.x, y + 1, p.rot)) y++;
    return y;
  }

  function tHardDrop() {
    var p = tetris.piece;
    var dist = tGhostY() - p.y;
    p.y += dist;
    tetris.score += dist * 2;
    if (dist > 0) tetris.lastMoveRotation = false;
    tLock();
  }

  function tCornersFilled(x, y) {
    var out = 0;
    [[0, 0], [2, 0], [0, 2], [2, 2]].forEach(function (c) {
      var bx = x + c[0];
      var by = y + c[1];
      if (bx < 0 || bx >= T_COLS || by >= T_ROWS || (by >= 0 && tetris.grid[by][bx])) out++;
    });
    return out;
  }

  function tFrontCornersFilled(x, y, rot) {
    var pairs = [
      [[0, 0], [2, 0]],
      [[2, 0], [2, 2]],
      [[0, 2], [2, 2]],
      [[0, 0], [0, 2]],
    ][rot];
    var out = 0;
    pairs.forEach(function (c) {
      var bx = x + c[0];
      var by = y + c[1];
      if (bx < 0 || bx >= T_COLS || by >= T_ROWS || (by >= 0 && tetris.grid[by][bx])) out++;
    });
    return out;
  }

  function flashAction(text) {
    tetrisActionEl.textContent = text;
    tetrisActionEl.classList.remove('is-flash');
    void tetrisActionEl.offsetWidth;
    tetrisActionEl.classList.add('is-flash');
  }

  function tLock() {
    var p = tetris.piece;
    var cells = T_SHAPES[p.type][p.rot];

    var tspin = false;
    var tspinMini = false;
    if (p.type === 'T' && tetris.lastMoveRotation && tCornersFilled(p.x, p.y) >= 3) {
      tspin = true;
      // Two front corners filled = proper T-spin; otherwise mini, unless
      // the piece got there via the deep (±1, 2) kick.
      if (tFrontCornersFilled(p.x, p.y, p.rot) < 2 && tetris.lastKickIndex !== 4) tspinMini = true;
    }

    var over = false;
    cells.forEach(function (c) {
      var bx = p.x + c[0];
      var by = p.y + c[1];
      if (by < 0) { over = true; return; }
      tetris.grid[by][bx] = T_DEFS[p.type].color;
    });
    if (over) { endTetris(); return; }

    var cleared = 0;
    for (var y = T_ROWS - 1; y >= 0; y--) {
      if (tetris.grid[y].every(Boolean)) {
        tetris.grid.splice(y, 1);
        tetris.grid.unshift(new Array(T_COLS).fill(null));
        cleared++;
        y++;
      }
    }

    var names = ['', 'SINGLE', 'DOUBLE', 'TRIPLE', 'QUAD'];
    var action = '';
    var base = 0;
    if (tspin) {
      base = (tspinMini ? [100, 200, 400, 400] : [400, 800, 1200, 1600])[cleared] * tetris.level;
      action = 'T-SPIN' + (tspinMini ? ' MINI' : '') + (cleared ? ' ' + names[cleared] : '');
    } else if (cleared) {
      base = [0, 100, 300, 500, 800][cleared] * tetris.level;
      if (cleared === 4) action = 'QUAD';
    }

    var b2bEligible = cleared === 4 || (tspin && cleared > 0);
    if (cleared > 0) {
      if (b2bEligible && tetris.b2b) {
        base = Math.floor(base * 1.5);
        tetris.b2bCount++;
        action = 'B2B ' + (action || names[cleared]);
      } else if (!b2bEligible) {
        tetris.b2b = false;
        tetris.b2bCount = 0;
      }
      if (b2bEligible) tetris.b2b = true;
      tetris.combo++;
      if (tetris.combo > 0) {
        tetris.score += 50 * tetris.combo * tetris.level;
        if (tetris.combo > 1) action = (action ? action + ' · ' : '') + tetris.combo + ' COMBO';
      }
    } else {
      tetris.combo = -1;
    }
    tetris.score += base;
    tetris.lines += cleared;
    tetris.level = Math.floor(tetris.lines / 10) + 1;
    if (action) flashAction(action);

    tetris.holdUsed = false;
    updateTetrisHud();
    tSpawnFromQueue();
  }

  function updateTetrisHud() {
    tetrisScoreEl.textContent = String(tetris ? tetris.score : 0);
    tetrisLinesEl.textContent = String(tetris ? tetris.lines : 0);
    tetrisLevelEl.textContent = String(tetris ? tetris.level : 1);
    tetrisComboEl.textContent = tetris && tetris.combo > 0 ? '×' + tetris.combo : '—';
    tetrisB2bEl.textContent = tetris && tetris.b2bCount > 0 ? '×' + tetris.b2bCount : '—';
  }

  function tStep(dt) {
    var t = tetris;
    var p = t.piece;

    if (t.dirHeld) {
      t.dasAcc += dt;
      if (t.dasAcc >= tCfg.das) {
        if (tCfg.arr === 0) {
          while (tTryShift(t.dirHeld)) { /* instant to wall */ }
        } else {
          t.arrAcc += dt;
          while (t.arrAcc >= tCfg.arr) {
            t.arrAcc -= tCfg.arr;
            if (!tTryShift(t.dirHeld)) { t.arrAcc = 0; break; }
          }
        }
      }
    }

    var delay = tGravityDelay();
    if (t.softHeld) delay = Math.max(delay / 20, 10);
    t.gravAcc += dt;
    while (t.gravAcc >= delay) {
      t.gravAcc -= delay;
      if (!tCollide(p.x, p.y + 1, p.rot)) {
        p.y++;
        t.lockResets = 0;
        t.lastMoveRotation = false;
        if (t.softHeld) { t.score += 1; updateTetrisHud(); }
      } else {
        break;
      }
    }

    if (tCollide(p.x, p.y + 1, p.rot)) {
      t.lockAcc += dt;
      if (t.lockAcc >= T_LOCK_MS) {
        tLock();
        return;
      }
    } else {
      t.lockAcc = 0;
    }
  }

  function drawTCell(ctx, x, y, px, color, ghost) {
    if (ghost) {
      ctx.globalAlpha = 0.18;
      ctx.fillStyle = color;
      ctx.fillRect(x * px + 1, y * px + 1, px - 2, px - 2);
      ctx.globalAlpha = 1;
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.strokeRect(x * px + 1.5, y * px + 1.5, px - 3, px - 3);
      return;
    }
    ctx.fillStyle = color;
    ctx.fillRect(x * px + 1, y * px + 1, px - 2, px - 2);
    ctx.fillStyle = 'rgba(255,255,255,0.18)';
    ctx.fillRect(x * px + 1, y * px + 1, px - 2, 3);
  }

  function drawTetris() {
    var ctx = tetrisCtx;
    ctx.clearRect(0, 0, tetrisCanvas.width, tetrisCanvas.height);
    ctx.strokeStyle = 'rgba(233,225,208,0.06)';
    ctx.lineWidth = 1;
    for (var gx = 1; gx < T_COLS; gx++) {
      ctx.beginPath(); ctx.moveTo(gx * T_PX + 0.5, 0); ctx.lineTo(gx * T_PX + 0.5, T_ROWS * T_PX); ctx.stroke();
    }
    for (var gy = 1; gy < T_ROWS; gy++) {
      ctx.beginPath(); ctx.moveTo(0, gy * T_PX + 0.5); ctx.lineTo(T_COLS * T_PX, gy * T_PX + 0.5); ctx.stroke();
    }
    if (!tetris) return;
    for (var y = 0; y < T_ROWS; y++) {
      for (var x = 0; x < T_COLS; x++) {
        if (tetris.grid[y][x]) drawTCell(ctx, x, y, T_PX, tetris.grid[y][x]);
      }
    }
    var p = tetris.piece;
    var cells = T_SHAPES[p.type][p.rot];
    var color = T_DEFS[p.type].color;
    var gy2 = tGhostY();
    if (gy2 > p.y) {
      cells.forEach(function (c) {
        var by = gy2 + c[1];
        if (by >= 0) drawTCell(ctx, p.x + c[0], by, T_PX, color, true);
      });
    }
    cells.forEach(function (c) {
      var by = p.y + c[1];
      if (by >= 0) drawTCell(ctx, p.x + c[0], by, T_PX, color);
    });
  }

  function drawMini(ctx, type, slotY, slotH, dim) {
    var cells = T_SHAPES[type][0];
    var minX = 4, maxX = 0, minY = 4, maxY = 0;
    cells.forEach(function (c) {
      minX = Math.min(minX, c[0]); maxX = Math.max(maxX, c[0]);
      minY = Math.min(minY, c[1]); maxY = Math.max(maxY, c[1]);
    });
    var px = 18;
    var w = (maxX - minX + 1) * px;
    var h = (maxY - minY + 1) * px;
    var ox = (ctx.canvas.width - w) / 2;
    var oy = slotY + (slotH - h) / 2;
    ctx.globalAlpha = dim ? 0.35 : 1;
    cells.forEach(function (c) {
      ctx.fillStyle = T_DEFS[type].color;
      ctx.fillRect(ox + (c[0] - minX) * px + 1, oy + (c[1] - minY) * px + 1, px - 2, px - 2);
      ctx.fillStyle = 'rgba(255,255,255,0.18)';
      ctx.fillRect(ox + (c[0] - minX) * px + 1, oy + (c[1] - minY) * px + 1, px - 2, 2);
    });
    ctx.globalAlpha = 1;
  }

  function drawTHold() {
    tHoldCtx.clearRect(0, 0, tHoldCanvas.width, tHoldCanvas.height);
    if (tetris && tetris.hold) drawMini(tHoldCtx, tetris.hold, 0, tHoldCanvas.height, tetris.holdUsed);
  }

  function drawTNext() {
    tNextCtx.clearRect(0, 0, tNextCanvas.width, tNextCanvas.height);
    if (!tetris) return;
    for (var i = 0; i < 5 && i < tetris.queue.length; i++) {
      drawMini(tNextCtx, tetris.queue[i], i * 66, 66, false);
    }
  }

  function tetrisFrame(ts) {
    if (!tetris) { tetrisRaf = null; return; }
    var dt = tetrisLastTs ? Math.min(ts - tetrisLastTs, 100) : 16;
    tetrisLastTs = ts;
    tStep(dt);
    if (tetris) {
      drawTetris();
      tetrisRaf = requestAnimationFrame(tetrisFrame);
    } else {
      tetrisRaf = null;
    }
  }

  function startTetris() {
    var grid = [];
    for (var y = 0; y < T_ROWS; y++) grid.push(new Array(T_COLS).fill(null));
    tetris = {
      grid: grid, bag: [], queue: [], piece: null, hold: null, holdUsed: false,
      score: 0, lines: 0, level: 1, combo: -1, b2b: false, b2bCount: 0,
      gravAcc: 0, lockAcc: 0, lockResets: 0,
      lastMoveRotation: false, lastKickIndex: 0,
      dirHeld: 0, leftHeld: false, rightHeld: false, dasAcc: 0, arrAcc: 0, softHeld: false,
    };
    tRefillQueue();
    tSpawnFromQueue();
    updateTetrisHud();
    drawTHold();
    tetrisActionEl.textContent = '';
    tetrisOverlay.hidden = true;
    tetrisLastTs = 0;
    drawTetris();
    if (!tetrisRaf) tetrisRaf = requestAnimationFrame(tetrisFrame);
  }

  function endTetris() {
    var finalScore = tetris ? tetris.score : 0;
    tetris = null;
    if (tetrisRaf) { cancelAnimationFrame(tetrisRaf); tetrisRaf = null; }
    tetrisMsg.textContent = 'top out · score ' + finalScore;
    tetrisStartBtn.textContent = 'play again';
    tetrisOverlay.hidden = false;
    submitScore('tetris', finalScore);
  }

  function stopTetris(abandon) {
    if (!tetris) return;
    if (abandon && tetris.score > 0) submitScore('tetris', tetris.score);
    tetris = null;
    if (tetrisRaf) { cancelAnimationFrame(tetrisRaf); tetrisRaf = null; }
    tetrisMsg.textContent = 'move · rotate · hold · hard drop — see controls';
    tetrisStartBtn.textContent = 'play';
    tetrisOverlay.hidden = false;
  }

  tetrisStartBtn.addEventListener('click', startTetris);

  // ---------------------------------------------------------------------
  // Minesweeper — 16×16, 40 mines, first click always safe
  // ---------------------------------------------------------------------

  var minesGrid = document.getElementById('mines-grid');
  var minesLeftEl = document.getElementById('mines-left');
  var minesTimeEl = document.getElementById('mines-time');
  var minesBestEl = document.getElementById('mines-best');
  var minesBanner = document.getElementById('mines-banner');
  var minesBannerText = document.getElementById('mines-banner-text');
  var minesAgainBtn = document.getElementById('mines-again');
  var MINES_W = 16;
  var MINES_H = 16;
  var MINES_N = 40;
  var mines = null;
  var minesCells = [];
  var minesTimer = null;
  var minesBuilt = false;
  var minesBestTime = null;

  function minesIndex(x, y) { return y * MINES_W + x; }

  function minesNeighbors(i) {
    var x = i % MINES_W;
    var y = Math.floor(i / MINES_W);
    var out = [];
    for (var dy = -1; dy <= 1; dy++) {
      for (var dx = -1; dx <= 1; dx++) {
        if (!dx && !dy) continue;
        var nx = x + dx;
        var ny = y + dy;
        if (nx >= 0 && nx < MINES_W && ny >= 0 && ny < MINES_H) out.push(minesIndex(nx, ny));
      }
    }
    return out;
  }

  function newMines() {
    if (minesTimer) { clearInterval(minesTimer); minesTimer = null; }
    mines = {
      cells: [],
      started: false,
      over: false,
      time: 0,
      revealed: 0,
      flags: 0,
    };
    for (var i = 0; i < MINES_W * MINES_H; i++) {
      mines.cells.push({ mine: false, open: false, flag: false, n: 0 });
    }
    minesLeftEl.textContent = String(MINES_N);
    minesTimeEl.textContent = '0';
    minesBanner.hidden = true;

    if (!minesBuilt) {
      minesBuilt = true;
      minesGrid.innerHTML = '';
      minesCells = [];
      for (var j = 0; j < MINES_W * MINES_H; j++) {
        (function (idx) {
          var cell = document.createElement('button');
          cell.type = 'button';
          cell.className = 'mine-cell';
          cell.addEventListener('click', function () { minesReveal(idx); });
          cell.addEventListener('contextmenu', function (e) {
            e.preventDefault();
            minesFlag(idx);
          });
          minesGrid.appendChild(cell);
          minesCells.push(cell);
        })(j);
      }
    }
    minesCells.forEach(function (c) {
      c.className = 'mine-cell';
      c.textContent = '';
      c.removeAttribute('data-n');
      c.disabled = false;
    });
  }

  function minesPlace(safeIdx) {
    var forbidden = {};
    forbidden[safeIdx] = true;
    minesNeighbors(safeIdx).forEach(function (n) { forbidden[n] = true; });
    var placed = 0;
    while (placed < MINES_N) {
      var i = Math.floor(Math.random() * MINES_W * MINES_H);
      if (forbidden[i] || mines.cells[i].mine) continue;
      mines.cells[i].mine = true;
      placed++;
    }
    for (var j = 0; j < mines.cells.length; j++) {
      if (mines.cells[j].mine) continue;
      mines.cells[j].n = minesNeighbors(j).filter(function (n) { return mines.cells[n].mine; }).length;
    }
  }

  function minesStartTimer() {
    minesTimer = setInterval(function () {
      if (!mines || mines.over) return;
      mines.time++;
      minesTimeEl.textContent = String(mines.time);
    }, 1000);
  }

  function minesOpenCell(i) {
    var c = mines.cells[i];
    c.open = true;
    mines.revealed++;
    var el = minesCells[i];
    el.classList.add('is-open');
    if (c.n > 0) {
      el.textContent = String(c.n);
      el.setAttribute('data-n', String(c.n));
    }
  }

  function minesReveal(i) {
    if (!mines || mines.over) return;
    var c = mines.cells[i];
    if (c.flag) return;
    if (c.open) { minesChord(i); return; }

    if (!mines.started) {
      mines.started = true;
      minesPlace(i);
      minesStartTimer();
    }

    if (c.mine) { minesLose(i); return; }

    var stack = [i];
    var seen = {};
    while (stack.length) {
      var cur = stack.pop();
      if (seen[cur]) continue;
      seen[cur] = true;
      var cell = mines.cells[cur];
      if (cell.open || cell.flag || cell.mine) continue;
      minesOpenCell(cur);
      if (cell.n === 0) {
        minesNeighbors(cur).forEach(function (n) { if (!seen[n]) stack.push(n); });
      }
    }
    minesCheckWin();
  }

  function minesChord(i) {
    var c = mines.cells[i];
    if (!c.open || c.n === 0) return;
    var ns = minesNeighbors(i);
    var flagged = ns.filter(function (n) { return mines.cells[n].flag; }).length;
    if (flagged !== c.n) return;
    ns.forEach(function (n) {
      var nc = mines.cells[n];
      if (nc.open || nc.flag || !mines || mines.over) return;
      if (nc.mine) { minesLose(n); return; }
      minesReveal(n);
    });
  }

  function minesFlag(i) {
    if (!mines || mines.over) return;
    var c = mines.cells[i];
    if (c.open) return;
    c.flag = !c.flag;
    mines.flags += c.flag ? 1 : -1;
    minesCells[i].classList.toggle('is-flag', c.flag);
    minesCells[i].textContent = c.flag ? '🚩' : '';
    minesLeftEl.textContent = String(MINES_N - mines.flags);
  }

  function minesLose(hitIdx) {
    mines.over = true;
    if (minesTimer) { clearInterval(minesTimer); minesTimer = null; }
    mines.cells.forEach(function (c, i) {
      if (c.mine) {
        minesCells[i].classList.add('is-open', 'is-mine');
        minesCells[i].textContent = '💣';
      } else if (c.flag) {
        minesCells[i].classList.add('is-wrong');
      }
    });
    minesCells[hitIdx].classList.add('is-boom');
    minesBannerText.textContent = '💥 boom — ' + mines.time + 's';
    minesBanner.hidden = false;
  }

  function minesCheckWin() {
    if (!mines || mines.over) return;
    if (mines.revealed >= MINES_W * MINES_H - MINES_N) {
      mines.over = true;
      if (minesTimer) { clearInterval(minesTimer); minesTimer = null; }
      if (minesBestTime === null || mines.time < minesBestTime) {
        minesBestTime = mines.time;
        minesBestEl.textContent = minesBestTime + 's';
      }
      minesBannerText.textContent = '✨ cleared in ' + mines.time + 's';
      minesBanner.hidden = false;
      submitScore('mines', Math.max(1, 1001 - mines.time));
    }
  }

  function stopMines() {
    if (!mines) return;
    if (mines.started && !mines.over) newMines();
    else if (minesTimer) { clearInterval(minesTimer); minesTimer = null; }
  }

  minesAgainBtn.addEventListener('click', newMines);

  // ---------------------------------------------------------------------
  // Cookie clicker
  // ---------------------------------------------------------------------

  var cookieBtn = document.getElementById('cookie-btn');
  var cookieShopEl = document.getElementById('cookie-shop');
  var cookieCountEl = document.getElementById('cookie-count');
  var cookieCpsEl = document.getElementById('cookie-cps');
  var cookieTotalEl = document.getElementById('cookie-total');
  var COOKIE_BUILDINGS = [
    { id: 'cursor', name: 'Cursor', base: 15, cps: 0.1 },
    { id: 'grandma', name: 'Grandma', base: 100, cps: 1 },
    { id: 'farm', name: 'Farm', base: 1100, cps: 8 },
    { id: 'factory', name: 'Factory', base: 12000, cps: 47 },
    { id: 'bank', name: 'Bank', base: 140000, cps: 260 },
    { id: 'temple', name: 'Temple', base: 2000000, cps: 1400 },
  ];
  var cookie = { cookies: 0, total: 0, owned: {} };
  var cookieTimer = null;
  var cookieDirty = false;
  var cookieSubmitCounter = 0;

  function cookieStorageKey() {
    return 'ss_cookie_' + (myRoom || '') + '_' + (myUsername || '').toLowerCase();
  }

  function loadCookieState() {
    cookie = { cookies: 0, total: 0, owned: {} };
    try {
      var raw = localStorage.getItem(cookieStorageKey());
      if (raw) {
        var p = JSON.parse(raw);
        if (p && typeof p === 'object') {
          cookie.cookies = Math.max(0, Number(p.cookies) || 0);
          cookie.total = Math.max(0, Number(p.total) || 0);
          if (p.owned && typeof p.owned === 'object') {
            COOKIE_BUILDINGS.forEach(function (b) {
              var n = Math.floor(Number(p.owned[b.id]) || 0);
              if (n > 0) cookie.owned[b.id] = n;
            });
          }
        }
      }
    } catch (e) { /* start fresh */ }
    buildCookieShop();
    updateCookieHud();
  }

  function saveCookieState() {
    try { localStorage.setItem(cookieStorageKey(), JSON.stringify(cookie)); } catch (e) { /* ignore */ }
  }

  function cookieCps() {
    return COOKIE_BUILDINGS.reduce(function (sum, b) {
      return sum + (cookie.owned[b.id] || 0) * b.cps;
    }, 0);
  }

  function buildingCost(b) {
    return Math.ceil(b.base * Math.pow(1.15, cookie.owned[b.id] || 0));
  }

  function buildCookieShop() {
    cookieShopEl.innerHTML = '';
    COOKIE_BUILDINGS.forEach(function (b) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'shop-item';
      btn.dataset.building = b.id;
      var left = document.createElement('span');
      var nm = document.createElement('span');
      nm.className = 'shop-name';
      var sub = document.createElement('span');
      sub.className = 'shop-sub';
      left.appendChild(nm);
      left.appendChild(sub);
      var cost = document.createElement('span');
      cost.className = 'shop-cost';
      btn.appendChild(left);
      btn.appendChild(cost);
      btn.addEventListener('click', function () {
        var c = buildingCost(b);
        if (cookie.cookies >= c) {
          cookie.cookies -= c;
          cookie.owned[b.id] = (cookie.owned[b.id] || 0) + 1;
          cookieDirty = true;
          updateCookieHud();
        }
      });
      cookieShopEl.appendChild(btn);
    });
  }

  function refreshCookieShop() {
    COOKIE_BUILDINGS.forEach(function (b) {
      var btn = cookieShopEl.querySelector('[data-building="' + b.id + '"]');
      if (!btn) return;
      var owned = cookie.owned[b.id] || 0;
      btn.querySelector('.shop-name').textContent = b.name + (owned ? ' × ' + owned : '');
      btn.querySelector('.shop-sub').textContent = '+' + b.cps + ' cookies/sec each';
      var c = buildingCost(b);
      btn.querySelector('.shop-cost').textContent = fmtScore(c);
      btn.disabled = cookie.cookies < c;
    });
  }

  function updateCookieHud() {
    cookieCountEl.textContent = fmtScore(Math.floor(cookie.cookies));
    cookieCpsEl.textContent = String(Math.round(cookieCps() * 10) / 10);
    cookieTotalEl.textContent = fmtScore(Math.floor(cookie.total));
    refreshCookieShop();
  }

  cookieBtn.addEventListener('click', function () {
    cookie.cookies += 1;
    cookie.total += 1;
    cookieDirty = true;
    updateCookieHud();
  });

  function startCookieLoop() {
    if (cookieTimer) return;
    cookieTimer = setInterval(function () {
      var cps = cookieCps();
      if (cps > 0) {
        cookie.cookies += cps;
        cookie.total += cps;
        cookieDirty = true;
      }
      if (cookieDirty) {
        cookieDirty = false;
        saveCookieState();
        if (currentView === 'games' && activeGame === 'cookie') updateCookieHud();
      }
      if (++cookieSubmitCounter >= 20) {
        cookieSubmitCounter = 0;
        submitScore('cookie', cookie.total);
      }
    }, 1000);
  }

  function stopCookieLoop() {
    if (cookieTimer) { clearInterval(cookieTimer); cookieTimer = null; }
    saveCookieState();
  }

  // ---------------------------------------------------------------------
  // Arcade keyboard dispatch — snake uses simple directions, tetris uses
  // the per-user binds (matched on e.code). Keybind capture eats the next
  // keydown while listening.
  // ---------------------------------------------------------------------

  document.addEventListener('keydown', function (e) {
    if (currentView !== 'games') return;

    if (bindCapture) {
      e.preventDefault();
      var btn = tBindsEl.querySelector('.bind-btn.is-listening');
      if (e.code !== 'Escape') {
        tCfg.binds[bindCapture] = e.code;
        saveTetrisCfg();
      }
      if (btn) {
        btn.classList.remove('is-listening');
        btn.textContent = keyLabel(tCfg.binds[btn.dataset.action]);
      }
      bindCapture = null;
      return;
    }

    if (activeGame === 'snake' && snake) {
      var d = SNAKE_DIRS[e.key ? e.key.toLowerCase() : ''];
      if (d) {
        e.preventDefault();
        if (d.x !== -snake.dir.x || d.y !== -snake.dir.y) snake.nextDir = d;
      }
      return;
    }

    if (activeGame === 'tetris' && tetris) {
      var b = tCfg.binds;
      var code = e.code;
      if (code === b.left) {
        e.preventDefault();
        if (!e.repeat) {
          tetris.leftHeld = true;
          tetris.dirHeld = -1;
          tetris.dasAcc = 0;
          tetris.arrAcc = 0;
          tTryShift(-1);
        }
      } else if (code === b.right) {
        e.preventDefault();
        if (!e.repeat) {
          tetris.rightHeld = true;
          tetris.dirHeld = 1;
          tetris.dasAcc = 0;
          tetris.arrAcc = 0;
          tTryShift(1);
        }
      } else if (code === b.soft) {
        e.preventDefault();
        tetris.softHeld = true;
      } else if (code === b.hard) {
        e.preventDefault();
        if (!e.repeat) tHardDrop();
      } else if (code === b.cw) {
        e.preventDefault();
        if (!e.repeat) tRotate(1);
      } else if (code === b.ccw) {
        e.preventDefault();
        if (!e.repeat) tRotate(-1);
      } else if (code === b.r180) {
        e.preventDefault();
        if (!e.repeat) tRotate(2);
      } else if (code === b.hold) {
        e.preventDefault();
        if (!e.repeat) tHoldPiece();
      }
    }
  });

  document.addEventListener('keyup', function (e) {
    if (!tetris) return;
    var b = tCfg.binds;
    if (e.code === b.left) {
      tetris.leftHeld = false;
      if (tetris.dirHeld === -1) {
        tetris.dirHeld = tetris.rightHeld ? 1 : 0;
        tetris.dasAcc = 0;
        tetris.arrAcc = 0;
      }
    } else if (e.code === b.right) {
      tetris.rightHeld = false;
      if (tetris.dirHeld === 1) {
        tetris.dirHeld = tetris.leftHeld ? -1 : 0;
        tetris.dasAcc = 0;
        tetris.arrAcc = 0;
      }
    } else if (e.code === b.soft) {
      tetris.softHeld = false;
    }
  });

  // ---------------------------------------------------------------------
  // Hidden keyboard combos. Q+W+O+P (held together on the essay) opens the
  // gate; G+P+T (from chat/games) opens the assistant; G+A+M+E (from
  // chat/assistant) opens the arcade. Tab is the panic key: from anywhere
  // past the essay it snaps straight back, even mid-typing.
  // ---------------------------------------------------------------------

  var COMBOS = [
    { keys: ['q', 'w', 'o', 'p'], from: ['essay'], fired: false, go: function () { showView('gate'); } },
    { keys: ['g', 'p', 't'], from: ['chat', 'games'], fired: false, go: function () { showView('gpt'); } },
    { keys: ['g', 'a', 'm', 'e'], from: ['chat', 'gpt'], fired: false, go: function () { showView('games'); } },
  ];
  var COMBO_KEYS = Object.create(null);
  COMBOS.forEach(function (c) {
    c.keys.forEach(function (k) { COMBO_KEYS[k] = true; });
  });
  var heldKeys = Object.create(null);

  function comboHeld(c) {
    return c.keys.every(function (k) { return heldKeys[k]; });
  }

  function isTypingTarget(el) {
    if (!el) return false;
    var tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || el.isContentEditable;
  }

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Tab') {
      if (currentView !== 'essay') {
        e.preventDefault();
        showView('essay');
      }
      return;
    }

    var k = e.key ? e.key.toLowerCase() : '';
    if (!COMBO_KEYS[k]) return;

    if (isTypingTarget(e.target)) {
      // A combo key still physically held from before a view switch —
      // swallow its auto-repeat so it can't type into the newly-focused
      // input (this is what used to leave a stray letter in the boxes).
      if (heldKeys[k]) e.preventDefault();
      return;
    }

    heldKeys[k] = true;
    COMBOS.forEach(function (c) {
      if (!c.fired && c.from.indexOf(currentView) !== -1 && comboHeld(c)) {
        c.fired = true;
        e.preventDefault();
        c.go();
      }
    });
  });

  document.addEventListener('keyup', function (e) {
    var k = e.key ? e.key.toLowerCase() : '';
    if (COMBO_KEYS[k]) delete heldKeys[k];
    COMBOS.forEach(function (c) { if (!comboHeld(c)) c.fired = false; });
  });

  window.addEventListener('blur', function () {
    heldKeys = Object.create(null);
    COMBOS.forEach(function (c) { c.fired = false; });
  });

  // ---------------------------------------------------------------------
  // Publication page: section tabs, scroll reveals, progress rail
  // ---------------------------------------------------------------------

  var pubTabs = Array.prototype.slice.call(document.querySelectorAll('.pub-tab'));
  var pubPanels = Array.prototype.slice.call(document.querySelectorAll('.pub-panel'));
  var pubTabsBar = document.getElementById('pub-tabs');

  function activatePubTab(name) {
    pubTabs.forEach(function (t) {
      var active = t.dataset.tab === name;
      t.classList.toggle('is-active', active);
      t.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    pubPanels.forEach(function (p) {
      var active = p.dataset.panel === name;
      p.classList.toggle('is-active', active);
      if (active) {
        p.querySelectorAll('[data-reveal]').forEach(function (el) { el.classList.add('in-view'); });
      }
    });
    if (pubTabsBar) {
      var top = pubTabsBar.getBoundingClientRect().top;
      if (top < 0) pubTabsBar.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  pubTabs.forEach(function (tab) {
    tab.addEventListener('click', function () { activatePubTab(tab.dataset.tab); });
  });

  var revealEls = document.querySelectorAll('[data-reveal]');
  if (revealEls.length && 'IntersectionObserver' in window) {
    var revealObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('in-view');
            revealObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.1, rootMargin: '0px 0px -40px 0px' }
    );
    revealEls.forEach(function (el) { revealObserver.observe(el); });
  } else {
    revealEls.forEach(function (el) { el.classList.add('in-view'); });
  }

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

  // ---------------------------------------------------------------------
  // Go
  // ---------------------------------------------------------------------

  bootstrapRouting();
})();
