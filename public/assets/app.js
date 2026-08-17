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
  // Chat content encryption
  // -----------------------
  // The server stores and relays chat text as an opaque blob — it never
  // sees plaintext. The key is an AES-GCM key derived (PBKDF2) from the
  // *site password itself*, which is the one secret every room member is
  // guaranteed to already know. The salt below is public/fixed (all the
  // secrecy comes from the password), which is what makes this workable
  // for a single shared room rather than a 1:1 conversation.
  //
  // Honest limits, worth knowing:
  //  - Anyone who knows the site password can decrypt every message —
  //    same trust boundary the room already has today, just extended to
  //    message content instead of only "who's allowed to see the room".
  //  - Images are NOT covered by this (still gated server-side by session,
  //    same as avatars, but not encrypted) — see SECURITY.md.
  //  - The key lives in this tab's sessionStorage so a page refresh keeps
  //    working without re-typing the password. Opening the room in a new
  //    tab (or after closing the old one) needs the password once to
  //    re-derive the same key locally — nothing is sent to the server for
  //    this, it's just how the local decrypt key gets rebuilt.
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
    } catch (e) { /* sessionStorage unavailable (private mode etc.) — key just won't survive a refresh */ }
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

  // Returns the decrypted string, or null if it can't be decrypted (wrong/
  // missing key, or a message that predates encryption being turned on).
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
      if (cryptoAvailable) roomKey = await loadCachedRoomKey();
      setUnlockVisible(cryptoAvailable && !roomKey);
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
  var gateSubmit = null;
  var gateCard = document.querySelector('.minimal-gate');
  var gateBack = null;

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
        // Derive the room encryption key from the password while it's still
        // in memory — it's never sent anywhere for this purpose, and the
        // server never receives it after this point.
        if (cryptoAvailable) {
          try { await setRoomKey(gateInput.value); } catch (e) { /* chat will fall back to an unlock prompt */ }
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
  var sendBtn = document.getElementById('send-btn');
  var whoNameEl = document.getElementById('who-name');
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
  var pollInFlight = false; // guards against overlapping poll() calls racing on `since`
  var renderedIds = Object.create(null); // message id -> true, once its DOM node exists — the actual fix for double-rendered messages
  var replyingTo = null; // { id, username, preview } or null

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

  // ---- reply state -------------------------------------------------

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

  // ---- emoji picker --------------------------------------------------

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

  // ---- unlock (room key) overlay -------------------------------------

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
      // Verify by trying to decrypt something already on screen/in hand.
      // With nothing to check against yet (empty room), we accept it —
      // there's no way to verify offline, and worst case a mistyped
      // password just means your own first message won't decrypt for
      // others either, which you'd immediately notice.
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
      } catch (err) { /* ignore — key still works for this tab session */ }
      unlockInput.value = '';
      unlockInput.disabled = false;
      setUnlockVisible(false);
      // Re-render anything currently on screen with the freshly unlocked key.
      messagesEl.innerHTML = '';
      renderedIds = Object.create(null);
      since = 0;
      await poll();
      scrollToBottom();
    } catch (err) {
      unlockError.textContent = 'Something went wrong. Try again.';
      unlockInput.disabled = false;
    }
  });

  // ---- rendering -------------------------------------------------------

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

    var wrap = document.createElement('div');
    wrap.className = 'msg msg-enter' + (m.username === myUsername ? ' self' : '');
    wrap.dataset.msgId = m.id;

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
    body.appendChild(meta);

    if (m.replyTo) {
      body.appendChild(await buildReplyQuoteEl(m.replyTo));
    }

    var previewForReply; // plain text used if *this* message later gets replied to

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
        wrap.setAttribute('data-cipher', m.text); // lets the unlock flow probe against a real message
      }
      text.textContent = plain === null ? '🔒 Unable to decrypt this message' : plain; // safe: textContent, never innerHTML
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

    wrap.appendChild(avatar);
    wrap.appendChild(body);
    messagesEl.appendChild(wrap);
    since = Math.max(since, m.ts);

    // Let the browser paint the base state before triggering the enter
    // transition, then drop the marker class once it's done.
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
    if (pollInFlight) return; // avoid overlapping fetches racing on `since`
    pollInFlight = true;
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
      await renderMessages(data.messages || []);
    } catch (e) { /* transient network hiccup — next poll will retry */ }
    finally { pollInFlight = false; }
  }

  function startChatPolling() {
    if (pollTimer) return;
    since = 0;
    renderedIds = Object.create(null);
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
        // Render straight from the send response instead of triggering
        // another poll() — this was the actual source of doubled messages:
        // the periodic poll and a post-send poll could both read the same
        // stale `since` and both append the same message. Rendering it
        // directly here means there's nothing to race, and the id-based
        // dedup in renderOne() covers the interval poll picking it up too.
        await renderMessages([data.message]);
        scrollToBottom(true);
      } else if (!res.ok) {
        setChatStatus(data.error || 'Could not send that message.', true);
        setTimeout(function () { setChatStatus(''); }, 3000);
      }
    } catch (e) {
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
    } catch (e) {
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
    clearRoomKey();
    cancelReply();
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

  // ---------------------------------------------------------------------
  // Entry to the gate is now keyboard-only: hold Q+W+O+P together while on
  // the essay page. There's no visible button hinting this exists. F5 is a
  // quick-escape back to the essay page from anywhere past it (gate, setup,
  // or chat) — it's intercepted (default refresh suppressed) only when
  // there's actually somewhere to escape from; on the essay page itself F5
  // behaves like a normal refresh.
  // ---------------------------------------------------------------------

  var ENTRY_COMBO = ['q', 'w', 'o', 'p'];
  var heldKeys = Object.create(null);
  var entryComboFired = false;

  function entryComboHeld() {
    return ENTRY_COMBO.every(function (k) { return heldKeys[k]; });
  }

  function isTypingTarget(el) {
    if (!el) return false;
    var tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || el.isContentEditable;
  }

  document.addEventListener('keydown', function (e) {
    if (e.key === 'F5') {
      if (currentView !== 'essay') {
        e.preventDefault();
        setGateError('');
        showView('essay');
      }
      return;
    }

    var k = e.key ? e.key.toLowerCase() : '';
    if (ENTRY_COMBO.indexOf(k) === -1) return;
    if (isTypingTarget(e.target)) return; // don't hijack typing into the password/username/message fields

    heldKeys[k] = true;
    if (!entryComboFired && currentView === 'essay' && entryComboHeld()) {
      entryComboFired = true;
      setGateError('');
      showView('gate');
    }
  });

  document.addEventListener('keyup', function (e) {
    var k = e.key ? e.key.toLowerCase() : '';
    if (ENTRY_COMBO.indexOf(k) !== -1) delete heldKeys[k];
    if (!entryComboHeld()) entryComboFired = false;
  });

  // Held keys can't be tracked across a focus/tab switch — reset so a
  // stale key doesn't silently count toward the next attempt.
  window.addEventListener('blur', function () {
    heldKeys = Object.create(null);
    entryComboFired = false;
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

  // Sidebar navigation: click a link to smooth-scroll to its section (a
  // "sublink" additionally jumps straight to the matching research-studio
  // tab). Whichever tracked section is currently in view gets its link(s)
  // highlighted, so the sidebar always shows roughly where you are.
  var sidebarNav = document.getElementById('sidebar-nav');
  var navToggle = document.getElementById('nav-toggle');
  var navScrim = document.getElementById('nav-scrim');
  var sidebarLinks = Array.prototype.slice.call(document.querySelectorAll('.sidebar-link, .sidebar-sublink'));

  function closeMobileNav() {
    sidebarNav.classList.remove('is-open');
    navToggle.setAttribute('aria-expanded', 'false');
    navScrim.hidden = true;
  }
  function openMobileNav() {
    sidebarNav.classList.add('is-open');
    navToggle.setAttribute('aria-expanded', 'true');
    navScrim.hidden = false;
  }
  navToggle.addEventListener('click', function () {
    if (sidebarNav.classList.contains('is-open')) closeMobileNav(); else openMobileNav();
  });
  navScrim.addEventListener('click', closeMobileNav);

  sidebarLinks.forEach(function (link) {
    link.addEventListener('click', function (e) {
      e.preventDefault();
      var target = document.getElementById(link.dataset.target);
      if (link.dataset.panel) {
        var tabBtn = document.querySelector('.research-tab[data-panel="' + link.dataset.panel + '"]');
        if (tabBtn) tabBtn.click();
      }
      // Always align to the section's top edge (with a bit of breathing room
      // via `scroll-margin-top` in CSS), not center — the active-link
      // IntersectionObserver below watches a band near the top of the
      // viewport, matching this, rather than the middle.
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      closeMobileNav();
    });
  });

  var trackedSections = Array.prototype.slice.call(document.querySelectorAll(
    '#hero, #research-studio, #lab-notes, #quiz-deck, #field-notes, .essay section[data-accent], #sec-closing'
  ));
  if (trackedSections.length && 'IntersectionObserver' in window) {
    var navObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          var links = sidebarNav.querySelectorAll('[data-target="' + entry.target.id + '"]');
          if (!links.length) return;
          sidebarLinks.forEach(function (l) { l.classList.remove('is-active'); });
          links.forEach(function (l) { l.classList.add('is-active'); });
        });
      },
      { threshold: 0.25, rootMargin: '0px 0px -55% 0px' }
    );
    trackedSections.forEach(function (s) { navObserver.observe(s); });
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


  // Research studio interactions
  var researchTabs = Array.prototype.slice.call(document.querySelectorAll('.research-tab'));
  var researchPanels = Array.prototype.slice.call(document.querySelectorAll('.research-panel'));
  researchTabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      var name = tab.dataset.panel;
      researchTabs.forEach(function (t) {
        var active = t === tab;
        t.classList.toggle('is-active', active);
        t.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      researchPanels.forEach(function (panel) {
        panel.classList.toggle('is-active', panel.dataset.panelView === name);
      });
    });
  });

  document.querySelectorAll('.expandable').forEach(function (card) {
    card.addEventListener('click', function () {
      card.classList.toggle('is-open');
      var marker = card.querySelector('b');
      if (marker) marker.textContent = card.classList.contains('is-open') ? '−' : '+';
    });
  });

  var scenarioResult = document.getElementById('scenario-result');
  document.querySelectorAll('[data-scenario]').forEach(function (button) {
    button.addEventListener('click', function () {
      var responses = {
        conformity: 'Speaking up can introduce a minority viewpoint and make disagreement socially visible.',
        observation: 'Asking what others think can surface hidden disagreement without immediately taking a side.',
        compliance: 'Staying silent may preserve harmony, but it can also reinforce the appearance of unanimous agreement.'
      };
      scenarioResult.textContent = responses[button.dataset.scenario];
    });
  });

  var frameReadout = document.getElementById('frame-readout');
  var frameDetail = document.getElementById('frame-detail');
  document.querySelectorAll('.frame-choice').forEach(function (button) {
    button.addEventListener('click', function () {
      var loss = button.dataset.frame === 'loss';
      frameReadout.textContent = loss ? 'Loss frame' : 'Gain frame';
      frameDetail.textContent = loss
        ? 'The message emphasizes avoiding a negative outcome; the reference point is what could be lost.'
        : 'The message emphasizes a positive outcome; the reference point is what could be gained.';
    });
  });

  var biasResult = document.getElementById('bias-result');
  document.querySelectorAll('[data-answer]').forEach(function (button) {
    button.addEventListener('click', function () {
      biasResult.textContent = button.dataset.answer === 'no'
        ? 'Correct. 20% off $100 is $80; another 20% off is $64. Sequential percentages apply to the new price.'
        : 'Not quite. The second 20% applies to $80, not the original $100.';
    });
  });

  var timelineCopy = document.getElementById('timeline-copy');
  var timelineText = {
    '1': 'A group begins with contact: people notice one another, assess safety and relevance, and form initial impressions.',
    '2': 'People begin to align around shared interests, roles, expectations, or influential members.',
    '3': 'Repeated patterns become norms. What was once negotiated can become assumed.',
    '4': 'The group can become part of how members describe themselves, changing the meaning of belonging.'
  };
  document.querySelectorAll('.timeline-step').forEach(function (step) {
    step.addEventListener('click', function () {
      document.querySelectorAll('.timeline-step').forEach(function (s) { s.classList.remove('is-active'); });
      step.classList.add('is-active');
      timelineCopy.textContent = timelineText[step.dataset.step];
    });
  });

  document.querySelectorAll('[data-quiz]').forEach(function (button) {
    button.addEventListener('click', function () {
      var feedback = document.getElementById('quiz-feedback');
      document.querySelectorAll('[data-quiz]').forEach(function (b) { b.classList.remove('picked'); });
      button.classList.add('picked');
      feedback.textContent = button.dataset.quiz === 'right'
        ? 'Correct. Confirmation bias describes the tendency to seek, interpret, or remember information in ways that support an existing belief.'
        : 'Try again. The key idea is selective processing around an existing belief.';
    });
  });

  document.querySelectorAll('[data-jump]').forEach(function (button) {
    button.addEventListener('click', function () {
      var target = document.getElementById(button.dataset.jump);
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  // ---------------------------------------------------------------------
  // Go
  // ---------------------------------------------------------------------

  bootstrapRouting();
})();
