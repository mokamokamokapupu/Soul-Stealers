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
    // Chat polling doubles as a keepalive; the assistant and arcade views
    // have no steady traffic of their own, so ping the session there to
    // keep the server from treating this username's claim as stale.
    setKeepalive(name === 'gpt' || name === 'games');

    if (name === 'gate') {
      var pw = document.getElementById('password');
      if (pw) pw.focus();
    } else if (name === 'setup') {
      var un = document.getElementById('username');
      if (un) un.focus();
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
  // Shared session/CSRF state, refreshed from /api/session as needed.
  // The frontend never decides who is authorized — it only mirrors
  // whatever the server's session bootstrap says, purely for UI purposes.
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
      updateRoomTag();
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
  // Chat view (was chat.js)
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
  var pollInFlight = false; // guards against overlapping poll() calls racing on `since`
  var renderedIds = Object.create(null); // message id -> true, once its DOM node exists — the actual fix for double-rendered messages
  var lastAuthor = null; // who sent the most recently rendered message, for grouping
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
      lastAuthor = null;
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
      nameSpan.textContent = m.username; // textContent — never innerHTML — no HTML injection possible
      meta.appendChild(nameSpan);
      meta.appendChild(document.createTextNode(' · ' + fmtTime(m.ts)));
      body.appendChild(meta);
    }

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

    wrap.appendChild(lead);
    wrap.appendChild(body);
    messagesEl.appendChild(wrap);
    lastAuthor = m.username;
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
    myRoom = null;
    csrfToken = null;
    clearRoomKey();
    cancelReply();
    updateRoomTag();
    // Re-bootstrap to pick up a fresh session/CSRF token, then land on essay.
    var res = await fetch('/api/session', { credentials: 'same-origin' }).catch(function () { return null; });
    if (res) {
      try { applySessionData(await res.json()); } catch (e) { /* ignore */ }
    }
    resetGpt();
    lastSubmitted = { snake: 0, tetris: 0, cookie: 0 };
    showView('essay');
  });

  // ---------------------------------------------------------------------
  // Appearance settings: interface scale + color skins, persisted locally.
  // The scale works by resizing the root font (everything downstream is
  // rem-based); skins swap the CSS custom properties while in the private
  // views only, so the public essay always looks untouched.
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
  } catch (e) { /* private mode — settings just won't persist */ }

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
  // Assistant view (G+P+T). History lives only in this tab's memory; the
  // server relays the conversation to its configured backend and never
  // stores it.
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
      gptMessagesEl.scrollTop = gptMessagesEl.scrollHeight;
    }
  });

  // ---------------------------------------------------------------------
  // Arcade (G+M+E): Snake, Tetris, and a cookie clicker, with a per-room
  // leaderboard keyed to chat usernames. Scores are personal bests; the
  // server only ever raises them.
  // ---------------------------------------------------------------------

  var gamesWho = document.getElementById('games-who');
  var gamesBack = document.getElementById('games-back');
  var gameTabs = Array.prototype.slice.call(document.querySelectorAll('.game-tab'));
  var activeGame = 'snake';
  var lastSubmitted = { snake: 0, tetris: 0, cookie: 0 };

  gamesBack.addEventListener('click', function () { showView('chat'); });

  function fmtScore(n) {
    if (n >= 1e9) return (n / 1e9).toFixed(1) + 'b';
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'm';
    if (n >= 1e4) return Math.round(n / 1e3) + 'k';
    return String(Math.floor(n));
  }

  function renderLeaderboard(scores) {
    ['snake', 'tetris', 'cookie'].forEach(function (game) {
      var ol = document.getElementById('lb-' + game);
      if (!ol) return;
      ol.innerHTML = '';
      var list = (scores && scores[game]) || [];
      if (!list.length) {
        var empty = document.createElement('li');
        empty.className = 'lb-empty';
        empty.textContent = 'no scores yet';
        ol.appendChild(empty);
        return;
      }
      list.forEach(function (row) {
        var li = document.createElement('li');
        if (myUsername && row.username && row.username.toLowerCase() === myUsername.toLowerCase()) {
          li.classList.add('is-me');
        }
        var name = document.createElement('span');
        name.className = 'lb-name';
        name.textContent = row.username;
        var val = document.createElement('b');
        val.textContent = fmtScore(row.score);
        li.appendChild(name);
        li.appendChild(val);
        ol.appendChild(li);
      });
    });
  }

  async function fetchLeaderboard() {
    try {
      var res = await fetch('/api/games/scores', { credentials: 'same-origin' });
      if (!res.ok) return;
      var data = await res.json();
      renderLeaderboard(data.scores);
    } catch (e) { /* leaderboard just stays as-is */ }
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
    } catch (e) { /* score will resubmit on the next event */ }
  }

  function setActiveGame(name) {
    if (activeGame !== name) {
      stopSnake(true);
      stopTetris(true);
    }
    activeGame = name;
    gameTabs.forEach(function (t) { t.classList.toggle('is-active', t.dataset.game === name); });
    document.getElementById('stage-snake').hidden = name !== 'snake';
    document.getElementById('stage-tetris').hidden = name !== 'tetris';
    document.getElementById('stage-cookie').hidden = name !== 'cookie';
  }

  gameTabs.forEach(function (tab) {
    tab.addEventListener('click', function () { setActiveGame(tab.dataset.game); });
  });

  function enterGames() {
    gamesWho.textContent = myUsername || '—';
    loadCookieState();
    startCookieLoop();
    fetchLeaderboard();
  }

  function leaveGames() {
    stopSnake(true);
    stopTetris(true);
    submitScore('cookie', cookie.total);
    stopCookieLoop();
  }

  // ---- snake ---------------------------------------------------------

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
  var snake = null;
  var snakeTimer = null;
  var snakeBest = 0;

  function snakeSpawnFood(s) {
    while (true) {
      var p = {
        x: Math.floor(Math.random() * SNAKE_CELLS),
        y: Math.floor(Math.random() * SNAKE_CELLS),
      };
      var clash = s.body.some(function (b) { return b.x === p.x && b.y === p.y; });
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
    snakeCtx.beginPath();
    snakeCtx.arc(snake.food.x * SNAKE_PX + 10, snake.food.y * SNAKE_PX + 10, 7, 0, Math.PI * 2);
    snakeCtx.fill();
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
      delay: 130,
    };
    snake.food = snakeSpawnFood(snake);
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
    if (head.x === snake.food.x && head.y === snake.food.y) {
      snake.score += 10;
      snakeScoreEl.textContent = String(snake.score);
      snake.food = snakeSpawnFood(snake);
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

  // ---- tetris --------------------------------------------------------

  var tetrisCanvas = document.getElementById('tetris-canvas');
  var tetrisCtx = tetrisCanvas.getContext('2d');
  var tetrisNextCanvas = document.getElementById('tetris-next');
  var tetrisNextCtx = tetrisNextCanvas.getContext('2d');
  var tetrisOverlay = document.getElementById('tetris-overlay');
  var tetrisMsg = document.getElementById('tetris-msg');
  var tetrisStartBtn = document.getElementById('tetris-start');
  var tetrisScoreEl = document.getElementById('tetris-score');
  var tetrisLinesEl = document.getElementById('tetris-lines');
  var tetrisLevelEl = document.getElementById('tetris-level');
  var TETRIS_HINT = '← → move · ↑ rotate · ↓ soft drop · space hard drop';
  var TETRIS_COLS = 10;
  var TETRIS_ROWS = 20;
  var TETRIS_PX = 24;
  var TETROMINOES = {
    I: { color: '#6fc0c9', size: 4, cells: [[0, 1], [1, 1], [2, 1], [3, 1]] },
    J: { color: '#6f93c9', size: 3, cells: [[0, 0], [0, 1], [1, 1], [2, 1]] },
    L: { color: '#c9a15a', size: 3, cells: [[2, 0], [0, 1], [1, 1], [2, 1]] },
    O: { color: '#c9c26f', size: 2, cells: [[0, 0], [1, 0], [0, 1], [1, 1]] },
    S: { color: '#6fc9a1', size: 3, cells: [[1, 0], [2, 0], [0, 1], [1, 1]] },
    T: { color: '#9b7fd6', size: 3, cells: [[1, 0], [0, 1], [1, 1], [2, 1]] },
    Z: { color: '#c97a6f', size: 3, cells: [[0, 0], [1, 0], [1, 1], [2, 1]] },
  };
  var TETRIS_LINE_SCORES = [0, 100, 300, 500, 800];
  var tetris = null;
  var tetrisTimer = null;

  function shuffle(arr) {
    for (var i = arr.length - 1; i > 0; i--) {
      var j = Math.floor(Math.random() * (i + 1));
      var t = arr[i]; arr[i] = arr[j]; arr[j] = t;
    }
    return arr;
  }

  function tetrisNewPiece() {
    if (!tetris.bag.length) tetris.bag = shuffle(['I', 'J', 'L', 'O', 'S', 'T', 'Z']);
    var type = tetris.bag.pop();
    return {
      type: type,
      cells: TETROMINOES[type].cells.map(function (c) { return [c[0], c[1]]; }),
      x: type === 'O' ? 4 : 3,
      y: -1,
    };
  }

  function tetrisCollides(piece, dx, dy, cells) {
    var cs = cells || piece.cells;
    for (var i = 0; i < cs.length; i++) {
      var bx = piece.x + cs[i][0] + dx;
      var by = piece.y + cs[i][1] + dy;
      if (bx < 0 || bx >= TETRIS_COLS || by >= TETRIS_ROWS) return true;
      if (by >= 0 && tetris.grid[by][bx]) return true;
    }
    return false;
  }

  function tryMovePiece(dx, dy) {
    if (tetrisCollides(tetris.piece, dx, dy)) return false;
    tetris.piece.x += dx;
    tetris.piece.y += dy;
    return true;
  }

  function tetrisDelay() {
    return Math.max(90, 700 - (tetris.level - 1) * 60);
  }

  function updateTetrisHud() {
    tetrisScoreEl.textContent = String(tetris.score);
    tetrisLinesEl.textContent = String(tetris.lines);
    tetrisLevelEl.textContent = String(tetris.level);
  }

  function drawTetrisCell(ctx, x, y, color, px) {
    ctx.fillStyle = color;
    ctx.fillRect(x * px + 1, y * px + 1, px - 2, px - 2);
  }

  function drawTetris() {
    tetrisCtx.clearRect(0, 0, tetrisCanvas.width, tetrisCanvas.height);
    if (!tetris) return;
    for (var y = 0; y < TETRIS_ROWS; y++) {
      for (var x = 0; x < TETRIS_COLS; x++) {
        if (tetris.grid[y][x]) drawTetrisCell(tetrisCtx, x, y, tetris.grid[y][x], TETRIS_PX);
      }
    }
    var p = tetris.piece;
    var color = TETROMINOES[p.type].color;
    p.cells.forEach(function (c) {
      var by = p.y + c[1];
      if (by >= 0) drawTetrisCell(tetrisCtx, p.x + c[0], by, color, TETRIS_PX);
    });
  }

  function drawTetrisNext() {
    tetrisNextCtx.clearRect(0, 0, tetrisNextCanvas.width, tetrisNextCanvas.height);
    if (!tetris || !tetris.next) return;
    var t = TETROMINOES[tetris.next.type];
    var px = 20;
    var offset = (tetrisNextCanvas.width - t.size * px) / 2;
    tetris.next.cells.forEach(function (c) {
      tetrisNextCtx.fillStyle = t.color;
      tetrisNextCtx.fillRect(offset + c[0] * px + 1, offset + c[1] * px + 1, px - 2, px - 2);
    });
  }

  function startTetris() {
    var grid = [];
    for (var y = 0; y < TETRIS_ROWS; y++) grid.push(new Array(TETRIS_COLS).fill(null));
    tetris = { grid: grid, bag: [], score: 0, lines: 0, level: 1, piece: null, next: null };
    tetris.piece = tetrisNewPiece();
    tetris.next = tetrisNewPiece();
    updateTetrisHud();
    tetrisOverlay.hidden = true;
    drawTetris();
    drawTetrisNext();
    tetrisTimer = setTimeout(tetrisTick, tetrisDelay());
  }

  function tetrisTick() {
    tetrisTimer = null;
    if (!tetris) return;
    if (!tryMovePiece(0, 1)) lockPiece();
    if (!tetris) return;
    drawTetris();
    tetrisTimer = setTimeout(tetrisTick, tetrisDelay());
  }

  function lockPiece() {
    var p = tetris.piece;
    var over = false;
    p.cells.forEach(function (c) {
      var bx = p.x + c[0];
      var by = p.y + c[1];
      if (by < 0) { over = true; return; }
      tetris.grid[by][bx] = TETROMINOES[p.type].color;
    });
    if (over) { endTetris(); return; }
    var cleared = 0;
    for (var y = TETRIS_ROWS - 1; y >= 0; y--) {
      if (tetris.grid[y].every(Boolean)) {
        tetris.grid.splice(y, 1);
        tetris.grid.unshift(new Array(TETRIS_COLS).fill(null));
        cleared++;
        y++;
      }
    }
    if (cleared) {
      tetris.lines += cleared;
      tetris.level = Math.floor(tetris.lines / 10) + 1;
      tetris.score += TETRIS_LINE_SCORES[cleared] * tetris.level;
    }
    tetris.piece = tetris.next;
    tetris.next = tetrisNewPiece();
    updateTetrisHud();
    drawTetrisNext();
    if (tetrisCollides(tetris.piece, 0, 0)) endTetris();
  }

  function tetrisMove(dx) {
    if (tryMovePiece(dx, 0)) drawTetris();
  }

  function tetrisRotate() {
    var p = tetris.piece;
    var size = TETROMINOES[p.type].size;
    var rotated = p.cells.map(function (c) { return [size - 1 - c[1], c[0]]; });
    var kicks = [0, -1, 1, -2, 2];
    for (var i = 0; i < kicks.length; i++) {
      if (!tetrisCollides(p, kicks[i], 0, rotated)) {
        p.cells = rotated;
        p.x += kicks[i];
        drawTetris();
        return;
      }
    }
  }

  function tetrisSoftDrop() {
    if (tryMovePiece(0, 1)) {
      tetris.score += 1;
      updateTetrisHud();
      drawTetris();
    }
  }

  function tetrisHardDrop() {
    var n = 0;
    while (tryMovePiece(0, 1)) n++;
    tetris.score += n * 2;
    updateTetrisHud();
    lockPiece();
    if (tetris) drawTetris();
  }

  function endTetris() {
    if (tetrisTimer) { clearTimeout(tetrisTimer); tetrisTimer = null; }
    var finalScore = tetris ? tetris.score : 0;
    tetris = null;
    tetrisMsg.textContent = 'game over · score ' + finalScore;
    tetrisStartBtn.textContent = 'play again';
    tetrisOverlay.hidden = false;
    submitScore('tetris', finalScore);
  }

  function stopTetris(abandon) {
    if (tetrisTimer) { clearTimeout(tetrisTimer); tetrisTimer = null; }
    if (!tetris) return;
    if (abandon && tetris.score > 0) submitScore('tetris', tetris.score);
    tetris = null;
    tetrisMsg.textContent = TETRIS_HINT;
    tetrisStartBtn.textContent = 'play';
    tetrisOverlay.hidden = false;
  }

  tetrisStartBtn.addEventListener('click', startTetris);

  var SNAKE_DIRS = {
    arrowup: { x: 0, y: -1 }, w: { x: 0, y: -1 },
    arrowdown: { x: 0, y: 1 }, s: { x: 0, y: 1 },
    arrowleft: { x: -1, y: 0 }, a: { x: -1, y: 0 },
    arrowright: { x: 1, y: 0 }, d: { x: 1, y: 0 },
  };

  document.addEventListener('keydown', function (e) {
    if (currentView !== 'games') return;
    var k = e.key ? e.key.toLowerCase() : '';
    if (activeGame === 'snake' && snake) {
      var d = SNAKE_DIRS[k];
      if (d) {
        e.preventDefault();
        if (d.x !== -snake.dir.x || d.y !== -snake.dir.y) snake.nextDir = d;
      }
    } else if (activeGame === 'tetris' && tetris) {
      if (k === 'arrowleft') { e.preventDefault(); tetrisMove(-1); }
      else if (k === 'arrowright') { e.preventDefault(); tetrisMove(1); }
      else if (k === 'arrowdown') { e.preventDefault(); tetrisSoftDrop(); }
      else if (k === 'arrowup' || k === 'x') { e.preventDefault(); tetrisRotate(); }
      else if (k === ' ') { e.preventDefault(); tetrisHardDrop(); }
    }
  });

  // ---- cookie clicker --------------------------------------------------

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
    } catch (e) { /* corrupt or unavailable — start fresh */ }
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
  // Essay interactivity: scroll-reveal, discreet entry mark, section index
  // nav with active-section highlighting, and scroll-progress rail.
  // ---------------------------------------------------------------------

  // ---------------------------------------------------------------------
  // Hidden keyboard combos. Q+W+O+P (held together on the essay) opens the
  // gate; G+P+T (from chat/games) opens the assistant; G+M+E (from
  // chat/assistant) opens the arcade. Tab is the panic key: from anywhere
  // past the essay it snaps straight back, even mid-typing.
  // ---------------------------------------------------------------------

  var COMBOS = [
    { keys: ['q', 'w', 'o', 'p'], from: ['essay'], fired: false, go: function () { setGateError(''); showView('gate'); } },
    { keys: ['g', 'p', 't'], from: ['chat', 'games'], fired: false, go: function () { showView('gpt'); } },
    { keys: ['g', 'm', 'e'], from: ['chat', 'gpt'], fired: false, go: function () { showView('games'); } },
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
        setGateError('');
        showView('essay');
      }
      return;
    }

    var k = e.key ? e.key.toLowerCase() : '';
    if (!COMBO_KEYS[k]) return;
    if (isTypingTarget(e.target)) return; // don't hijack typing into the password/username/message fields

    heldKeys[k] = true;
    COMBOS.forEach(function (c) {
      if (!c.fired && c.from.indexOf(currentView) !== -1 && comboHeld(c)) {
        c.fired = true;
        c.go();
      }
    });
  });

  document.addEventListener('keyup', function (e) {
    var k = e.key ? e.key.toLowerCase() : '';
    if (COMBO_KEYS[k]) delete heldKeys[k];
    COMBOS.forEach(function (c) { if (!comboHeld(c)) c.fired = false; });
  });

  // Held keys can't be tracked across a focus/tab switch — reset so a
  // stale key doesn't silently count toward the next attempt.
  window.addEventListener('blur', function () {
    heldKeys = Object.create(null);
    COMBOS.forEach(function (c) { c.fired = false; });
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
        conformity: 'Speaking up injects a minority view into the room. Disagreement suddenly becomes visible — and cheaper for the next person to voice.',
        observation: 'Asking what others think can surface hidden disagreement without you having to plant a flag first.',
        compliance: 'Staying silent keeps the peace, but it also feeds the illusion that everyone agrees.'
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
        ? 'Correct — 20% off $100 is $80, and the second 20% comes off the $80. Final price: $64. Sequential discounts compound; they don\'t add.'
        : 'Not quite. The second 20% applies to $80, not the original $100 — so $64, not $60.';
    });
  });

  var timelineCopy = document.getElementById('timeline-copy');
  var timelineText = {
    '1': 'It starts with contact: people notice each other, size up safety and relevance, and form first impressions that are annoyingly durable.',
    '2': 'People start aligning around shared interests, roles, expectations, or whoever has the most gravity in the room.',
    '3': 'Repeated patterns harden into norms. What was once negotiated quietly becomes assumed.',
    '4': 'Eventually the group becomes part of how its members describe themselves — and belonging starts to mean something different.'
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
        ? 'Correct. Confirmation bias is the tendency to seek, read, and remember information in ways that flatter what you already believe.'
        : 'Not quite — the key idea is selective processing around a belief you already hold.';
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
