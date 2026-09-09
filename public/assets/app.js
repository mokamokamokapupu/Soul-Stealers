(function () {
  'use strict';

  var VIEWS = ['essay', 'gate', 'setup', 'chat', 'games'];
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
    if (myUsername) startPresence();
    nudgePresence();

    if (name === 'gate') {
      gateInput.value = '';
      setGateError('');
      gateInput.focus();
    } else if (name === 'setup') {
      setupInput.value = '';
      setSetupError('');
      setupInput.focus();
    }
  }

  // Activity shown next to each name. Rides along on requests already being made;
  // the server only accepts a fixed set of codes and this file re-labels them.

  var IDLE_AFTER_MS = 3 * 60 * 1000;
  var lastInteractionAt = Date.now();
  ['mousedown', 'keydown', 'touchstart', 'wheel', 'mousemove'].forEach(function (evt) {
    document.addEventListener(evt, function () { lastInteractionAt = Date.now(); }, { passive: true });
  });
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) lastInteractionAt = Date.now();
  });

  function gameIsRunning() {
    if (activeGame === 'snake') return !!snake;
    if (activeGame === 'tetris') return !!tetris;
    if (activeGame === 'mines') return !!(mines && !mines.over);
    if (activeGame === 'doom') return !!(doomInstance && doomRaf);
    if (activeGame === 'poker') return !!poker;
    if (activeGame === 'cookie') return true;
    return false;
  }

  function currentActivityCode() {
    if (document.hidden || Date.now() - lastInteractionAt > IDLE_AFTER_MS) return 'idle';
    if (currentView === 'chat') return 'chat';
    if (currentView === 'games') {
      // A game being played is more specific than "listening"; music rides along.
      if (activeGame && (gameIsRunning() || !spotifyPlaying)) return 'game:' + activeGame;
      if (spotifyPlaying) return 'spotify';
      return 'arcade';
    }
    if (currentView === 'essay') return 'essay';
    return 'idle';
  }

  function currentListening() {
    if (!spotifyPlaying || !spotifyNowTrack || !spotifyNowTrack.name) return null;
    return { name: spotifyNowTrack.name, artists: spotifyNowTrack.artists || '' };
  }

  function withActivity(url) {
    return url + (url.indexOf('?') === -1 ? '?' : '&') + 'activity=' + encodeURIComponent(currentActivityCode());
  }

  // Beats from every view. Piggy-backing on whatever requests a view happened
  // to make is what left people showing as "looking at chat" long after.
  var PRESENCE_INTERVAL_MS = 20000;
  var presenceTimer = null;
  var presenceInFlight = false;
  var lastPresenceKey = '';
  var feedSince = 0;
  var latestFeed = [];

  async function sendPresence(force) {
    if (!myUsername || !csrfToken) return;
    if (presenceInFlight) return;
    var activity = currentActivityCode();
    var listening = currentListening();
    var key = activity + '|' + (listening ? listening.name + '|' + listening.artists : '');
    if (!force && key === lastPresenceKey && presenceTimer) return;
    lastPresenceKey = key;
    presenceInFlight = true;
    try {
      var res = await fetch('/api/presence', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ activity: activity, track: listening, feedSince: feedSince }),
      });
      if (!res.ok) return;
      var data = await res.json();
      if (data.activeUsers) updateActiveUsers(data.activeUsers);
      if (data.feed) mergeFeed(data.feed);
    } catch (e) { /* transient — the next beat retries */ }
    finally { presenceInFlight = false; }
  }

  function startPresence() {
    if (presenceTimer) return;
    presenceTimer = setInterval(function () { sendPresence(true); }, PRESENCE_INTERVAL_MS);
    sendPresence(true);
  }

  function stopPresence() {
    if (presenceTimer) { clearInterval(presenceTimer); presenceTimer = null; }
    lastPresenceKey = '';
  }

  function nudgePresence() {
    if (!presenceTimer) return;
    sendPresence(false);
  }

  document.addEventListener('visibilitychange', function () { nudgePresence(); });


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

  // Chat content encryption. The server only ever sees an opaque blob. The AES-GCM
  // key is derived (PBKDF2) from the site password every room member already knows.

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

  // Same key and layout as encryptText, on raw bytes instead of base64.
  async function encryptBytes(bytes) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, roomKey, bytes);
    var combined = new Uint8Array(iv.length + cipherBuf.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(cipherBuf), iv.length);
    return combined;
  }

  async function decryptBytes(bytes) {
    if (!roomKey || !bytes || bytes.length < 13) return null;
    try {
      var iv = bytes.slice(0, 12);
      var data = bytes.slice(12);
      var plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, roomKey, data);
      return new Uint8Array(plainBuf);
    } catch (e) {
      return null;
    }
  }

  // The server only sees ciphertext, so magic bytes are checked here instead —
  // before encrypting, and again after decrypting. Mirrors detectImageType.
  function sniffImageMime(bytes) {
    if (!bytes || bytes.length < 12) return null;
    if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg';
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 &&
        bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a) return 'image/png';
    if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
        bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return 'image/webp';
    return null;
  }

  // Every object URL minted for a decrypted image, so they can be released
  // when the message list is torn down instead of pinning the decrypted
  // bytes in memory for the life of the tab.
  var decryptedImageUrls = [];
  function releaseDecryptedImageUrls() {
    for (var i = 0; i < decryptedImageUrls.length; i++) {
      try { URL.revokeObjectURL(decryptedImageUrls[i]); } catch (e) { /* already gone */ }
    }
    decryptedImageUrls = [];
  }

  async function decryptChatImage(imageId) {
    var res = await fetch(chatImageUrl(imageId), { credentials: 'same-origin' });
    if (!res.ok) return null;
    var raw = new Uint8Array(await res.arrayBuffer());
    var plain = await decryptBytes(raw);
    if (!plain) return null;
    var mime = sniffImageMime(plain);
    if (!mime) return null; // decrypted to something that isn't an image — refuse it
    var url = URL.createObjectURL(new Blob([plain], { type: mime }));
    decryptedImageUrls.push(url);
    return url;
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
  // id -> { el, body, textEl, msg }, so an edit can be applied in place.
  var rendered = Object.create(null);
  var lastAuthor = null; // who sent the most recently rendered message, for grouping
  var replyingTo = null;
  var roomClearedAt = null; // server's last-clear stamp; a jump means wipe the view

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

  // username (lowercased) -> upload version, so a new picture is a new URL.
  var avatarVersions = Object.create(null);

  function avatarUrl(username) {
    var name = username || '';
    var v = avatarVersions[name.toLowerCase()];
    return '/api/avatar/' + encodeURIComponent(name) + (v ? '?v=' + v : '');
  }

  function applyAvatarVersions(map) {
    if (!map) return;
    Object.keys(map).forEach(function (key) {
      var v = map[key];
      if (!v || avatarVersions[key] === v) return;
      avatarVersions[key] = v;
      refreshAvatarImages(key);
    });
  }

  function refreshAvatarImages(usernameKey) {
    var prefix = '/api/avatar/';
    var imgs = document.querySelectorAll('img[src^="' + prefix + '"]');
    Array.prototype.forEach.call(imgs, function (img) {
      var raw = img.getAttribute('src').slice(prefix.length).split('?')[0];
      var name;
      try { name = decodeURIComponent(raw); } catch (e) { name = raw; }
      if (name.toLowerCase() === usernameKey) img.src = avatarUrl(name);
    });
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
        autoGrowComposer();
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
      releaseDecryptedImageUrls();
      messagesEl.innerHTML = '';
      renderedIds = Object.create(null);
      rendered = Object.create(null);
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

  function msgStamp(m) {
    return Math.max(m.ts, m.editedAt || 0);
  }

  async function renderOne(m) {
    if (renderedIds[m.id]) {
      since = Math.max(since, msgStamp(m));
      await applyEditToRendered(m);
      return;
    }
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
      if (m.encrypted) {
        // Ciphertext: fetch it, decrypt it here, and only then hand the
        // bytes to <img> as a blob URL. Images sent before this feature
        // existed have no `encrypted` flag and still load the old way.
        img.classList.add('is-decrypting');
        decryptChatImage(m.imageId).then(function (objUrl) {
          img.classList.remove('is-decrypting');
          if (objUrl) {
            img.src = objUrl;
          } else {
            img.remove();
            var locked = document.createElement('div');
            locked.className = 'text is-locked';
            locked.textContent = '🔒 Unable to decrypt this image';
            figure.appendChild(locked);
          }
        });
      } else {
        img.src = chatImageUrl(m.imageId);
      }
      figure.appendChild(img);
      figure.addEventListener('click', function () { if (img.src) openLightbox(img.src); });
      body.appendChild(figure);
      previewForReply = '📷 Photo';
      rendered[m.id] = { el: wrap, body: body, textEl: null, msg: m };
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
      body.appendChild(buildEditedBadge(m));
      previewForReply = plain === null ? '🔒 message' : plain;
      rendered[m.id] = { el: wrap, body: body, textEl: text, msg: m };
    }

    var actions = document.createElement('div');
    actions.className = 'msg-actions';
    var replyBtn = document.createElement('button');
    replyBtn.type = 'button';
    replyBtn.className = 'msg-action-btn';
    replyBtn.textContent = '↩ Reply';
    replyBtn.addEventListener('click', function () { startReply(m.id, m.username, truncate(String(previewForReply).replace(/\s+/g, ' '), 80)); });
    actions.appendChild(replyBtn);
    if (m.type === 'text' && m.username === myUsername) {
      var editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'msg-action-btn';
      editBtn.textContent = '✎ Edit';
      editBtn.addEventListener('click', function () { startEditMessage(m.id); });
      actions.appendChild(editBtn);
    }
    body.appendChild(actions);

    wrap.appendChild(lead);
    wrap.appendChild(body);
    messagesEl.appendChild(wrap);
    lastAuthor = m.username;
    since = Math.max(since, msgStamp(m));

    requestAnimationFrame(function () {
      requestAnimationFrame(function () { wrap.classList.add('msg-enter-active'); });
    });
    setTimeout(function () { wrap.classList.remove('msg-enter', 'msg-enter-active'); }, 500);
  }

  // -------------------------------------------------------------------
  // Editing — the author rewrites a message, everyone keeps the old wording
  // -------------------------------------------------------------------

  async function plaintextOf(cipher) {
    if (!cryptoAvailable) return cipher;
    var out = await decryptText(cipher);
    return out === null ? null : out;
  }

  function buildEditedBadge(m) {
    var badge = document.createElement('button');
    badge.type = 'button';
    badge.className = 'msg-edited';
    badge.textContent = '(edited)';
    badge.title = 'See earlier versions';
    badge.hidden = !m.editedAt;
    badge.addEventListener('click', function () {
      var entry = rendered[m.id];
      openEditHistory(entry ? entry.msg : m);
    });
    return badge;
  }

  async function applyEditToRendered(m) {
    var entry = rendered[m.id];
    if (!entry) return;
    var prev = entry.msg;
    entry.msg = m;
    if (m.type !== 'text' || !entry.textEl) return;
    if (prev && prev.text === m.text && prev.editedAt === m.editedAt) return;

    var plain = await plaintextOf(m.text);
    entry.textEl.textContent = plain === null ? '🔒 Unable to decrypt this message' : plain;
    entry.textEl.classList.toggle('is-locked', plain === null);
    if (cryptoAvailable) entry.el.setAttribute('data-cipher', m.text);
    var badge = entry.body.querySelector('.msg-edited');
    if (badge) badge.hidden = !m.editedAt;
    entry.el.classList.add('is-edit-flash');
    setTimeout(function () { entry.el.classList.remove('is-edit-flash'); }, 900);
  }

  var editingId = null;

  async function startEditMessage(id) {
    var entry = rendered[id];
    if (!entry || !entry.textEl || entry.msg.username !== myUsername) return;
    if (cryptoAvailable && !roomKey) { setUnlockVisible(true); return; }
    if (editingId && editingId !== id) cancelEditMessage();

    var current = await plaintextOf(entry.msg.text);
    if (current === null) {
      setChatStatus('That message cannot be decrypted here, so it cannot be edited.', true);
      setTimeout(function () { setChatStatus(''); }, 3000);
      return;
    }

    editingId = id;
    var form = document.createElement('div');
    form.className = 'msg-edit';
    var box = document.createElement('textarea');
    box.className = 'msg-edit-input';
    box.maxLength = 500;
    box.rows = 1;
    box.value = current;
    var row = document.createElement('div');
    row.className = 'msg-edit-actions';
    var save = document.createElement('button');
    save.type = 'button';
    save.className = 'msg-edit-save';
    save.textContent = 'Save';
    var cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'msg-edit-cancel';
    cancel.textContent = 'Cancel';
    var hint = document.createElement('span');
    hint.className = 'msg-edit-hint';
    hint.textContent = 'enter saves · esc cancels';
    row.appendChild(save);
    row.appendChild(cancel);
    row.appendChild(hint);
    form.appendChild(box);
    form.appendChild(row);

    entry.textEl.hidden = true;
    entry.body.insertBefore(form, entry.textEl.nextSibling);
    entry.editForm = form;

    function grow() {
      box.style.height = 'auto';
      box.style.height = Math.min(box.scrollHeight, 200) + 'px';
    }
    box.addEventListener('input', grow);
    grow();
    box.focus();
    box.setSelectionRange(box.value.length, box.value.length);

    save.addEventListener('click', function () { commitEditMessage(id, box.value); });
    cancel.addEventListener('click', cancelEditMessage);
    box.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { e.preventDefault(); cancelEditMessage(); }
      else if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
        e.preventDefault();
        commitEditMessage(id, box.value);
      }
    });
  }

  function cancelEditMessage() {
    if (!editingId) return;
    var entry = rendered[editingId];
    if (entry) {
      if (entry.editForm) { entry.editForm.remove(); entry.editForm = null; }
      if (entry.textEl) entry.textEl.hidden = false;
    }
    editingId = null;
  }

  async function commitEditMessage(id, raw) {
    var entry = rendered[id];
    if (!entry) return;
    var text = String(raw || '').trim();
    if (!text) return;
    var wasPlain = await plaintextOf(entry.msg.text);
    if (text === wasPlain) { cancelEditMessage(); return; }

    var payload = cryptoAvailable ? await encryptText(text) : text;
    try {
      var res = await fetch('/api/chat/edit', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ id: id, text: payload }),
      });
      if (res.status === 403) { showView('gate'); return; }
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok || !data.message) {
        setChatStatus(data.error || 'Could not save that edit.', true);
        setTimeout(function () { setChatStatus(''); }, 3000);
        return;
      }
      cancelEditMessage();
      await applyEditToRendered(data.message);
      since = Math.max(since, msgStamp(data.message));
    } catch (e) {
      setChatStatus('Could not save that edit.', true);
      setTimeout(function () { setChatStatus(''); }, 3000);
    }
  }

  async function openEditHistory(m) {
    var overlay = document.createElement('div');
    overlay.className = 'history-overlay';
    var card = document.createElement('div');
    card.className = 'history-card';

    var head = document.createElement('div');
    head.className = 'history-head';
    var title = document.createElement('h3');
    title.textContent = 'Edit history';
    var closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'history-close';
    closeBtn.setAttribute('aria-label', 'Close edit history');
    closeBtn.textContent = '×';
    head.appendChild(title);
    head.appendChild(closeBtn);
    card.appendChild(head);

    var list = document.createElement('ol');
    list.className = 'history-list';

    var versions = (m.history || []).slice();
    versions.push({ text: m.text, ts: m.editedAt || m.ts, current: true });

    for (var i = versions.length - 1; i >= 0; i--) {
      var v = versions[i];
      var li = document.createElement('li');
      li.className = 'history-item' + (v.current ? ' is-current' : '');
      var meta = document.createElement('div');
      meta.className = 'history-meta';
      meta.textContent = (v.current ? 'Now' : 'Version ' + (i + 1)) + ' · ' + fmtTime(v.ts);
      var textEl = document.createElement('div');
      textEl.className = 'history-text';
      var plain = await plaintextOf(v.text);
      textEl.textContent = plain === null ? '🔒 Unable to decrypt this version' : plain;
      if (plain === null) textEl.classList.add('is-locked');
      li.appendChild(meta);
      li.appendChild(textEl);
      list.appendChild(li);
    }

    card.appendChild(list);
    overlay.appendChild(card);

    function close() {
      overlay.remove();
      document.removeEventListener('keydown', esc);
    }
    function esc(e) { if (e.key === 'Escape') close(); }
    closeBtn.addEventListener('click', close);
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
    document.addEventListener('keydown', esc);

    document.body.appendChild(overlay);
    requestAnimationFrame(function () { overlay.classList.add('is-open'); });
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

  function resetChatView() {
    messagesEl.innerHTML = '<p class="empty-state">It\'s quiet. Say something.</p>';
    renderedIds = Object.create(null);
    rendered = Object.create(null);
    lastAuthor = null;
    cancelReply();
  }

  async function poll() {
    if (pollInFlight) return;
    pollInFlight = true;
    try {
      var res = await fetch(withActivity('/api/chat/messages?since=' + since + '&feedSince=' + feedSince), { credentials: 'same-origin' });
      if (res.status === 403) {
        stopChatPolling();
        showView('gate');
        return;
      }
      var data = await res.json();
      if (typeof data.clearedAt === 'number') {
        if (roomClearedAt === null) {
          roomClearedAt = data.clearedAt;
        } else if (data.clearedAt > roomClearedAt) {
          roomClearedAt = data.clearedAt;
          resetChatView();
        }
      }
      applyAvatarVersions(data.avatarVersions);
      await renderMessages(data.messages || []);
      updateActiveUsers(data.activeUsers || []);
      mergeFeed(data.feed || []);
    } catch (e) { /* transient — next poll retries */ }
    finally { pollInFlight = false; }
  }

  function startChatPolling() {
    if (pollTimer) return;
    since = 0;
    roomClearedAt = null;
    renderedIds = Object.create(null);
    rendered = Object.create(null);
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

  // A textarea doesn't submit on Enter by itself, so wire it up: Enter
  // sends, Shift+Enter (or Ctrl/Cmd+Enter) drops to a new line. isComposing
  // guards IME input, where Enter is picking a candidate, not sending.
  function autoGrowComposer() {
    msgInput.style.height = 'auto';
    msgInput.style.height = Math.min(msgInput.scrollHeight, 136) + 'px';
  }

  msgInput.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter') return;
    if (e.isComposing || e.keyCode === 229) return;
    if (e.shiftKey || e.ctrlKey || e.metaKey || e.altKey) return;
    e.preventDefault();
    if (composer.requestSubmit) composer.requestSubmit();
    else composer.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
  });
  msgInput.addEventListener('input', autoGrowComposer);

  composer.addEventListener('submit', async function (e) {
    e.preventDefault();
    var text = msgInput.value.trim();
    if (!text) return;

    if (text.toLowerCase() === '/clearchat') {
      msgInput.value = ''; autoGrowComposer();
      try {
        var clearRes = await fetch('/api/chat/clear', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'X-CSRF-Token': csrfToken },
        });
        if (clearRes.status === 403) { showView('gate'); return; }
        var clearData = await clearRes.json();
        if (clearRes.ok) {
          roomClearedAt = clearData.clearedAt || roomClearedAt;
          resetChatView();
          setChatStatus('chat cleared for everyone');
          setTimeout(function () { setChatStatus(''); }, 2500);
        } else {
          setChatStatus(clearData.error || 'Could not clear the chat.', true);
          setTimeout(function () { setChatStatus(''); }, 3000);
        }
      } catch (err) {
        setChatStatus('Could not clear the chat.', true);
        setTimeout(function () { setChatStatus(''); }, 3000);
      }
      return;
    }

    if (cryptoAvailable && !roomKey) { setUnlockVisible(true); return; }

    msgInput.value = ''; autoGrowComposer();
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
      msgInput.value = text; autoGrowComposer();
    } finally {
      sendBtn.disabled = false;
      sendBtn.classList.remove('is-sending');
    }
  });

  // Shared by the file picker and by pasting. The server sniffs the real bytes.
  var CHAT_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
  var MAX_CHAT_IMAGE_CLIENT_BYTES = 5 * 1024 * 1024;

  async function sendChatImageBlob(blob) {
    if (!blob) return;
    if (CHAT_IMAGE_TYPES.indexOf(blob.type) === -1) {
      setChatStatus('Use a JPEG, PNG, or WebP image.', true);
      setTimeout(function () { setChatStatus(''); }, 3000);
      return;
    }
    // 28 bytes of IV+tag get added by encryption, so stop a little short
    // of the server's hard cap rather than failing after the upload.
    if (blob.size > MAX_CHAT_IMAGE_CLIENT_BYTES - 1024) {
      setChatStatus('Image is too large (5MB max).', true);
      setTimeout(function () { setChatStatus(''); }, 3000);
      return;
    }

    var pendingReplyTo = replyingTo ? replyingTo.id : undefined;
    cancelReply();
    setChatStatus('Sending image…');
    try {
      // Encrypt before upload so the server only ever holds ciphertext. Falls back to
      // plaintext only where Web Crypto is unavailable, same as message text does.
      var body = blob;
      var contentType = blob.type;
      var enc = false;
      if (cryptoAvailable && roomKey) {
        var rawBytes = new Uint8Array(await blob.arrayBuffer());
        if (!sniffImageMime(rawBytes)) {
          setChatStatus('That file isn\u2019t a JPEG, PNG, or WebP image.', true);
          setTimeout(function () { setChatStatus(''); }, 3000);
          return;
        }
        body = await encryptBytes(rawBytes);
        contentType = 'application/octet-stream';
        enc = true;
      }
      var url = '/api/chat/image?enc=' + (enc ? '1' : '0') +
        (pendingReplyTo ? '&replyTo=' + encodeURIComponent(pendingReplyTo) : '');
      var res = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': contentType, 'X-CSRF-Token': csrfToken },
        body: body,
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
    }
  }

  imageBtnInput.addEventListener('change', function () {
    var file = imageBtnInput.files && imageBtnInput.files[0];
    // Clear the input up front, not in a finally: picking the *same* file
    // twice in a row otherwise fires no change event at all the second
    // time. The File object stays valid after this.
    imageBtnInput.value = '';
    if (file) sendChatImageBlob(file);
  });

  // Paste an image into the chat. Only acts when the clipboard really carries an
  // image file, so plain text pastes are untouched.
  document.addEventListener('paste', function (e) {
    if (currentView !== 'chat') return;
    if (!e.clipboardData || !e.clipboardData.items) return;
    var items = e.clipboardData.items;
    var blob = null;
    for (var i = 0; i < items.length; i++) {
      if (items[i].kind === 'file' && items[i].type && items[i].type.indexOf('image/') === 0) {
        blob = items[i].getAsFile();
        if (blob) break;
      }
    }
    if (!blob) return;
    e.preventDefault();
    sendChatImageBlob(blob);
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
        var key = (myUsername || '').toLowerCase();
        avatarVersions[key] = data.avatarVersion || Date.now();
        myAvatarEl.src = avatarUrl(myUsername);
        refreshAvatarImages(key);
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
    stopPresence();
    latestFeed.length = 0;
    feedSince = 0;
    renderFeed();
    updateActiveUsers([]);
    myUsername = null;
    myRoom = null;
    csrfToken = null;
    clearRoomKey();
    releaseDecryptedImageUrls();
    cancelReply();
    updateRoomTag();
    var res = await fetch('/api/session', { credentials: 'same-origin' }).catch(function () { return null; });
    if (res) {
      try { applySessionData(await res.json()); } catch (e) { /* ignore */ }
    }
    lastSubmitted = { snake: 0, tetris: 0, mines: 0, poker: 0, cookie: 0 };
    showView('essay');
  });

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
    var scaled = currentView === 'chat' || currentView === 'games';
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

  var ACTIVE_PANEL_KEY = 'ss_active_users_open';
  var activeUsersBtn = document.getElementById('active-users-btn');
  var activeUsersPanel = document.getElementById('active-users-panel');
  var activeUsersList = document.getElementById('active-users-list');
  var activeUsersCount = document.getElementById('active-users-count');
  var activeUsersEmpty = document.getElementById('active-users-empty');
  var activeCountBadge = document.getElementById('active-count-badge');

  function setActiveUsersPanelOpen(open) {
    activeUsersPanel.hidden = !open;
    activeUsersBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    activeUsersBtn.classList.toggle('is-active', open);
    try { localStorage.setItem(ACTIVE_PANEL_KEY, open ? '1' : '0'); } catch (e) { /* private mode */ }
  }

  activeUsersBtn.addEventListener('click', function () {
    setActiveUsersPanelOpen(activeUsersPanel.hidden);
  });

  var startPanelOpen = false;
  try { startPanelOpen = localStorage.getItem(ACTIVE_PANEL_KEY) === '1'; } catch (e) { /* private mode */ }
  setActiveUsersPanelOpen(startPanelOpen);

  // Codes come from the server's fixed ACTIVITY_CODES list; anything not
  // in this map (including null) just shows no label at all.
  var ACTIVITY_LABELS = {
    'chat': 'looking at chat',
    'essay': 'reading the essay',
    'arcade': 'in the arcade',
    'spotify': 'listening to Spotify',
    'idle': 'idle',
    'game:snake': 'playing Snake',
    'game:tetris': 'playing Tetris',
    'game:mines': 'playing Mines',
    'game:poker': 'playing Poker',
    'game:cookie': 'playing Cookie Clicker',
    'game:doom': 'playing Doom',
  };

  function buildUserRow(entry, className) {
    // Older servers sent a bare string here; accept both shapes so a stale
    // cached page doesn't render "[object Object]".
    var name = typeof entry === 'string' ? entry : (entry && entry.name);
    if (!name) return null;
    var activity = typeof entry === 'string' ? null : (entry && entry.activity);
    var listening = typeof entry === 'string' ? null : (entry && entry.listening);

    var li = document.createElement('li');
    li.className = className + (name === myUsername ? ' is-me' : '');
    var img = document.createElement('img');
    img.className = 'avatar';
    img.alt = '';
    img.loading = 'lazy';
    img.src = avatarUrl(name);
    var info = document.createElement('span');
    info.className = 'active-user-info';
    var span = document.createElement('span');
    span.className = 'active-user-name';
    span.textContent = name; // textContent — never innerHTML
    info.appendChild(span);

    var label = ACTIVITY_LABELS[activity];
    if (label) {
      var act = document.createElement('span');
      act.className = 'active-user-activity' + (activity === 'idle' ? ' is-idle' : '');
      act.textContent = label; // textContent — and only ever from the map above
      info.appendChild(act);
    }
    if (listening && listening.name) {
      var song = document.createElement('span');
      song.className = 'active-user-song';
      var note = document.createElement('span');
      note.className = 'active-user-note';
      note.setAttribute('aria-hidden', 'true');
      note.textContent = '\u266a';
      var songText = document.createElement('span');
      songText.className = 'active-user-song-text';
      songText.textContent = listening.artists
        ? listening.name + ' \u2014 ' + listening.artists
        : listening.name;
      song.appendChild(note);
      song.appendChild(songText);
      info.appendChild(song);
    }

    li.appendChild(img);
    li.appendChild(info);
    return li;
  }

  function updateActiveUsers(list) {
    list = list || [];
    var count = String(list.length);
    activeUsersCount.textContent = count;
    if (activeCountBadge) {
      activeCountBadge.textContent = count;
      activeCountBadge.hidden = list.length === 0;
    }
    // Presence beats carry versions too, so an avatar change still lands on
    // people sitting in the arcade with chat polling stopped.
    var versions = null;
    list.forEach(function (entry) {
      if (entry && entry.name && entry.avatarVersion) {
        if (!versions) versions = Object.create(null);
        versions[entry.name.toLowerCase()] = entry.avatarVersion;
      }
    });
    applyAvatarVersions(versions);

    activeUsersList.innerHTML = '';
    activeUsersEmpty.hidden = list.length !== 0;
    list.forEach(function (entry) {
      var row = buildUserRow(entry, 'active-user-row');
      if (row) activeUsersList.appendChild(row);
    });
    renderSidebarPresence(list);
  }

  // ---------------------------------------------------------------------
  // Room sidebar — who is here, and what everyone has been up to
  // ---------------------------------------------------------------------

  var sidebarNowEl = document.getElementById('sidebar-now');
  var sidebarNowEmpty = document.getElementById('sidebar-now-empty');
  var sidebarFeedEl = document.getElementById('sidebar-feed');
  var sidebarFeedEmpty = document.getElementById('sidebar-feed-empty');
  var sidebarToggle = document.getElementById('sidebar-toggle');

  function renderSidebarPresence(list) {
    if (!sidebarNowEl) return;
    sidebarNowEl.innerHTML = '';
    var any = 0;
    list.forEach(function (entry) {
      var row = buildUserRow(entry, 'sidebar-user-row');
      if (row) { sidebarNowEl.appendChild(row); any++; }
    });
    if (sidebarNowEmpty) sidebarNowEmpty.hidden = any !== 0;
  }

  function mergeFeed(entries) {
    if (entries && entries.length) {
      entries.forEach(function (e) {
        if (!e || !e.id) return;
        if (e.ts > feedSince) feedSince = e.ts;
        var at = -1;
        for (var i = 0; i < latestFeed.length; i++) {
          if (latestFeed[i].id === e.id) { at = i; break; }
        }
        if (at === -1) latestFeed.push(e);
        else latestFeed[at] = e;
      });
      latestFeed.sort(function (a, b) { return a.ts - b.ts; });
      if (latestFeed.length > 40) latestFeed.splice(0, latestFeed.length - 40);
    }
    renderFeed();
  }

  function relativeTime(ts) {
    var secs = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (secs < 45) return 'just now';
    var mins = Math.round(secs / 60);
    if (mins < 60) return mins + 'm ago';
    return Math.round(mins / 60) + 'h ago';
  }

  function renderFeed() {
    if (!sidebarFeedEl) return;
    sidebarFeedEl.innerHTML = '';
    if (sidebarFeedEmpty) sidebarFeedEmpty.hidden = latestFeed.length !== 0;
    for (var i = latestFeed.length - 1; i >= 0; i--) {
      var e = latestFeed[i];
      var li = document.createElement('li');
      li.className = 'sidebar-feed-row';

      var img = document.createElement('img');
      img.className = 'avatar';
      img.alt = '';
      img.loading = 'lazy';
      img.src = avatarUrl(e.username);

      var body = document.createElement('span');
      body.className = 'sidebar-feed-body';
      var line = document.createElement('span');
      line.className = 'sidebar-feed-line';

      var who = document.createElement('strong');
      who.textContent = e.username;
      line.appendChild(who);

      if (e.kind === 'track') {
        line.appendChild(document.createTextNode(' listened to '));
        var song = document.createElement('em');
        song.textContent = e.artists ? e.detail + ' \u2014 ' + e.artists : e.detail;
        line.appendChild(song);
      } else {
        line.appendChild(document.createTextNode(' started ' + (ACTIVITY_LABELS[e.detail] || 'in the arcade')));
      }

      var when = document.createElement('span');
      when.className = 'sidebar-feed-time';
      when.textContent = relativeTime(e.ts);

      body.appendChild(line);
      body.appendChild(when);
      li.appendChild(img);
      li.appendChild(body);
      sidebarFeedEl.appendChild(li);
    }
  }

  if (sidebarToggle) {
    sidebarToggle.addEventListener('click', function () {
      var open = !document.body.classList.toggle('sidebar-collapsed');
      sidebarToggle.setAttribute('aria-expanded', String(open));
      try { localStorage.setItem('ss_sidebar_open', open ? '1' : '0'); } catch (e) { /* ignore */ }
    });
    try {
      if (localStorage.getItem('ss_sidebar_open') === '0') {
        document.body.classList.add('sidebar-collapsed');
        sidebarToggle.setAttribute('aria-expanded', 'false');
      }
    } catch (e) { /* ignore */ }
  }

  setInterval(function () { if (latestFeed.length) renderFeed(); }, 60000);

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
  var GAME_LABELS = { snake: 'Snake', tetris: 'Tetris', mines: 'Minesweeper', doom: 'Doom', poker: 'Poker', cookie: 'Cookie Clicker' };
  var activeGame = 'snake';
  var lastScores = {};
  var lastSubmitted = { snake: 0, tetris: 0, mines: 0, poker: 0, cookie: 0 };

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
    lbPodium.innerHTML = '';
    lbRest.innerHTML = '';
    if (activeGame === 'doom') {
      lbEmpty.hidden = false;
      lbEmpty.textContent = 'no scores in hell — rip and tear';
      return;
    }
    lbEmpty.innerHTML = 'No champions yet.<br>Set the first score.';
    var list = lastScores[activeGame] || [];
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
      stopDoom();
      stopPoker(true);
      bindCapture = null;
    }
    activeGame = name;
    gameTabs.forEach(function (t) { t.classList.toggle('is-active', t.dataset.game === name); });
    ['snake', 'tetris', 'mines', 'doom', 'poker', 'cookie'].forEach(function (g) {
      document.getElementById('stage-' + g).hidden = g !== name;
    });
    renderActiveLb();
    nudgePresence();
  }

  gameTabs.forEach(function (tab) {
    tab.addEventListener('click', function () { setActiveGame(tab.dataset.game); });
  });

  function enterGames() {
    gamesWho.textContent = myUsername || '—';
    loadCookieState();
    startCookieLoop();
    loadTetrisCfg();
    initPoker();
    if (!minesBuilt) newMines();
    fetchLeaderboard();
    refreshSpotifyStatus();
  }

  function leaveGames() {
    stopSnake(true);
    stopTetris(true);
    stopMines();
    stopDoom();
    stopPoker(true);
    submitScore('cookie', cookie.total);
    stopCookieLoop();
    stopSpotifyPolling();
  }

  var spotifyWindow = document.getElementById('spotify-window');
  var spotifyWindowHead = document.getElementById('spotify-window-head');
  var spotifyMaximizeBackdrop = document.getElementById('spotify-maximize-backdrop');
  var spotifyMaximizeBtn = document.getElementById('spotify-maximize-btn');
  var spotifyBodyDisabled = document.getElementById('spotify-body-disabled');
  var spotifyBodyDisconnected = document.getElementById('spotify-body-disconnected');
  var spotifyApp = document.getElementById('spotify-app');
  var spotifyConnectBtn = document.getElementById('spotify-connect-btn');
  var spotifyDisconnectBtn = document.getElementById('spotify-disconnect-btn');
  var spotifyAccountName = document.getElementById('spotify-account-name');
  var spotifyStatusMsg = document.getElementById('spotify-status-msg');

  // Nav
  var spotifyNavHome = document.getElementById('spotify-nav-home');
  var spotifyNavSearch = document.getElementById('spotify-nav-search');
  var spotifyNavLibraryToggle = document.getElementById('spotify-nav-library-toggle');
  var spotifyLibraryBody = document.getElementById('spotify-library-body');
  var spotifyPlaylistsStatus = document.getElementById('spotify-playlists-status');
  var spotifyPlaylistsListEl = document.getElementById('spotify-playlists-list');
  var spotifyPinnedListEl = document.getElementById('spotify-pinned-list');
  var spotifyReconnectEl = document.getElementById('spotify-reconnect');
  var spotifyReconnectText = document.getElementById('spotify-reconnect-text');
  var spotifyReconnectBtn = document.getElementById('spotify-reconnect-btn');

  // Search
  var spotifySearchBar = document.getElementById('spotify-search-bar');
  var spotifySearchForm = document.getElementById('spotify-search-form');
  var spotifySearchInput = document.getElementById('spotify-search-input');
  var spotifySearchStatus = document.getElementById('spotify-search-status');
  var spotifySearchTracksSection = document.getElementById('spotify-search-tracks-section');
  var spotifySearchTracksEl = document.getElementById('spotify-search-tracks');
  var spotifySearchArtistsSection = document.getElementById('spotify-search-artists-section');
  var spotifySearchArtistsEl = document.getElementById('spotify-search-artists');
  var spotifySearchAlbumsSection = document.getElementById('spotify-search-albums-section');
  var spotifySearchAlbumsEl = document.getElementById('spotify-search-albums');
  var spotifySearchPlaylistsSection = document.getElementById('spotify-search-playlists-section');
  var spotifySearchPlaylistsEl = document.getElementById('spotify-search-playlists');

  // Views
  var spotifyViews = {
    home: document.getElementById('spotify-view-home'),
    search: document.getElementById('spotify-view-search'),
    playlist: document.getElementById('spotify-view-playlist'),
    album: document.getElementById('spotify-view-album'),
    artist: document.getElementById('spotify-view-artist'),
  };
  var spotifyHomeEmpty = document.getElementById('spotify-home-empty');
  var spotifyHomeGrid = document.getElementById('spotify-home-grid');
  var spotifyHomeFeatured = document.getElementById('spotify-home-featured');
  var spotifyHomeCount = document.getElementById('spotify-home-count');

  // Playlist detail
  var spotifyPlaylistBackBtn = document.getElementById('spotify-playlist-back');
  var spotifyPlaylistArt = document.getElementById('spotify-playlist-art');
  var spotifyPlaylistArtPlaceholder = document.getElementById('spotify-playlist-art-placeholder');
  var spotifyPlaylistNameEl = document.getElementById('spotify-playlist-name');
  var spotifyPlaylistMetaEl = document.getElementById('spotify-playlist-meta');
  var spotifyPlaylistPlayAllBtn = document.getElementById('spotify-playlist-playall');
  var spotifyPlaylistTracksStatus = document.getElementById('spotify-playlist-tracks-status');
  var spotifyPlaylistTracksEl = document.getElementById('spotify-playlist-tracks');
  var spotifyLoadMoreBtn = document.getElementById('spotify-loadmore-btn');

  // Album detail
  var spotifyAlbumBackBtn = document.getElementById('spotify-album-back');
  var spotifyAlbumArt = document.getElementById('spotify-album-art');
  var spotifyAlbumArtPlaceholder = document.getElementById('spotify-album-art-placeholder');
  var spotifyAlbumNameEl = document.getElementById('spotify-album-name');
  var spotifyAlbumMetaEl = document.getElementById('spotify-album-meta');
  var spotifyAlbumPlayAllBtn = document.getElementById('spotify-album-playall');
  var spotifyAlbumTracksStatus = document.getElementById('spotify-album-tracks-status');
  var spotifyAlbumTracksEl = document.getElementById('spotify-album-tracks');

  // Artist detail
  var spotifyArtistBackBtn = document.getElementById('spotify-artist-back');
  var spotifyArtistArt = document.getElementById('spotify-artist-art');
  var spotifyArtistArtPlaceholder = document.getElementById('spotify-artist-art-placeholder');
  var spotifyArtistNameEl = document.getElementById('spotify-artist-name');
  var spotifyArtistMetaEl = document.getElementById('spotify-artist-meta');
  var spotifyArtistStatus = document.getElementById('spotify-artist-status');
  var spotifyArtistTopSection = document.getElementById('spotify-artist-top-section');
  var spotifyArtistTopTracksEl = document.getElementById('spotify-artist-top-tracks');
  var spotifyArtistAlbumsSection = document.getElementById('spotify-artist-albums-section');
  var spotifyArtistAlbumsEl = document.getElementById('spotify-artist-albums');
  var spotifyArtistSinglesSection = document.getElementById('spotify-artist-singles-section');
  var spotifyArtistSinglesEl = document.getElementById('spotify-artist-singles');
  var spotifyArtistPlayAllBtn = document.getElementById('spotify-artist-playall');

  // Player bar
  var spotifyNowplaying = document.getElementById('spotify-nowplaying');
  var spotifyArt = document.getElementById('spotify-art');
  var spotifyTrackName = document.getElementById('spotify-track-name');
  var spotifyTrackArtists = document.getElementById('spotify-track-artists');
  var spotifyNothingPlaying = document.getElementById('spotify-nothing-playing');
  var spotifyShuffleBtn = document.getElementById('spotify-shuffle');
  var spotifyPrevBtn = document.getElementById('spotify-prev');
  var spotifyToggleBtn = document.getElementById('spotify-toggle');
  var spotifyNextBtn = document.getElementById('spotify-next');
  var spotifyRepeatBtn = document.getElementById('spotify-repeat');
  var spotifyTimeElapsed = document.getElementById('spotify-time-elapsed');
  var spotifyTimeTotal = document.getElementById('spotify-time-total');
  var spotifyProgressTrack = document.getElementById('spotify-progress-track');
  var spotifyProgressFill = document.getElementById('spotify-progress-fill');
  var spotifyVolumeSlider = document.getElementById('spotify-volume-slider');
  var spotifyVolIcon = document.getElementById('spotify-vol-icon');

  var spotifyConnected = false;
  var spotifyPlaying = false;
  var spotifyNowTrack = null;
  var spotifyShuffleOn = false;
  var spotifyShuffleToggling = false;
  var spotifyRepeatMode = 'off';
  var spotifyRepeatToggling = false;
  var spotifyDjPlaying = false;
  var spotifyPollTimer = null;
  var spotifyProgressTimer = null;
  var spotifyProgressMs = 0;
  var spotifyDurationMs = 0;
  var spotifyProgressLastSync = 0;
  var spotifySearchDebounce = null;
  var spotifyVolumeDebounce = null;
  var spotifyDraggingVolume = false;

  var spotifySdkReady = false;
  var spotifyPlayer = null;
  var spotifyDeviceId = null;
  var spotifyPlayerInitStarted = false;

  var spotifyCurrentView = 'home';
  var spotifyPlaylistsLoaded = false;
  var spotifyCurrentPlaylist = null;
  var spotifyTracksNextOffset = null;
  var spotifyPlaylistTrackUris = [];
  var spotifyArtistTopUris = [];
  var spotifyCurrentAlbumId = null;
  var spotifyCurrentArtistId = null;

  function setSpotifyStatusMsg(msg) {
    if (!spotifyStatusMsg) return;
    spotifyStatusMsg.textContent = msg || '';
    spotifyStatusMsg.hidden = !msg;
  }

  function spotifyFormatDuration(ms) {
    var totalSec = Math.max(0, Math.floor((ms || 0) / 1000));
    var min = Math.floor(totalSec / 60);
    var sec = totalSec % 60;
    return min + ':' + (sec < 10 ? '0' : '') + sec;
  }

  async function refreshSpotifyStatus() {
    if (!spotifyWindow) return;
    try {
      var res = await fetch('/api/spotify/status', { credentials: 'same-origin' });
      if (!res.ok) return;
      var data = await res.json();
      var wasConnected = spotifyConnected;
      spotifyConnected = !!data.connected;
      spotifyBodyDisabled.hidden = !!data.enabled;
      spotifyBodyDisconnected.hidden = !data.enabled || spotifyConnected;
      spotifyApp.hidden = !spotifyConnected;
      if (spotifyMaximizeBtn) spotifyMaximizeBtn.hidden = !spotifyConnected;
      if (spotifyReconnectEl) {
        var needs = spotifyConnected && data.needsReconnect;
        spotifyReconnectEl.hidden = !needs;
        if (needs && spotifyReconnectText) {
          spotifyReconnectText.textContent = 'This connection predates a permission the player now needs. Reconnect to finish setting it up.';
        }
      }
      if (!spotifyConnected && data.error) setSpotifyStatusMsg(data.error);
      if (spotifyConnected) {
        spotifyAccountName.textContent = data.displayName ? 'Connected as ' + data.displayName : 'Connected';
        startSpotifyPolling();
        refreshNowPlaying();
        initSpotifyPlayer();
        // A fresh connection (including reconnecting after a disconnect)
        // starts browsing from scratch — old playlist/search data belonged
        // to whatever was connected before.
        if (!wasConnected) resetSpotifyBrowsing();
      } else {
        stopSpotifyPolling();
        disconnectSpotifyPlayer();
        if (spotifyWindow.classList.contains('is-maximized')) spotifyRestore();
      }
    } catch (e) { /* transient — tries again next time the games view opens */ }
  }

  function resetSpotifyBrowsing() {
    spotifyPlaylistsLoaded = false;
    spotifyCurrentPlaylist = null;
    spotifyTracksNextOffset = null;
    spotifyCurrentAlbumId = null;
    spotifyCurrentArtistId = null;
    spotifyShuffleOn = false;
    if (spotifyShuffleBtn) spotifyShuffleBtn.setAttribute('aria-pressed', 'false');
    if (spotifyPlaylistsListEl) { spotifyPlaylistsListEl.innerHTML = ''; spotifyPlaylistsListEl.hidden = true; }
    if (spotifyPinnedListEl) { spotifyPinnedListEl.innerHTML = ''; spotifyPinnedListEl.hidden = true; }
    if (spotifyHomeGrid) spotifyHomeGrid.innerHTML = '';
    if (spotifyHomeFeatured) spotifyHomeFeatured.innerHTML = '';
    spotifyRepeatMode = 'off';
    setRepeatUi('off');
    if (spotifySearchInput) spotifySearchInput.value = '';
    spotifyClearSearchResults();
    setSpotifySearchStatus('Search for a song, artist, album, or playlist.');
    spotifyViewHistory.length = 0;
    spotifySwitchView('home');
    loadSpotifyPlaylists();
  }

  function startSpotifyPolling() {
    if (spotifyPollTimer) return;
    spotifyPollTimer = setInterval(refreshNowPlaying, 6000);
    if (!spotifyProgressTimer) spotifyProgressTimer = setInterval(spotifyTickProgress, 1000);
  }
  function stopSpotifyPolling() {
    if (spotifyPollTimer) { clearInterval(spotifyPollTimer); spotifyPollTimer = null; }
    if (spotifyProgressTimer) { clearInterval(spotifyProgressTimer); spotifyProgressTimer = null; }
  }

  function spotifyTickProgress() {
    if (!spotifyPlaying || !spotifyDurationMs) return;
    spotifyProgressMs = Math.min(spotifyDurationMs, spotifyProgressMs + 1000);
    spotifyRenderProgress();
  }

  function spotifyRenderProgress() {
    if (spotifyTimeElapsed) spotifyTimeElapsed.textContent = spotifyFormatDuration(spotifyProgressMs);
    if (spotifyTimeTotal) spotifyTimeTotal.textContent = spotifyFormatDuration(spotifyDurationMs);
    var pct = spotifyDurationMs ? Math.min(100, (spotifyProgressMs / spotifyDurationMs) * 100) : 0;
    if (spotifyProgressFill) spotifyProgressFill.style.width = pct + '%';
    if (spotifyProgressTrack) spotifyProgressTrack.setAttribute('aria-valuenow', String(Math.round(pct)));
  }

  async function refreshNowPlaying() {
    if (!spotifyConnected) return;
    try {
      var res = await fetch('/api/spotify/now-playing', { credentials: 'same-origin' });
      if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); return; }
      if (!res.ok) return;
      var data = await res.json();
      var wasPlaying = spotifyPlaying;
      var wasTrack = spotifyNowTrack ? spotifyNowTrack.name : null;
      spotifyPlaying = !!data.playing;
      spotifyToggleBtn.textContent = spotifyPlaying ? '⏸' : '▶';
      spotifyToggleBtn.setAttribute('aria-label', spotifyPlaying ? 'Pause' : 'Play');
      spotifyDjPlaying = !!data.isDj;
      if (data.track) {
        spotifyNowTrack = data.track;
        spotifyNowplaying.hidden = false;
        spotifyNothingPlaying.hidden = true;
        spotifyTrackName.textContent = data.track.name || '';
        renderNowPlayingArtists(data.track, data.isDj);
        if (data.track.albumArt) {
          spotifyArt.src = data.track.albumArt;
          spotifyArt.hidden = false;
        } else {
          spotifyArt.hidden = true;
        }
        spotifyDurationMs = data.track.durationMs || 0;
        spotifyProgressMs = data.progressMs || 0;
      } else {
        spotifyNowTrack = null;
        spotifyNowplaying.hidden = true;
        spotifyNothingPlaying.hidden = false;
        spotifyDurationMs = 0;
        spotifyProgressMs = 0;
      }
      if (typeof data.repeat === 'string' && !spotifyRepeatToggling) setRepeatUi(data.repeat);
      markDjRow();
      if (wasPlaying !== spotifyPlaying || wasTrack !== (spotifyNowTrack ? spotifyNowTrack.name : null)) {
        nudgePresence();
      }
      spotifyRenderProgress();
      if (typeof data.volumePercent === 'number' && !spotifyDraggingVolume && spotifyVolumeSlider) {
        spotifyVolumeSlider.value = String(data.volumePercent);
        spotifyUpdateVolumeIcon(data.volumePercent);
      }
      // Mirrors Spotify's own shuffle state (it can be turned on/off from
      // any of the user's devices, not just this tab), unless a click here
      // just changed it and that request hasn't resolved yet.
      if (typeof data.shuffle === 'boolean' && !spotifyShuffleToggling && spotifyShuffleBtn) {
        spotifyShuffleOn = data.shuffle;
        spotifyShuffleBtn.setAttribute('aria-pressed', spotifyShuffleOn ? 'true' : 'false');
      }
    } catch (e) { /* transient — next poll picks it back up */ }
  }

  function renderNowPlayingArtists(track, isDj) {
    if (!spotifyTrackArtists) return;
    spotifyTrackArtists.innerHTML = '';
    if (isDj) {
      var badge = document.createElement('span');
      badge.className = 'spotify-dj-badge';
      badge.textContent = 'DJ';
      spotifyTrackArtists.appendChild(badge);
    }
    var list = (track && track.artistList) || [];
    if (!list.length) {
      spotifyTrackArtists.appendChild(document.createTextNode((track && track.artists) || ''));
      return;
    }
    list.forEach(function (a, i) {
      if (i) spotifyTrackArtists.appendChild(document.createTextNode(', '));
      if (a.id) {
        var link = document.createElement('button');
        link.type = 'button';
        link.className = 'spotify-artist-link';
        link.textContent = a.name;
        link.addEventListener('click', function () { openSpotifyArtist(a.id); });
        spotifyTrackArtists.appendChild(link);
      } else {
        spotifyTrackArtists.appendChild(document.createTextNode(a.name));
      }
    });
  }

  var REPEAT_UI = {
    off: { icon: '🔁', label: 'Repeat off', pressed: 'false' },
    context: { icon: '🔁', label: 'Repeating this playlist', pressed: 'true' },
    track: { icon: '🔂', label: 'Repeating this song', pressed: 'true' },
  };

  function setRepeatUi(mode) {
    spotifyRepeatMode = REPEAT_UI[mode] ? mode : 'off';
    if (!spotifyRepeatBtn) return;
    var ui = REPEAT_UI[spotifyRepeatMode];
    spotifyRepeatBtn.textContent = ui.icon;
    spotifyRepeatBtn.title = ui.label;
    spotifyRepeatBtn.setAttribute('aria-label', ui.label);
    spotifyRepeatBtn.setAttribute('aria-pressed', ui.pressed);
    spotifyRepeatBtn.dataset.mode = spotifyRepeatMode;
  }

  if (spotifyRepeatBtn) {
    spotifyRepeatBtn.addEventListener('click', async function () {
      // Same cycle as Spotify's own button: off, whole playlist, one song.
      var order = ['off', 'context', 'track'];
      var next = order[(order.indexOf(spotifyRepeatMode) + 1) % order.length];
      var previous = spotifyRepeatMode;
      setRepeatUi(next);
      spotifyRepeatToggling = true;
      setSpotifyStatusMsg('');
      try {
        var res = await fetch('/api/spotify/repeat', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
          body: JSON.stringify(spotifyDeviceId ? { state: next, deviceId: spotifyDeviceId } : { state: next }),
        });
        var data = await res.json().catch(function () { return {}; });
        if (!res.ok) {
          setRepeatUi(previous);
          setSpotifyStatusMsg(data.error || 'Could not change repeat.');
          if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
        }
      } catch (e) {
        setRepeatUi(previous);
        setSpotifyStatusMsg('Could not reach Spotify.');
      }
      spotifyRepeatToggling = false;
    });
  }

  if (spotifyReconnectBtn) {
    spotifyReconnectBtn.addEventListener('click', function () {
      setSpotifyStatusMsg('');
      openSpotifyPopup();
    });
  }

  function markDjRow() {
    var rows = document.querySelectorAll('[data-spotify-dj]');
    Array.prototype.forEach.call(rows, function (el) {
      el.classList.toggle('is-playing', spotifyDjPlaying && spotifyPlaying);
    });
  }

  window.onSpotifyWebPlaybackSDKReady = function () {
    spotifySdkReady = true;
    if (spotifyConnected) initSpotifyPlayer();
  };

  function initSpotifyPlayer() {
    if (spotifyPlayerInitStarted) return;
    if (!spotifySdkReady || typeof Spotify === 'undefined' || !Spotify.Player) return;
    spotifyPlayerInitStarted = true;

    spotifyPlayer = new Spotify.Player({
      name: 'Soul Studies',
      getOAuthToken: function (cb) {
        fetch('/api/spotify/player-token', { credentials: 'same-origin' })
          .then(function (res) { if (!res.ok) throw new Error('token fetch failed'); return res.json(); })
          .then(function (data) { cb(data.accessToken); })
          .catch(function () { /* the SDK calls this again on its own retry cycle */ });
      },
      volume: 0.5,
    });

    spotifyPlayer.addListener('ready', function (data) {
      spotifyDeviceId = (data && data.device_id) || null;
    });
    spotifyPlayer.addListener('not_ready', function () {
      spotifyDeviceId = null;
    });
    spotifyPlayer.addListener('initialization_error', function (data) {
      console.error('[spotify player] initialization_error', data && data.message);
    });
    spotifyPlayer.addListener('authentication_error', function (data) {
      console.error('[spotify player] authentication_error', data && data.message);
    });
    spotifyPlayer.addListener('account_error', function (data) {
      // The SDK reports both 'not Premium' and 'not approved for this app' here.
      console.error('[spotify player] account_error', data && data.message);
      setSpotifyStatusMsg('In-browser playback unavailable for this account (needs Spotify Premium, and the account must be approved for this app) — controlling your other active device instead.');
    });
    spotifyPlayer.addListener('playback_error', function (data) {
      console.error('[spotify player] playback_error', data && data.message);
    });
    spotifyPlayer.addListener('player_state_changed', function (state) {
      if (!state) return;
      spotifyPlaying = !state.paused;
      if (spotifyToggleBtn) {
        spotifyToggleBtn.textContent = spotifyPlaying ? '⏸' : '▶';
        spotifyToggleBtn.setAttribute('aria-label', spotifyPlaying ? 'Pause' : 'Play');
      }
      spotifyDurationMs = state.duration || 0;
      spotifyProgressMs = state.position || 0;
      var track = state.track_window && state.track_window.current_track;
      if (track && spotifyNowplaying && spotifyNothingPlaying) {
        var artistList = (Array.isArray(track.artists) ? track.artists : []).map(function (a) {
          return { id: (a.uri || '').replace('spotify:artist:', '') || null, name: a.name || '' };
        });
        spotifyNowTrack = {
          name: track.name || '',
          artists: artistList.map(function (a) { return a.name; }).join(', '),
          artistList: artistList,
        };
        spotifyNowplaying.hidden = false;
        spotifyNothingPlaying.hidden = true;
        if (spotifyTrackName) spotifyTrackName.textContent = track.name || '';
        renderNowPlayingArtists(spotifyNowTrack, spotifyDjPlaying);
        var art = track.album && Array.isArray(track.album.images) && track.album.images[0] && track.album.images[0].url;
        if (spotifyArt) {
          if (art) { spotifyArt.src = art; spotifyArt.hidden = false; } else { spotifyArt.hidden = true; }
        }
      }
      if (typeof state.repeat_mode === 'number' && !spotifyRepeatToggling) {
        setRepeatUi(['off', 'context', 'track'][state.repeat_mode] || 'off');
      }
      spotifyRenderProgress();
      nudgePresence();
    });

    spotifyPlayer.connect();
  }

  function disconnectSpotifyPlayer() {
    if (spotifyPlayer) { try { spotifyPlayer.disconnect(); } catch (e) { /* already gone */ } }
    spotifyPlayer = null;
    spotifyDeviceId = null;
    spotifyPlayerInitStarted = false;
  }

  var spotifyPopupWatch = null;

  function openSpotifyPopup() {
    var w = 420, h = 720;
    var left = window.screenX + Math.max(0, (window.outerWidth - w) / 2);
    var top = window.screenY + Math.max(0, (window.outerHeight - h) / 2);
    var popup = window.open('/api/spotify/login', 'spotify-connect', 'width=' + w + ',height=' + h + ',left=' + left + ',top=' + top);
    if (!popup) {
      // Popup blocked — fall back to a normal top-level navigation; the
      // return trip is picked up by handleSpotifyRedirectParam() below.
      window.location.href = '/api/spotify/login';
      return;
    }
    setSpotifyStatusMsg('Finish connecting in the Spotify window…');
    // If the postMessage never lands, fall back to asking the server.
    if (spotifyPopupWatch) clearInterval(spotifyPopupWatch);
    spotifyPopupWatch = setInterval(function () {
      if (!popup.closed) return;
      clearInterval(spotifyPopupWatch);
      spotifyPopupWatch = null;
      setSpotifyStatusMsg('');
      refreshSpotifyStatus();
    }, 700);
  }

  if (spotifyConnectBtn) {
    spotifyConnectBtn.addEventListener('click', function () {
      setSpotifyStatusMsg('');
      openSpotifyPopup();
    });
  }

  if (spotifyDisconnectBtn) {
    spotifyDisconnectBtn.addEventListener('click', async function () {
      try {
        await fetch('/api/spotify/disconnect', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        });
      } catch (e) { /* falls back to whatever refreshSpotifyStatus() reports next */ }
      spotifyConnected = false;
      stopSpotifyPolling();
      disconnectSpotifyPlayer();
      refreshSpotifyStatus();
    });
  }

  var spotifyDockParent = null;
  var spotifyDockNextSibling = null;

  function spotifyMaximize() {
    if (!spotifyWindow || spotifyWindow.classList.contains('is-maximized')) return;
    spotifyDockParent = spotifyWindow.parentNode;
    spotifyDockNextSibling = spotifyWindow.nextSibling;
    document.body.appendChild(spotifyMaximizeBackdrop);
    document.body.appendChild(spotifyWindow);
    spotifyMaximizeBackdrop.hidden = false;
    spotifyWindow.classList.add('is-maximized');
    if (spotifyMaximizeBtn) {
      spotifyMaximizeBtn.setAttribute('aria-pressed', 'true');
      spotifyMaximizeBtn.setAttribute('aria-label', 'Restore Spotify window');
    }
    document.addEventListener('keydown', spotifyMaximizeKeydown);
  }

  function spotifyRestore() {
    if (!spotifyWindow || !spotifyWindow.classList.contains('is-maximized')) return;
    spotifyWindow.classList.remove('is-maximized');
    spotifyMaximizeBackdrop.hidden = true;
    if (spotifyDockParent) {
      spotifyDockParent.insertBefore(spotifyWindow, spotifyDockNextSibling);
      spotifyDockParent.insertBefore(spotifyMaximizeBackdrop, spotifyWindow);
    }
    if (spotifyMaximizeBtn) {
      spotifyMaximizeBtn.setAttribute('aria-pressed', 'false');
      spotifyMaximizeBtn.setAttribute('aria-label', 'Maximize Spotify window');
    }
    document.removeEventListener('keydown', spotifyMaximizeKeydown);
  }

  function spotifyMaximizeKeydown(e) {
    if (e.key === 'Escape') spotifyRestore();
  }

  if (spotifyMaximizeBtn) {
    spotifyMaximizeBtn.addEventListener('click', function () {
      if (spotifyWindow.classList.contains('is-maximized')) spotifyRestore();
      else spotifyMaximize();
    });
  }
  if (spotifyMaximizeBackdrop) {
    spotifyMaximizeBackdrop.addEventListener('click', spotifyRestore);
  }

  // ---------------------------------------------------------------------
  // Transport, seek, and volume
  // ---------------------------------------------------------------------

  async function spotifyTransport(action, errorFallback) {
    setSpotifyStatusMsg('');
    try {
      var res = await fetch('/api/spotify/' + action, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        // Once the in-page player is ready, target it directly so play/
        // pause/skip actually control audio in this tab instead of
        // whatever device Spotify last considered active elsewhere.
        body: JSON.stringify(spotifyDeviceId ? { deviceId: spotifyDeviceId } : {}),
      });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) {
        setSpotifyStatusMsg(data.error || errorFallback);
        if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
        return;
      }
      setTimeout(refreshNowPlaying, 400);
    } catch (e) {
      setSpotifyStatusMsg(errorFallback);
    }
  }

  if (spotifyToggleBtn) {
    spotifyToggleBtn.addEventListener('click', function () {
      spotifyTransport(spotifyPlaying ? 'pause' : 'play', 'Could not reach Spotify.');
    });
  }
  if (spotifyPrevBtn) {
    spotifyPrevBtn.addEventListener('click', function () { spotifyTransport('previous', 'Could not go back.'); });
  }
  if (spotifyNextBtn) {
    spotifyNextBtn.addEventListener('click', function () { spotifyTransport('next', 'Could not skip.'); });
  }

  if (spotifyShuffleBtn) {
    spotifyShuffleBtn.addEventListener('click', async function () {
      var next = !spotifyShuffleOn;
      spotifyShuffleOn = next;
      spotifyShuffleToggling = true;
      spotifyShuffleBtn.setAttribute('aria-pressed', next ? 'true' : 'false');
      setSpotifyStatusMsg('');
      try {
        var res = await fetch('/api/spotify/shuffle', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
          body: JSON.stringify(spotifyDeviceId ? { state: next, deviceId: spotifyDeviceId } : { state: next }),
        });
        var data = await res.json().catch(function () { return {}; });
        if (!res.ok) {
          // Revert the optimistic toggle — Spotify didn't actually apply it.
          spotifyShuffleOn = !next;
          spotifyShuffleBtn.setAttribute('aria-pressed', spotifyShuffleOn ? 'true' : 'false');
          setSpotifyStatusMsg(data.error || 'Could not change shuffle.');
          if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
        }
      } catch (e) {
        spotifyShuffleOn = !next;
        spotifyShuffleBtn.setAttribute('aria-pressed', spotifyShuffleOn ? 'true' : 'false');
        setSpotifyStatusMsg('Could not reach Spotify.');
      }
      spotifyShuffleToggling = false;
    });
  }

  if (spotifyProgressTrack) {
    spotifyProgressTrack.addEventListener('click', async function (e) {
      if (!spotifyDurationMs || !spotifyPlaying) return;
      var rect = spotifyProgressTrack.getBoundingClientRect();
      var ratio = rect.width ? Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width)) : 0;
      var positionMs = Math.round(ratio * spotifyDurationMs);
      spotifyProgressMs = positionMs;
      spotifyRenderProgress();
      try {
        var res = await fetch('/api/spotify/seek', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
          body: JSON.stringify(spotifyDeviceId ? { positionMs: positionMs, deviceId: spotifyDeviceId } : { positionMs: positionMs }),
        });
        var data = await res.json().catch(function () { return {}; });
        if (!res.ok) {
          setSpotifyStatusMsg(data.error || 'Could not seek.');
          if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
        }
      } catch (e) { setSpotifyStatusMsg('Could not reach Spotify.'); }
    });
  }

  function spotifyUpdateVolumeIcon(percent) {
    if (!spotifyVolIcon) return;
    spotifyVolIcon.textContent = percent <= 0 ? '🔇' : (percent < 50 ? '🔉' : '🔊');
  }

  if (spotifyVolumeSlider) {
    spotifyVolumeSlider.addEventListener('input', function () {
      spotifyDraggingVolume = true;
      var percent = Number(spotifyVolumeSlider.value);
      spotifyUpdateVolumeIcon(percent);
      if (spotifyVolumeDebounce) clearTimeout(spotifyVolumeDebounce);
      spotifyVolumeDebounce = setTimeout(async function () {
        try {
          var res = await fetch('/api/spotify/volume', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            body: JSON.stringify(spotifyDeviceId ? { percent: percent, deviceId: spotifyDeviceId } : { percent: percent }),
          });
          var data = await res.json().catch(function () { return {}; });
          if (!res.ok) {
            setSpotifyStatusMsg(data.error || 'Could not change the volume.');
            if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
          }
        } catch (e) { setSpotifyStatusMsg('Could not reach Spotify.'); }
        spotifyDraggingVolume = false;
      }, 300);
    });
  }

  async function playSpotify(body) {
    setSpotifyStatusMsg('');
    if (spotifyDeviceId) {
      var bodyWithDevice = {};
      for (var k in body) { if (Object.prototype.hasOwnProperty.call(body, k)) bodyWithDevice[k] = body[k]; }
      bodyWithDevice.deviceId = spotifyDeviceId;
      body = bodyWithDevice;
    }
    try {
      var res = await fetch('/api/spotify/play', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify(body),
      });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) {
        setSpotifyStatusMsg(data.error || 'Could not play that.');
        if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
        return;
      }
      setTimeout(refreshNowPlaying, 400);
    } catch (e) {
      setSpotifyStatusMsg('Could not reach Spotify.');
    }
  }
  function playSpotifyTrack(uri) { playSpotify({ uri: uri }); }
  // Liked Songs and artist top tracks have no context of their own, so they
  // go over as an explicit list; without this they stop after one song.
  function playSpotifyUris(uris, startUri) {
    playSpotify(startUri ? { uris: uris, offsetUri: startUri } : { uris: uris });
  }
  function playSpotifyContext(contextUri) { playSpotify({ contextUri: contextUri }); }
  function playSpotifyContextTrack(contextUri, offsetUri) { playSpotify({ contextUri: contextUri, offsetUri: offsetUri }); }

  var spotifyQueueMsgTimer = null;
  async function spotifyQueueTrack(uri) {
    setSpotifyStatusMsg('');
    if (spotifyQueueMsgTimer) { clearTimeout(spotifyQueueMsgTimer); spotifyQueueMsgTimer = null; }
    try {
      var res = await fetch('/api/spotify/queue', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify(spotifyDeviceId ? { uri: uri, deviceId: spotifyDeviceId } : { uri: uri }),
      });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) {
        setSpotifyStatusMsg(data.error || 'Could not add that to the queue.');
        if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
        return;
      }
      setSpotifyStatusMsg('Added to queue.');
      spotifyQueueMsgTimer = setTimeout(function () { setSpotifyStatusMsg(''); }, 2500);
    } catch (e) {
      setSpotifyStatusMsg('Could not reach Spotify.');
    }
  }

  function fillArtistLinks(container, track) {
    container.innerHTML = '';
    var list = (track && track.artistList) || [];
    if (!list.length) {
      container.textContent = (track && track.artists) || '';
      return;
    }
    list.forEach(function (a, i) {
      if (i) container.appendChild(document.createTextNode(', '));
      if (a.id) {
        var link = document.createElement('button');
        link.type = 'button';
        link.className = 'spotify-artist-link';
        link.textContent = a.name;
        link.addEventListener('click', function (e) { e.stopPropagation(); openSpotifyArtist(a.id); });
        container.appendChild(link);
      } else {
        container.appendChild(document.createTextNode(a.name));
      }
    });
  }

  // A numbered track row for a table (playlist/album/artist top tracks/
  // search songs): index, small art, name+artist, optional album, duration.
  function buildTrackTableRow(track, index, onPlay, onQueue) {
    var li = document.createElement('li');
    // A div, not a button: the artist and album names inside it are their own
    // controls, and a button cannot legally contain other buttons.
    var btn = document.createElement('div');
    btn.className = 'spotify-track-row';
    btn.setAttribute('role', 'button');
    btn.tabIndex = 0;
    btn.setAttribute('aria-label', 'Play ' + (track.name || 'track') + (track.artists ? ' by ' + track.artists : ''));

    var idx = document.createElement('span');
    idx.className = 'spotify-track-idx';
    idx.textContent = String(index);

    var main = document.createElement('span');
    main.className = 'spotify-track-row-main';
    var img;
    if (track.albumArt) {
      img = document.createElement('img');
      img.className = 'spotify-track-row-art';
      img.alt = '';
      img.loading = 'lazy';
      img.src = track.albumArt;
    } else {
      img = document.createElement('span');
      img.className = 'spotify-track-row-art spotify-row-art-glyph';
      img.setAttribute('aria-hidden', 'true');
      img.textContent = '♪';
    }
    var info = document.createElement('span');
    info.className = 'spotify-track-row-info';
    var name = document.createElement('span');
    name.className = 'spotify-track-row-name';
    name.textContent = track.name || '';
    var artist = document.createElement('span');
    artist.className = 'spotify-track-row-artist';
    fillArtistLinks(artist, track);
    info.appendChild(name);
    info.appendChild(artist);
    main.appendChild(img);
    main.appendChild(info);

    var album = document.createElement('span');
    album.className = 'spotify-track-row-album';
    if (track.albumId) {
      var albumLink = document.createElement('button');
      albumLink.type = 'button';
      albumLink.className = 'spotify-artist-link';
      albumLink.textContent = track.album || '';
      albumLink.addEventListener('click', function (e) { e.stopPropagation(); openSpotifyAlbum(track.albumId); });
      album.appendChild(albumLink);
    } else {
      album.textContent = track.album || '';
    }

    var duration = document.createElement('span');
    duration.className = 'spotify-track-row-duration';
    duration.textContent = spotifyFormatDuration(track.durationMs);

    btn.appendChild(idx);
    btn.appendChild(main);
    btn.appendChild(album);
    btn.appendChild(duration);
    btn.addEventListener('click', function () { onPlay(track); });
    btn.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onPlay(track); }
    });
    li.appendChild(btn);

    if (onQueue) {
      var queueBtn = document.createElement('button');
      queueBtn.type = 'button';
      queueBtn.className = 'spotify-track-queue-btn';
      queueBtn.setAttribute('aria-label', 'Add ' + (track.name || 'track') + ' to queue');
      queueBtn.title = 'Add to queue';
      queueBtn.textContent = '+';
      queueBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        onQueue(track);
      });
      li.appendChild(queueBtn);
    }
    return li;
  }

  // null means "Spotify didn't say", which is not the same as an empty
  // playlist — saying "0 songs" there is what made every playlist look empty.
  function trackCountLabel(count) {
    if (typeof count !== 'number') return '';
    return count === 1 ? '1 song' : count + ' songs';
  }

  // Small sidebar-style row, reused for the "Your Library" playlist list.
  function buildPlaylistNavRow(playlist, onOpen) {
    var li = document.createElement('li');
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'spotify-row-btn';
    btn.setAttribute('aria-label', 'Open playlist ' + (playlist.name || ''));
    var art;
    if (playlist.image) {
      art = document.createElement('img');
      art.className = 'spotify-row-art';
      art.alt = '';
      art.loading = 'lazy';
      art.src = playlist.image;
    } else {
      art = document.createElement('span');
      art.className = 'spotify-row-art spotify-row-art-glyph';
      art.setAttribute('aria-hidden', 'true');
      art.textContent = playlist.kind === 'dj' ? '🎧' : (playlist.kind === 'liked' ? '♥' : '♪');
    }
    var info = document.createElement('div');
    info.className = 'spotify-row-info';
    var name = document.createElement('span');
    name.className = 'spotify-row-name';
    name.textContent = playlist.name || '';
    var sub = document.createElement('span');
    sub.className = 'spotify-row-sub';
    var count = trackCountLabel(playlist.trackCount);
    var owner = playlist.kind === 'liked' ? '' : playlist.owner;
    sub.textContent = [owner, count].filter(Boolean).join(' · ') || 'Playlist';
    info.appendChild(name);
    info.appendChild(sub);
    var chevron = document.createElement('span');
    chevron.className = 'spotify-row-play-icon';
    chevron.setAttribute('aria-hidden', 'true');
    chevron.textContent = '›';
    btn.appendChild(art);
    btn.appendChild(info);
    btn.appendChild(chevron);
    btn.addEventListener('click', function () { onOpen(playlist); });
    li.appendChild(btn);
    return li;
  }

  // Card for the Home grid and for artist/album/playlist search results.
  // `kind` picks the label shown as the subtitle when no better one is
  // given, and `round` draws circular artwork (used for artists).
  function buildCard(opts) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'spotify-card';
    btn.setAttribute('aria-label', opts.label || opts.name || '');
    if (opts.image) {
      var img = document.createElement('img');
      img.className = 'spotify-card-art';
      img.alt = '';
      img.loading = 'lazy';
      img.src = opts.image;
      btn.appendChild(img);
    } else {
      var placeholder = document.createElement('span');
      placeholder.className = 'spotify-card-art-placeholder';
      placeholder.setAttribute('aria-hidden', 'true');
      placeholder.textContent = opts.glyph || '♪';
      btn.appendChild(placeholder);
    }
    var name = document.createElement('span');
    name.className = 'spotify-card-name';
    name.textContent = opts.name || '';
    btn.appendChild(name);
    if (opts.sub) {
      var sub = document.createElement('span');
      sub.className = 'spotify-card-sub';
      sub.textContent = opts.sub;
      btn.appendChild(sub);
    }
    btn.addEventListener('click', opts.onClick);
    return btn;
  }

  function setSpotifySearchStatus(msg) {
    if (!spotifySearchStatus) return;
    spotifySearchStatus.textContent = msg || '';
    spotifySearchStatus.hidden = !msg;
  }

  function setSpotifyPlaylistsStatus(msg) {
    if (!spotifyPlaylistsStatus) return;
    spotifyPlaylistsStatus.textContent = msg || '';
    spotifyPlaylistsStatus.hidden = !msg;
  }

  // ---------------------------------------------------------------------
  // View navigation — one view visible at a time inside .spotify-main.
  // ---------------------------------------------------------------------

  var spotifyViewHistory = [];
  function spotifySwitchView(name, isBack) {
    if (!isBack && name !== spotifyCurrentView) {
      spotifyViewHistory.push(spotifyCurrentView);
      if (spotifyViewHistory.length > 20) spotifyViewHistory.shift();
    }
    spotifyCurrentView = name;
    Object.keys(spotifyViews).forEach(function (key) {
      if (spotifyViews[key]) spotifyViews[key].hidden = key !== name;
    });
    spotifySearchBar.hidden = name !== 'search';
    spotifyNavHome.classList.toggle('is-active', name === 'home');
    spotifyNavSearch.classList.toggle('is-active', name === 'search');
    if (spotifyMain) spotifyMain.scrollTop = 0;
  }
  function spotifyGoBack() { spotifySwitchView(spotifyViewHistory.pop() || 'home', true); }
  var spotifyMain = document.getElementById('spotify-main');

  if (spotifyNavHome) spotifyNavHome.addEventListener('click', function () { spotifySwitchView('home'); });
  if (spotifyNavSearch) {
    spotifyNavSearch.addEventListener('click', function () {
      spotifySwitchView('search');
      if (spotifySearchInput) spotifySearchInput.focus();
    });
  }
  if (spotifyNavLibraryToggle) {
    spotifyNavLibraryToggle.addEventListener('click', function () {
      var open = spotifyLibraryBody.classList.toggle('is-open');
      spotifyNavLibraryToggle.setAttribute('aria-expanded', String(open));
    });
  }

  async function loadSpotifyPlaylists() {
    spotifyPlaylistsListEl.innerHTML = '';
    spotifyPinnedListEl.innerHTML = '';
    spotifyPinnedListEl.hidden = true;
    spotifyHomeGrid.innerHTML = '';
    spotifyHomeFeatured.innerHTML = '';
    if (spotifyHomeCount) spotifyHomeCount.hidden = true;
    setSpotifyPlaylistsStatus('Loading playlists…');
    try {
      var res = await fetch('/api/spotify/playlists', { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return {}; });
      spotifyPlaylistsLoaded = true;
      if (!res.ok) {
        setSpotifyPlaylistsStatus(data.error || 'Could not load playlists.');
        if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
        return;
      }

      var pinned = [];
      if (data.dj) pinned.push(data.dj);
      if (data.liked) pinned.push(data.liked);
      pinned.forEach(function (entry) {
        var row = buildPlaylistNavRow(entry, openSpotifyPlaylist);
        if (entry.kind === 'dj') row.firstChild.setAttribute('data-spotify-dj', '1');
        spotifyPinnedListEl.appendChild(row);
        spotifyHomeFeatured.appendChild(buildCard({
          name: entry.name,
          image: entry.image,
          glyph: entry.kind === 'dj' ? '🎧' : '♥',
          sub: entry.kind === 'dj' ? 'Made for you by Spotify' : trackCountLabel(entry.trackCount),
          label: 'Open ' + entry.name,
          onClick: function () { openSpotifyPlaylist(entry); },
        }));
      });
      spotifyPinnedListEl.hidden = pinned.length === 0;
      markDjRow();

      var playlists = data.playlists || [];
      if (!playlists.length) {
        setSpotifyPlaylistsStatus('No playlists found on this account.');
        spotifyHomeEmpty.hidden = false;
        spotifyPlaylistsListEl.hidden = true;
        return;
      }
      setSpotifyPlaylistsStatus('');
      spotifyHomeEmpty.hidden = true;
      playlists.forEach(function (pl) {
        spotifyPlaylistsListEl.appendChild(buildPlaylistNavRow(pl, openSpotifyPlaylist));
        spotifyHomeGrid.appendChild(buildCard({
          name: pl.name, image: pl.image,
          sub: trackCountLabel(pl.trackCount) || pl.owner || 'Playlist',
          label: 'Open playlist ' + (pl.name || ''),
          onClick: function () { openSpotifyPlaylist(pl); },
        }));
      });
      spotifyPlaylistsListEl.hidden = false;
      if (spotifyHomeCount) {
        spotifyHomeCount.textContent = playlists.length + (playlists.length === 1 ? ' playlist' : ' playlists') +
          (data.truncated ? ' (showing the first 600)' : '');
        spotifyHomeCount.hidden = false;
      }
    } catch (e) {
      setSpotifyPlaylistsStatus('Could not reach Spotify — try again.');
    }
  }

  function spotifyClearSearchResults() {
    [spotifySearchTracksEl, spotifySearchArtistsEl, spotifySearchAlbumsEl, spotifySearchPlaylistsEl].forEach(function (el) { if (el) el.innerHTML = ''; });
    [spotifySearchTracksSection, spotifySearchArtistsSection, spotifySearchAlbumsSection, spotifySearchPlaylistsSection].forEach(function (el) { if (el) el.hidden = true; });
  }

  async function runSpotifySearch(q) {
    spotifyClearSearchResults();
    if (!q) {
      setSpotifySearchStatus('Search for a song, artist, album, or playlist.');
      return;
    }
    setSpotifySearchStatus('Searching…');
    try {
      var res = await fetch('/api/spotify/search?q=' + encodeURIComponent(q), { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) {
        if (res.status === 429) { setSpotifySearchStatus(data.error || 'Too many searches — slow down a little.'); return; }
        setSpotifySearchStatus(data.error || 'Search failed — try again.');
        if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
        return;
      }
      var tracks = data.tracks || [], artists = data.artists || [], albums = data.albums || [], playlists = data.playlists || [];
      if (!tracks.length && !artists.length && !albums.length && !playlists.length) {
        setSpotifySearchStatus('No results for "' + q + '".');
        return;
      }
      setSpotifySearchStatus('');
      if (tracks.length) {
        tracks.forEach(function (t, i) { spotifySearchTracksEl.appendChild(buildTrackTableRow(t, i + 1, function (tt) { playSpotifyTrack(tt.uri); }, function (tt) { spotifyQueueTrack(tt.uri); })); });
        spotifySearchTracksSection.hidden = false;
      }
      if (artists.length) {
        artists.forEach(function (a) { spotifySearchArtistsEl.appendChild(buildCard({ name: a.name, image: a.image, sub: 'Artist', onClick: function () { openSpotifyArtist(a.id); } })); });
        spotifySearchArtistsSection.hidden = false;
      }
      if (albums.length) {
        albums.forEach(function (al) { spotifySearchAlbumsEl.appendChild(buildCard({ name: al.name, image: al.image, sub: al.artists || 'Album', onClick: function () { openSpotifyAlbum(al.id); } })); });
        spotifySearchAlbumsSection.hidden = false;
      }
      if (playlists.length) {
        playlists.forEach(function (pl) { spotifySearchPlaylistsEl.appendChild(buildCard({ name: pl.name, image: pl.image, sub: pl.owner ? 'By ' + pl.owner : 'Playlist', onClick: function () { openSpotifyPlaylist(pl); } })); });
        spotifySearchPlaylistsSection.hidden = false;
      }
    } catch (e) {
      setSpotifySearchStatus('Could not reach Spotify — try again.');
    }
  }

  if (spotifySearchForm) {
    spotifySearchForm.addEventListener('submit', function (e) { e.preventDefault(); });
  }
  if (spotifySearchInput) {
    // Debounced so typing doesn't fire a request per keystroke — the
    // request only actually goes out ~300ms after the user stops typing.
    spotifySearchInput.addEventListener('input', function () {
      var q = spotifySearchInput.value.trim();
      if (spotifySearchDebounce) clearTimeout(spotifySearchDebounce);
      spotifySearchDebounce = setTimeout(function () { runSpotifySearch(q); }, 300);
    });
  }

  function renderPlaylistMeta(playlist, total) {
    var count = trackCountLabel(typeof total === 'number' ? total : playlist.trackCount);
    var owner = playlist.kind === 'liked' ? '' : (playlist.owner ? 'By ' + playlist.owner : '');
    spotifyPlaylistMetaEl.textContent = [owner, count].filter(Boolean).join(' · ');
  }

  async function openSpotifyPlaylist(playlist) {
    spotifyCurrentPlaylist = playlist;
    spotifyTracksNextOffset = null;
    spotifyPlaylistTrackUris = [];
    spotifySwitchView('playlist');
    spotifyPlaylistNameEl.textContent = playlist.name || '';
    renderPlaylistMeta(playlist);
    if (playlist.image) { spotifyPlaylistArt.src = playlist.image; spotifyPlaylistArt.hidden = false; spotifyPlaylistArtPlaceholder.hidden = true; }
    else {
      spotifyPlaylistArt.hidden = true;
      spotifyPlaylistArtPlaceholder.hidden = false;
      spotifyPlaylistArtPlaceholder.textContent =
        playlist.kind === 'dj' ? '🎧' : (playlist.kind === 'liked' ? '♥' : '♪');
    }
    spotifyPlaylistTracksEl.innerHTML = '';
    spotifyPlaylistTracksEl.hidden = true;

    // The DJ has no track list to fetch — it is a live stream Spotify picks.
    if (playlist.kind === 'dj') {
      spotifyLoadMoreBtn.hidden = true;
      spotifyPlaylistMetaEl.textContent = 'Spotify picks the music and talks between songs.';
      setSpotifyPlaylistTracksStatus('Press play and the DJ takes over. Skip a track and it adjusts.');
      return;
    }
    await loadSpotifyPlaylistTracks(true);
  }

  async function loadSpotifyPlaylistTracks(reset) {
    if (!spotifyCurrentPlaylist) return;
    if (reset) {
      spotifyPlaylistTracksEl.innerHTML = '';
      spotifyTracksNextOffset = null;
    }
    setSpotifyPlaylistTracksStatus('Loading tracks…');
    spotifyLoadMoreBtn.hidden = true;
    try {
      var offset = reset ? 0 : (spotifyTracksNextOffset || 0);
      var url = spotifyCurrentPlaylist.kind === 'liked'
        ? '/api/spotify/liked?offset=' + offset
        : '/api/spotify/playlists/' + encodeURIComponent(spotifyCurrentPlaylist.id) + '/tracks?offset=' + offset;
      var res = await fetch(url, { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) {
        setSpotifyPlaylistTracksStatus(data.error || 'Could not load that playlist.');
        if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
        return;
      }
      var tracks = data.tracks || [];
      if (!tracks.length && reset) {
        setSpotifyPlaylistTracksStatus('This playlist is empty (or its tracks are unavailable).');
        spotifyPlaylistTracksEl.hidden = true;
        return;
      }
      setSpotifyPlaylistTracksStatus('');
      if (typeof data.total === 'number') renderPlaylistMeta(spotifyCurrentPlaylist, data.total);
      var startIdx = spotifyPlaylistTracksEl.children.length;
      tracks.forEach(function (track, i) {
        if (track.uri) spotifyPlaylistTrackUris.push(track.uri);
        spotifyPlaylistTracksEl.appendChild(buildTrackTableRow(track, startIdx + i + 1, function (t) {
          // Play within the playlist's own context so Spotify queues and
          // auto-advances through the rest of the playlist afterward,
          // instead of stopping once this one track ends.
          var contextUri = spotifyCurrentPlaylist && spotifyCurrentPlaylist.uri;
          if (contextUri) playSpotifyContextTrack(contextUri, t.uri);
          else playSpotifyUris(spotifyPlaylistTrackUris, t.uri);
        }, function (t) { spotifyQueueTrack(t.uri); }));
      });
      spotifyPlaylistTracksEl.hidden = false;
      spotifyTracksNextOffset = data.nextOffset;
      spotifyLoadMoreBtn.hidden = spotifyTracksNextOffset == null;
    } catch (e) {
      setSpotifyPlaylistTracksStatus('Could not reach Spotify — try again.');
    }
  }

  function setSpotifyPlaylistTracksStatus(msg) {
    if (!spotifyPlaylistTracksStatus) return;
    spotifyPlaylistTracksStatus.textContent = msg || '';
    spotifyPlaylistTracksStatus.hidden = !msg;
  }

  if (spotifyPlaylistBackBtn) spotifyPlaylistBackBtn.addEventListener('click', spotifyGoBack);
  if (spotifyPlaylistPlayAllBtn) {
    spotifyPlaylistPlayAllBtn.addEventListener('click', function () {
      if (!spotifyCurrentPlaylist) return;
      if (spotifyCurrentPlaylist.uri) playSpotifyContext(spotifyCurrentPlaylist.uri);
      else if (spotifyPlaylistTrackUris.length) playSpotifyUris(spotifyPlaylistTrackUris);
    });
  }
  if (spotifyLoadMoreBtn) spotifyLoadMoreBtn.addEventListener('click', function () { loadSpotifyPlaylistTracks(false); });

  // ---------------------------------------------------------------------
  // Album detail — one request gets the header + full track list.
  // ---------------------------------------------------------------------

  async function openSpotifyAlbum(albumId) {
    spotifyCurrentAlbumId = albumId;
    spotifySwitchView('album');
    spotifyAlbumNameEl.textContent = '';
    spotifyAlbumMetaEl.textContent = '';
    spotifyAlbumArt.hidden = true;
    spotifyAlbumArtPlaceholder.hidden = false;
    spotifyAlbumTracksEl.innerHTML = '';
    spotifyAlbumTracksEl.hidden = true;
    setSpotifyAlbumTracksStatus('Loading…');
    try {
      var res = await fetch('/api/spotify/albums/' + encodeURIComponent(albumId), { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) {
        setSpotifyAlbumTracksStatus(data.error || 'Could not load that album.');
        if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
        return;
      }
      var album = data.album || {};
      spotifyAlbumNameEl.textContent = album.name || '';
      spotifyAlbumMetaEl.innerHTML = '';
      fillArtistLinks(spotifyAlbumMetaEl, { artists: album.artists, artistList: album.artistList });
      var albumBits = [album.year, trackCountLabel(album.totalTracks)].filter(Boolean).join(' · ');
      if (albumBits) spotifyAlbumMetaEl.appendChild(document.createTextNode(' · ' + albumBits));
      if (album.image) { spotifyAlbumArt.src = album.image; spotifyAlbumArt.hidden = false; spotifyAlbumArtPlaceholder.hidden = true; }
      spotifyAlbumPlayAllBtn.onclick = function () { if (album.uri) playSpotifyContext(album.uri); };
      var tracks = data.tracks || [];
      if (!tracks.length) {
        setSpotifyAlbumTracksStatus('No playable tracks on this album.');
        return;
      }
      setSpotifyAlbumTracksStatus('');
      tracks.forEach(function (track, i) {
        spotifyAlbumTracksEl.appendChild(buildTrackTableRow(track, i + 1, function (t) {
          // Same reasoning as the playlist rows above: play within the
          // album's own context so it auto-advances through the rest of
          // the album afterward.
          if (album.uri) playSpotifyContextTrack(album.uri, t.uri);
          else playSpotifyTrack(t.uri);
        }, function (t) { spotifyQueueTrack(t.uri); }));
      });
      spotifyAlbumTracksEl.hidden = false;
    } catch (e) {
      setSpotifyAlbumTracksStatus('Could not reach Spotify — try again.');
    }
  }

  function setSpotifyAlbumTracksStatus(msg) {
    if (!spotifyAlbumTracksStatus) return;
    spotifyAlbumTracksStatus.textContent = msg || '';
    spotifyAlbumTracksStatus.hidden = !msg;
  }

  if (spotifyAlbumBackBtn) spotifyAlbumBackBtn.addEventListener('click', spotifyGoBack);

  // ---------------------------------------------------------------------
  // Artist detail — header + popular tracks + discography.
  // ---------------------------------------------------------------------

  async function openSpotifyArtist(artistId) {
    spotifyCurrentArtistId = artistId;
    spotifySwitchView('artist');
    spotifyArtistNameEl.textContent = '';
    spotifyArtistMetaEl.textContent = '';
    spotifyArtistArt.hidden = true;
    spotifyArtistArtPlaceholder.hidden = false;
    spotifyArtistTopTracksEl.innerHTML = '';
    spotifyArtistTopSection.hidden = true;
    spotifyArtistAlbumsEl.innerHTML = '';
    spotifyArtistAlbumsSection.hidden = true;
    spotifyArtistSinglesEl.innerHTML = '';
    spotifyArtistSinglesSection.hidden = true;
    if (spotifyArtistPlayAllBtn) spotifyArtistPlayAllBtn.hidden = true;
    spotifyArtistTopUris = [];
    setSpotifyArtistStatus('Loading…');
    try {
      var res = await fetch('/api/spotify/artists/' + encodeURIComponent(artistId), { credentials: 'same-origin' });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) {
        setSpotifyArtistStatus(data.error || 'Could not load that artist.');
        if (res.status === 401) { spotifyConnected = false; refreshSpotifyStatus(); }
        return;
      }
      var artist = data.artist || {};
      spotifyArtistNameEl.textContent = artist.name || '';
      var metaBits = [];
      if (typeof artist.followers === 'number') {
        metaBits.push(formatFollowers(artist.followers) + ' followers');
      }
      if (artist.genres && artist.genres.length) metaBits.push(artist.genres.join(', '));
      spotifyArtistMetaEl.textContent = metaBits.join(' · ');
      if (artist.image) { spotifyArtistArt.src = artist.image; spotifyArtistArt.hidden = false; spotifyArtistArtPlaceholder.hidden = true; }
      setSpotifyArtistStatus('');

      var topTracks = data.topTracks || [];
      if (topTracks.length) {
        var top = topTracks.slice(0, 10);
        spotifyArtistTopUris = top.map(function (t) { return t.uri; }).filter(Boolean);
        top.forEach(function (track, i) {
          spotifyArtistTopTracksEl.appendChild(buildTrackTableRow(track, i + 1, function (t) {
            playSpotifyUris(spotifyArtistTopUris, t.uri);
          }, function (t) { spotifyQueueTrack(t.uri); }));
        });
        spotifyArtistTopSection.hidden = false;
        if (spotifyArtistPlayAllBtn) spotifyArtistPlayAllBtn.hidden = false;
      }

      function fillShelf(list, el, section) {
        if (!list || !list.length) return false;
        list.forEach(function (al) {
          el.appendChild(buildCard({
            name: al.name,
            image: al.image,
            sub: [al.year, trackCountLabel(al.totalTracks)].filter(Boolean).join(' · ') || 'Album',
            label: 'Open album ' + (al.name || ''),
            onClick: function () { openSpotifyAlbum(al.id); },
          }));
        });
        section.hidden = false;
        return true;
      }
      var hasAlbums = fillShelf(data.albums, spotifyArtistAlbumsEl, spotifyArtistAlbumsSection);
      var hasSingles = fillShelf(data.singles, spotifyArtistSinglesEl, spotifyArtistSinglesSection);
      if (!topTracks.length && !hasAlbums && !hasSingles) setSpotifyArtistStatus('Nothing found for this artist.');
    } catch (e) {
      setSpotifyArtistStatus('Could not reach Spotify — try again.');
    }
  }

  function setSpotifyArtistStatus(msg) {
    if (!spotifyArtistStatus) return;
    spotifyArtistStatus.textContent = msg || '';
    spotifyArtistStatus.hidden = !msg;
  }

  function formatFollowers(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'K';
    return String(n);
  }

  if (spotifyArtistPlayAllBtn) {
    spotifyArtistPlayAllBtn.addEventListener('click', function () {
      if (spotifyArtistTopUris.length) playSpotifyUris(spotifyArtistTopUris);
    });
  }

  if (spotifyArtistBackBtn) spotifyArtistBackBtn.addEventListener('click', spotifyGoBack);

  function handleSpotifyRedirectParam() {
    var params = new URLSearchParams(window.location.search);
    var flag = params.get('spotify');
    if (!flag) return;
    try { window.history.replaceState(null, '', window.location.pathname); } catch (e) { /* ignore */ }

    if (window.opener && !window.opener.closed) {
      try {
        window.opener.postMessage({ source: 'soulstudies-spotify', status: flag }, window.location.origin);
      } catch (e) { /* ignore */ }
      window.close();
      return;
    }

    if (currentView !== 'chat' && currentView !== 'games') showView('games');
    refreshSpotifyStatus();
    if (flag === 'denied') setSpotifyStatusMsg('Spotify connection was cancelled.');
    else if (flag === 'notallowed') setSpotifyStatusMsg('This Spotify account is not approved for this app yet. Whoever set up the Spotify app has to add it under User Management in the Spotify developer dashboard — Spotify only lets a handful of accounts use an app until then. (Nothing to do with Premium.)');
    else if (flag === 'error') setSpotifyStatusMsg('Could not connect to Spotify — try again.');
  }

  window.addEventListener('message', function (event) {
    if (event.origin !== window.location.origin) return;
    if (!event.data || event.data.source !== 'soulstudies-spotify') return;
    if (spotifyPopupWatch) { clearInterval(spotifyPopupWatch); spotifyPopupWatch = null; }
    if (event.data.status === 'connected') {
      setSpotifyStatusMsg('');
      refreshSpotifyStatus();
    } else if (event.data.status === 'denied') {
      setSpotifyStatusMsg('Spotify connection was cancelled.');
    } else if (event.data.status === 'notallowed') {
      setSpotifyStatusMsg('This Spotify account is not approved for this app yet. Whoever set up the Spotify app has to add it under User Management in the Spotify developer dashboard — Spotify only lets a handful of accounts use an app until then. (Nothing to do with Premium.)');
    } else {
      setSpotifyStatusMsg('Could not connect to Spotify — try again.');
    }
  });

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

    var fullRows = [];
    for (var y = T_ROWS - 1; y >= 0; y--) {
      if (tetris.grid[y].every(Boolean)) fullRows.push(y);
    }
    var cleared = fullRows.length;

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
    var prevLevel = tetris.level;
    tetris.level = Math.floor(tetris.lines / 10) + 1;
    if (tetris.level > prevLevel) action = (action ? action + ' · ' : '') + 'LEVEL ' + tetris.level;
    if (action) flashAction(action);

    tetris.holdUsed = false;
    updateTetrisHud();

    if (cleared) {
      // Held on screen for a beat, then collapsed in tFinishClear.
      tetris.piece = null;
      tetris.clearing = { rows: fullRows, elapsed: 0, big: cleared >= 4 || tspin };
      return;
    }
    tSpawnFromQueue();
  }

  var T_CLEAR_MS = 190;

  function tFinishClear() {
    // Take every cleared row out first, then put the replacements back on
    // top — unshifting between splices would shift the remaining indices.
    var rows = tetris.clearing.rows.slice().sort(function (a, b) { return a - b; });
    for (var i = rows.length - 1; i >= 0; i--) tetris.grid.splice(rows[i], 1);
    for (var j = 0; j < rows.length; j++) tetris.grid.unshift(new Array(T_COLS).fill(null));
    tetris.clearing = null;
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
    if (t.clearing) {
      t.clearing.elapsed += dt;
      if (t.clearing.elapsed >= T_CLEAR_MS) tFinishClear();
      return;
    }
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

  function roundRectPath(ctx, x, y, w, h, r) {
    var rad = Math.min(r, w / 2, h / 2);
    ctx.beginPath();
    ctx.moveTo(x + rad, y);
    ctx.arcTo(x + w, y, x + w, y + h, rad);
    ctx.arcTo(x + w, y + h, x, y + h, rad);
    ctx.arcTo(x, y + h, x, y, rad);
    ctx.arcTo(x, y, x + w, y, rad);
    ctx.closePath();
  }

  function drawTCell(ctx, x, y, px, color, ghost) {
    var gx = x * px + 1;
    var gy = y * px + 1;
    var size = px - 2;

    if (ghost) {
      ctx.globalAlpha = 0.14;
      ctx.fillStyle = color;
      roundRectPath(ctx, gx, gy, size, size, 4);
      ctx.fill();
      ctx.globalAlpha = 0.55;
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      roundRectPath(ctx, gx + 0.75, gy + 0.75, size - 1.5, size - 1.5, 3.5);
      ctx.stroke();
      ctx.globalAlpha = 1;
      return;
    }

    var grad = ctx.createLinearGradient(gx, gy, gx, gy + size);
    grad.addColorStop(0, color);
    grad.addColorStop(1, shadeColor(color, -0.28));
    ctx.fillStyle = grad;
    roundRectPath(ctx, gx, gy, size, size, 4);
    ctx.fill();

    ctx.fillStyle = 'rgba(255,255,255,0.22)';
    roundRectPath(ctx, gx + 2, gy + 2, size - 4, Math.max(2, size * 0.22), 2);
    ctx.fill();

    ctx.strokeStyle = 'rgba(0,0,0,0.32)';
    ctx.lineWidth = 1;
    roundRectPath(ctx, gx + 0.5, gy + 0.5, size - 1, size - 1, 4);
    ctx.stroke();
  }

  function shadeColor(hex, amount) {
    var n = parseInt(hex.slice(1), 16);
    var r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
    function mix(c) {
      return Math.max(0, Math.min(255, Math.round(amount < 0 ? c * (1 + amount) : c + (255 - c) * amount)));
    }
    return 'rgb(' + mix(r) + ',' + mix(g) + ',' + mix(b) + ')';
  }

  function drawTetris() {
    var ctx = tetrisCtx;
    var W = tetrisCanvas.width;
    var H = tetrisCanvas.height;
    ctx.clearRect(0, 0, W, H);

    var bg = ctx.createLinearGradient(0, 0, 0, H);
    bg.addColorStop(0, 'rgba(16,20,29,0.95)');
    bg.addColorStop(1, 'rgba(8,10,15,0.98)');
    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, W, H);

    ctx.strokeStyle = 'rgba(233,225,208,0.05)';
    ctx.lineWidth = 1;
    for (var gx = 1; gx < T_COLS; gx++) {
      ctx.beginPath(); ctx.moveTo(gx * T_PX + 0.5, 0); ctx.lineTo(gx * T_PX + 0.5, T_ROWS * T_PX); ctx.stroke();
    }
    for (var gy = 1; gy < T_ROWS; gy++) {
      ctx.beginPath(); ctx.moveTo(0, gy * T_PX + 0.5); ctx.lineTo(T_COLS * T_PX, gy * T_PX + 0.5); ctx.stroke();
    }
    if (!tetris) return;

    var clearing = tetris.clearing;
    var t = clearing ? Math.min(1, clearing.elapsed / T_CLEAR_MS) : 0;
    var clearRows = Object.create(null);
    if (clearing) clearing.rows.forEach(function (r) { clearRows[r] = true; });

    for (var y = 0; y < T_ROWS; y++) {
      var isClearing = clearRows[y];
      if (isClearing) {
        ctx.save();
        ctx.translate(0, (y + 0.5) * T_PX);
        ctx.scale(1, Math.max(0.02, 1 - t * 0.85));
        ctx.translate(0, -(y + 0.5) * T_PX);
        ctx.globalAlpha = 1 - t * 0.65;
      }
      for (var x = 0; x < T_COLS; x++) {
        if (tetris.grid[y][x]) drawTCell(ctx, x, y, T_PX, tetris.grid[y][x]);
      }
      if (isClearing) {
        ctx.globalAlpha = 0.55 * (1 - t);
        ctx.fillStyle = '#fdf7e8';
        roundRectPath(ctx, 1, y * T_PX + 1, T_COLS * T_PX - 2, T_PX - 2, 4);
        ctx.fill();
        ctx.globalAlpha = 1;
        ctx.restore();
      }
    }

    if (clearing) {
      var half = (T_COLS * T_PX) / 2;
      var reach = half * Math.min(1, t * 1.6);
      clearing.rows.forEach(function (r) {
        var cy = r * T_PX + T_PX / 2;
        var g = ctx.createLinearGradient(half - reach, 0, half + reach, 0);
        g.addColorStop(0, 'rgba(147,184,154,0)');
        g.addColorStop(0.5, 'rgba(233,225,208,' + (0.85 * (1 - t)).toFixed(3) + ')');
        g.addColorStop(1, 'rgba(147,184,154,0)');
        ctx.fillStyle = g;
        ctx.fillRect(half - reach, cy - 1.5, reach * 2, 3);
      });
      return;
    }

    var p = tetris.piece;
    if (!p) return;
    var cells = T_SHAPES[p.type][p.rot];
    var color = T_DEFS[p.type].color;
    var gy2 = tGhostY();
    if (gy2 > p.y) {
      cells.forEach(function (c) {
        var by = gy2 + c[1];
        if (by >= 0) drawTCell(ctx, p.x + c[0], by, T_PX, color, true);
      });
    }
    ctx.save();
    ctx.shadowColor = color;
    ctx.shadowBlur = 10;
    cells.forEach(function (c) {
      var by = p.y + c[1];
      if (by >= 0) drawTCell(ctx, p.x + c[0], by, T_PX, color);
    });
    ctx.restore();
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
    ctx.save();
    ctx.translate(ox - minX * px, oy - minY * px);
    cells.forEach(function (c) {
      drawTCell(ctx, c[0], c[1], px, T_DEFS[type].color);
    });
    ctx.restore();
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
      clearing: null, flash: 0,
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

  var doomCanvas = document.getElementById('doom-canvas');
  var doomCtx = doomCanvas.getContext('2d');
  var doomOverlay = document.getElementById('doom-overlay');
  var doomMsg = document.getElementById('doom-msg');
  var doomStartBtn = document.getElementById('doom-start');
  var doomStatusEl = document.getElementById('doom-status');
  var DOOM_W = 640;
  var DOOM_H = 400;
  var doomInstance = null;
  var doomMemory = null;
  var doomRaf = null;
  var doomLoading = false;
  var doomKeysDown = Object.create(null);

  function doomKeyCode(keyCode) {
    switch (keyCode) {
      case 8: return 127;
      case 17: return 0x80 + 0x1d;
      case 18: return 0x80 + 0x38;
      case 37: return 0xac;
      case 38: return 0xad;
      case 39: return 0xae;
      case 40: return 0xaf;
      default:
        if (keyCode >= 65 && keyCode <= 90) return keyCode + 32;
        if (keyCode >= 112 && keyCode <= 123) return keyCode + 75;
        return keyCode;
    }
  }

  function doomDraw(ptr) {
    var buf = new Uint8ClampedArray(doomMemory.buffer, ptr, DOOM_W * DOOM_H * 4);
    doomCtx.putImageData(new ImageData(buf, DOOM_W, DOOM_H), 0, 0);
  }

  function doomLoopFrame() {
    if (!doomInstance || !doomRaf) { doomRaf = null; return; }
    doomInstance.exports.doom_loop_step();
    doomRaf = requestAnimationFrame(doomLoopFrame);
  }

  async function startDoom() {
    if (doomInstance) {
      doomOverlay.hidden = true;
      doomStatusEl.textContent = 'running';
      if (!doomRaf) doomRaf = requestAnimationFrame(doomLoopFrame);
      return;
    }
    if (doomLoading) return;
    doomLoading = true;
    doomStartBtn.disabled = true;
    doomStatusEl.textContent = 'loading…';
    try {
      doomMemory = new WebAssembly.Memory({ initial: 108 });
      var noop = function () {};
      var imports = {
        js: {
          js_console_log: noop,
          js_stdout: noop,
          js_stderr: noop,
          js_milliseconds_since_start: function () { return performance.now(); },
          js_draw_screen: doomDraw,
        },
        env: { memory: doomMemory },
      };
      var resp = await fetch('/assets/doom.wasm');
      if (!resp.ok) throw new Error('fetch failed');
      var bytes = await resp.arrayBuffer();
      var result = await WebAssembly.instantiate(bytes, imports);
      doomInstance = result.instance;
      doomInstance.exports.main();
      doomOverlay.hidden = true;
      doomStatusEl.textContent = 'running';
      doomRaf = requestAnimationFrame(doomLoopFrame);
    } catch (e) {
      doomStatusEl.textContent = 'failed';
      doomMsg.textContent = 'Could not load the engine. Refresh and try again.';
    } finally {
      doomLoading = false;
      doomStartBtn.disabled = false;
    }
  }

  function stopDoom() {
    if (doomRaf) { cancelAnimationFrame(doomRaf); doomRaf = null; }
    if (doomInstance) {
      Object.keys(doomKeysDown).forEach(function (k) {
        doomInstance.exports.add_browser_event(1, Number(k));
      });
      doomStatusEl.textContent = 'paused';
      doomMsg.textContent = 'paused — your run is kept';
      doomStartBtn.textContent = 'resume';
      doomOverlay.hidden = false;
    }
    doomKeysDown = Object.create(null);
  }

  doomStartBtn.addEventListener('click', startDoom);

  var pokerChipsEl = document.getElementById('poker-chips');
  var pokerPotEl = document.getElementById('poker-pot');
  var pokerBoardEl = document.getElementById('poker-board');
  var pokerMsgEl = document.getElementById('poker-msg');
  var pokerOverlay = document.getElementById('poker-overlay');
  var pokerOverlayMsg = document.getElementById('poker-overlay-msg');
  var pokerDealBtn = document.getElementById('poker-deal');
  var pokerActionsEl = document.getElementById('poker-actions');
  var pokerFoldBtn = document.getElementById('poker-fold');
  var pokerCallBtn = document.getElementById('poker-call');
  var pokerRaiseBtn = document.getElementById('poker-raise');
  var pokerRaiseAmt = document.getElementById('poker-raise-amt');
  var pokerRaiseVal = document.getElementById('poker-raise-val');

  var POKER_BOTS = ['raven', 'onyx', 'clover'];
  var POKER_SB = 10;
  var POKER_BB = 20;
  var POKER_START = 1000;
  var POKER_IDLE_MSG = 'texas hold\'em · you vs three bots · chips carry between visits';
  var SUITS = ['♠', '♥', '♦', '♣'];
  var RANK_CHARS = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'];
  var POKER_HAND_NAMES = ['high card', 'a pair', 'two pair', 'three of a kind', 'a straight',
    'a flush', 'a full house', 'four of a kind', 'a straight flush'];

  var poker = null;
  var pokerGen = 0;
  var pokerDealer = 3;
  var pokerStacks = null;

  function pokerStorageKey() {
    return 'ss_poker_' + (myRoom || '') + '_' + (myUsername || '').toLowerCase();
  }

  function loadPokerChips() {
    var chips = POKER_START;
    try {
      var raw = localStorage.getItem(pokerStorageKey());
      if (raw) {
        var n = Math.floor(Number(JSON.parse(raw).chips));
        if (n > 0) chips = n;
      }
    } catch (e) { /* fresh stack */ }
    return chips;
  }

  function savePokerChips() {
    if (!pokerStacks) return;
    try { localStorage.setItem(pokerStorageKey(), JSON.stringify({ chips: pokerStacks[0] })); } catch (e) { /* ignore */ }
  }

  function initPoker() {
    pokerGen++;
    pokerStacks = [loadPokerChips(), POKER_START, POKER_START, POKER_START];
    poker = null;
    pokerDealer = Math.floor(Math.random() * 4);
    pokerOverlayMsg.textContent = POKER_IDLE_MSG;
    pokerDealBtn.textContent = 'deal me in';
    pokerOverlay.hidden = false;
    pokerBoardEl.innerHTML = '';
    pokerMsgEl.textContent = '';
    for (var s = 0; s < 4; s++) document.getElementById('poker-seat-' + s).innerHTML = '';
    hidePokerActions();
    updatePokerHud();
  }

  // Cards are ints 0..51: rank = c >> 2 (0 = deuce … 12 = ace), suit = c & 3.

  function pokerEval5(cs) {
    var ranks = cs.map(function (c) { return c >> 2; }).sort(function (a, b) { return b - a; });
    var flush = cs.every(function (c) { return (c & 3) === (cs[0] & 3); });
    var counts = {};
    ranks.forEach(function (r) { counts[r] = (counts[r] || 0) + 1; });
    var groups = Object.keys(counts).map(Number).map(function (r) { return [counts[r], r]; });
    groups.sort(function (a, b) { return b[0] - a[0] || b[1] - a[1]; });
    var straightHigh = -1;
    if (groups.length === 5) {
      if (ranks[0] - ranks[4] === 4) straightHigh = ranks[0];
      else if (ranks[0] === 12 && ranks[1] === 3) straightHigh = 3;
    }
    if (flush && straightHigh >= 0) return [8, straightHigh];
    if (groups[0][0] === 4) return [7, groups[0][1], groups[1][1]];
    if (groups[0][0] === 3 && groups[1][0] === 2) return [6, groups[0][1], groups[1][1]];
    if (flush) return [5].concat(ranks);
    if (straightHigh >= 0) return [4, straightHigh];
    if (groups[0][0] === 3) return [3, groups[0][1], groups[1][1], groups[2][1]];
    if (groups[0][0] === 2 && groups[1][0] === 2) return [2, groups[0][1], groups[1][1], groups[2][1]];
    if (groups[0][0] === 2) return [1, groups[0][1], groups[1][1], groups[2][1], groups[3][1]];
    return [0].concat(ranks);
  }

  function pokerCmp(a, b) {
    for (var i = 0; i < Math.max(a.length, b.length); i++) {
      var d = (a[i] || 0) - (b[i] || 0);
      if (d) return d;
    }
    return 0;
  }

  function pokerEval7(cs) {
    var best = null;
    for (var i = 0; i < 7; i++) {
      for (var j = i + 1; j < 7; j++) {
        var five = [];
        for (var k = 0; k < 7; k++) if (k !== i && k !== j) five.push(cs[k]);
        var v = pokerEval5(five);
        if (!best || pokerCmp(v, best) > 0) best = v;
      }
    }
    return best;
  }

  function pokerPot() {
    return poker ? poker.players.reduce(function (s, p) { return s + p.total; }, 0) : 0;
  }

  function pokerCommit(p, amount) {
    amount = Math.min(amount, p.chips);
    p.chips -= amount;
    p.bet += amount;
    p.total += amount;
    if (p.chips === 0) p.allIn = true;
    pokerStacks[p.seat] = p.chips;
  }

  function startPokerHand() {
    if (!pokerStacks) return;
    for (var i = 0; i < 4; i++) if (pokerStacks[i] <= 0) pokerStacks[i] = POKER_START;
    savePokerChips();

    var deck = [];
    for (var c = 0; c < 52; c++) deck.push(c);
    for (var d = deck.length - 1; d > 0; d--) {
      var j = Math.floor(Math.random() * (d + 1));
      var t = deck[d]; deck[d] = deck[j]; deck[j] = t;
    }

    pokerDealer = (pokerDealer + 1) % 4;
    poker = { deck: deck, board: [], stage: 0, currentBet: 0, minRaise: POKER_BB, toAct: -1, players: [], settled: false };
    for (var s = 0; s < 4; s++) {
      poker.players.push({
        seat: s,
        name: s === 0 ? (myUsername || 'you') : POKER_BOTS[s - 1],
        chips: pokerStacks[s],
        cards: [deck.pop(), deck.pop()],
        bet: 0,
        total: 0,
        folded: false,
        allIn: false,
        out: false,
        acted: false,
        say: '',
        revealed: s === 0,
      });
    }

    pokerCommit(poker.players[(pokerDealer + 1) % 4], POKER_SB);
    pokerCommit(poker.players[(pokerDealer + 2) % 4], POKER_BB);
    poker.currentBet = POKER_BB;
    poker.toAct = (pokerDealer + 3) % 4;

    pokerOverlay.hidden = true;
    pokerMsgEl.textContent = '';
    renderPoker();
    pokerAdvanceTurn();
  }

  function pokerRoundDone() {
    var live = poker.players.filter(function (p) { return !p.folded && !p.out && !p.allIn; });
    return live.every(function (p) { return p.acted && p.bet === poker.currentBet; });
  }

  function pokerAdvanceTurn() {
    if (!poker || poker.settled) return;
    var alive = poker.players.filter(function (p) { return !p.folded && !p.out; });
    if (alive.length === 1) { pokerAwardUncontested(alive[0]); return; }
    if (pokerRoundDone()) { pokerNextStreet(); return; }
    var guard = 0;
    while (guard++ < 8) {
      var p = poker.players[poker.toAct];
      if (!p.folded && !p.out && !p.allIn && !(p.acted && p.bet === poker.currentBet)) break;
      poker.toAct = (poker.toAct + 1) % 4;
    }
    renderPoker();
    var actor = poker.players[poker.toAct];
    if (actor.seat === 0) {
      showPokerActions();
    } else {
      var gen = pokerGen;
      setTimeout(function () {
        if (gen !== pokerGen || !poker || poker.settled) return;
        pokerBotAct(actor);
      }, 650 + Math.random() * 550);
    }
  }

  function pokerDoAction(p, action, raiseTo) {
    if (action === 'fold') {
      p.folded = true;
      p.acted = true;
      p.say = 'fold';
    } else if (action === 'call') {
      var owe = poker.currentBet - p.bet;
      pokerCommit(p, owe);
      p.acted = true;
      p.say = owe > 0 ? (p.allIn ? 'all-in' : 'call') : 'check';
    } else {
      raiseTo = Math.max(raiseTo, poker.currentBet + poker.minRaise);
      var add = raiseTo - p.bet;
      if (add >= p.chips) { add = p.chips; raiseTo = p.bet + add; }
      pokerCommit(p, add);
      if (raiseTo > poker.currentBet) {
        poker.minRaise = Math.max(POKER_BB, raiseTo - poker.currentBet);
        poker.currentBet = raiseTo;
        poker.players.forEach(function (o) { if (o !== p) o.acted = false; });
      }
      p.acted = true;
      p.say = p.allIn ? 'all-in' : (poker.board.length ? 'bet ' + raiseTo : 'raise ' + raiseTo);
    }
    poker.toAct = (poker.toAct + 1) % 4;
    hidePokerActions();
    renderPoker();
    pokerAdvanceTurn();
  }

  function pokerNextStreet() {
    poker.players.forEach(function (p) { p.bet = 0; p.acted = false; p.say = ''; });
    poker.currentBet = 0;
    poker.minRaise = POKER_BB;
    if (poker.stage === 0) { poker.board.push(poker.deck.pop(), poker.deck.pop(), poker.deck.pop()); poker.stage = 1; }
    else if (poker.stage === 1) { poker.board.push(poker.deck.pop()); poker.stage = 2; }
    else if (poker.stage === 2) { poker.board.push(poker.deck.pop()); poker.stage = 3; }
    else { pokerShowdown(); return; }
    renderPoker();
    var canAct = poker.players.filter(function (p) { return !p.folded && !p.out && !p.allIn; });
    if (canAct.length <= 1) {
      var gen = pokerGen;
      setTimeout(function () { if (gen === pokerGen && poker && !poker.settled) pokerNextStreet(); }, 900);
      return;
    }
    poker.toAct = (pokerDealer + 1) % 4;
    pokerAdvanceTurn();
  }

  function pokerAwardUncontested(winner) {
    poker.settled = true;
    var pot = pokerPot();
    winner.chips += pot;
    pokerStacks[winner.seat] = winner.chips;
    pokerFinishHand(winner.name + ' takes ' + pot + ' uncontested');
  }

  function pokerShowdown() {
    poker.settled = true;
    var contenders = poker.players.filter(function (p) { return !p.folded && !p.out; });
    contenders.forEach(function (p) {
      p.revealed = true;
      p.handVal = pokerEval7(p.cards.concat(poker.board));
    });

    // Split the money into side pots by all-in level; any uncalled excess
    // falls into a pot only its owner is eligible for, i.e. a refund.
    var levels = contenders.map(function (p) { return p.total; })
      .filter(function (v, i, a) { return a.indexOf(v) === i; })
      .sort(function (a, b) { return a - b; });
    var prev = 0;
    var winnersNamed = {};
    levels.forEach(function (level) {
      var potHere = 0;
      poker.players.forEach(function (p) { potHere += Math.max(0, Math.min(p.total, level) - prev); });
      var eligible = contenders.filter(function (p) { return p.total >= level; });
      var best = null;
      eligible.forEach(function (p) { if (!best || pokerCmp(p.handVal, best.handVal) > 0) best = p; });
      var winners = eligible.filter(function (p) { return pokerCmp(p.handVal, best.handVal) === 0; });
      var share = Math.floor(potHere / winners.length);
      var rem = potHere - share * winners.length;
      winners.forEach(function (w, i) {
        w.chips += share + (i === 0 ? rem : 0);
        if (winners.length < eligible.length || eligible.length > 1) winnersNamed[w.name] = w.handVal;
      });
      prev = level;
    });
    poker.players.forEach(function (p) { pokerStacks[p.seat] = p.chips; });
    var names = Object.keys(winnersNamed);
    var msg = names.length
      ? names.map(function (n) { return n + ' wins with ' + POKER_HAND_NAMES[winnersNamed[n][0]]; }).join(' · ')
      : 'pot returned';
    pokerFinishHand(msg);
  }

  function pokerFinishHand(msg) {
    poker.players.forEach(function (p) { p.total = 0; p.bet = 0; });
    hidePokerActions();
    savePokerChips();
    submitScore('poker', pokerStacks[0]);
    renderPoker();
    pokerMsgEl.textContent = msg;
    var gen = pokerGen;
    setTimeout(function () {
      if (gen !== pokerGen) return;
      pokerOverlayMsg.textContent = msg + (pokerStacks[0] <= 0 ? ' — you\'re felted; a fresh 1000 is waiting' : '');
      pokerDealBtn.textContent = 'next hand';
      pokerOverlay.hidden = false;
    }, 2600);
  }

  function pokerBotAct(p) {
    var owe = poker.currentBet - p.bet;
    var pot = pokerPot();
    var strength;
    if (poker.stage === 0) {
      var r1 = p.cards[0] >> 2;
      var r2 = p.cards[1] >> 2;
      var hi = Math.max(r1, r2);
      var lo = Math.min(r1, r2);
      if (r1 === r2) {
        strength = 0.55 + r1 / 26;
      } else {
        strength = hi / 24 + lo / 48;
        if ((p.cards[0] & 3) === (p.cards[1] & 3)) strength += 0.06;
        if (hi - lo === 1) strength += 0.05;
        if (hi >= 11) strength += 0.08;
      }
    } else {
      var v = pokerEval7(p.cards.concat(poker.board));
      strength = Math.min(0.25 + v[0] * 0.11 + (v[1] || 0) / 160, 1);
    }
    strength += (Math.random() - 0.5) * 0.12;

    var potOdds = owe > 0 ? owe / (pot + owe) : 0;
    if (owe === 0) {
      if (strength > 0.62 && Math.random() < 0.7) {
        pokerDoAction(p, 'raise', poker.currentBet + Math.max(poker.minRaise, Math.round(pot * 0.05) * 10));
      } else {
        pokerDoAction(p, 'call');
      }
    } else if (strength > 0.78 && Math.random() < 0.65) {
      pokerDoAction(p, 'raise', poker.currentBet + Math.max(poker.minRaise, Math.round(pot * 0.06) * 10));
    } else if (strength > potOdds + 0.12 || owe <= POKER_BB || Math.random() < 0.06) {
      pokerDoAction(p, 'call');
    } else {
      pokerDoAction(p, 'fold');
    }
  }

  function showPokerActions() {
    var me = poker.players[0];
    var owe = poker.currentBet - me.bet;
    pokerCallBtn.textContent = owe > 0 ? (owe >= me.chips ? 'all-in (' + me.chips + ')' : 'call ' + owe) : 'check';
    var minTo = poker.currentBet + poker.minRaise;
    var maxTo = me.bet + me.chips;
    var canRaise = maxTo > poker.currentBet;
    pokerRaiseAmt.min = String(Math.min(minTo, maxTo));
    pokerRaiseAmt.max = String(maxTo);
    pokerRaiseAmt.value = String(Math.min(Math.max(minTo, POKER_BB * 3), maxTo));
    pokerRaiseVal.textContent = pokerRaiseAmt.value;
    pokerRaiseBtn.disabled = !canRaise;
    pokerRaiseAmt.disabled = !canRaise;
    pokerActionsEl.hidden = false;
  }

  function hidePokerActions() {
    pokerActionsEl.hidden = true;
  }

  function pokerCardEl(card, hidden) {
    var el = document.createElement('div');
    el.className = 'pcard' + (hidden ? ' back' : '');
    if (!hidden && card != null) {
      var suit = card & 3;
      if (suit === 1 || suit === 2) el.classList.add('red');
      var rank = document.createElement('b');
      rank.textContent = RANK_CHARS[card >> 2];
      var glyph = document.createElement('span');
      glyph.textContent = SUITS[suit];
      el.appendChild(rank);
      el.appendChild(glyph);
    }
    return el;
  }

  function renderPoker() {
    if (!poker) return;
    poker.players.forEach(function (p) {
      var seatEl = document.getElementById('poker-seat-' + p.seat);
      seatEl.innerHTML = '';
      var name = document.createElement('span');
      name.className = 'poker-name';
      name.textContent = p.name;
      var chips = document.createElement('span');
      chips.className = 'poker-stack';
      chips.textContent = String(p.chips);
      var cardsWrap = document.createElement('div');
      cardsWrap.className = 'poker-cards';
      p.cards.forEach(function (c) { cardsWrap.appendChild(pokerCardEl(c, !p.revealed)); });
      seatEl.appendChild(cardsWrap);
      seatEl.appendChild(name);
      seatEl.appendChild(chips);
      if (p.seat === pokerDealer) {
        var dbtn = document.createElement('span');
        dbtn.className = 'poker-dealer';
        dbtn.textContent = 'D';
        seatEl.appendChild(dbtn);
      }
      if (p.bet > 0 || p.say) {
        var say = document.createElement('span');
        say.className = 'poker-say';
        say.textContent = p.say || String(p.bet);
        seatEl.appendChild(say);
      }
      seatEl.classList.toggle('is-folded', p.folded);
      seatEl.classList.toggle('is-turn', !poker.settled && poker.toAct === p.seat && !p.folded);
    });
    pokerBoardEl.innerHTML = '';
    for (var i = 0; i < 5; i++) {
      pokerBoardEl.appendChild(i < poker.board.length ? pokerCardEl(poker.board[i], false) : pokerCardEl(null, true));
    }
    updatePokerHud();
  }

  function updatePokerHud() {
    pokerChipsEl.textContent = String(pokerStacks ? pokerStacks[0] : 0);
    pokerPotEl.textContent = String(pokerPot());
  }

  function stopPoker(abandon) {
    pokerGen++;
    if (!poker) return;
    if (abandon && !poker.settled) {
      // A hand interrupted mid-play never happened: everyone gets their
      // chips back.
      poker.players.forEach(function (p) {
        p.chips += p.total;
        pokerStacks[p.seat] = p.chips;
      });
    }
    poker = null;
    savePokerChips();
    hidePokerActions();
    pokerOverlayMsg.textContent = POKER_IDLE_MSG;
    pokerDealBtn.textContent = 'deal me in';
    pokerOverlay.hidden = false;
    updatePokerHud();
  }

  pokerRaiseAmt.addEventListener('input', function () {
    pokerRaiseVal.textContent = pokerRaiseAmt.value;
  });
  pokerFoldBtn.addEventListener('click', function () {
    if (poker && !poker.settled && poker.toAct === 0) pokerDoAction(poker.players[0], 'fold');
  });
  pokerCallBtn.addEventListener('click', function () {
    if (poker && !poker.settled && poker.toAct === 0) pokerDoAction(poker.players[0], 'call');
  });
  pokerRaiseBtn.addEventListener('click', function () {
    if (poker && !poker.settled && poker.toAct === 0) pokerDoAction(poker.players[0], 'raise', Number(pokerRaiseAmt.value));
  });
  pokerDealBtn.addEventListener('click', startPokerHand);

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

    if (activeGame === 'doom' && doomInstance && doomRaf) {
      if (e.key === 'Tab') return; // the panic key stays global
      var dk = doomKeyCode(e.keyCode);
      doomKeysDown[dk] = true;
      doomInstance.exports.add_browser_event(0, dk);
      e.preventDefault();
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

    if (activeGame === 'tetris' && tetris && tetris.piece) {
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
    if (doomInstance && currentView === 'games' && activeGame === 'doom') {
      var dk = doomKeyCode(e.keyCode);
      if (doomKeysDown[dk]) {
        delete doomKeysDown[dk];
        doomInstance.exports.add_browser_event(1, dk);
        e.preventDefault();
        return;
      }
    }
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

  var COMBOS = [
    { keys: ['q', 'w', 'o', 'p'], from: ['essay'], fired: false, go: function () { showView('gate'); } },
    { keys: ['g', 'a', 'm', 'e'], from: ['chat'], fired: false, go: function () { showView('games'); } },
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
        // The panic key should leave nothing audible behind — stop any
        // Spotify playback (in-browser SDK or a remote-controlled device)
        // the instant it fires, same as clicking pause.
        if (spotifyConnected && spotifyPlaying) spotifyTransport('pause', '');
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

  bootstrapRouting().then(handleSpotifyRedirectParam);
})();
