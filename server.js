'use strict';

/**
 * SOUL STUDIES — backend server
 * -----------------------------
 * Deliberately built with ZERO third-party dependencies (Node built-ins only)
 * so it runs anywhere with `node server.js` — no npm install, no network
 * access required, nothing to go stale.
 *
 * Security model (see SECURITY.md for the full writeup):
 *  - Room passwords are never stored or shipped in any frontend file.
 *    Each one exists only as a salted scrypt hash on disk (data/config.json).
 *  - All access-control decisions (password gate, username stage, chat)
 *    are enforced SERVER-SIDE on every API call, using a signed/opaque
 *    session id in an HttpOnly cookie. Client-side page routing is
 *    convenience only — it grants nothing.
 *  - Login attempts are rate-limited and lock out per IP.
 *  - All state-changing requests require a per-session CSRF token.
 *  - There is no SQL/NoSQL involved (flat in-memory + JSON-file storage),
 *    so classic injection is structurally not possible — but all input
 *    is still validated/allow-listed, because that's the correct default
 *    regardless of storage engine.
 *
 * Rooms
 * -----
 * This server hosts two completely independent chatrooms, each behind its
 * own password/"code" (see ROOMS below). A session is attached to exactly
 * one room the moment its password is verified (in /api/login), and every
 * piece of room data — chat history, usernames-in-use, avatars, chat
 * images — lives in its own per-room namespace (own Maps/arrays, own
 * on-disk files/directories). Nothing is shared or cross-visible between
 * rooms; they only happen to run in the same process.
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const AVATARS_DIR = path.join(DATA_DIR, 'avatars');
const CHAT_IMAGES_DIR = path.join(DATA_DIR, 'chat-images');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');
const PORT = process.env.PORT || 3000;

const MAX_BODY_BYTES = 8 * 1024; // 8KB — plenty for password/username/chat payloads
const MAX_AVATAR_BYTES = 3 * 1024 * 1024; // 3MB — reasonable cap for a profile picture
const MAX_CHAT_IMAGE_BYTES = 5 * 1024 * 1024; // 5MB — cap for an in-chat image
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24h
// Any printable characters are allowed in a username (1-20 chars, no
// control characters). Usernames are NEVER used directly as file paths —
// see userFileBase(), which encodes them to a fixed-safe alphabet first.
const USERNAME_RE = /^[^\x00-\x1F\x7F]{1,20}$/;
const LEGACY_USERNAME_RE = /^[a-z0-9_]{1,20}$/;
const RESERVED_USERNAMES = new Set(['admin', 'system', 'moderator', 'root', 'soulstudies']);
// Message text is now an opaque, client-encrypted (AES-GCM) blob, base64-encoded
// with a 12-byte IV prepended — see public/assets/app.js. The server never sees
// plaintext chat content, so this cap sizes the ciphertext, not the message a
// person actually typed (the real 500-character limit is still enforced
// client-side on the input itself before it's ever encrypted).
const MAX_MESSAGE_LEN = 4000;
const MAX_MESSAGES_KEPT = 300;
const ALLOWED_AVATAR_EXTS = ['jpg', 'png', 'webp'];
const REPLY_ID_RE = /^[0-9a-fA-F-]{1,100}$/;
const GAME_IDS = ['snake', 'tetris', 'mines', 'cookie'];
const MAX_GAME_SCORE = 1e15;
const USERNAME_STALE_MS = 90 * 1000;
const MAX_GPT_BODY_BYTES = 256 * 1024;
const GPT_API_URL = process.env.GPT_API_URL || 'https://text.pollinations.ai/openai';
const GPT_API_KEY = process.env.GPT_API_KEY || '';
const GPT_MODEL = process.env.GPT_MODEL || 'openai';

// ---------------------------------------------------------------------------
// Room definitions — each one is a fully independent chatroom with its own
// password/code. `defaultPassword` only applies the very first time a room
// has no stored hash yet AND no env var override is set — it's what makes
// "meowmeow" work immediately without any extra deployment step. Either
// room's password can still be overridden any time via its env var, exactly
// like the original single-room app.
// ---------------------------------------------------------------------------

const ROOMS = [
  { id: 'overwatch', envVar: 'SOUL_STUDIES_PASSWORD', label: 'Overwatch' },
  { id: 'meowmeow', envVar: 'SOUL_STUDIES_PASSWORD_2', label: 'meowmeow', defaultPassword: 'meowmeow' },
];

// ---------------------------------------------------------------------------
// Setup / config (password hashes live ONLY here, server-side, never sent out)
// ---------------------------------------------------------------------------

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(AVATARS_DIR)) fs.mkdirSync(AVATARS_DIR, { recursive: true });
if (!fs.existsSync(CHAT_IMAGES_DIR)) fs.mkdirSync(CHAT_IMAGES_DIR, { recursive: true });

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function loadOrCreateConfig() {
  let stored = {};
  if (fs.existsSync(CONFIG_PATH)) {
    try { stored = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); } catch (e) { stored = {}; }
  }

  // Migrate the old single-room format ({salt, hash, createdAt}, from before
  // this app supported multiple rooms) — that hash belongs to what is now
  // the "overwatch" room, so carry it forward instead of generating a new
  // password and breaking anyone who already knows the old one.
  if (stored.salt && stored.hash && !stored.rooms) {
    stored = { rooms: { overwatch: { salt: stored.salt, hash: stored.hash } }, createdAt: stored.createdAt || Date.now() };
  }
  if (!stored.rooms) stored.rooms = {};

  let changed = false;
  for (const room of ROOMS) {
    const envPassword = process.env[room.envVar];
    if (envPassword) {
      // Explicit operator-provided password always wins and is re-hashed fresh.
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword(envPassword, salt);
      stored.rooms[room.id] = { salt, hash };
      changed = true;
      console.log('[soul-studies] Password for room "' + room.label + '" set from ' + room.envVar + ' env var.');
      continue;
    }

    if (stored.rooms[room.id]) continue; // already has a stored hash — keep it

    const password = room.defaultPassword || crypto.randomBytes(9).toString('base64url');
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    stored.rooms[room.id] = { salt, hash };
    changed = true;

    if (!room.defaultPassword) {
      console.log('');
      console.log('==================================================================');
      console.log(' SOUL STUDIES — no password configured for room "' + room.label + '", generated one for you:');
      console.log('');
      console.log('   ' + password);
      console.log('');
      console.log(' Save it somewhere safe. To set your own instead, set ' + room.envVar + '.');
      console.log('==================================================================');
      console.log('');
    }
  }

  if (!stored.createdAt) stored.createdAt = Date.now();
  if (changed) fs.writeFileSync(CONFIG_PATH, JSON.stringify(stored), { mode: 0o600 });
  return stored;
}

let config = loadOrCreateConfig();

// Returns the matching room id, or null if the candidate doesn't match any
// room's password.
function verifyPasswordForRoom(candidate) {
  if (typeof candidate !== 'string' || candidate.length === 0 || candidate.length > 200) {
    return null;
  }
  for (const room of ROOMS) {
    const roomConfig = config.rooms[room.id];
    if (!roomConfig) continue;
    const candidateHash = Buffer.from(hashPassword(candidate, roomConfig.salt), 'hex');
    const storedHash = Buffer.from(roomConfig.hash, 'hex');
    if (candidateHash.length !== storedHash.length) continue;
    if (crypto.timingSafeEqual(candidateHash, storedHash)) return room.id;
  }
  return null;
}

// ---------------------------------------------------------------------------
// In-memory state: sessions, login rate limiting
// ---------------------------------------------------------------------------

/** sid -> { stage: 'none'|'password_ok'|'active', room, username, csrfToken, expires, ip } */
const sessions = new Map();

/** ip -> { failCount, windowStart, lockedUntil } */
const loginAttempts = new Map();

// ---------------------------------------------------------------------------
// Per-room state: chat history, username claims, avatars, chat images.
// Kept in separate namespaces (separate Maps/arrays/directories) per room id
// so the two rooms never share or leak into each other.
// ---------------------------------------------------------------------------

function loadJsonArray(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return []; // missing or corrupt file — start fresh rather than crash
  }
}

function messagesPathFor(roomId) {
  return path.join(DATA_DIR, 'messages-' + roomId + '.json');
}

function scoresPathFor(roomId) {
  return path.join(DATA_DIR, 'scores-' + roomId + '.json');
}

function loadScores(roomId) {
  let stored = {};
  try {
    stored = JSON.parse(fs.readFileSync(scoresPathFor(roomId), 'utf8'));
  } catch (e) {
    stored = {};
  }
  const scores = {};
  for (const game of GAME_IDS) {
    scores[game] = {};
    const entries = stored && typeof stored === 'object' ? stored[game] : null;
    if (!entries || typeof entries !== 'object') continue;
    for (const key of Object.keys(entries)) {
      const rec = entries[key];
      if (rec && typeof rec.username === 'string' && USERNAME_RE.test(rec.username) &&
          typeof rec.score === 'number' && isFinite(rec.score) && rec.score >= 0) {
        scores[game][key] = { username: rec.username, score: Math.floor(rec.score), ts: rec.ts || 0 };
      }
    }
  }
  return scores;
}

function topScores(roomState) {
  const out = {};
  for (const game of GAME_IDS) {
    out[game] = Object.values(roomState.scores[game])
      .sort((a, b) => b.score - a.score)
      .slice(0, 10);
  }
  return out;
}

// One-time migration of pre-multi-room data (a flat data/messages.json, and
// avatars/chat-images stored directly under data/avatars, data/chat-images)
// into the "overwatch" room's namespace, so existing chat history and
// uploaded pictures survive the upgrade instead of silently vanishing.
function migrateLegacyOverwatchData() {
  const legacyMessagesPath = path.join(DATA_DIR, 'messages.json');
  const newMessagesPath = messagesPathFor('overwatch');
  if (fs.existsSync(legacyMessagesPath) && !fs.existsSync(newMessagesPath)) {
    fs.renameSync(legacyMessagesPath, newMessagesPath);
  }

  const overwatchAvatarsDir = path.join(AVATARS_DIR, 'overwatch');
  if (!fs.existsSync(overwatchAvatarsDir)) fs.mkdirSync(overwatchAvatarsDir, { recursive: true });
  for (const entry of fs.readdirSync(AVATARS_DIR, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const dest = path.join(overwatchAvatarsDir, entry.name);
    if (!fs.existsSync(dest)) fs.renameSync(path.join(AVATARS_DIR, entry.name), dest);
  }

  const overwatchChatImagesDir = path.join(CHAT_IMAGES_DIR, 'overwatch');
  if (!fs.existsSync(overwatchChatImagesDir)) fs.mkdirSync(overwatchChatImagesDir, { recursive: true });
  for (const entry of fs.readdirSync(CHAT_IMAGES_DIR, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const dest = path.join(overwatchChatImagesDir, entry.name);
    if (!fs.existsSync(dest)) fs.renameSync(path.join(CHAT_IMAGES_DIR, entry.name), dest);
  }
}

migrateLegacyOverwatchData();

/** roomId -> { messages, byId, dirty, avatarsDir, chatImagesDir,
 *  avatarExtByUser, chatImageExtById, usernameOwners } */
const rooms = Object.create(null);

for (const room of ROOMS) {
  const avatarsDir = path.join(AVATARS_DIR, room.id);
  const chatImagesDir = path.join(CHAT_IMAGES_DIR, room.id);
  if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir, { recursive: true });
  if (!fs.existsSync(chatImagesDir)) fs.mkdirSync(chatImagesDir, { recursive: true });

  const messages = loadJsonArray(messagesPathFor(room.id));
  const byId = new Map();
  for (const m of messages) byId.set(m.id, m);

  const avatarExtByUser = new Map();
  for (const entry of fs.readdirSync(avatarsDir, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const ext = path.extname(entry.name).slice(1).toLowerCase();
    if (!ALLOWED_AVATAR_EXTS.includes(ext)) continue;
    const base = path.basename(entry.name, path.extname(entry.name));
    const key = decodeUserFileBase(base);
    if (key) avatarExtByUser.set(key, { ext, base });
  }

  const chatImageExtById = new Map();
  for (const entry of fs.readdirSync(chatImagesDir, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const ext = path.extname(entry.name).slice(1).toLowerCase();
    const base = path.basename(entry.name, path.extname(entry.name)).toLowerCase();
    if (ALLOWED_AVATAR_EXTS.includes(ext)) {
      chatImageExtById.set(base, ext);
    }
  }

  rooms[room.id] = {
    messages,
    byId,
    dirty: false,
    scores: loadScores(room.id),
    scoresDirty: false,
    avatarsDir,
    chatImagesDir,
    avatarExtByUser,
    chatImageExtById,
    // lowercase username -> sid, see releaseUsername below. A name is only
    // unavailable *within this room* while an active session there is
    // actually using it — the same name can be used independently in the
    // other room at the same time.
    usernameOwners: new Map(),
  };
}

/** Resolve an optional client-supplied reply target (within the given room)
 * into a safe, server-verified preview object — or undefined if it doesn't
 * check out. Never trusts client-provided username/text for the preview:
 * it's always looked up from the actual stored message. For a type:'text'
 * parent, the parent's ciphertext is copied onto the reply so any recipient
 * can render the quoted snippet locally (with their own room key) even if
 * that older message has since scrolled out of their poll window — the
 * server still never sees plaintext, it's just shuttling opaque bytes
 * around a second time. */
function resolveReplyTo(roomState, rawId) {
  if (typeof rawId !== 'string' || !REPLY_ID_RE.test(rawId)) return undefined;
  const parent = roomState.byId.get(rawId);
  if (!parent) return undefined;
  const preview = { id: parent.id, username: parent.username, ts: parent.ts, type: parent.type || 'text' };
  if (preview.type === 'text') preview.cipher = parent.text;
  return preview;
}

/** Shared 400ms-between-messages throttle for both text and image sends,
 * so the two endpoints can't be combined to double the effective rate. */
function tooFast(session) {
  const now = Date.now();
  if (session.lastMessageAt && now - session.lastMessageAt < 400) return true;
  session.lastMessageAt = now;
  return false;
}

/** Debounced disk writes: chat can be chatty, so coalesce writes instead of
 * doing a synchronous fs write on every single message. Worst case on an
 * unclean shutdown you lose the last ~2s of messages, not the whole history. */
function scheduleSave(roomId) {
  rooms[roomId].dirty = true;
}

setInterval(() => {
  for (const roomId of Object.keys(rooms)) {
    const r = rooms[roomId];
    if (r.dirty) {
      r.dirty = false;
      fs.writeFile(messagesPathFor(roomId), JSON.stringify(r.messages), () => {});
    }
    if (r.scoresDirty) {
      r.scoresDirty = false;
      fs.writeFile(scoresPathFor(roomId), JSON.stringify(r.scores), () => {});
    }
  }
}, 2000).unref();

function flushSaveSync() {
  for (const roomId of Object.keys(rooms)) {
    try {
      fs.writeFileSync(messagesPathFor(roomId), JSON.stringify(rooms[roomId].messages));
      fs.writeFileSync(scoresPathFor(roomId), JSON.stringify(rooms[roomId].scores));
    } catch (e) { /* best effort on shutdown */ }
  }
}

process.on('SIGINT', () => { flushSaveSync(); process.exit(0); });
process.on('SIGTERM', () => { flushSaveSync(); process.exit(0); });

function newSession(ip) {
  const sid = crypto.randomBytes(24).toString('hex');
  const session = {
    stage: 'none',
    room: null,
    username: null,
    csrfToken: crypto.randomBytes(16).toString('hex'),
    expires: Date.now() + SESSION_TTL_MS,
    lastSeen: Date.now(),
    ip,
  };
  sessions.set(sid, session);
  return { sid, session };
}

/** Release a username claim held by this session in its room, if any —
 * called on logout and on session expiry so the name becomes available
 * again (in that room only). */
function releaseUsername(sid, session) {
  if (!session || !session.username || !session.room) return;
  const roomState = rooms[session.room];
  if (!roomState) return;
  const key = session.username.toLowerCase();
  if (roomState.usernameOwners.get(key) === sid) {
    roomState.usernameOwners.delete(key);
  }
}

function getSession(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const sid = cookies.sid;
  if (!sid) return null;
  const session = sessions.get(sid);
  if (!session) return null;
  if (session.expires < Date.now()) {
    sessions.delete(sid);
    return null;
  }
  return { sid, session };
}

function parseCookies(header) {
  const out = {};
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function clientIp(req) {
  // Not trusting X-Forwarded-For blindly since there's no reverse proxy
  // configured by default here; falls back to the raw socket address.
  return req.socket.remoteAddress || 'unknown';
}

function checkRateLimit(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip) || { failCount: 0, windowStart: now, lockedUntil: 0 };
  if (rec.lockedUntil > now) {
    return { allowed: false, retryAfterSec: Math.ceil((rec.lockedUntil - now) / 1000) };
  }
  // Reset window every 10 minutes
  if (now - rec.windowStart > 10 * 60 * 1000) {
    rec.failCount = 0;
    rec.windowStart = now;
  }
  return { allowed: true, rec };
}

function recordLoginFailure(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip) || { failCount: 0, windowStart: now, lockedUntil: 0 };
  rec.failCount += 1;
  if (rec.failCount >= 5) {
    rec.lockedUntil = now + 15 * 60 * 1000; // 15 minute lockout
  }
  loginAttempts.set(ip, rec);
}

function recordLoginSuccess(ip) {
  loginAttempts.delete(ip);
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function sendJson(res, status, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  }, extraHeaders || {}));
  res.end(body);
}

function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
  );
}

function setSessionCookie(res, sid, req) {
  const secure = req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
  const parts = [
    `sid=${sid}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Strict',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  if (secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function readJsonBody(req, maxBytes) {
  const limit = maxBytes || MAX_BODY_BYTES;
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject({ status: 413, message: 'Payload too large' });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (e) {
        reject({ status: 400, message: 'Invalid JSON' });
      }
    });
    req.on('error', () => reject({ status: 400, message: 'Bad request' }));
  });
}

function readRawBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject({ status: 413, message: 'Image is too large.' });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', () => reject({ status: 400, message: 'Bad request' }));
  });
}

// ---------------------------------------------------------------------------
// Avatar handling — validated ONLY by sniffing real file bytes. The
// client-supplied filename and Content-Type header are never trusted for
// this decision; they're not even read.
// ---------------------------------------------------------------------------

const AVATAR_MIME = { jpg: 'image/jpeg', png: 'image/png', webp: 'image/webp' };

function detectImageType(buf) {
  if (buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return { ext: 'jpg' };
  }
  if (
    buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47 &&
    buf[4] === 0x0d && buf[5] === 0x0a && buf[6] === 0x1a && buf[7] === 0x0a
  ) {
    return { ext: 'png' };
  }
  if (buf.slice(0, 4).toString('ascii') === 'RIFF' && buf.slice(8, 12).toString('ascii') === 'WEBP') {
    return { ext: 'webp' };
  }
  return null;
}

// Usernames may contain any printable characters, so the on-disk file name
// is always the base64url encoding of the (lowercased) name, prefixed to
// distinguish it from legacy plain-name files. Nothing user-controlled is
// ever used as a path component.
function userFileBase(usernameKey) {
  return 'u_' + Buffer.from(usernameKey, 'utf8').toString('base64url');
}

function decodeUserFileBase(base) {
  if (base.startsWith('u_')) {
    try {
      const key = Buffer.from(base.slice(2), 'base64url').toString('utf8');
      return USERNAME_RE.test(key) ? key : null;
    } catch (e) {
      return null;
    }
  }
  return LEGACY_USERNAME_RE.test(base) ? base : null;
}

function saveAvatarFile(avatarsDir, usernameKey, ext, buf) {
  const base = userFileBase(usernameKey);
  // Remove any previous avatar for this name (other extensions, and any
  // legacy plain-name file) so nothing orphaned keeps being served.
  for (const anyExt of ALLOWED_AVATAR_EXTS) {
    const stale = [];
    if (anyExt !== ext) stale.push(path.join(avatarsDir, base + '.' + anyExt));
    if (LEGACY_USERNAME_RE.test(usernameKey)) stale.push(path.join(avatarsDir, usernameKey + '.' + anyExt));
    for (const f of stale) {
      if (fs.existsSync(f)) {
        try { fs.unlinkSync(f); } catch (e) { /* best effort */ }
      }
    }
  }
  // Write to a temp file then rename — avoids ever serving a partially
  // written file if a read races an in-progress upload.
  const finalPath = path.join(avatarsDir, base + '.' + ext);
  const tmpPath = finalPath + '.tmp-' + crypto.randomBytes(6).toString('hex');
  fs.writeFileSync(tmpPath, buf, { mode: 0o600 });
  fs.renameSync(tmpPath, finalPath);
}

function saveChatImageFile(chatImagesDir, id, ext, buf) {
  // Chat images are content-addressed by a fresh random id each time (unlike
  // avatars, which are replaced in place per-username), so there's no stale
  // file to clean up here — just write-to-temp-then-rename as usual so a
  // concurrent read never sees a partially written file.
  const finalPath = path.join(chatImagesDir, id + '.' + ext);
  const tmpPath = finalPath + '.tmp-' + crypto.randomBytes(6).toString('hex');
  fs.writeFileSync(tmpPath, buf, { mode: 0o600 });
  fs.renameSync(tmpPath, finalPath);
}

function escapeXml(str) {
  return String(str).replace(/[<>&"']/g, (c) => ({
    '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;',
  }[c]));
}

const AVATAR_PALETTE = ['#8b7355', '#6f8f76', '#93b89a', '#a65b4b', '#5b7fa6', '#a68b5b'];

function letterAvatarSvg(username) {
  const letter = escapeXml((username.charAt(0) || '?').toUpperCase());
  let hash = 0;
  for (let i = 0; i < username.length; i++) hash = (hash * 31 + username.charCodeAt(i)) >>> 0;
  const color = AVATAR_PALETTE[hash % AVATAR_PALETTE.length];
  return (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">' +
    '<rect width="64" height="64" rx="14" fill="' + color + '"/>' +
    '<text x="32" y="43" font-family="Georgia, serif" font-size="26" fill="#0f1219" ' +
    'text-anchor="middle">' + letter + '</text></svg>'
  );
}

function sendSvg(res, svg) {
  res.writeHead(200, {
    'Content-Type': 'image/svg+xml; charset=utf-8',
    'Cache-Control': 'private, max-age=120',
  });
  res.end(svg);
}

function requireCsrf(req, session) {
  const header = req.headers['x-csrf-token'];
  if (typeof header !== 'string') return false;
  const a = Buffer.from(header);
  const b = Buffer.from(session.csrfToken);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function callGptUpstream(messages) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = new URL(GPT_API_URL); } catch (e) { return reject(new Error('Bad GPT_API_URL')); }
    const payload = JSON.stringify({ model: GPT_MODEL, messages });
    const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) };
    if (GPT_API_KEY) headers.Authorization = 'Bearer ' + GPT_API_KEY;
    const lib = target.protocol === 'http:' ? http : https;
    const upstream = lib.request(target, { method: 'POST', headers, timeout: 12000 }, (resp) => {
      const chunks = [];
      let size = 0;
      resp.on('data', (c) => {
        size += c.length;
        if (size > 1024 * 1024) {
          reject(new Error('Upstream response too large'));
          upstream.destroy();
          return;
        }
        chunks.push(c);
      });
      resp.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        if (resp.statusCode < 200 || resp.statusCode >= 300) {
          return reject(new Error('Upstream status ' + resp.statusCode));
        }
        let reply = null;
        try {
          const parsed = JSON.parse(raw);
          if (parsed && parsed.choices && parsed.choices[0] && parsed.choices[0].message) {
            reply = parsed.choices[0].message.content;
          } else if (typeof parsed === 'string') {
            reply = parsed;
          }
        } catch (e) {
          reply = raw;
        }
        if (typeof reply !== 'string' || reply.trim().length === 0) {
          return reject(new Error('Empty upstream reply'));
        }
        resolve(reply);
      });
    });
    upstream.on('timeout', () => upstream.destroy(new Error('Upstream timeout')));
    upstream.on('error', reject);
    upstream.end(payload);
  });
}

function sanitizeText(str, maxLen) {
  if (typeof str !== 'string') return null;
  const stripped = str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim();
  if (stripped.length === 0 || stripped.length > maxLen) return null;
  return stripped;
}

// ---------------------------------------------------------------------------
// Static file serving (public/ only, path-traversal safe)
// ---------------------------------------------------------------------------

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
};

// The frontend is now a single-page app: every one of these paths serves
// the exact same shell (public/index.html), which then renders the right
// view client-side based on /api/session — see public/assets/app.js. This
// is UX-routing convenience only, identical in spirit to the old pretty
// routes; it grants nothing. Every API endpoint in handleApi() below
// independently re-checks session.stage (and session.room) on every
// request regardless of which path loaded the page, so hitting /chat or
// /setup directly without a valid session still can't reach any protected
// data — try it with curl and no cookie, you still get 403, not chat
// history.
const PRETTY_ROUTES = {
  '/': '/index.html',
  '/portal': '/index.html',
  '/setup': '/index.html',
  '/chat': '/index.html',
};

function serveStatic(req, res, urlPath) {
  let rel = urlPath.split('?')[0];
  rel = PRETTY_ROUTES[rel] || rel;
  const resolved = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!resolved.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }
  fs.readFile(resolved, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }
    const ext = path.extname(resolved);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------------------------------------------------------------------------
// API route handlers
// ---------------------------------------------------------------------------

async function handleApi(req, res, pathname) {
  let { sid, session } = getSession(req) || {};
  if (!session) {
    const created = newSession(clientIp(req));
    sid = created.sid;
    session = created.session;
    setSessionCookie(res, sid, req);
  }
  session.lastSeen = Date.now();

  // GET /api/session — bootstrap info for the frontend (no secrets)
  if (pathname === '/api/session' && req.method === 'GET') {
    return sendJson(res, 200, {
      stage: session.stage,
      username: session.username,
      room: session.room,
      csrfToken: session.csrfToken,
    });
  }

  // POST /api/login — the ONLY place passwords are ever checked. Whichever
  // room's password matches is the room this session is now attached to
  // for the rest of its life; the two codes lead to two independent rooms.
  if (pathname === '/api/login' && req.method === 'POST') {
    const ip = clientIp(req);
    const rl = checkRateLimit(ip);
    if (!rl.allowed) {
      return sendJson(res, 429, { error: 'Too many attempts. Try again later.', retryAfterSec: rl.retryAfterSec });
    }
    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });

    const matchedRoom = verifyPasswordForRoom(body.password);
    if (matchedRoom) {
      recordLoginSuccess(ip);
      session.stage = 'password_ok';
      session.room = matchedRoom;
      session.csrfToken = crypto.randomBytes(16).toString('hex'); // rotate on privilege change
      return sendJson(res, 200, { ok: true, csrfToken: session.csrfToken, room: matchedRoom });
    } else {
      recordLoginFailure(ip);
      return sendJson(res, 401, { error: 'Incorrect password' });
    }
  }

  // POST /api/username — requires having passed the password gate
  if (pathname === '/api/username' && req.method === 'POST') {
    if (session.stage === 'none' || !session.room) return sendJson(res, 403, { error: 'Not authorized' });
    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });

    const username = typeof body.username === 'string' ? body.username.trim() : '';
    if (!USERNAME_RE.test(username)) {
      return sendJson(res, 400, { error: 'Use 1-20 characters.' });
    }
    const roomState = rooms[session.room];
    const key = username.toLowerCase();
    if (RESERVED_USERNAMES.has(key)) {
      return sendJson(res, 409, { error: 'That name is taken. Try another.' });
    }
    // A claim is only honored while its owning session is alive AND has been
    // seen recently. Without the staleness check, closing or wiping a tab
    // (which discards the sid cookie) left the old session holding the name
    // for up to 24h, locking the user out of their own username.
    const owner = roomState.usernameOwners.get(key);
    if (owner && owner !== sid) {
      const ownerSession = sessions.get(owner);
      const ownerAlive = ownerSession &&
        ownerSession.expires > Date.now() &&
        Date.now() - (ownerSession.lastSeen || 0) < USERNAME_STALE_MS;
      if (ownerAlive) {
        return sendJson(res, 409, { error: 'That name is taken. Try another.' });
      }
      if (ownerSession) {
        ownerSession.stage = 'password_ok';
        ownerSession.username = null;
      }
      roomState.usernameOwners.delete(key);
    }
    releaseUsername(sid, session);
    roomState.usernameOwners.set(key, sid);
    session.username = username;
    session.stage = 'active';
    session.csrfToken = crypto.randomBytes(16).toString('hex'); // rotate on privilege change
    return sendJson(res, 200, { ok: true, username, room: session.room, csrfToken: session.csrfToken });
  }

  // GET /api/chat/messages — requires an active (username-created) session
  if (pathname === '/api/chat/messages' && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    const roomState = rooms[session.room];
    const url = new URL(req.url, 'http://internal');
    const since = Number(url.searchParams.get('since')) || 0;
    const recent = roomState.messages.filter((m) => m.ts > since).slice(-100);
    return sendJson(res, 200, { messages: recent, serverTime: Date.now() });
  }

  // POST /api/chat/send — requires an active session. `text` is an opaque
  // client-encrypted blob (see MAX_MESSAGE_LEN comment) — the server just
  // stores and relays it. Optional `replyTo` is the id of the message being
  // replied to; resolveReplyTo() re-derives everything about it server-side
  // rather than trusting whatever the client claims.
  if (pathname === '/api/chat/send' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    if (tooFast(session)) return sendJson(res, 429, { error: 'Sending too fast.' });

    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    const text = sanitizeText(body.text, MAX_MESSAGE_LEN);
    if (!text) return sendJson(res, 400, { error: 'Message could not be sent.' });

    const roomState = rooms[session.room];
    const now = Date.now();
    const msg = { id: crypto.randomUUID(), username: session.username, type: 'text', text, ts: now };
    const replyTo = resolveReplyTo(roomState, body.replyTo);
    if (replyTo) msg.replyTo = replyTo;
    roomState.messages.push(msg);
    roomState.byId.set(msg.id, msg);
    if (roomState.messages.length > MAX_MESSAGES_KEPT) {
      roomState.messages.splice(0, roomState.messages.length - MAX_MESSAGES_KEPT);
      roomState.byId.clear();
      for (const m of roomState.messages) roomState.byId.set(m.id, m);
    }
    scheduleSave(session.room);
    return sendJson(res, 200, { ok: true, message: msg });
  }

  // POST /api/chat/image[?replyTo=<id>] — requires an active session. The
  // raw request body is the image itself (mirrors /api/avatar). Images are
  // NOT end-to-end encrypted in this version — see SECURITY.md — they're
  // gated the same way avatars are: only reachable by an authenticated,
  // active session in this room, never served from the public static
  // directory.
  if (pathname === '/api/chat/image' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    if (tooFast(session)) return sendJson(res, 429, { error: 'Sending too fast.' });

    let buf;
    try {
      buf = await readRawBody(req, MAX_CHAT_IMAGE_BYTES);
    } catch (e) {
      return sendJson(res, e.status || 400, { error: e.message });
    }
    if (!buf || buf.length === 0) return sendJson(res, 400, { error: 'No image received.' });

    const detected = detectImageType(buf);
    if (!detected) {
      return sendJson(res, 400, { error: 'Only JPEG, PNG, or WebP images are allowed.' });
    }

    const roomState = rooms[session.room];
    const now = Date.now();
    const imgId = crypto.randomUUID();
    try {
      saveChatImageFile(roomState.chatImagesDir, imgId, detected.ext, buf);
      roomState.chatImageExtById.set(imgId, detected.ext);
    } catch (e) {
      return sendJson(res, 500, { error: 'Could not save image.' });
    }

    const url = new URL(req.url, 'http://internal');
    const msg = {
      id: crypto.randomUUID(),
      username: session.username,
      type: 'image',
      imageId: imgId,
      imageExt: detected.ext,
      ts: now,
    };
    const replyTo = resolveReplyTo(roomState, url.searchParams.get('replyTo'));
    if (replyTo) msg.replyTo = replyTo;
    roomState.messages.push(msg);
    roomState.byId.set(msg.id, msg);
    if (roomState.messages.length > MAX_MESSAGES_KEPT) {
      roomState.messages.splice(0, roomState.messages.length - MAX_MESSAGES_KEPT);
      roomState.byId.clear();
      for (const m of roomState.messages) roomState.byId.set(m.id, m);
    }
    scheduleSave(session.room);
    return sendJson(res, 200, { ok: true, message: msg });
  }

  // GET /api/chat-image/<id> — serve a previously sent chat image. Gated
  // behind the same "active session, this room" check as chat itself,
  // exactly like /api/avatar/<username> below.
  if (pathname.startsWith('/api/chat-image/') && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    const roomState = rooms[session.room];

    const id = pathname.slice('/api/chat-image/'.length);
    if (!REPLY_ID_RE.test(id)) return sendJson(res, 400, { error: 'Invalid image id' });
    const ext = roomState.chatImageExtById.get(id);
    if (!ext) return sendJson(res, 404, { error: 'Not found' });

    const filePath = path.join(roomState.chatImagesDir, id + '.' + ext);
    fs.readFile(filePath, (err, data) => {
      if (err) return sendJson(res, 404, { error: 'Not found' });
      res.writeHead(200, {
        'Content-Type': AVATAR_MIME[ext],
        // Each id is freshly random and content never changes once sent,
        // so this is safe to cache hard, unlike the mutable avatar URLs.
        'Cache-Control': 'private, max-age=31536000, immutable',
      });
      res.end(data);
    });
    return;
  }

  // POST /api/logout
  if (pathname === '/api/logout' && req.method === 'POST') {
    releaseUsername(sid, session);
    sessions.delete(sid);
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0');
    return sendJson(res, 200, { ok: true });
  }

  // POST /api/avatar — upload/replace the profile picture for the CURRENT
  // session's username, scoped to the current session's room. Requires an
  // active (username-created) session, so this is exactly as gated as chat
  // itself.
  if (pathname === '/api/avatar' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });

    let buf;
    try {
      buf = await readRawBody(req, MAX_AVATAR_BYTES);
    } catch (e) {
      return sendJson(res, e.status || 400, { error: e.message });
    }
    if (!buf || buf.length === 0) return sendJson(res, 400, { error: 'No image received.' });

    // The client-declared Content-Type and any filename are never trusted.
    // The real file type is determined ONLY by sniffing the file's magic
    // bytes, and only JPEG/PNG/WebP are accepted.
    const detected = detectImageType(buf);
    if (!detected) {
      return sendJson(res, 400, { error: 'Only JPEG, PNG, or WebP images are allowed.' });
    }

    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    try {
      saveAvatarFile(roomState.avatarsDir, key, detected.ext, buf);
      roomState.avatarExtByUser.set(key, { ext: detected.ext, base: userFileBase(key) });
    } catch (e) {
      return sendJson(res, 500, { error: 'Could not save image.' });
    }
    return sendJson(res, 200, {
      ok: true,
      avatarUrl: '/api/avatar/' + encodeURIComponent(session.username) + '?v=' + Date.now(),
    });
  }

  // GET /api/avatar/<username> — serve a profile picture, scoped to the
  // current session's room. Gated behind the same "active session" check
  // as chat itself: avatars aren't served from the public static directory
  // and aren't reachable by anyone who hasn't passed the password gate and
  // joined that specific room. Falls back to a generated "initial" avatar
  // if the user hasn't uploaded one.
  if (pathname.startsWith('/api/avatar/') && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    const roomState = rooms[session.room];

    const raw = pathname.slice('/api/avatar/'.length);
    let username;
    try { username = decodeURIComponent(raw); } catch (e) { username = raw; }
    if (!USERNAME_RE.test(username)) return sendJson(res, 400, { error: 'Invalid username' });

    const key = username.toLowerCase();
    const rec = roomState.avatarExtByUser.get(key);
    if (rec) {
      const filePath = path.join(roomState.avatarsDir, rec.base + '.' + rec.ext);
      fs.readFile(filePath, (err, data) => {
        if (err) {
          return sendSvg(res, letterAvatarSvg(username));
        }
        res.writeHead(200, {
          'Content-Type': AVATAR_MIME[rec.ext],
          'Cache-Control': 'private, max-age=120',
        });
        res.end(data);
      });
      return;
    }
    return sendSvg(res, letterAvatarSvg(username));
  }

  // GET /api/games/scores — leaderboard for this session's room
  if (pathname === '/api/games/scores' && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    return sendJson(res, 200, { scores: topScores(rooms[session.room]) });
  }

  // POST /api/games/score — record a personal best for one game
  if (pathname === '/api/games/score' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    const game = body.game;
    const score = Number(body.score);
    if (!GAME_IDS.includes(game) || !isFinite(score) || score < 0 || score > MAX_GAME_SCORE) {
      return sendJson(res, 400, { error: 'Invalid score.' });
    }
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const clean = Math.floor(score);
    const current = roomState.scores[game][key];
    if (!current || clean > current.score) {
      roomState.scores[game][key] = { username: session.username, score: clean, ts: Date.now() };
      roomState.scoresDirty = true;
    }
    return sendJson(res, 200, { ok: true, scores: topScores(roomState) });
  }

  // POST /api/gpt — relay a conversation to the configured AI backend.
  // The server adds the operator's API key (if any) so it never reaches
  // the browser.
  if (pathname === '/api/gpt' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    let body;
    try { body = await readJsonBody(req, MAX_GPT_BODY_BYTES); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    const rawMessages = Array.isArray(body.messages) ? body.messages.slice(-20) : [];
    const messages = [];
    for (const m of rawMessages) {
      if (!m || (m.role !== 'user' && m.role !== 'assistant')) continue;
      const content = sanitizeText(m.content, 8000);
      if (!content) continue;
      messages.push({ role: m.role, content });
    }
    if (messages.length === 0 || messages[messages.length - 1].role !== 'user') {
      return sendJson(res, 400, { error: 'Nothing to send.' });
    }
    try {
      const reply = await callGptUpstream(messages);
      return sendJson(res, 200, { reply: reply.slice(0, 20000) });
    } catch (e) {
      return sendJson(res, 502, { error: 'The AI backend is unreachable right now.' });
    }
  }

  return sendJson(res, 404, { error: 'Not found' });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  applySecurityHeaders(res);
  const pathname = req.url.split('?')[0];

  if (pathname.startsWith('/api/')) {
    handleApi(req, res, pathname).catch((err) => {
      console.error('[soul-studies] Unhandled error:', err);
      sendJson(res, 500, { error: 'Internal error' });
    });
    return;
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    return serveStatic(req, res, pathname);
  }

  res.writeHead(405); res.end('Method not allowed');
});

// Periodic cleanup of expired sessions — also frees any username the
// session was holding (in its room), so it becomes available for reuse.
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) {
    if (s.expires < now) {
      releaseUsername(sid, s);
      sessions.delete(sid);
    }
  }
}, 60 * 1000).unref();

server.listen(PORT, () => {
  console.log(`[soul-studies] Listening on http://localhost:${PORT}`);
});
