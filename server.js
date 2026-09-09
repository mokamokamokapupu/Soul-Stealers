'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');
const zlib = require('zlib');
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
const MAX_MESSAGE_LEN = 4000;
const MAX_MESSAGES_KEPT = 300;
const ALLOWED_AVATAR_EXTS = ['jpg', 'png', 'webp'];
// 'enc' = AES-GCM ciphertext this server can't read. Avatars stay real images.
const ALLOWED_CHAT_IMAGE_EXTS = ['jpg', 'png', 'webp', 'enc'];
const REPLY_ID_RE = /^[0-9a-fA-F-]{1,100}$/;
const GAME_IDS = ['snake', 'tetris', 'mines', 'poker', 'cookie'];
// Closed set of activity codes. Never free text: the client re-labels these for display.
const ACTIVITY_CODES = [
  'chat', 'essay', 'arcade', 'spotify', 'idle',
  'game:snake', 'game:tetris', 'game:mines', 'game:poker', 'game:cookie', 'game:doom',
];
const MAX_GAME_SCORE = 1e15;
// How long a reported activity stays believable without a refresh.
const ACTIVITY_STALE_MS = 2 * 60 * 1000;
const USERNAME_STALE_MS = 90 * 1000;

const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID || '';
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET || '';
const SPOTIFY_ENABLED = Boolean(SPOTIFY_CLIENT_ID && SPOTIFY_CLIENT_SECRET);
const SPOTIFY_SCOPES = [
  'user-read-email',
  'user-read-private',
  'user-read-playback-state',
  'user-read-currently-playing',
  'user-modify-playback-state',
  'playlist-read-private',
  'playlist-read-collaborative',
  // 'streaming' is required by the Web Playback SDK; accounts linked before it need a reconnect.
  'streaming',
].join(' ');
// Signs the OAuth `state` so the callback works without the SameSite=Strict cookie.
const SPOTIFY_STATE_SECRET = crypto.randomBytes(32);
const SPOTIFY_STATE_TTL_MS = 5 * 60 * 1000;

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

/** sid -> { stage: 'none'|'password_ok'|'active', room, username, csrfToken, expires, ip } */
const sessions = new Map();

/** ip -> { failCount, windowStart, lockedUntil } */
const loginAttempts = new Map();

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

/** Seeded records merged in at boot: the free Render plan has no persistent disk,
 * so every deploy wipes data/. A seed only ever raises a score, never lowers one. */
function loadSeedScores() {
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(ROOT, 'seed-scores.json'), 'utf8'));
    return raw && typeof raw === 'object' ? raw : {};
  } catch (e) {
    return {};
  }
}
const SEED_SCORES = loadSeedScores();

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

  // Merge the committed records on top. A seed only ever RAISES a score: if
  // that player already has a higher live score it wins, and if they later
  // score lower their record still stands — which is what a record means.
  const seedRoom = SEED_SCORES && typeof SEED_SCORES === 'object' ? SEED_SCORES[roomId] : null;
  if (seedRoom && typeof seedRoom === 'object') {
    for (const game of GAME_IDS) {
      const seeded = seedRoom[game];
      if (!Array.isArray(seeded)) continue;
      for (const rec of seeded) {
        if (!rec || typeof rec.username !== 'string' || !USERNAME_RE.test(rec.username)) continue;
        if (typeof rec.score !== 'number' || !isFinite(rec.score) || rec.score < 0 || rec.score > MAX_GAME_SCORE) continue;
        const key = rec.username.toLowerCase();
        const score = Math.floor(rec.score);
        const current = scores[game][key];
        if (!current || score > current.score) {
          scores[game][key] = { username: rec.username, score, ts: rec.ts || 0 };
        }
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

function spotifyTokensPathFor(roomId) {
  return path.join(DATA_DIR, 'spotify-' + roomId + '.json');
}

function loadSpotifyTokens(roomId) {
  let stored = {};
  try {
    stored = JSON.parse(fs.readFileSync(spotifyTokensPathFor(roomId), 'utf8'));
  } catch (e) {
    stored = {};
  }
  const tokens = {};
  if (stored && typeof stored === 'object') {
    for (const key of Object.keys(stored)) {
      const rec = stored[key];
      if (rec && typeof rec.accessToken === 'string' && typeof rec.refreshToken === 'string' &&
          typeof rec.expiresAt === 'number') {
        tokens[key] = {
          accessToken: rec.accessToken,
          refreshToken: rec.refreshToken,
          expiresAt: rec.expiresAt,
          scope: typeof rec.scope === 'string' ? rec.scope : '',
          displayName: typeof rec.displayName === 'string' ? rec.displayName : '',
          connectedAt: typeof rec.connectedAt === 'number' ? rec.connectedAt : Date.now(),
        };
      }
    }
  }
  return tokens;
}

function sessionsPath() {
  return path.join(DATA_DIR, 'sessions.json');
}

// Persisted to data/sessions.json so a restart doesn't silently log everyone out.
function loadSessions() {
  let stored;
  try {
    stored = JSON.parse(fs.readFileSync(sessionsPath(), 'utf8'));
  } catch (e) {
    return; // missing or corrupt file — start with no sessions, not a crash
  }
  if (!Array.isArray(stored)) return;
  const now = Date.now();
  const roomIds = new Set(ROOMS.map((r) => r.id));
  for (const entry of stored) {
    if (!Array.isArray(entry) || entry.length !== 2) continue;
    const [sid, s] = entry;
    if (typeof sid !== 'string' || !/^[0-9a-f]{16,64}$/i.test(sid)) continue;
    if (!s || typeof s !== 'object') continue;
    if (s.stage !== 'none' && s.stage !== 'password_ok' && s.stage !== 'active') continue;
    if (typeof s.expires !== 'number' || s.expires <= now) continue; // drop expired
    if (s.room !== null && !roomIds.has(s.room)) continue;
    if (s.username !== null && (typeof s.username !== 'string' || !USERNAME_RE.test(s.username))) continue;
    if (typeof s.csrfToken !== 'string' || !/^[0-9a-f]{32}$/i.test(s.csrfToken)) continue;
    const session = {
      stage: s.stage,
      room: s.room,
      username: s.username,
      csrfToken: s.csrfToken,
      expires: s.expires,
      lastSeen: typeof s.lastSeen === 'number' ? s.lastSeen : now,
      ip: typeof s.ip === 'string' ? s.ip : 'unknown',
    };
    sessions.set(sid, session);
    // Re-claim the username slot in its room so a second person can't grab
    // the same name out from under a session restored from disk.
    if (session.stage === 'active' && session.username && session.room) {
      const roomState = rooms[session.room];
      const key = session.username.toLowerCase();
      if (roomState && !RESERVED_USERNAMES.has(key) && !roomState.usernameOwners.has(key)) {
        roomState.usernameOwners.set(key, sid);
      }
    }
  }
}

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

/** roomId -> { messages, byId, dirty, spotifyTokens, spotifyDirty,
 *  avatarsDir, chatImagesDir, avatarExtByUser, chatImageExtById,
 *  usernameOwners } */
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
    if (ALLOWED_CHAT_IMAGE_EXTS.includes(ext)) {
      chatImageExtById.set(base, ext);
    }
  }

  rooms[room.id] = {
    messages,
    byId,
    dirty: false,
    clearedAt: 0,
    scores: loadScores(room.id),
    scoresDirty: false,
    spotifyTokens: loadSpotifyTokens(room.id),
    spotifyDirty: false,
    avatarsDir,
    chatImagesDir,
    avatarExtByUser,
    chatImageExtById,
    usernameOwners: new Map(),
  };
}

loadSessions();

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

function spotifyDeviceIdOrFalse(v) {
  if (v === undefined || v === null || v === '') return '';
  if (typeof v === 'string' && /^[A-Za-z0-9]{1,64}$/.test(v)) return v;
  return false;
}

/** Separate, tighter throttle for Spotify transport-control calls (play/
 * pause/skip), independent of the chat-message throttle above. */
function spotifyTooFast(session) {
  const now = Date.now();
  if (session.lastSpotifyActionAt && now - session.lastSpotifyActionAt < 250) return true;
  session.lastSpotifyActionAt = now;
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
    if (r.spotifyDirty) {
      r.spotifyDirty = false;
      fs.writeFile(spotifyTokensPathFor(roomId), JSON.stringify(r.spotifyTokens), { mode: 0o600 }, () => {});
    }
  }
  fs.writeFile(sessionsPath(), JSON.stringify(Array.from(sessions.entries())), { mode: 0o600 }, () => {});
}, 2000).unref();

function flushSaveSync() {
  for (const roomId of Object.keys(rooms)) {
    try {
      fs.writeFileSync(messagesPathFor(roomId), JSON.stringify(rooms[roomId].messages));
      fs.writeFileSync(scoresPathFor(roomId), JSON.stringify(rooms[roomId].scores));
      fs.writeFileSync(spotifyTokensPathFor(roomId), JSON.stringify(rooms[roomId].spotifyTokens), { mode: 0o600 });
    } catch (e) { /* best effort on shutdown */ }
  }
  try {
    fs.writeFileSync(sessionsPath(), JSON.stringify(Array.from(sessions.entries())), { mode: 0o600 });
  } catch (e) { /* best effort on shutdown */ }
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

function activeUsernamesInRoom(roomId) {
  const roomState = rooms[roomId];
  if (!roomState) return [];
  const now = Date.now();
  const names = [];
  for (const [key, sid] of roomState.usernameOwners) {
    const s = sessions.get(sid);
    if (s && s.username && now - (s.lastSeen || 0) < USERNAME_STALE_MS) {
      // An activity that stopped being refreshed a while ago is stale —
      // the tab is still checking in, but whatever it last said it was
      // doing is no longer worth believing, so fall back to unknown.
      const fresh = s.activity && now - (s.activityAt || 0) < ACTIVITY_STALE_MS;
      names.push({ name: s.username, activity: fresh ? s.activity : null });
    }
  }
  names.sort((a, b) => a.name.localeCompare(b.name));
  return names;
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
    // GET /api/spotify/player-token — the one place a token reaches the browser,
    // required by the Web Playback SDK. See the CSP note in applySecurityHeaders.
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' https://sdk.scdn.co; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; " +
    // blob: is for decrypted chat images, minted in-page from bytes it already holds.
    "img-src 'self' data: blob: https://*.scdn.co; " +
    "connect-src 'self' https://*.spotify.com wss://*.spotify.com https://*.scdn.co; " +
    "media-src 'self' blob: https://*.scdn.co; frame-src https://sdk.scdn.co https://*.spotify.com; " +
    "frame-ancestors 'none'; base-uri 'none'"
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

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
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

// Avatars are validated by sniffing real file bytes, never a filename or Content-Type.

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

// Usernames can hold any printable char, so the on-disk name is a hash, never the name itself.
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

function sanitizeText(str, maxLen) {
  if (typeof str !== 'string') return null;
  const stripped = str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim();
  if (stripped.length === 0 || stripped.length > maxLen) return null;
  return stripped;
}

function base64UrlJson(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

function signState(payload) {
  const body = base64UrlJson(payload);
  const sig = crypto.createHmac('sha256', SPOTIFY_STATE_SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}

function verifyState(state) {
  if (typeof state !== 'string' || state.length > 2000) return null;
  const idx = state.lastIndexOf('.');
  if (idx === -1) return null;
  const body = state.slice(0, idx);
  const sig = state.slice(idx + 1);
  const expected = crypto.createHmac('sha256', SPOTIFY_STATE_SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
  if (!payload || typeof payload !== 'object') return null;
  if (typeof payload.exp !== 'number' || payload.exp < Date.now()) return null;
  if (typeof payload.room !== 'string' || typeof payload.username !== 'string') return null;
  return payload;
}

function httpsRequestJson(options, body) {
  return new Promise((resolve, reject) => {
    const reqOptions = Object.assign({}, options, {
      headers: Object.assign({ 'Accept-Encoding': 'gzip, deflate, br' }, options.headers || {}),
    });
    const req = https.request(reqOptions, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        const encoding = (res.headers['content-encoding'] || '').toLowerCase();
        let decoded;
        try {
          if (!buf.length) decoded = buf;
          else if (encoding === 'gzip') decoded = zlib.gunzipSync(buf);
          else if (encoding === 'deflate') decoded = zlib.inflateSync(buf);
          else if (encoding === 'br') decoded = zlib.brotliDecompressSync(buf);
          else decoded = buf;
        } catch (e) {
          decoded = buf; // decoding failed — fall through and let JSON.parse fail cleanly below
        }
        const raw = decoded.toString('utf8');
        if (!raw) return resolve({ status: res.statusCode, json: null });
        try {
          resolve({ status: res.statusCode, json: JSON.parse(raw) });
        } catch (e) {
          resolve({ status: res.statusCode, json: null });
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => req.destroy(new Error('Spotify request timed out')));
    if (body) req.write(body);
    req.end();
  });
}

/** Fetches an image (album art) from Spotify's own CDN, following one
 * redirect hop if given. Small, best-effort buffering — album art is a few
 * tens of KB — no streaming complexity needed. */
function httpsGetBuffer(target) {
  return new Promise((resolve, reject) => {
    const req = https.request(target, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(httpsGetBuffer(res.headers.location));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        contentType: res.headers['content-type'] || 'application/octet-stream',
        buffer: Buffer.concat(chunks),
      }));
    });
    req.on('error', reject);
    req.setTimeout(10000, () => req.destroy(new Error('Spotify image request timed out')));
    req.end();
  });
}

/** Exchanges an authorization code, or a refresh token, for tokens. `params`
 * is the exact application/x-www-form-urlencoded grant body Spotify wants. */
function spotifyTokenRequest(params) {
  const body = new URLSearchParams(params).toString();
  const auth = Buffer.from(SPOTIFY_CLIENT_ID + ':' + SPOTIFY_CLIENT_SECRET).toString('base64');
  return httpsRequestJson({
    hostname: 'accounts.spotify.com',
    path: '/api/token',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body),
      'Authorization': 'Basic ' + auth,
    },
  }, body);
}

/** Authenticated call to the real Spotify Web API. `bodyObj` (if given) is
 * sent as JSON. Returns { status, json }. */
function spotifyApiRequest(method, urlPath, accessToken, bodyObj) {
  const body = bodyObj !== undefined ? JSON.stringify(bodyObj) : null;
  const headers = { 'Authorization': 'Bearer ' + accessToken };
  if (body) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(body);
  }
  return httpsRequestJson({ hostname: 'api.spotify.com', path: urlPath, method, headers }, body);
}

function logSpotifyIssue(context, status, json) {
  let snippet = '(no body)';
  try {
    if (json !== null && json !== undefined) snippet = JSON.stringify(json).slice(0, 500);
  } catch (e) { snippet = '(body not serializable)'; }
  console.error('[spotify] ' + context + ' -> HTTP ' + status + ' ' + snippet);
}

// A Spotify 403 is one of three things: account not allowlisted (most common),
// genuinely not Premium (reason PREMIUM_REQUIRED), or a token missing a scope.
// /v1/search needs neither scope nor Premium, so a 403 there is never Premium.
function spotifyForbiddenKind(json) {
  const err = (json && json.error) || {};
  const reason = typeof err.reason === 'string' ? err.reason : '';
  const message = typeof err.message === 'string' ? err.message : '';
  if (reason === 'PREMIUM_REQUIRED' || /premium/i.test(message)) return 'premium';
  if (/scope/i.test(message)) return 'scope';
  return 'allowlist';
}

const SPOTIFY_NOT_ALLOWED_MSG = 'This Spotify account is not approved for this app yet. Whoever set up the Spotify app has to add it under User Management in the Spotify developer dashboard — Spotify only lets a handful of accounts use an app until then. (Nothing to do with Premium.)';

function spotifyForbiddenMessage(action, json) {
  const kind = spotifyForbiddenKind(json);
  if (kind === 'premium') return action + ' needs Spotify Premium.';
  if (kind === 'scope') return 'Reconnect Spotify — this connection is missing a permission it now needs.';
  return SPOTIFY_NOT_ALLOWED_MSG;
}

function sendSpotifyForbidden(res, context, action, status, json) {
  logSpotifyIssue(context + ' (403 forbidden)', status, json);
  return sendJson(res, 409, {
    error: spotifyForbiddenMessage(action, json),
    notAllowed: spotifyForbiddenKind(json) === 'allowlist',
  });
}

async function ensureFreshSpotifyToken(roomState, key) {
  const rec = roomState.spotifyTokens[key];
  if (!rec) return null;
  if (rec.expiresAt - Date.now() > 60 * 1000) return rec.accessToken;

  try {
    const { status, json } = await spotifyTokenRequest({
      grant_type: 'refresh_token',
      refresh_token: rec.refreshToken,
    });
    if (status !== 200 || !json || !json.access_token) {
      logSpotifyIssue('token refresh for ' + key, status, json);
      delete roomState.spotifyTokens[key];
      roomState.spotifyDirty = true;
      return null;
    }
    rec.accessToken = json.access_token;
    if (json.refresh_token) rec.refreshToken = json.refresh_token;
    rec.expiresAt = Date.now() + (Number(json.expires_in) || 3600) * 1000;
    if (typeof json.scope === 'string') rec.scope = json.scope;
    roomState.spotifyDirty = true;
    return rec.accessToken;
  } catch (e) {
    return null;
  }
}

function dropSpotifyConnection(roomState, key) {
  if (roomState.spotifyTokens[key]) {
    delete roomState.spotifyTokens[key];
    roomState.spotifyDirty = true;
  }
}

function spotifyRedirectUri(req) {
  if (process.env.SPOTIFY_REDIRECT_URI) return process.env.SPOTIFY_REDIRECT_URI;
  const secure = req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
  return (secure ? 'https' : 'http') + '://' + req.headers.host + '/api/spotify/callback';
}

function simplifyTrack(t) {
  if (!t) return null;
  const images = (t.album && Array.isArray(t.album.images)) ? t.album.images : [];
  const art = images.length ? (images[Math.min(1, images.length - 1)] || images[0]).url : null;
  return {
    id: t.id,
    uri: t.uri,
    name: t.name,
    artists: Array.isArray(t.artists) ? t.artists.map((a) => a.name).join(', ') : '',
    album: t.album ? t.album.name : '',
    durationMs: t.duration_ms || 0,
    albumArt: art ? '/api/spotify/image?u=' + encodeURIComponent(art) : null,
  };
}

function simplifyPlaylist(p) {
  if (!p) return null;
  const images = Array.isArray(p.images) ? p.images : [];
  const art = images.length ? (images[Math.min(1, images.length - 1)] || images[0]).url : null;
  return {
    id: p.id,
    uri: p.uri,
    name: p.name,
    owner: p.owner ? (p.owner.display_name || p.owner.id || '') : '',
    trackCount: p.tracks ? (p.tracks.total || 0) : 0,
    image: art ? '/api/spotify/image?u=' + encodeURIComponent(art) : null,
  };
}

function simplifyArtist(a) {
  if (!a) return null;
  const images = Array.isArray(a.images) ? a.images : [];
  const art = images.length ? (images[Math.min(1, images.length - 1)] || images[0]).url : null;
  return {
    id: a.id,
    uri: a.uri,
    name: a.name,
    genres: Array.isArray(a.genres) ? a.genres.slice(0, 3) : [],
    image: art ? '/api/spotify/image?u=' + encodeURIComponent(art) : null,
  };
}

function simplifyAlbum(al) {
  if (!al) return null;
  const images = Array.isArray(al.images) ? al.images : [];
  const art = images.length ? (images[Math.min(1, images.length - 1)] || images[0]).url : null;
  return {
    id: al.id,
    uri: al.uri,
    name: al.name,
    artists: Array.isArray(al.artists) ? al.artists.map((a) => a.name).join(', ') : '',
    year: al.release_date ? String(al.release_date).slice(0, 4) : '',
    totalTracks: al.total_tracks || 0,
    image: art ? '/api/spotify/image?u=' + encodeURIComponent(art) : null,
  };
}

// Playlist items nest the track under `item`, not the deprecated `track` key.
function simplifyPlaylistItem(entry) {
  if (!entry || entry.is_local) return null;
  const t = entry.item || entry.track;
  if (!t || (t.type && t.type !== 'track')) return null;
  return simplifyTrack(t);
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
  '.wasm': 'application/wasm',
};

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

  // Any API call may carry ?activity=. Unknown values are dropped.
  if (session.stage === 'active') {
    const qi = req.url.indexOf('?');
    if (qi !== -1) {
      const activity = new URLSearchParams(req.url.slice(qi + 1)).get('activity');
      if (activity && ACTIVITY_CODES.includes(activity)) {
        session.activity = activity;
        session.activityAt = Date.now();
      }
    }
  }

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
    // A name is only held while its session is alive and recently seen.
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
    return sendJson(res, 200, {
      messages: recent,
      serverTime: Date.now(),
      clearedAt: roomState.clearedAt,
      activeUsers: activeUsernamesInRoom(session.room),
    });
  }

  // POST /api/chat/clear — wipe this room's entire history, including any
  // sent images on disk. Every room member has this power; other clients
  // notice via the clearedAt stamp on their next poll.
  if (pathname === '/api/chat/clear' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    const roomState = rooms[session.room];
    roomState.messages.length = 0;
    roomState.byId.clear();
    roomState.clearedAt = Date.now();
    for (const [imgId, ext] of roomState.chatImageExtById) {
      try { fs.unlinkSync(path.join(roomState.chatImagesDir, imgId + '.' + ext)); } catch (e) { /* best effort */ }
    }
    roomState.chatImageExtById.clear();
    scheduleSave(session.room);
    return sendJson(res, 200, { ok: true, clearedAt: roomState.clearedAt });
  }

  // POST /api/chat/send
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

  // POST /api/chat/image[?replyTo=<id>]
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

    // ?enc=1: body is AES-GCM ciphertext, so detectImageType can't run. The browser
    // checks magic bytes before encrypting and after decrypting instead, and these
    // bytes are only ever served as application/octet-stream, never as an image.
    const uploadUrl = new URL(req.url, 'http://internal');
    const encrypted = uploadUrl.searchParams.get('enc') === '1';

    let ext;
    if (encrypted) {
      // 12-byte IV + 16-byte GCM tag is the floor for a well-formed sealed
      // payload; anything shorter can't be one, whatever it claims.
      if (buf.length < 29) return sendJson(res, 400, { error: 'That image looks corrupted.' });
      ext = 'enc';
    } else {
      const detected = detectImageType(buf);
      if (!detected) {
        return sendJson(res, 400, { error: 'Only JPEG, PNG, or WebP images are allowed.' });
      }
      ext = detected.ext;
    }

    const roomState = rooms[session.room];
    const now = Date.now();
    const imgId = crypto.randomUUID();
    try {
      saveChatImageFile(roomState.chatImagesDir, imgId, ext, buf);
      roomState.chatImageExtById.set(imgId, ext);
    } catch (e) {
      return sendJson(res, 500, { error: 'Could not save image.' });
    }

    const msg = {
      id: crypto.randomUUID(),
      username: session.username,
      type: 'image',
      imageId: imgId,
      imageExt: ext,
      encrypted,
      ts: now,
    };
    const replyTo = resolveReplyTo(roomState, uploadUrl.searchParams.get('replyTo'));
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
        // An 'enc' file is ciphertext: it goes out as opaque bytes for the
        // page to fetch and decrypt, and is deliberately never labelled as
        // an image type, so no browser ever tries to render it directly.
        'Content-Type': AVATAR_MIME[ext] || 'application/octet-stream',
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

  // POST /api/avatar
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

  // GET /api/avatar/<username>
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

  // GET /api/spotify/login
  if (pathname === '/api/spotify/login' && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });

    const state = signState({
      room: session.room,
      username: session.username,
      nonce: crypto.randomBytes(8).toString('hex'),
      exp: Date.now() + SPOTIFY_STATE_TTL_MS,
    });
    const params = new URLSearchParams({
      client_id: SPOTIFY_CLIENT_ID,
      response_type: 'code',
      redirect_uri: spotifyRedirectUri(req),
      scope: SPOTIFY_SCOPES,
      state,
      show_dialog: 'false',
    });
    res.writeHead(302, { Location: 'https://accounts.spotify.com/authorize?' + params.toString() });
    return res.end();
  }

  // GET /api/spotify/callback
  if (pathname === '/api/spotify/callback' && req.method === 'GET') {
    const url = new URL(req.url, 'http://internal');
    const redirectHome = (flag) => { res.writeHead(302, { Location: '/?spotify=' + flag }); res.end(); };

    if (!SPOTIFY_ENABLED) return redirectHome('error');
    if (url.searchParams.get('error')) return redirectHome('denied');

    const payload = verifyState(url.searchParams.get('state'));
    if (!payload || !rooms[payload.room]) return redirectHome('error');

    const code = url.searchParams.get('code');
    if (typeof code !== 'string' || !code) return redirectHome('error');

    let tokenRes;
    try {
      tokenRes = await spotifyTokenRequest({
        grant_type: 'authorization_code',
        code,
        redirect_uri: spotifyRedirectUri(req),
      });
    } catch (e) {
      console.error('[spotify] callback token exchange threw', e && e.message);
      return redirectHome('error');
    }
    if (tokenRes.status !== 200 || !tokenRes.json || !tokenRes.json.access_token) {
      logSpotifyIssue('callback token exchange', tokenRes.status, tokenRes.json);
      return redirectHome('error');
    }

    const json = tokenRes.json;
    const roomState = rooms[payload.room];
    const key = payload.username.toLowerCase();

    let displayName = '';
    try {
      const me = await spotifyApiRequest('GET', '/v1/me', json.access_token);
      // 403 here = authorized but not on the app's allowlist. Refuse rather than save
      // a connection that would fail on every later call.
      if (me.status === 403) {
        logSpotifyIssue('callback /v1/me for ' + key, me.status, me.json);
        return redirectHome('notallowed');
      }
      if (me.status === 200 && me.json && typeof me.json.display_name === 'string') {
        displayName = me.json.display_name;
      }
    } catch (e) { /* not critical — the connection still succeeds without it */ }

    roomState.spotifyTokens[key] = {
      accessToken: json.access_token,
      refreshToken: json.refresh_token || (roomState.spotifyTokens[key] && roomState.spotifyTokens[key].refreshToken) || '',
      expiresAt: Date.now() + (Number(json.expires_in) || 3600) * 1000,
      scope: typeof json.scope === 'string' ? json.scope : '',
      displayName,
      connectedAt: Date.now(),
    };
    roomState.spotifyDirty = true;
    return redirectHome('connected');
  }

  // GET /api/spotify/status
  if (pathname === '/api/spotify/status' && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    const roomState = rooms[session.room];
    const rec = roomState.spotifyTokens[session.username.toLowerCase()];
    return sendJson(res, 200, {
      enabled: SPOTIFY_ENABLED,
      connected: Boolean(rec),
      displayName: rec ? rec.displayName : null,
    });
  }

  // POST /api/spotify/disconnect
  if (pathname === '/api/spotify/disconnect' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    if (roomState.spotifyTokens[key]) {
      delete roomState.spotifyTokens[key];
      roomState.spotifyDirty = true;
    }
    return sendJson(res, 200, { ok: true });
  }

  // GET /api/spotify/image?u=<encoded album-art URL>
  if (pathname === '/api/spotify/image' && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    const url = new URL(req.url, 'http://internal');
    let parsed;
    try { parsed = new URL(url.searchParams.get('u') || ''); } catch (e) { return sendJson(res, 400, { error: 'Invalid image URL' }); }
    const host = parsed.hostname;
    const allowed = parsed.protocol === 'https:' && (host === 'i.scdn.co' || host.endsWith('.scdn.co') || host.endsWith('.spotifycdn.com'));
    if (!allowed) return sendJson(res, 400, { error: 'Invalid image URL' });

    try {
      const { status, contentType, buffer } = await httpsGetBuffer(parsed.toString());
      if (status !== 200 || !buffer.length) return sendJson(res, 404, { error: 'Not found' });
      res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': 'private, max-age=86400, immutable' });
      return res.end(buffer);
    } catch (e) {
      return sendJson(res, 502, { error: 'Could not load image' });
    }
  }

  // GET /api/spotify/now-playing
  if (pathname === '/api/spotify/now-playing' && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    try {
      const { status, json } = await spotifyApiRequest('GET', '/v1/me/player', token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 204 || !json) return sendJson(res, 200, { connected: true, playing: false, track: null, volumePercent: null, shuffle: false, repeat: 'off' });
      return sendJson(res, 200, {
        connected: true,
        playing: Boolean(json.is_playing),
        progressMs: json.progress_ms || 0,
        track: simplifyTrack(json.item),
        volumePercent: (json.device && typeof json.device.volume_percent === 'number') ? json.device.volume_percent : null,
        shuffle: Boolean(json.shuffle_state),
        repeat: typeof json.repeat_state === 'string' ? json.repeat_state : 'off',
      });
    } catch (e) {
      console.error('[spotify] now-playing threw', e && e.message);
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // GET /api/spotify/player-token — the one place a token reaches the browser,
  // required by the Web Playback SDK. See the CSP note in applySecurityHeaders.
  if (pathname === '/api/spotify/player-token' && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });
    return sendJson(res, 200, { accessToken: token });
  }

  // POST /api/spotify/transfer
  if (pathname === '/api/spotify/transfer' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    if (spotifyTooFast(session)) return sendJson(res, 429, { error: 'Slow down a little.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    if (typeof body.deviceId !== 'string' || !/^[A-Za-z0-9]{1,64}$/.test(body.deviceId)) {
      return sendJson(res, 400, { error: 'Invalid device' });
    }

    try {
      const { status, json } = await spotifyApiRequest('PUT', '/v1/me/player', token, {
        device_ids: [body.deviceId],
        play: Boolean(body.play),
      });
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 403) return sendSpotifyForbidden(res, 'transfer', 'Playback control', status, json);
      if (status >= 400) { logSpotifyIssue('transfer', status, json); return sendJson(res, 502, { error: 'Spotify could not switch to this device.' }); }
      return sendJson(res, 200, { ok: true });
    } catch (e) {
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // POST /api/spotify/volume — body: { percent: 0-100 }.
  if (pathname === '/api/spotify/volume' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    if (spotifyTooFast(session)) return sendJson(res, 429, { error: 'Slow down a little.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    const percent = Math.round(Number(body.percent));
    if (!Number.isFinite(percent) || percent < 0 || percent > 100) return sendJson(res, 400, { error: 'Invalid volume' });
    const devId = spotifyDeviceIdOrFalse(body.deviceId);
    if (devId === false) return sendJson(res, 400, { error: 'Invalid device' });

    try {
      const { status, json } = await spotifyApiRequest('PUT', '/v1/me/player/volume?volume_percent=' + percent + (devId ? '&device_id=' + devId : ''), token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 404) return sendJson(res, 409, { error: 'Open Spotify on a device first, then try again.' });
      if (status === 403) return sendSpotifyForbidden(res, 'volume', 'Volume control', status, json);
      if (status >= 400) { logSpotifyIssue('volume', status, json); return sendJson(res, 502, { error: 'Spotify could not change the volume.' }); }
      return sendJson(res, 200, { ok: true });
    } catch (e) {
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // POST /api/spotify/seek — body: { positionMs: 0-... }. Lets the player
  // bar's progress track be click-to-seek, like the real Spotify player.
  if (pathname === '/api/spotify/seek' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    if (spotifyTooFast(session)) return sendJson(res, 429, { error: 'Slow down a little.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    const positionMs = Math.round(Number(body.positionMs));
    if (!Number.isFinite(positionMs) || positionMs < 0) return sendJson(res, 400, { error: 'Invalid position' });
    const devId = spotifyDeviceIdOrFalse(body.deviceId);
    if (devId === false) return sendJson(res, 400, { error: 'Invalid device' });

    try {
      const { status, json } = await spotifyApiRequest('PUT', '/v1/me/player/seek?position_ms=' + positionMs + (devId ? '&device_id=' + devId : ''), token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 404) return sendJson(res, 409, { error: 'Open Spotify on a device first, then try again.' });
      if (status === 403) return sendSpotifyForbidden(res, 'seek', 'Seeking', status, json);
      if (status >= 400) { logSpotifyIssue('seek', status, json); return sendJson(res, 502, { error: 'Spotify could not seek that.' }); }
      return sendJson(res, 200, { ok: true });
    } catch (e) {
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // GET /api/spotify/artists/<id>
  if (pathname.startsWith('/api/spotify/artists/') && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    const artistId = pathname.slice('/api/spotify/artists/'.length);
    if (!/^[A-Za-z0-9]{1,64}$/.test(artistId)) return sendJson(res, 400, { error: 'Invalid artist id' });

    try {
      const [artistRes, topRes, albumsRes] = await Promise.all([
        spotifyApiRequest('GET', '/v1/artists/' + artistId, token),
        spotifyApiRequest('GET', '/v1/artists/' + artistId + '/top-tracks?market=from_token', token),
        spotifyApiRequest('GET', '/v1/artists/' + artistId + '/albums?include_groups=album,single&limit=20', token),
      ]);
      if (artistRes.status === 401 || topRes.status === 401 || albumsRes.status === 401) {
        dropSpotifyConnection(roomState, key);
        return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });
      }
      if (artistRes.status === 404) return sendJson(res, 404, { error: 'Artist not found.' });
      if (artistRes.status !== 200 || !artistRes.json) {
        logSpotifyIssue('artist ' + artistId, artistRes.status, artistRes.json);
        return sendJson(res, 502, { error: 'Could not load that artist.' });
      }
      return sendJson(res, 200, {
        artist: simplifyArtist(artistRes.json),
        topTracks: topRes.status === 200 && topRes.json ? (topRes.json.tracks || []).map(simplifyTrack).filter(Boolean) : [],
        albums: albumsRes.status === 200 && albumsRes.json ? (albumsRes.json.items || []).map(simplifyAlbum).filter(Boolean) : [],
      });
    } catch (e) {
      console.error('[spotify] artist ' + artistId + ' threw', e && e.message);
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // GET /api/spotify/albums/<id>
  if (pathname.startsWith('/api/spotify/albums/') && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    const albumId = pathname.slice('/api/spotify/albums/'.length);
    if (!/^[A-Za-z0-9]{1,64}$/.test(albumId)) return sendJson(res, 400, { error: 'Invalid album id' });

    try {
      const { status, json } = await spotifyApiRequest('GET', '/v1/albums/' + albumId, token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 404) return sendJson(res, 404, { error: 'Album not found.' });
      if (status !== 200 || !json) {
        logSpotifyIssue('album ' + albumId, status, json);
        return sendJson(res, 502, { error: 'Could not load that album.' });
      }
      const albumStub = { name: json.name, images: json.images };
      const tracks = (json.tracks && Array.isArray(json.tracks.items) ? json.tracks.items : [])
        .map((t) => (t ? simplifyTrack(Object.assign({}, t, { album: t.album || albumStub })) : null))
        .filter(Boolean);
      return sendJson(res, 200, { album: simplifyAlbum(json), tracks });
    } catch (e) {
      console.error('[spotify] album ' + albumId + ' threw', e && e.message);
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // GET /api/spotify/search?q=
  if (pathname === '/api/spotify/search' && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    const url = new URL(req.url, 'http://internal');
    const q = sanitizeText(url.searchParams.get('q') || '', 200);
    if (!q) return sendJson(res, 200, { tracks: [], artists: [], albums: [], playlists: [] });

    try {
      const qs = new URLSearchParams({ q, type: 'track,artist,album,playlist', limit: '8' }).toString();
      const { status, json } = await spotifyApiRequest('GET', '/v1/search?' + qs, token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 429) return sendJson(res, 429, { error: 'Spotify is rate-limiting this connection — try again in a moment.' });
      if (status === 403) return sendSpotifyForbidden(res, 'search q="' + q + '"', 'Search', status, json);
      if (status !== 200 || !json) { logSpotifyIssue('search q="' + q + '"', status, json); return sendJson(res, 502, { error: 'Search failed.' }); }
      return sendJson(res, 200, {
        tracks: json.tracks ? (json.tracks.items || []).map(simplifyTrack).filter(Boolean) : [],
        artists: json.artists ? (json.artists.items || []).map(simplifyArtist).filter(Boolean) : [],
        albums: json.albums ? (json.albums.items || []).map(simplifyAlbum).filter(Boolean) : [],
        playlists: json.playlists ? (json.playlists.items || []).map(simplifyPlaylist).filter(Boolean) : [],
      });
    } catch (e) {
      console.error('[spotify] search q="' + q + '" threw', e && e.message);
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // GET /api/spotify/playlists?offset=0
  if (pathname === '/api/spotify/playlists' && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    const url = new URL(req.url, 'http://internal');
    const offset = Math.max(0, Number(url.searchParams.get('offset')) || 0);

    try {
      const qs = new URLSearchParams({ limit: '20', offset: String(offset) }).toString();
      const { status, json } = await spotifyApiRequest('GET', '/v1/me/playlists?' + qs, token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 403) return sendSpotifyForbidden(res, 'playlists offset=' + offset, 'Loading your playlists', status, json);
      if (status !== 200 || !json || !Array.isArray(json.items)) { logSpotifyIssue('playlists offset=' + offset, status, json); return sendJson(res, 502, { error: 'Could not load playlists.' }); }
      return sendJson(res, 200, {
        playlists: json.items.map(simplifyPlaylist).filter(Boolean),
        nextOffset: json.next ? offset + json.items.length : null,
      });
    } catch (e) {
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // GET /api/spotify/playlists/<id>/tracks?offset=0
  if (pathname.startsWith('/api/spotify/playlists/') && pathname.endsWith('/tracks') && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    const playlistId = pathname.slice('/api/spotify/playlists/'.length, -'/tracks'.length);
    if (!/^[A-Za-z0-9]{1,64}$/.test(playlistId)) return sendJson(res, 400, { error: 'Invalid playlist id' });

    const url = new URL(req.url, 'http://internal');
    const offset = Math.max(0, Number(url.searchParams.get('offset')) || 0);
    const fields = 'items(is_local,item(id,uri,name,type,duration_ms,artists(name),album(name,images))),next';

    try {
      const qs = new URLSearchParams({ limit: '50', offset: String(offset), fields }).toString();
      const { status, json } = await spotifyApiRequest('GET', '/v1/playlists/' + playlistId + '/items?' + qs, token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 404) return sendJson(res, 404, { error: 'Playlist not found.' });
      if (status === 429) return sendJson(res, 429, { error: 'Spotify is rate-limiting this connection — try again in a moment.' });
      if (status === 403) return sendSpotifyForbidden(res, 'playlist ' + playlistId + ' items offset=' + offset, 'Loading that playlist', status, json);
      if (status !== 200 || !json || !Array.isArray(json.items)) {
        logSpotifyIssue('playlist ' + playlistId + ' items offset=' + offset, status, json);
        return sendJson(res, 502, { error: 'Could not load that playlist.' });
      }
      return sendJson(res, 200, {
        tracks: json.items.map(simplifyPlaylistItem).filter(Boolean),
        nextOffset: json.next ? offset + json.items.length : null,
      });
    } catch (e) {
      console.error('[spotify] playlist ' + playlistId + ' items offset=' + offset + ' threw', e && e.message);
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // POST /api/spotify/play
  if (pathname === '/api/spotify/play' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    if (spotifyTooFast(session)) return sendJson(res, 429, { error: 'Slow down a little.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    let bodyObj;
    if (typeof body.contextUri === 'string' && /^spotify:(playlist|album):[A-Za-z0-9]+$/.test(body.contextUri)) {
      bodyObj = { context_uri: body.contextUri };
      if (typeof body.offsetUri === 'string' && /^spotify:track:[A-Za-z0-9]+$/.test(body.offsetUri)) {
        bodyObj.offset = { uri: body.offsetUri };
      }
    } else if (typeof body.uri === 'string' && body.uri.startsWith('spotify:track:')) {
      bodyObj = { uris: [body.uri] };
    }
    const devId = spotifyDeviceIdOrFalse(body.deviceId);
    if (devId === false) return sendJson(res, 400, { error: 'Invalid device' });

    try {
      const { status, json } = await spotifyApiRequest('PUT', '/v1/me/player/play' + (devId ? '?device_id=' + devId : ''), token, bodyObj);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 404) return sendJson(res, 409, { error: 'Open Spotify on a device first, then try again.' });
      if (status === 403) return sendSpotifyForbidden(res, 'play', 'Playback control', status, json);
      if (status >= 400) { logSpotifyIssue('play', status, json); return sendJson(res, 502, { error: 'Spotify could not play that.' }); }
      return sendJson(res, 200, { ok: true });
    } catch (e) {
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // POST /api/spotify/pause
  if (pathname === '/api/spotify/pause' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    if (spotifyTooFast(session)) return sendJson(res, 429, { error: 'Slow down a little.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    const devId = spotifyDeviceIdOrFalse(body.deviceId);
    if (devId === false) return sendJson(res, 400, { error: 'Invalid device' });

    try {
      const { status } = await spotifyApiRequest('PUT', '/v1/me/player/pause' + (devId ? '?device_id=' + devId : ''), token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 404) return sendJson(res, 409, { error: 'Open Spotify on a device first, then try again.' });
      if (status >= 400 && status !== 403) { logSpotifyIssue('pause', status, null); return sendJson(res, 502, { error: 'Spotify could not pause that.' }); }
      return sendJson(res, 200, { ok: true });
    } catch (e) {
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // POST /api/spotify/next
  if (pathname === '/api/spotify/next' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    if (spotifyTooFast(session)) return sendJson(res, 429, { error: 'Slow down a little.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    const devId = spotifyDeviceIdOrFalse(body.deviceId);
    if (devId === false) return sendJson(res, 400, { error: 'Invalid device' });

    try {
      const { status } = await spotifyApiRequest('POST', '/v1/me/player/next' + (devId ? '?device_id=' + devId : ''), token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 404) return sendJson(res, 409, { error: 'Open Spotify on a device first, then try again.' });
      if (status >= 400) { logSpotifyIssue('next', status, null); return sendJson(res, 502, { error: 'Spotify could not skip that.' }); }
      return sendJson(res, 200, { ok: true });
    } catch (e) {
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // POST /api/spotify/previous
  if (pathname === '/api/spotify/previous' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    if (spotifyTooFast(session)) return sendJson(res, 429, { error: 'Slow down a little.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    const devId = spotifyDeviceIdOrFalse(body.deviceId);
    if (devId === false) return sendJson(res, 400, { error: 'Invalid device' });

    try {
      const { status } = await spotifyApiRequest('POST', '/v1/me/player/previous' + (devId ? '?device_id=' + devId : ''), token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 404) return sendJson(res, 409, { error: 'Open Spotify on a device first, then try again.' });
      if (status >= 400) { logSpotifyIssue('previous', status, null); return sendJson(res, 502, { error: 'Spotify could not go back.' }); }
      return sendJson(res, 200, { ok: true });
    } catch (e) {
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // POST /api/spotify/shuffle
  if (pathname === '/api/spotify/shuffle' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    if (spotifyTooFast(session)) return sendJson(res, 429, { error: 'Slow down a little.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    const state = Boolean(body.state);
    const devId = spotifyDeviceIdOrFalse(body.deviceId);
    if (devId === false) return sendJson(res, 400, { error: 'Invalid device' });

    try {
      const { status, json } = await spotifyApiRequest('PUT', '/v1/me/player/shuffle?state=' + state + (devId ? '&device_id=' + devId : ''), token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 404) return sendJson(res, 409, { error: 'Open Spotify on a device first, then try again.' });
      if (status === 403) return sendSpotifyForbidden(res, 'shuffle', 'Shuffle', status, json);
      if (status >= 400) { logSpotifyIssue('shuffle', status, json); return sendJson(res, 502, { error: 'Spotify could not change shuffle.' }); }
      return sendJson(res, 200, { ok: true });
    } catch (e) {
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
    }
  }

  // POST /api/spotify/queue — body: { uri }. Adds one track to the end of
  // Spotify's own play queue for the active device, without interrupting
  // whatever's currently playing.
  if (pathname === '/api/spotify/queue' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });
    if (!SPOTIFY_ENABLED) return sendJson(res, 503, { error: 'Spotify is not configured on this server yet.' });
    if (spotifyTooFast(session)) return sendJson(res, 429, { error: 'Slow down a little.' });
    const roomState = rooms[session.room];
    const key = session.username.toLowerCase();
    const token = await ensureFreshSpotifyToken(roomState, key);
    if (!token) return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false });

    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    if (typeof body.uri !== 'string' || !/^spotify:track:[A-Za-z0-9]+$/.test(body.uri)) {
      return sendJson(res, 400, { error: 'Invalid track' });
    }
    const devId = spotifyDeviceIdOrFalse(body.deviceId);
    if (devId === false) return sendJson(res, 400, { error: 'Invalid device' });

    try {
      const { status, json } = await spotifyApiRequest('POST', '/v1/me/player/queue?uri=' + encodeURIComponent(body.uri) + (devId ? '&device_id=' + devId : ''), token);
      if (status === 401) { dropSpotifyConnection(roomState, key); return sendJson(res, 401, { error: 'Not connected to Spotify.', connected: false }); }
      if (status === 404) return sendJson(res, 409, { error: 'Open Spotify on a device first, then try again.' });
      if (status === 403) return sendSpotifyForbidden(res, 'queue', 'Queueing', status, json);
      if (status >= 400) { logSpotifyIssue('queue', status, json); return sendJson(res, 502, { error: 'Spotify could not queue that.' }); }
      return sendJson(res, 200, { ok: true });
    } catch (e) {
      return sendJson(res, 502, { error: 'Could not reach Spotify.' });
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
