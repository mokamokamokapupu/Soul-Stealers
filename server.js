'use strict';

/**
 * SOUL STUDIES — backend server
 * -----------------------------
 * Deliberately built with ZERO third-party dependencies (Node built-ins only)
 * so it runs anywhere with `node server.js` — no npm install, no network
 * access required, nothing to go stale.
 *
 * Security model (see SECURITY.md for the full writeup):
 *  - The site password is never stored or shipped in any frontend file.
 *    It exists only as a salted scrypt hash on disk (data/config.json).
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
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const AVATARS_DIR = path.join(DATA_DIR, 'avatars');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');
const MESSAGES_PATH = path.join(DATA_DIR, 'messages.json');
const PORT = process.env.PORT || 3000;

const MAX_BODY_BYTES = 8 * 1024; // 8KB — plenty for password/username/chat payloads
const MAX_AVATAR_BYTES = 3 * 1024 * 1024; // 3MB — reasonable cap for a profile picture
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;
const RESERVED_USERNAMES = new Set(['admin', 'system', 'moderator', 'root', 'soulstudies']);
const MAX_MESSAGE_LEN = 500;
const MAX_MESSAGES_KEPT = 300;
const ALLOWED_AVATAR_EXTS = ['jpg', 'png', 'webp'];

// ---------------------------------------------------------------------------
// Setup / config (password hash lives ONLY here, server-side, never sent out)
// ---------------------------------------------------------------------------

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(AVATARS_DIR)) fs.mkdirSync(AVATARS_DIR, { recursive: true });

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function loadOrCreateConfig() {
  const envPassword = process.env.SOUL_STUDIES_PASSWORD;

  if (envPassword) {
    // Explicit operator-provided password always wins and is re-hashed fresh.
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(envPassword, salt);
    const config = { salt, hash, createdAt: Date.now() };
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(config), { mode: 0o600 });
    console.log('[soul-studies] Password set from SOUL_STUDIES_PASSWORD env var.');
    return config;
  }

  if (fs.existsSync(CONFIG_PATH)) {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  }

  // First run, no env var: generate a strong random password so the site
  // is never left with a predictable or empty default password.
  const generated = crypto.randomBytes(9).toString('base64url');
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(generated, salt);
  const config = { salt, hash, createdAt: Date.now() };
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config), { mode: 0o600 });

  console.log('');
  console.log('==================================================================');
  console.log(' SOUL STUDIES — no password configured, generated one for you:');
  console.log('');
  console.log('   ' + generated);
  console.log('');
  console.log(' Save it somewhere safe. To set your own instead, stop the server');
  console.log(' and run:  SOUL_STUDIES_PASSWORD="your password" node server.js');
  console.log('==================================================================');
  console.log('');

  return config;
}

let config = loadOrCreateConfig();

function verifyPassword(candidate) {
  if (typeof candidate !== 'string' || candidate.length === 0 || candidate.length > 200) {
    return false;
  }
  const candidateHash = Buffer.from(hashPassword(candidate, config.salt), 'hex');
  const storedHash = Buffer.from(config.hash, 'hex');
  if (candidateHash.length !== storedHash.length) return false;
  return crypto.timingSafeEqual(candidateHash, storedHash);
}

// ---------------------------------------------------------------------------
// In-memory state: sessions, login rate limiting, users, chat messages
// ---------------------------------------------------------------------------

/** sid -> { stage: 'none'|'password_ok'|'active', username, csrfToken, expires, ip } */
const sessions = new Map();

/** ip -> { failCount, windowStart, lockedUntil } */
const loginAttempts = new Map();

/**
 * lowercase username -> sid that currently holds it. A name is only
 * unavailable while an active session is actually using it — it's freed
 * as soon as that session logs out or expires (or the server restarts,
 * since sessions themselves are in-memory and don't survive that either).
 * This intentionally does NOT persist to disk: usernames are a claim tied
 * to a live session, not a permanent registry, so the same person (or
 * anyone, once it's free) can reuse a name after the previous holder
 * leaves — fixing the earlier bug where a name became unusable forever
 * after a single use.
 */
const usernameOwners = new Map();

/** { id, username, text, ts }. Persisted to disk so chat history survives restarts. */
const messages = loadJsonArray(MESSAGES_PATH);

/**
 * lowercase username -> file extension ('jpg'|'png'|'webp') of an uploaded
 * avatar for that name. Rebuilt from disk at startup. Avatars are tied to
 * the username string itself (as requested), independent of any live
 * session, and stored server-side only — never as attacker-controlled
 * filenames or trusted client MIME types (see saveAvatarFile / detectImageType).
 */
const avatarExtByUser = new Map();
for (const entry of fs.readdirSync(AVATARS_DIR, { withFileTypes: true })) {
  if (!entry.isFile()) continue;
  const ext = path.extname(entry.name).slice(1).toLowerCase();
  const base = path.basename(entry.name, path.extname(entry.name)).toLowerCase();
  if (ALLOWED_AVATAR_EXTS.includes(ext) && USERNAME_RE.test(base)) {
    avatarExtByUser.set(base, ext);
  }
}

function loadJsonArray(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return []; // missing or corrupt file — start fresh rather than crash
  }
}

/** Debounced disk writes: chat can be chatty, so coalesce writes instead of
 * doing a synchronous fs write on every single message. Worst case on an
 * unclean shutdown you lose the last ~2s of messages, not the whole history. */
let messagesDirty = false;

function scheduleSave() {
  messagesDirty = true;
}

setInterval(() => {
  if (messagesDirty) {
    messagesDirty = false;
    fs.writeFile(MESSAGES_PATH, JSON.stringify(messages), () => {});
  }
}, 2000).unref();

function flushSaveSync() {
  try {
    fs.writeFileSync(MESSAGES_PATH, JSON.stringify(messages));
  } catch (e) { /* best effort on shutdown */ }
}

process.on('SIGINT', () => { flushSaveSync(); process.exit(0); });
process.on('SIGTERM', () => { flushSaveSync(); process.exit(0); });

function newSession(ip) {
  const sid = crypto.randomBytes(24).toString('hex');
  const session = {
    stage: 'none',
    username: null,
    csrfToken: crypto.randomBytes(16).toString('hex'),
    expires: Date.now() + SESSION_TTL_MS,
    ip,
  };
  sessions.set(sid, session);
  return { sid, session };
}

/** Release a username claim held by this session, if any — called on
 * logout and on session expiry so the name becomes available again. */
function releaseUsername(sid, session) {
  if (!session || !session.username) return;
  const key = session.username.toLowerCase();
  if (usernameOwners.get(key) === sid) {
    usernameOwners.delete(key);
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

function saveAvatarFile(usernameKey, ext, buf) {
  // Remove any previous avatar for this name under a different extension,
  // so switching file types doesn't leave orphaned files being served.
  for (const otherExt of ALLOWED_AVATAR_EXTS) {
    if (otherExt === ext) continue;
    const stale = path.join(AVATARS_DIR, usernameKey + '.' + otherExt);
    if (fs.existsSync(stale)) {
      try { fs.unlinkSync(stale); } catch (e) { /* best effort */ }
    }
  }
  // Write to a temp file then rename — avoids ever serving a partially
  // written file if a read races an in-progress upload.
  const finalPath = path.join(AVATARS_DIR, usernameKey + '.' + ext);
  const tmpPath = finalPath + '.tmp-' + crypto.randomBytes(6).toString('hex');
  fs.writeFileSync(tmpPath, buf, { mode: 0o600 });
  fs.renameSync(tmpPath, finalPath);
  avatarExtByUser.set(usernameKey, ext);
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
// independently re-checks session.stage on every request regardless of
// which path loaded the page, so hitting /chat or /setup directly without
// a valid session still can't reach any protected data — try it with curl
// and no cookie, you still get 403, not chat history.
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

  // GET /api/session — bootstrap info for the frontend (no secrets)
  if (pathname === '/api/session' && req.method === 'GET') {
    return sendJson(res, 200, {
      stage: session.stage,
      username: session.username,
      csrfToken: session.csrfToken,
    });
  }

  // POST /api/login — the ONLY place the password is ever checked
  if (pathname === '/api/login' && req.method === 'POST') {
    const ip = clientIp(req);
    const rl = checkRateLimit(ip);
    if (!rl.allowed) {
      return sendJson(res, 429, { error: 'Too many attempts. Try again later.', retryAfterSec: rl.retryAfterSec });
    }
    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });

    if (verifyPassword(body.password)) {
      recordLoginSuccess(ip);
      session.stage = 'password_ok';
      session.csrfToken = crypto.randomBytes(16).toString('hex'); // rotate on privilege change
      return sendJson(res, 200, { ok: true, csrfToken: session.csrfToken });
    } else {
      recordLoginFailure(ip);
      return sendJson(res, 401, { error: 'Incorrect password' });
    }
  }

  // POST /api/username — requires having passed the password gate
  if (pathname === '/api/username' && req.method === 'POST') {
    if (session.stage === 'none') return sendJson(res, 403, { error: 'Not authorized' });
    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });

    const username = typeof body.username === 'string' ? body.username.trim() : '';
    if (!USERNAME_RE.test(username)) {
      return sendJson(res, 400, { error: 'Use 3-20 letters, numbers, or underscores.' });
    }
    const key = username.toLowerCase();
    const owner = usernameOwners.get(key);
    if (RESERVED_USERNAMES.has(key) || (owner && owner !== sid)) {
      return sendJson(res, 409, { error: 'That name is taken. Try another.' });
    }
    usernameOwners.set(key, sid);
    session.username = username;
    session.stage = 'active';
    session.csrfToken = crypto.randomBytes(16).toString('hex'); // rotate on privilege change
    return sendJson(res, 200, { ok: true, username, csrfToken: session.csrfToken });
  }

  // GET /api/chat/messages — requires an active (username-created) session
  if (pathname === '/api/chat/messages' && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    const url = new URL(req.url, 'http://internal');
    const since = Number(url.searchParams.get('since')) || 0;
    const recent = messages.filter((m) => m.ts > since).slice(-100);
    return sendJson(res, 200, { messages: recent, serverTime: Date.now() });
  }

  // POST /api/chat/send — requires an active session
  if (pathname === '/api/chat/send' && req.method === 'POST') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });
    if (!requireCsrf(req, session)) return sendJson(res, 403, { error: 'Invalid request token' });

    const now = Date.now();
    if (session.lastMessageAt && now - session.lastMessageAt < 400) {
      return sendJson(res, 429, { error: 'Sending too fast.' });
    }

    let body;
    try { body = await readJsonBody(req); } catch (e) { return sendJson(res, e.status || 400, { error: e.message }); }
    const text = sanitizeText(body.text, MAX_MESSAGE_LEN);
    if (!text) return sendJson(res, 400, { error: 'Message must be 1-500 characters.' });

    session.lastMessageAt = now;
    const msg = { id: crypto.randomUUID(), username: session.username, text, ts: now };
    messages.push(msg);
    if (messages.length > MAX_MESSAGES_KEPT) messages.splice(0, messages.length - MAX_MESSAGES_KEPT);
    scheduleSave();
    return sendJson(res, 200, { ok: true, message: msg });
  }

  // POST /api/logout
  if (pathname === '/api/logout' && req.method === 'POST') {
    releaseUsername(sid, session);
    sessions.delete(sid);
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0');
    return sendJson(res, 200, { ok: true });
  }

  // POST /api/avatar — upload/replace the profile picture for the CURRENT
  // session's username. Requires an active (username-created) session, so
  // this is exactly as gated as chat itself.
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

    const key = session.username.toLowerCase();
    try {
      saveAvatarFile(key, detected.ext, buf);
    } catch (e) {
      return sendJson(res, 500, { error: 'Could not save image.' });
    }
    return sendJson(res, 200, {
      ok: true,
      avatarUrl: '/api/avatar/' + encodeURIComponent(session.username) + '?v=' + Date.now(),
    });
  }

  // GET /api/avatar/<username> — serve a profile picture. Gated behind the
  // same "active session" check as chat itself: avatars aren't served from
  // the public static directory and aren't reachable by anyone who hasn't
  // passed the password gate and joined the room. Falls back to a generated
  // "initial" avatar if the user hasn't uploaded one.
  if (pathname.startsWith('/api/avatar/') && req.method === 'GET') {
    if (session.stage !== 'active') return sendJson(res, 403, { error: 'Not authorized' });

    const raw = pathname.slice('/api/avatar/'.length);
    let username;
    try { username = decodeURIComponent(raw); } catch (e) { username = raw; }
    if (!USERNAME_RE.test(username)) return sendJson(res, 400, { error: 'Invalid username' });

    const key = username.toLowerCase();
    const ext = avatarExtByUser.get(key);
    if (ext) {
      const filePath = path.join(AVATARS_DIR, key + '.' + ext);
      fs.readFile(filePath, (err, data) => {
        if (err) {
          return sendSvg(res, letterAvatarSvg(username));
        }
        res.writeHead(200, {
          'Content-Type': AVATAR_MIME[ext],
          'Cache-Control': 'private, max-age=120',
        });
        res.end(data);
      });
      return;
    }
    return sendSvg(res, letterAvatarSvg(username));
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
// session was holding, so it becomes available for reuse.
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
