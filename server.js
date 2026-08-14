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
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');
const MESSAGES_PATH = path.join(DATA_DIR, 'messages.json');
const USERNAMES_PATH = path.join(DATA_DIR, 'usernames.json');
const PORT = process.env.PORT || 3000;

const MAX_BODY_BYTES = 8 * 1024; // 8KB — plenty for password/username/chat payloads
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;
const RESERVED_USERNAMES = new Set(['admin', 'system', 'moderator', 'root', 'soulstudies']);
const MAX_MESSAGE_LEN = 500;
const MAX_MESSAGES_KEPT = 300;

// ---------------------------------------------------------------------------
// Setup / config (password hash lives ONLY here, server-side, never sent out)
// ---------------------------------------------------------------------------

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

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

/** lowercase username -> true. Persisted to disk so names don't collide across restarts. */
const takenUsernames = new Set(loadJsonArray(USERNAMES_PATH));

/** { id, username, text, ts }. Persisted to disk so chat history survives restarts. */
const messages = loadJsonArray(MESSAGES_PATH);

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
let usernamesDirty = false;

function scheduleSave() {
  messagesDirty = true;
  usernamesDirty = true;
}

setInterval(() => {
  if (messagesDirty) {
    messagesDirty = false;
    fs.writeFile(MESSAGES_PATH, JSON.stringify(messages), () => {});
  }
  if (usernamesDirty) {
    usernamesDirty = false;
    fs.writeFile(USERNAMES_PATH, JSON.stringify(Array.from(takenUsernames)), () => {});
  }
}, 2000).unref();

function flushSaveSync() {
  try {
    fs.writeFileSync(MESSAGES_PATH, JSON.stringify(messages));
    fs.writeFileSync(USERNAMES_PATH, JSON.stringify(Array.from(takenUsernames)));
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

const PRETTY_ROUTES = {
  '/': '/index.html',
  '/portal': '/portal.html',
  '/setup': '/setup.html',
  '/chat': '/chat.html',
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
    if (RESERVED_USERNAMES.has(key) || takenUsernames.has(key)) {
      return sendJson(res, 409, { error: 'That name is taken. Try another.' });
    }
    takenUsernames.add(key);
    scheduleSave();
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
    sessions.delete(sid);
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0');
    return sendJson(res, 200, { ok: true });
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

// Periodic cleanup of expired sessions
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) {
    if (s.expires < now) sessions.delete(sid);
  }
}, 60 * 1000).unref();

server.listen(PORT, () => {
  console.log(`[soul-studies] Listening on http://localhost:${PORT}`);
});
