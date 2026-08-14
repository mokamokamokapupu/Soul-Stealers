# Security notes

This app was built to specifically avoid four vulnerability classes common in
AI-generated apps. Here's how each is addressed, and what it would look like
if it *weren't*.

## 1. Broken access control / missing row-level security

**The mistake this avoids:** gating pages only in the frontend (e.g. a React
route guard) while the actual data — messages, user list — is reachable
directly from any API endpoint with no server-side check. An attacker just
calls the API directly and skips the UI entirely.

**What this app does instead:** every API endpoint independently checks the
session's `stage` server-side before doing anything (`server.js`,
`handleApi`). `/api/chat/messages` and `/api/chat/send` return `403` unless
the session has reached `stage === 'active'` (password verified *and*
username created). The HTML pages redirect client-side for UX only — that
redirect grants nothing; try hitting `/api/chat/messages` with curl and no
valid session, you get `403`, not data. Confirmed by test: fresh session →
`GET /api/chat/messages` → `403 Not authorized`.

## 2. Exposed secrets in the frontend

**The mistake this avoids:** hardcoding the password (or a hash of it) in a
JS file the browser downloads, or in an `.env` value that gets bundled into
client code — either way, view-source gets you in.

**What this app does instead:** the password never leaves the server.
`data/config.json` holds only a salted `scrypt` hash, generated server-side
and never included in any HTTP response. No frontend file — not
`portal.js`, not `index.html`, nothing — contains the password, a hash of
it, or any credential. There are no API keys in this app at all (no
third-party services are called), so there's nothing else to leak.

## 3. Missing or weak authentication / authorization

**The mistake this avoids:** no rate limiting on login (allows brute
force), no CSRF protection (allows a malicious page to submit actions as a
logged-in user), predictable or missing session tokens, or a default/blank
password.

**What this app does instead:**
- Sessions use 24 bytes of `crypto.randomBytes`, set as an `HttpOnly`,
  `SameSite=Strict` cookie — not readable by JS, not sent cross-site.
- Every state-changing request needs a per-session CSRF token in a custom
  header; the token rotates whenever the session's privilege level changes.
- Login attempts are rate-limited per IP: 5 failures locks that IP out for
  15 minutes. Confirmed by test: 5 wrong passwords → 6th attempt returns
  `429` with a 900-second retry window.
- There is no default password. If you don't set one, the server generates
  a random one on first run and prints it once to the console (server-side
  only — never to a browser).
- Password comparison uses `crypto.timingSafeEqual` to avoid timing attacks.

## 4. Injection (SQL/NoSQL)

**The mistake this avoids:** building queries with string concatenation, or
trusting user input to be well-formed before it reaches a database or shell.

**What this app does instead:** there's no SQL or NoSQL database in this app
at all — chat messages and session state live in memory, so there's no query
language for an attacker to inject into, structurally. That said, all input
is still validated, because "no database yet" isn't a permanent excuse:
- Usernames must match `^[A-Za-z0-9_]{3,20}$` — allow-listed, not
  blocklisted.
- Chat messages are capped at 500 characters, stripped of control
  characters, and rejected if empty.
- On the way back out, the chat client renders messages with
  `textContent`, never `innerHTML` — so even if you send
  `<img src=x onerror=alert(1)>` as a message (tested — it's accepted and
  stored, since it's valid *text*), it's displayed as the literal string,
  never parsed as HTML or executed. Confirmed by test.
- If you later add a real database, keep using parameterized
  queries/prepared statements — never string-concatenate user input into a
  query — and keep the same allow-list validation at the boundary.

## Known limitations (by design, for a single-process demo)

- **Chat history and usernames persist; sessions don't.** Messages and
  taken usernames are written to `data/messages.json` and
  `data/usernames.json` (debounced, roughly every 2 seconds, plus a
  synchronous flush on `SIGINT`/`SIGTERM` so a normal shutdown doesn't lose
  the last couple of seconds of chat). A restart keeps the conversation and
  reserved names, but active login sessions still reset — everyone has to
  re-enter the password and reuse (or re-pick) their name. If you outgrow
  flat JSON files (heavy traffic, need to query/filter messages), swap them
  for a real datastore — SQLite via parameterized queries, or Postgres — the
  validation/authorization logic above doesn't need to change, only the
  storage layer. On a host with an ephemeral filesystem (some free-tier
  containers wipe local disk on redeploy, though not on a simple restart),
  you'd need a persistent volume or an external database for this to
  survive a redeploy specifically.
- **Single shared room, no moderation.** There's no reporting, muting, or
  banning. If this goes further than a couple of trusted people, add those
  before anything else.
- **One shared password, not per-user accounts.** Everyone who knows the
  password gets in and picks any available name; there's no way to
  distinguish returning users from new ones, and no password reset flow
  because there's no per-user password. If you need real accounts, that's a
  bigger change (persistent user table, per-user password hashes, login by
  identity not just a shared secret).
- **No HTTPS built in.** `node server.js` serves plain HTTP. Fine for
  localhost; if you expose this to the internet, put it behind a reverse
  proxy (Caddy, nginx, or a platform like Render/Railway) that terminates
  TLS, so the session cookie and password aren't sent in the clear.
