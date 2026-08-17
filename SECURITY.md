# Security notes

This app was built to specifically avoid several vulnerability classes
common in AI-generated apps. Here's how each is addressed, and what it
would look like if it *weren't*.

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

## 5. Profile picture uploads

**The mistake this avoids:** trusting a client-supplied filename (path
traversal — `../../server.js`) or a client-supplied `Content-Type` header
(an attacker can label an HTML or SVG file `image/png` and get it served
back with a browser-executable type, or smuggle a polyglot file past an
extension check).

**What this app does instead:**
- `POST /api/avatar` reads the request body as opaque bytes and never looks
  at any filename or the request's `Content-Type` header for validation.
  The real type is decided ONLY by sniffing the first bytes of the file
  against the actual JPEG/PNG/WebP magic numbers (`detectImageType` in
  `server.js`); anything else is rejected with `400`, regardless of what it
  claims to be.
- Uploads are capped at 3MB, enforced while reading the stream (the
  connection is dropped once the cap is exceeded, not after buffering the
  whole thing).
- The file is saved server-side under a name derived from the session's
  *own* validated username (`^[A-Za-z0-9_]{3,20}$`) — never from anything
  in the upload itself — so there's no path to write outside
  `data/avatars/`.
- `GET /api/avatar/<username>` requires the same `stage === 'active'`
  check as chat itself — profile pictures aren't reachable by anyone who
  hasn't passed the password gate and joined the room, and aren't served
  from the public static directory. A user with no uploaded picture gets a
  small generated "initial" avatar instead of a broken image or a 404 that
  would leak whether a name has ever been used.
- Uploading requires the same per-session CSRF token as every other
  state-changing request.

**Known limitation:** validation is magic-byte sniffing plus a size cap,
not a full image decode — there's no dependency-free way to fully parse
JPEG/PNG/WebP structure with zero third-party packages. This is enough to
block non-image files and mislabeled MIME types, which is the actual
attack this defends against (nothing is ever interpreted as HTML/SVG/JS,
and nothing is written with an attacker-chosen path). If you later add an
image-processing library, re-encoding every upload (e.g. to a fixed-size
PNG) instead of storing the original bytes verbatim would be a further
hardening step.

## 6. Chat image uploads

Same threat model and defenses as profile pictures (section 5) — magic-byte
sniffing via `detectImageType`, a size cap (5MB, enforced while streaming),
no trust in client filename/`Content-Type`, write-to-temp-then-rename, and
the same `stage === 'active'` + CSRF gating. The one difference: each chat
image gets a fresh random id (`crypto.randomUUID()`) rather than being keyed
to a username, since a room can have many images per person and — unlike an
avatar — a chat image is never replaced in place.

**Known limitation:** chat images are stored and served as plaintext files
server-side (not covered by the encryption in section 7 below) — anyone with
disk access to the server, or the server operator, can view them. This is
the same trust boundary the room already had for "who can see this content
at all" (an active, password-gated session), just not extended to
content-at-rest confidentiality for images specifically. If that matters for
your use of this app, don't send images you wouldn't want the operator to be
able to see.

## 7. Chat message content encryption

Text messages are encrypted client-side (AES-GCM, Web Crypto API) with a key
derived (`PBKDF2`, 150,000 iterations, SHA-256) from the site password
itself — the one secret every room member already has. The server stores
and relays only the ciphertext in `data/messages.json`; it has no way to
decrypt it, including the server operator reading that file directly.

**How the key is obtained, and its limits:**
- The key is derived client-side at the moment someone types the password
  into the gate — the password itself is never transmitted for this
  purpose, only used locally to compute the key.
- It's cached in that browser tab's `sessionStorage` so a page refresh
  doesn't require re-entering the password. Opening the room in a new tab
  (or after closing the old one) shows an "unlock" prompt asking for the
  password again, purely to rebuild the same key locally — again, nothing
  is sent to the server for this step.
- Because the salt is fixed and public (not secret — all the entropy comes
  from the password), **anyone who knows the site password can derive the
  same key and read every message.** This doesn't add a new privacy
  boundary beyond "who's allowed in the room" — it adds protection against
  a different threat: someone with access to the server's disk, backups, or
  logs (including the operator) being able to read message content without
  also knowing the room password.
- Reactions/edits aren't a thing here, so there's no metadata leak from
  those — but message *timestamps* and the *sender's username* are still
  visible to the server in the clear (needed for ordering, rate limiting,
  and display), only the message text itself is opaque to it.
- If a message can't be decrypted (wrong/missing key, or a message stored
  before this feature existed), the UI shows a "🔒 Unable to decrypt this
  message" placeholder rather than crashing or showing garbage.

## Network privacy / "untraceability"

This app follows standard privacy hygiene rather than anything built to
defeat abuse investigation or make senders unidentifiable within the room:

- The server never sends any client's IP address to any other client — it's
  used only in-memory, only for the login rate-limiter (section 3), and is
  never written to disk or exposed through any API response.
- The session cookie (`sid`) is `HttpOnly` (invisible to JavaScript, so a
  malicious script on the page can't read or exfiltrate it) and is likewise
  never shown to other users. There's no "device ID" concept anywhere in
  this app to begin with — nothing device-specific is collected, fingerprinted,
  or transmitted.
- Transport security (HTTPS) is a hosting-layer concern, not something this
  zero-dependency app can add to itself — see "No HTTPS built in" below.
  Put it behind TLS if you deploy it publicly; that's what actually protects
  traffic from network-level observation, not application code.
- What this app deliberately does **not** do: route traffic through
  Tor/relays, pad or delay messages to defeat timing analysis, or otherwise
  try to make the room resistant to a legal/abuse investigation. Within the
  room, whoever posts a message is still visibly that username to everyone
  else present — that's necessary for the chat to function as a chat.

## Known limitations (by design, for a single-process demo)

- **Chat history persists; usernames and sessions don't.** Messages are
  written to `data/messages.json` (debounced, roughly every 2 seconds, plus
  a synchronous flush on `SIGINT`/`SIGTERM` so a normal shutdown doesn't
  lose the last couple of seconds of chat). Usernames, on the other hand,
  are deliberately **not** persisted — a name is reserved only for as long
  as the session that claimed it is still active, and is released the
  moment that session logs out or expires (or the process restarts, since
  sessions are in-memory only). That's what lets the same person reuse
  their usual name the next time they show up, instead of every name
  becoming permanently unusable after a single use. It also means two
  different people can end up using the same display name at different
  times — there's no per-user identity to prevent that (see below).
  Uploaded avatars persist on disk under `data/avatars/`, keyed to the
  username string itself, independent of any session — if you free up a
  name and someone else claims it later, they'll see whatever picture was
  last uploaded for that name until they replace it. If you outgrow flat
  JSON files for chat history (heavy traffic, need to query/filter
  messages), swap them for a real datastore — SQLite via parameterized
  queries, or Postgres — the validation/authorization logic above doesn't
  need to change, only the storage layer. On a host with an ephemeral
  filesystem (some free-tier containers wipe local disk on redeploy, though
  not on a simple restart), you'd need a persistent volume or an external
  database for chat history and avatars to survive a redeploy
  specifically.
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
