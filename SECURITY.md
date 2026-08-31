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

## 8. Spotify integration (OAuth)

The games page can optionally link a Spotify account (per room + username,
same identity as everything else) to search and control playback. This
talks to a real third-party API, so it gets its own threat-model writeup.

**The mistakes this avoids:**
- **Asking for the user's Spotify password directly.** This app never sees
  it, never asks for it, and couldn't accept it if it wanted to — all of it
  goes through Spotify's own OAuth "Authorization Code" flow. The only
  thing this server ever holds is an access/refresh token pair, scoped to
  exactly the permissions requested (search, read playback state, control
  playback) and revocable by the user at any time from
  `open.spotify.com/account/apps`, independent of this app.
- **Embedding Spotify's login page in an iframe**, which would look like
  this site is presenting Spotify's login (and which Spotify itself blocks
  via its own frame-busting headers, precisely to prevent that pattern).
  Instead, "Connect Spotify" opens Spotify's real login in a separate popup
  window; this site's own page never navigates away and never touches
  Spotify credentials in any form.
- **A forgeable OAuth `state` parameter**, which would let one session's
  callback be replayed against another session, or let an attacker link
  their own Spotify account to a victim's username. The `state` value is
  HMAC-signed server-side (`signState`/`verifyState` in `server.js`) with a
  key generated fresh at process start and never exposed — a tampered or
  expired (5-minute TTL) state is rejected outright.
- **Relying on the session cookie surviving the OAuth redirect.** This
  app's session cookie is `SameSite=Strict` (see section 3) specifically so
  it's never sent cross-site — which also means it can't be trusted to
  identify who's returning from `accounts.spotify.com`. The signed `state`
  parameter carries that identity instead, so the callback works correctly
  regardless of how the browser handles the cookie on that hop.
- **An open image-proxy.** Album art is fetched server-side and re-served
  from this app's own origin (`/api/spotify/image`) rather than the browser
  loading `i.scdn.co` URLs directly, so the Content-Security-Policy doesn't
  need to trust a third-party host. The `u` parameter is checked against an
  allowlist of Spotify's actual CDN hostnames before anything is fetched, so
  this endpoint can't be turned into a general-purpose SSRF/open proxy.
- **Storing tokens where the browser (or an XSS) could read them.** Access
  and refresh tokens live only in `data/spotify-<room>.json` on the server
  (written with `0o600` permissions, like the room password hashes) and are
  never included in any API response to the browser — the frontend only
  ever learns *whether* a username is connected, and to whom.
- **Trusting a playlist/album/artist id as a raw path segment.** `GET
  /api/spotify/playlists/<id>/tracks`, `/api/spotify/albums/<id>`, and
  `/api/spotify/artists/<id>` all validate the id against Spotify's own id
  shape (`^[A-Za-z0-9]{1,64}$`) before it's ever interpolated into the
  outbound request path to `api.spotify.com` — the same "allow-list, not
  block-list" rule as usernames and every other piece of user input in this
  app (section 4).

Playlist browsing (search was there from the start) needs two additional
scopes — `playlist-read-private` and `playlist-read-collaborative` — on top
of the original set. Spotify only grants what was actually requested at
authorization time, so an account connected before this scope was added
needs to reconnect once (disconnect, then "Connect Spotify" again) before
its playlists will load; search and playback control keep working
regardless.

**2026-08-31 fix — playlist tracks weren't loading.** `GET
/api/spotify/playlists/<id>/tracks` was calling Spotify's now-deprecated
`GET /v1/playlists/{id}/tracks` with a `fields` filter written for an older
response shape (`track(...)`). Spotify's current schema nests the actual
track under `item`, not `track` (a playlist item can also be a podcast
episode, hence the more generic field name), so the filter was selecting a
field that no longer exists. Fixed by switching to the current,
non-deprecated `GET /v1/playlists/{id}/items` endpoint and the current field
name — no scope, auth, or trust-boundary change, this was a response-shape
bug, not a security issue. The same audit turned up a second bug: `GET
/api/spotify/search` was requesting `limit=12`, which is out of Spotify's
current documented 0–10 range for `/v1/search`, causing every search to be
rejected; fixed by requesting a value inside that range (and, since this
touched search anyway, it now returns categorized tracks/artists/albums/
playlists in one call instead of tracks only). Every Spotify API call that
comes back with an unexpected status now also logs the status and a short
response snippet server-side (`logSpotifyIssue` in `server.js`, never the
access token itself), so a future regression like this shows up in the
server logs immediately instead of only as a generic error message in the
UI.

**New endpoints, same trust model.** `POST /api/spotify/volume` and `POST
/api/spotify/seek` follow the exact same pattern as the existing playback
endpoints (`play`/`pause`/`next`/`previous`): CSRF-protected, throttled via
`spotifyTooFast`, and proxy a single Spotify Web API call with no new state
stored anywhere. `GET /api/spotify/artists/<id>` and `GET
/api/spotify/albums/<id>` are read-only catalog lookups (no additional scope
required beyond what's already requested) added for the redesigned window's
artist/album pages.

**What happens if Spotify itself revokes access** (the user disconnects the
app from their Spotify account settings, rather than clicking "disconnect"
in this app): the next API call gets a `401` from Spotify's own servers,
this app drops the stale local tokens immediately (`dropSpotifyConnection`),
and the UI falls back to "Connect Spotify" — it doesn't get stuck showing a
connection that no longer actually works.

**Known limitation:** like section 6 (chat images), this is a
server-operator trust boundary, not a zero-trust one — whoever can read
`data/spotify-<room>.json` on disk (i.e., whoever can already read
`data/config.json`, the password hashes) could technically use a stored
token to make Spotify API calls as that user until it's disconnected or
naturally expires without renewal. This is the same trust level the
operator already has over every other piece of server-held state in this
app (chat history, avatars); it isn't a new category of exposure introduced
by this feature.

**2026-08-31 fix — "Connect Spotify" returning `{"error":"Not authorized"}"`
before the OAuth flow could even start, on the live deployment only (the
local mock test setup never showed this).** Traced the live request:
`GET /api/spotify/login` requires `session.stage === 'active'`, which the
frontend expects to already be true because the person just finished
logging in. Pulled the live Render logs for the exact window and found the
real cause — not a Spotify config or cookie/origin problem: `sessions` was
an in-memory-only `Map`, and the free-tier instance this app runs on stops
and restarts its Node process on its own (spins down after a few idle
minutes, restarts on the next request) far more often than a real deploy
happens — the logs showed 7 process restarts in 4 hours, only 3 of which
were actual `git push` deploys. Every one of those restarts started with an
empty `sessions` Map, so a browser that still held a `sid` cookie from
before the restart silently became a brand-new, unauthenticated session on
its very next request — invisible for a quick chat action, but exactly the
shape of failure a slower multi-step flow like "open Spotify's consent
page and come back" is likely to straddle. Confirmed with a live
reproduction: log in, kill the process, start a fresh one against the same
`data/` directory, replay the original browser's cookie — `Not authorized`
every time, before the fix.
Fixed by persisting `sessions` to `data/sessions.json` the same
debounced/best-effort way messages, scores, and Spotify tokens already are
(`loadSessions()`/the shared save interval/`flushSaveSync()` in
`server.js`), reloaded on boot including re-claiming each restored
session's username slot in its room so a second person can't grab the same
name out from under it. This survives the common case (an idle
respawn on the same instance, filesystem intact) but — like Spotify tokens
— does not survive an actual new deploy (Render builds a fresh checkout
each time), so a real deploy still logs everyone out once; that's expected
and unchanged. Verified end-to-end with the exact repro above (session
recognized and username slot correctly re-claimed after a simulated
restart) and by re-running the full local mock/Playwright suite, which
still passed all 34 checks.

**2026-08-31 addition — real in-browser audio via the Web Playback SDK,
not just remote control.** Before this, every playback control
(`play`/`pause`/`next`/`previous`/`volume`/`seek`) sent a command to
*whatever Spotify Connect device was already active* (a phone, the desktop
app, etc.) — this app never produced any audio itself. Spotify's Web
Playback SDK is the only way to actually decode and play audio inside a
browser tab, and it has one hard, non-negotiable requirement: it needs a
live OAuth access token handed to it in JavaScript to open its own
DRM-authenticated connection to Spotify — there's no way to proxy that
server-side, because it's not a normal HTTP call this server can make on
the browser's behalf. `GET /api/spotify/player-token` is the one
deliberate, narrow exception to "the browser never talks to Spotify
directly" elsewhere in this doc: it hands out the same server-held access
token already used for every other Spotify call here, nothing new or
weaker, scoped by the same `session.stage === 'active'` check as
everything else, and the frontend never caches it beyond a single SDK
callback. The Content-Security-Policy gained a matching, equally narrow
carve-out (`script-src` for `sdk.scdn.co`, `connect-src`/`frame-src` for
Spotify's own domains) — every other directive is unchanged. Requires the
new `streaming` OAuth scope (already-connected accounts need to reconnect
once, same pattern as the playlist scopes above) and a Spotify Premium
account on the connected account (Spotify's SDK itself enforces this,
firing an `account_error` the frontend already handles). This is
additive, not a replacement: `POST /api/spotify/play` and the other
transport endpoints now accept an optional `deviceId` to target this tab's
player specifically once it's ready; when it isn't (no Premium, SDK
blocked, not yet connected), every control keeps working exactly as
before by remote-controlling whatever device is already active elsewhere.
`POST /api/spotify/transfer` is a new endpoint (same CSRF/throttle pattern
as the other playback routes) that makes the in-page player the active
device.
Verified in this sandbox: the token/transfer endpoints and device-targeted
play/pause/next/previous/seek/volume calls all work correctly against a
schema-accurate mock; the frontend correctly registers
`onSpotifyWebPlaybackSDKReady` and degrades to the pre-existing
remote-control behavior with zero regressions (the same 34-check suite
still passes) when the SDK script can't load — which is also exactly what
this sandbox's own network restrictions do to it here, so that fallback
path got real, if accidental, coverage. What could **not** be verified
here, and needs a live check: whether `sdk.scdn.co` and the CSP's Spotify
wildcards are sufficient for the SDK to actually connect and stream from a
real browser reaching real Spotify infrastructure (Spotify doesn't publish
a fixed hostname list for this — the wildcards are a considered choice,
not a copied one), and the full real-audio experience (Premium account,
EME/DRM handshake, actual sound). If the browser console shows a CSP
"Refused to connect" violation once this is live, it will name the exact
host to add.

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

- **Chat history, sessions, and (as of 2026-08-31) the usernames tied to
  active sessions all persist across a same-instance restart; nothing
  survives a real new deploy.** Messages are written to
  `data/messages.json` (debounced, roughly every 2 seconds, plus a
  synchronous flush on `SIGINT`/`SIGTERM` so a normal shutdown doesn't lose
  the last couple of seconds of chat), and sessions now follow the exact
  same pattern (`data/sessions.json` — see section 8's 2026-08-31 fix for
  why this was added: the free-tier host this app runs on restarts its
  process on its own far more often than it's actually redeployed, and an
  in-memory-only session store silently logged people out on every one of
  those). A username is still only reserved for as long as the session
  that claimed it is genuinely active — restoring a session from disk on
  boot re-claims its username slot too, so that lets the same person
  resume where they left off after a restart, while a session that
  actually expired (or never existed) still can't hold a name hostage.
  None of this survives an actual new deploy, since Render builds a fresh
  checkout each time — a real deploy still logs everyone out, same as
  before. It also means two different people can end up using the same
  display name at different times (once a session's claim has genuinely
  lapsed) — there's no per-user identity to prevent that (see below).
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
- **Spotify is opt-in and off by default.** Every `/api/spotify/*` endpoint
  checks for `SPOTIFY_CLIENT_ID`/`SPOTIFY_CLIENT_SECRET` and returns a plain
  "not configured" error if they're unset, rather than half-working or
  crashing — nothing about the rest of the app depends on Spotify being set
  up. The OAuth redirect URI is derived from the incoming request's own
  `Host` header by default (matching whatever it's actually deployed as),
  or can be pinned with `SPOTIFY_REDIRECT_URI` — either way it has to match,
  character-for-character, what's registered on the Spotify Developer
  dashboard for the app.
