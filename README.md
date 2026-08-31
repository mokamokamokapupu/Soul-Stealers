# Soul Studies

A small essay on the concept of "soul," gated behind a password, leading to
a username-creation step and a single shared chat room.

Zero dependencies — pure Node.js. Nothing to `npm install`, nothing that can
go stale.

## Run it

You need [Node.js](https://nodejs.org) 18 or newer installed.

```
cd soul-studies
node server.js
```

Then open **http://localhost:3000** in your browser.

### Setting the password

If you don't set one, the server makes up a strong random password the
first time it runs and prints it once to your terminal — copy it down, it
won't be shown again (though you can always reset it, see below).

To set your own password instead:

```
SOUL_STUDIES_PASSWORD="whatever you want" node server.js
```

On Windows (PowerShell):

```
$env:SOUL_STUDIES_PASSWORD="whatever you want"; node server.js
```

To change the password later, just re-run the server with a new
`SOUL_STUDIES_PASSWORD` — it overwrites the stored hash. To wipe it
entirely and get a fresh random one, delete `data/config.json` and restart
without the env var.

### Putting it on the internet (optional)

Running it on your own machine only serves `localhost` — nobody outside
your network can reach it. If you want other people to use it over the
internet, you'll need to run it on a server (a $5-6/month box on Render,
Railway, Fly.io, or similar all work — upload this folder and set them to
run `node server.js`) and ideally put it behind HTTPS (most of those
platforms do this for you automatically). See `SECURITY.md` for the one
thing this app doesn't do for you (TLS termination) if you go that route.

### Setting up Spotify (optional)

The games page can link a Spotify account and browse it from a resizable,
Spotify-desktop-style window right there — Home, categorized search (songs/
artists/albums/playlists), full playlist and album pages with pagination,
artist pages, and a persistent player bar (art, transport, seekable progress
bar, volume, shuffle). Drag the window's bottom-right corner to resize it, or
use the maximize button to expand it over most of the page. It's entirely
optional and off by default; the rest of the app works exactly the same
without it.

Playing a song from inside a playlist or album queues up and auto-advances
through the rest of it afterward, same as the real Spotify app — the shuffle
button next to the transport controls randomizes that order. Playing a
standalone track from search results or an artist's top tracks doesn't
carry a queue with it, by design. Every track row also has a small "+"
button (shown on hover, or when focused) to add that track to the queue
without interrupting whatever's currently playing.

To turn it on:

1. Go to [developer.spotify.com/dashboard](https://developer.spotify.com/dashboard)
   and log in with your Spotify account.
2. Click **Create app**. Any name/description is fine.
3. Under **Redirect URI**, add `https://<your-domain>/api/spotify/callback`
   (swap in whatever domain this ends up running on — for local testing
   that's `http://localhost:3000/api/spotify/callback`). It has to match
   exactly, so add both if you test locally and deploy for real.
4. Save, then copy the **Client ID** and reveal the **Client Secret** from
   the app's settings page.
5. Set both as environment variables alongside `SOUL_STUDIES_PASSWORD`:

```
SPOTIFY_CLIENT_ID="your client id" SPOTIFY_CLIENT_SECRET="your client secret" node server.js
```

If you registered more than one redirect URI (step 3), you don't need to
tell the server which one — it's derived automatically from whatever
domain a given request actually came in on.

With a Premium account, this page can play audio itself — clicking a track
loads it into the player bar right here via Spotify's Web Playback SDK, no
other device needed. Without Premium (a Spotify-side requirement, not
something this app can work around), the same controls fall back to
remote-controlling whatever Spotify device is already active elsewhere
(the app on a phone, desktop, or Spotify's own web player). Search and
account linking work either way. See `SECURITY.md` for the full security
writeup of this integration, including what changed to make in-browser
playback possible.

## How the flow works

1. **`/`** — the essay (public, no password needed). A small pulsing mark
   at the bottom links to the gate.
2. **`/portal`** — enter the password.
3. **`/setup`** — pick a display name (3–20 letters/numbers/underscores).
4. **`/chat`** — one shared room, everyone who's in sees the same
   messages. Each name can have a profile picture (click your avatar in
   the top bar to upload one); a name is only reserved while someone's
   actively using it, so it's free again once they leave. Messages support
   replies (hover a message → Reply), images (📷 in the composer), and an
   emoji picker (😊 in the composer). Text messages are end-to-end
   encrypted with a key derived from the site password — see `SECURITY.md`
   for exactly what that does and doesn't protect against.

Read `SECURITY.md` for what's actually enforcing that flow (hint: never the
frontend by itself).
