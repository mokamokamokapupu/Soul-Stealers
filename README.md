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

## How the flow works

1. **`/`** — the essay (public, no password needed). A small pulsing mark
   at the bottom links to the gate.
2. **`/portal`** — enter the password.
3. **`/setup`** — pick a display name (3–20 letters/numbers/underscores).
4. **`/chat`** — one shared room, everyone who's in sees the same
   messages. Each name can have a profile picture (click your avatar in
   the top bar to upload one); a name is only reserved while someone's
   actively using it, so it's free again once they leave.

Read `SECURITY.md` for what's actually enforcing that flow (hint: never the
frontend by itself).
