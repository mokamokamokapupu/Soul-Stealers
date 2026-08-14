# Legacy multi-page frontend (pre-SPA)

This folder holds the original per-page frontend (portal.html, setup.html,
chat.html, and their matching portal.js/setup.js/chat.js/site.js) from
before the site was converted to a single-page app.

They are kept here for reference only and are NOT served by the app
anymore (they've been moved out of `public/`, which is the only directory
server.js serves static files from). All of their functionality now lives
in `public/index.html` + `public/assets/app.js`.

Safe to delete once you've confirmed the SPA (public/index.html) covers
everything you need.
