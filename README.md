# Top Fight Zone 3D - website + multiplayer server

No npm packages needed. Requires Node 18+.

    node server.js          # http://localhost:3000   (PORT=8080 node server.js to change it)
    node test.js            # runs the server self-test

`public/index.html` is the game; the server serves it at `/` and adds accounts, cloud save,
leaderboard and live rooms on the same address, so nothing else needs configuring.

## Hosting
It must run on a host that can run a Node process (Render, Railway, Fly.io, a VPS...). Static-only hosts
(GitHub Pages, Netlify drop, etc.) can show the game but cannot run accounts or multiplayer.
- Put it behind HTTPS (the game then uses wss:// automatically).
- Behind a proxy/load balancer set `TRUST_PROXY=1` so rate limits use the real visitor IP.
- Accounts live in `DATA_DIR/users.json` (default `./data`). Use a persistent disk/volume or accounts vanish on redeploy.
- Only ONE server instance (rooms live in memory).
- If the game page is hosted on a different domain than the server: set `ALLOWED_ORIGIN=https://your-game-site`
  on the server and add `<script>window.TFZ_SERVER='https://your-server'</script>` before the game script in index.html.

## What it does
- Unique usernames (3-16 letters/numbers/_, case-insensitive, a few reserved names), passwords hashed with scrypt, 30-day login tokens.
- Cloud save: vods, skins, levels, battle pass and badges follow the account. Logging in loads the cloud save.
- Live rooms of 2-6 players: quick match (auto-starts 10s after 2+ players), private room codes, host start button.
- Leaderboard by online wins (matches shorter than 15 seconds do not count).

## Known limits
- Each player's game decides its own position/stamina (that keeps it smooth), so a determined cheater could tamper with
  their own client. Fine for friends; a ranked public game would need server-side physics.
- No password reset / e-mail yet (forgot password = new account).
- Move damage-over-time and hits work online; "Chaos Swap" only teleports you.
