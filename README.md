# Lua Restore — new standalone site

A new starter website for authorized Luraph Lua/Luau analysis. It includes a dark dashboard UI,
a Cloudflare Worker gateway, and a Python API that calls an upstream public deobfuscator.

Upstream project:
https://github.com/larpcorrupt/luraph-v15-v14.x-deobfuscator

Its README describes separate engines for Luraph v14.7, v14.8, v14.9 and v15. This is target-version
support, not a guarantee that every input is fully restored. The API reports results as
`completed_unverified` and never executes the recovered output automatically.

## Project layout
- `site/`: static website (deploy to Cloudflare Pages or any static host)
- `worker/`: Cloudflare Worker gateway
- `engine/`: Dockerized Python API

## 1. Deploy the engine
Deploy `engine/` to a Docker-capable host. Configure:
- `ENGINE_TOKEN`: long random secret shared with Worker only.
- Optional `ENGINE_TIMEOUT_SECONDS`: default 180.

Health: `GET /health`

**Important:** upstream analysis may instrument/run protected scripts inside a harness. Use an isolated container, network egress restrictions, CPU/memory/process limits, and only analyze scripts you own or are authorized to inspect. The starter has a timeout, temporary directory, and Linux resource limits, but production sandboxing must be enforced by the hosting platform too.

The Dockerfile only checks that the expected CLI files exist; it does not prove the upstream native Luau tooling builds or runs on Linux. Validate that against a pinned reviewed commit. Upstream docs note Windows binaries may be included and Linux users may need compatible Luau tooling.

## 2. Configure Cloudflare Worker
In `worker/wrangler.toml`, set `ALLOWED_ORIGINS` and `SITE_ORIGIN` to your actual website origin. Then:
```sh
cd worker
npx wrangler secret put SITE_ACCESS_KEY
npx wrangler secret put ENGINE_URL
npx wrangler secret put ENGINE_TOKEN
npx wrangler deploy
```
Use the same `ENGINE_TOKEN` on the Python service and Worker. `SITE_ACCESS_KEY` is the key visitors enter in the UI. This is a single shared access key, not a full account system; do not use it as a substitute for per-user accounts, quotas, or billing.

## 3. Deploy the site
Deploy the contents of `site/` to Cloudflare Pages. Configure a route or reverse proxy so `/api/deobfuscate` reaches the Worker. If Worker is hosted on a different origin, edit `API_BASE` in `site/app.js` and update CORS handling in the Worker.

## Version mapping
- `auto`: checks a visible Luraph version header; unknown/stripped headers currently default to v14.7. For unknown headers, choose a version manually.
- `14.7`, `14.8`, `14.9`: `cli.py --engine VERSION`
- `15.0`: `deob.py --obfuscator luraph_v15`

## API input
```json
{"version":"14.8","source":"-- authorized source"}
```

## Before production
- Pin the upstream Git commit.
- Build and test Linux Luau tools.
- Test known-good authorized samples for all four versions.
- Add per-user authentication, quotas, queueing, request limits and rate limits.
- Disable outbound network from the engine unless explicitly required.
- Never log source or recovered code.
- Review outputs before running them.
