# Lua Restore — Cloudflare Worker-only starter

This version serves the single-page UI and API from one Cloudflare Worker using Workers Static Assets. It removes the Python/Render service and its environment variables.

## Important engine limitation

The original package's recovery engine is Python-based and invokes external Luau tools. Those programs do not become executable in a standard Cloudflare Worker simply by uploading them. This package intentionally returns `503 ENGINE_NOT_BUNDLED` for valid recovery requests rather than fabricating a recovered result. Luraph 14.7, 14.8, 14.9 and 15.0 are accepted as version labels, but actual recovery is **not implemented or verified** in this Worker-only package. The UI checks `/health` and disables the analysis button while `engineReady` is false.

## Files

- `public/index.html`, `public/style.css`, `public/app.js`: one-page UI
- `src/index.js`: Worker API and static asset routing
- `wrangler.toml`: single Worker + static assets config
- `tests/worker.test.js`: API behavior tests

## Deploy

1. Upload the contents of this folder to a GitHub repository.
2. In Cloudflare, create a Worker and connect the repository using Workers Builds, or deploy from a local environment with Wrangler.
3. Add a Worker secret named `SITE_ACCESS_KEY` with a value of at least 16 characters. This is a single shared access key, not individual user authentication; do not treat it as a complete account system.
4. Deploy.
5. Open `https://<worker-name>.<account-subdomain>.workers.dev/health`. It should say `ok: true` and `engineReady: false` until a real engine is integrated.
6. Configure a Cloudflare rate-limiting rule for `POST /api/deobfuscate` before exposing the endpoint publicly. The Worker-only starter does not implement durable per-user rate limits.

No `ENGINE_URL`, `ENGINE_TOKEN`, `ALLOWED_ORIGINS`, or `SITE_ORIGIN` are needed because the API and UI share the same origin and there is no upstream engine service.

## Local checks

Requires Node.js 20+.

```bash
npm run check
```

These checks validate JavaScript syntax, request validation, and error behavior; they do not test Luraph deobfuscation, Cloudflare deployment, or a production rate-limit policy.
