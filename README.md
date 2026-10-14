# LuaMoon — single-repository Cloudflare Worker

One GitHub repository contains the website, API, Lua/Luau obfuscation engine, account system, API key manager, and private script storage.

## Included working features

- Main site, sign-up/login page, dashboard, loader builder, obfuscator UI.
- Lua/Luau compatibility transformation and experimental VM mode through `POST /api/obfuscate`.
- Email + invite-code registration and password login; passwords are PBKDF2-SHA-256 hashed and sessions use HttpOnly/Secure cookies.
- D1-backed accounts, sessions, API key hashes, and user-owned Lua scripts.
- API keys are only shown once at creation, can be revoked, and can authenticate loader requests.
- Script upload/list/download/delete and per-user ownership checks.
- Protected loader endpoint `GET /api/loader/:scriptId` accepts `x-api-key` or `Authorization: Bearer ...`.
- 900 KB per saved script limit (D1 row limits make 50 MiB uploads unsuitable for database storage); obfuscation itself accepts up to 50 MiB subject to Worker limits.
- GitHub Actions test workflow.

## Required setup before deployment

1. Create a D1 database named `LuaMoon-DB` in Cloudflare.
2. Copy its database ID into `wrangler.jsonc`, replacing `REPLACE_WITH_D1_DATABASE_ID`.
3. Run `npx wrangler d1 migrations apply LuaMoon-DB --remote` from the project root.
4. Set a strong invite-code secret: `npx wrangler secret put INVITE_CODE` and enter the invite code you want to give new users. Signup is intentionally disabled until this secret is set.
5. Install dependencies with `npm install`, run `npm test`, then deploy with `npx wrangler deploy`.
6. Once the Worker works on its `workers.dev` address, add `jinhyuk.xyz` as a Custom Domain in Worker Settings → Domains & Routes. Follow the DNS instructions Cloudflare shows.
7. Push the project root contents (not a nested ZIP folder) to a single GitHub repository. Configure Cloudflare's Git deployment or deploy with Wrangler after each push.

Do not commit invite codes, user passwords, API keys, or `.dev.vars`. Do not expose API keys in public GitHub repositories. A generated loader includes a placeholder; replace it with a real API key only in scripts you control. Anyone who obtains that key can retrieve scripts associated with that key's account, so revoke exposed keys immediately.

## Local development

The Worker API expects D1 for accounts and saved scripts. For local testing, create a local D1 database with Wrangler and apply migrations:

```sh
npm install
npx wrangler d1 migrations apply LuaMoon-DB --local
npx wrangler secret put INVITE_CODE --local
npm test
npm run dev
```

## API routes

- `GET /api/health`
- `POST /api/auth/signup` `{ "email", "password", "inviteCode" }`
- `POST /api/auth/login` `{ "email", "password" }`
- `POST /api/auth/logout`
- `GET /api/me`
- `GET /api/keys`, `POST /api/keys` `{ "label" }`, `DELETE /api/keys/:id`
- `GET /api/scripts`, `POST /api/scripts` `{ "name", "source" }`, `GET/DELETE /api/scripts/:id`
- `GET /api/loader/:id` with `x-api-key: lm_...`
- `POST /api/obfuscate` `{ "source", "language": "lua|luau", "mode": "compatibility|vm" }`

## Limitations

The obfuscator is experimental and cannot guarantee secrecy or compatibility with every Lua/Luau runtime. VM mode has a narrower grammar and may run more slowly. Test generated code in the exact runtime you target. This is not a payment processor or an email-verification system; registration is invite-code gated. Public production deployment should add Cloudflare rate-limiting rules and monitoring. Analytics and payment cards are not implemented.
