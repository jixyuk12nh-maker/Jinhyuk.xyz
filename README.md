# jinhyuk.xyz — single-repository Cloudflare Worker

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

1. Create a D1 database named `jinhyuk.xyz-DB` in Cloudflare.
2. Make sure `wrangler.jsonc` contains your own D1 `database_id` (shown in the Cloudflare dashboard).
3. Run `npx wrangler d1 migrations apply jinhyuk.xyz-DB --remote` from the project root.
4. Set a strong invite-code secret: `npx wrangler secret put INVITE_CODE` and enter the invite code you want to give new users. Signup is intentionally disabled until this secret is set.
5. Install dependencies with `npm install`, run `npm test`, then deploy with `npx wrangler deploy`.
6. Once the Worker works on its `workers.dev` address, add `jinhyuk.xyz` as a Custom Domain in Worker Settings → Domains & Routes. Follow the DNS instructions Cloudflare shows.
7. Push the project root contents (not a nested ZIP folder) to a single GitHub repository. Configure Cloudflare's Git deployment or deploy with Wrangler after each push.

Do not commit invite codes, user passwords, API keys, or `.dev.vars`. Do not expose API keys in public GitHub repositories. A generated loader includes a placeholder; replace it with a real API key only in scripts you control. Anyone who obtains that key can retrieve scripts associated with that key's account, so revoke exposed keys immediately.

## Local development

The Worker API expects D1 for accounts and saved scripts. For local testing, create a local D1 database with Wrangler and apply migrations:

```sh
npm install
npx wrangler d1 migrations apply jinhyuk.xyz-DB --local
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


## Owner, administrator, visitor management

This project includes a restricted Developer Studio at `/developer` (served by `public/developer.html`). Only signed-in users with `role=owner` or `role=admin` can enter; Worker routes enforce the same permission checks. New account IDs are 5 alphanumeric characters. Existing accounts created before this update keep their current IDs.

### Cloudflare setup

1. Confirm `wrangler.jsonc` uses the correct Worker name and your own D1 `database_id`. Do not use another project's database ID.
2. Set the Worker variable `OWNER_EMAIL` to the exact email address the owner will use to sign up. In Cloudflare, open Workers & Pages → your Worker → Settings → Variables and Secrets, then add `OWNER_EMAIL` as a Text variable. Set `OWNER_SETUP_CODE` and `INVITE_CODE` as secrets (for example, with `npx wrangler secret put OWNER_SETUP_CODE` and `npx wrangler secret put INVITE_CODE`). The owner must use the owner email and owner setup code during signup. Do not share `OWNER_SETUP_CODE`.
3. Apply migrations with `npx wrangler d1 migrations apply jinhyuk.xyz-DB --remote` after verifying the database name and binding `DB`.
4. Deploy with `npm run deploy`.
5. The owner can promote/demote users and manage the IP blacklist. Admins can view visitor and account records and block/unblock ordinary users.

Visitor IPs and user agents are security logs and can be personal data. Publish a privacy notice, limit access and retention, and delete logs when no longer needed. This code does not itself create a legal basis for collection.

### Security notes

- `run_worker_first` in `wrangler.jsonc` sends every request except plain static files (`style.css`, `app.js`, `logo.svg`) through the Worker. This is what makes the IP blacklist, page-visit logging and the `/developer` gate work for page URLs. If you add new static files, add a matching `"!/file"` entry.
- Login and signup are limited to 10 attempts per minute per IP (best-effort, per Worker instance). Add a Cloudflare rate-limiting rule for stronger protection.
- The owner email can only be registered with the correct `OWNER_SETUP_CODE`; otherwise signup with that email is rejected.
- Sessions that have expired and access logs older than 90 days are pruned automatically.
