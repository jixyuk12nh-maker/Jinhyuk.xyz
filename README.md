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
- 900 KB per saved script and 30 saved scripts per user (D1 row limits make large uploads unsuitable for database storage).
- Obfuscation input limit: 2 MiB in compatibility mode, 128 KiB in VM mode. A Worker isolate only has about 128 MB of memory; measured memory use is roughly 50x the input size (compatibility) and several hundred x (VM), so the old 50 MiB limit could never work and let a single request crash the isolate.
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

- **Developer/owner code** (`OWNER_SETUP_CODE`): it is required to register the owner (together with `OWNER_EMAIL`) and again to unlock the Developer Studio. Every unlock lasts 1 hour, is bound to the current login session, and ends on logout. It is rejected for any other email, and all failures return the same generic error. The signup form only shows the code field at `/auth.html#owner`. Only the owner and admins who know the code can open the Studio.
- **Failed-login lockout**: 5 failed logins (or signups, or developer-code attempts) per IP in 15 minutes, and 10 failed logins per account in 15 minutes, return HTTP 429. Counts are stored in D1 (`access_logs`), so they hold across every Worker instance. Change `MAX_FAILS_PER_IP`, `MAX_FAILS_PER_ACCOUNT` and `FAIL_WINDOW_MS` at the top of `src/index.js`.
- **PBKDF2** uses 100,000 iterations, the maximum Cloudflare Workers allow. Higher values throw `NotSupportedError`, so signup and login would fail in production.
- `run_worker_first` in `wrangler.jsonc` sends every request except plain static files (`style.css`, `app.js`, `logo.svg`) through the Worker. This is what makes the IP blacklist, page-visit logging and the `/developer` gate work for page URLs. If you add new static files, add a matching `"!/file"` entry.
- The IP blacklist applies to pages and all API routes except `/api/health`. The owner cannot blacklist their own current IP.
- Cross-origin POST/DELETE requests are rejected (Origin check on top of `SameSite=Lax` cookies). Every response carries `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, HSTS and `Permissions-Policy`; HTML also gets a Content-Security-Policy (inline scripts are still allowed because the pages use them).
- Each user keeps at most 10 active sessions, 5 API keys and 30 scripts. Expired sessions and access logs older than 90 days are pruned automatically; page-view logging is limited to one row per IP every 30 seconds.
- A blocked account is only revealed to someone who also knows its password. Blocked users' API keys stop working for the loader.

### Cloudflare plan note

Hashing a password (100,000 PBKDF2 iterations) and obfuscating a script both use real CPU time. The Workers Free plan allows only 10 ms CPU per request, so login, signup and obfuscation may fail there with error 1102; use Workers Paid for production.


## 처음 계정 만들기

회원가입 없이 첫 계정을 직접 만들 수 있습니다. 비밀번호는 저장소에 남기지 말고 실행할 때만 입력하세요.

```sh
ACCOUNT_PASSWORD='원하는비밀번호(10자 이상)' npm run create-account -- 내이메일@example.com owner --remote
```

- 권한은 `owner`(기본), `admin`, `user` 중 선택합니다. 마지막 `--remote`는 배포된 D1에, `--local`은 로컬 D1에 바로 넣습니다. 생략하면 SQL만 출력합니다.
- 먼저 `npx wrangler d1 migrations apply jinhyuk.xyz-DB --remote`로 테이블을 만들어 두어야 합니다.
- 소유자 계정으로 개발자 스튜디오(`/developer`)에 들어가려면 `OWNER_SETUP_CODE` 비밀값도 설정해야 합니다.
