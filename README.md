# jinhyuk.xyz

Cloudflare Worker 하나로 만든 사이트입니다. 기능은 세 가지예요.

- **회원가입 / 로그인**: 이메일 + 비밀번호(10자 이상) + 초대 코드로 가입하고, 로그인하면 세션 쿠키(HttpOnly, 14일)가 발급됩니다.
- **대시보드** (`/dashboard`): 로그인한 사용자만 열 수 있습니다. 서버(Worker)가 직접 확인하고, 아니면 `/auth`로 보냅니다.
- **난독화기** (`/obfuscator.html`, `/engine.html`): Lua/Luau 난독화. `POST /api/obfuscate`는 로그인 없이 쓸 수 있습니다.

계정 테이블(`accounts`, `account_sessions`)은 첫 요청 때 Worker가 스스로 만듭니다. 마이그레이션 명령은 필요 없습니다.

## 배포

1. `wrangler.jsonc`의 `database_id`가 `npx wrangler d1 list`에 나온 `jinhyuk_xyz`의 ID와 같은지 확인합니다.
2. 초대 코드를 설정합니다(가입할 때 입력하는 코드): `npx wrangler secret put INVITE_CODE`
3. `npm install` → `npm test` → `npm run deploy`

배포 후 `https://jinhyuk.xyz/api/health`를 열어 `"database":true,"schema":true,"inviteCodeSet":true`인지 확인하세요. 값이 `false`인 항목이 문제의 위치를 알려줍니다.

## API

- `POST /api/auth/signup` `{ email, password, inviteCode }` → 201 (바로 로그인됨)
- `POST /api/auth/login` `{ email, password }`
- `POST /api/auth/logout`
- `GET /api/me` → 로그인 상태 확인
- `GET /api/health`
- `POST /api/obfuscate` `{ source, language: "lua|luau", mode: "compatibility|vm" }`

가입 오류는 구분해서 알려 줍니다: 초대 코드 틀림 403, 이미 가입된 이메일 409, `INVITE_CODE` 미설정 503, DB 연결 문제 503.

## 알아둘 점

- 비밀번호는 PBKDF2-SHA-256(100,000회)으로 해시합니다. Workers **Free** 플랜은 요청당 CPU가 10 ms라 가입/로그인에서 Cloudflare 오류 1102가 날 수 있습니다. 운영에는 Workers Paid를 권장합니다.
- 로그인/가입 실패 제한(IP당 15분에 5회)은 Worker 인스턴스 메모리에 저장되는 보조 장치입니다. 확실히 막으려면 Cloudflare 대시보드의 Rate limiting rules로 `/api/auth/*`를 제한하세요.
- 예전 버전이 만들었던 `users`, `api_keys`, `scripts`, `sessions`, `access_logs`, `ip_blacklist` 테이블은 더 이상 쓰지 않습니다. 필요 없으면 D1 콘솔에서 지워도 됩니다.
- 난독화는 비밀을 보장하지 못하는 실험적 기능입니다. 실제 실행 환경에서 꼭 테스트하세요.

## 로컬 개발

```sh
npm install
npm test
npm run dev
```
