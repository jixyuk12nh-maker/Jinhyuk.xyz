# jinhyuk.xyz

Cloudflare Worker 하나로 만든 사이트입니다. 기능은 네 가지예요.

- **회원가입 / 로그인**: 이메일 + 비밀번호(10자 이상) + 초대 코드로 가입하고, 로그인하면 세션 쿠키(HttpOnly, 14일)가 발급됩니다.
- **대시보드** (`/dashboard`): 로그인한 사용자만 열 수 있습니다. 서버(Worker)가 직접 확인하고, 아니면 `/auth`로 보냅니다.
- **관리자 대시보드** (`/admin`): 관리자 권한이 있는 계정만 열 수 있습니다. 방문자 통계, 가입자 목록, 초대 코드 만들기(일반/관리자)가 있어요. 관리자가 아니면 `/dashboard`로 보냅니다.
- **난독화기** (`/obfuscator.html`, `/engine.html`): Lua/Luau 난독화. `POST /api/obfuscate`는 로그인 없이 쓸 수 있습니다.

테이블(`accounts`, `account_sessions`, `signup_codes`, `visits`)은 첫 요청 때 Worker가 스스로 만듭니다. 마이그레이션 명령은 필요 없습니다. 예전 DB의 `accounts`에는 `role` 열이 자동으로 추가되고, 기존 계정은 모두 일반 권한이 됩니다.

## 배포

1. `wrangler.jsonc`의 `database_id`가 `npx wrangler d1 list`에 나온 `jinhyuk_xyz`의 ID와 같은지 확인합니다.
2. **관리자 계정**을 만듭니다. 관리자용 고정 코드를 정하고(`npx wrangler secret put ADMIN_INVITE_CODE`), 가입 화면의 초대 코드 칸에 그 코드를 넣고 가입하면 관리자 권한 계정이 됩니다. 이미 만든 계정을 관리자로 바꾸려면 D1 콘솔에서 `UPDATE accounts SET role='admin' WHERE email='내이메일';`을 실행하세요. 첫 관리자를 만든 뒤에는 시크릿을 지우는 것을 권장합니다(`npx wrangler secret delete ADMIN_INVITE_CODE`). 이후 관리자 코드는 관리자 대시보드에서 만들 수 있어요.
3. `npm install` → `npm test` → `npm run deploy`

배포 후 `https://jinhyuk.xyz/api/health`를 열어 `"database":true,"schema":true`인지 확인하세요(`inviteCodeSet`/`adminCodeSet`은 고정 코드 `INVITE_CODE`/`ADMIN_INVITE_CODE`를 설정했을 때만 `true`입니다). 값이 `false`인 항목이 문제의 위치를 알려줍니다.

## 초대 코드와 권한

가입하려면 초대 코드가 필요하고, 코드마다 **권한(일반 / 관리자)** 이 정해져 있습니다. 가입한 계정은 그 코드의 권한을 갖습니다.

| 어디서 | 권한 | 설명 |
| --- | --- | --- |
| 메인화면 **초대 코드 받기** | 일반 | 로그인 없이 누구나. 1회용, 1시간 유효, IP당 1시간 5개, 미사용 코드는 전체 500개까지 |
| 관리자 대시보드 **초대 코드 만들기** | 일반 또는 관리자 | 관리자가 종류를 고릅니다. 1회용, 7일 유효, 미사용 코드는 100개까지 |
| 고정 코드 `INVITE_CODE` (선택) | 일반 | 여러 번 쓸 수 있는 코드 |
| 고정 코드 `ADMIN_INVITE_CODE` (선택) | 관리자 | 첫 관리자를 만들 때 쓰고, 이후에는 지우는 것을 권장합니다 |

- 로그인 없이 받는 코드는 **항상 일반 권한**입니다. 관리자 코드는 관리자만 만들 수 있어요.
- 코드 원문은 DB에 저장하지 않고(SHA-256 해시만 저장) 만든 직후 화면에서만 볼 수 있습니다. 관리자 대시보드 목록에는 끝 4자리, 종류, 상태, 누가 썼는지가 표시되고, 쓰지 않은 코드는 삭제할 수 있습니다.
- 대소문자, 공백, 하이픈은 가입할 때 구분하지 않습니다.
- 메인화면에서 누구나 일반 코드를 받을 수 있으니 사실상 공개 가입입니다. 막고 싶다면 `POST /api/invites`(공개 생성) 처리 부분과 메인화면의 `#getInvite` 버튼을 지우고, 관리자가 만든 코드나 고정 코드만 쓰세요.

## 관리자 대시보드 (`/admin`)

- **방문자**: 오늘 방문 수 / 방문자 수 / 가입자 수와 최근 7일 막대. 한국 시간 기준 날짜로 셉니다.
- **초대 코드 만들기**: 종류(일반/관리자)를 고르고 만들면 코드가 한 번만 표시됩니다. 만든 코드 목록과 삭제도 여기서 합니다.
- **가입자**: 이메일, 권한, 가입 시각.

방문 기록은 메인화면(`/`), `/auth`, `/obfuscator.html`, `/engine.html`을 GET으로 열 때 한 번씩 올라갑니다. **IP 주소 원문은 저장하지 않고** 날짜가 섞인 해시만 저장하며, 같은 날 같은 IP는 방문자 1명으로 셉니다. 90일이 지난 기록은 자동으로 지워집니다. 봇 방문도 함께 셉니다.

## API

- `POST /api/auth/signup` `{ email, password, inviteCode }` → 201 (바로 로그인됨)
- `POST /api/auth/login` `{ email, password }`
- `POST /api/auth/logout`
- `GET /api/me` → 로그인 상태 확인 (`role`: `user` | `admin` 포함)
- `POST /api/invites` → 일반 권한 초대 코드 자동 생성 `{ code, role: "user", expiresAt }` (로그인 불필요, IP당 1시간 5개)
- `GET /api/admin/invites` · `POST /api/admin/invites` `{ role: "user|admin" }` · `DELETE /api/admin/invites/:id` → 초대 코드 목록/생성/삭제 (관리자 전용)
- `GET /api/admin/overview` → 방문자 통계와 가입자 목록 (관리자 전용)
- `GET /api/health`
- `POST /api/obfuscate` `{ source, language: "lua|luau", mode: "compatibility|vm" }`

가입 오류는 구분해서 알려 줍니다: 초대 코드가 틀리거나 이미 쓰였거나 만료됨 403, 이미 가입된 이메일 409, DB 연결 문제 503. 관리자 API는 로그인하지 않으면 401, 관리자가 아니면 403입니다.

## 알아둘 점

- 비밀번호는 PBKDF2-SHA-256(100,000회)으로 해시합니다. Workers **Free** 플랜은 요청당 CPU가 10 ms라 가입/로그인에서 Cloudflare 오류 1102가 날 수 있습니다. 운영에는 Workers Paid를 권장합니다.
- 로그인/가입 실패 제한(IP당 15분에 5회)은 Worker 인스턴스 메모리에 저장되는 보조 장치입니다. 확실히 막으려면 Cloudflare 대시보드의 Rate limiting rules로 `/api/auth/*`를 제한하세요.
- 권한은 가입할 때 코드가 정하며 화면에서 바꾸는 기능은 없습니다. 바꾸려면 D1 콘솔에서 `UPDATE accounts SET role='user' WHERE email='...';`처럼 직접 수정하세요.
- 예전 버전이 만들었던 `users`, `api_keys`, `scripts`, `sessions`, `access_logs`, `ip_blacklist` 테이블은 더 이상 쓰지 않습니다. 필요 없으면 D1 콘솔에서 지워도 됩니다.
- 난독화는 비밀을 보장하지 못하는 실험적 기능입니다. 실제 실행 환경에서 꼭 테스트하세요.

## 로컬 개발

```sh
npm install
npm test
npm run dev
```
