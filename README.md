# jinhyuk.xyz

Cloudflare Worker 하나로 돌아가는 사이트입니다. 화면은 새 UI 시안을 그대로 쓰고, 난독화 엔진은 기존 프로젝트에서 그대로 가져왔습니다.

## 페이지

| 경로 | 파일 | 접근 |
| --- | --- | --- |
| `/` | `public/index.html` | 누구나 |
| `/obfuscator.html` | `public/obfuscator.html` | 누구나 (로그인 불필요) |
| `/login.html`, `/auth` | `public/login.html` | 누구나 (로그인하면 `/dashboard`로) |
| `/register.html` | `public/register.html` | 누구나 (초대 코드 필요) |
| `/dashboard` | `public/dashboard.html` | 로그인 필요. 관리자는 방문 기록·회원·초대코드 관리, 일반 회원은 계정 정보 |
| `/admin` | `public/dashboard.html` | 관리자만 (아니면 `/dashboard`로) |
| `/privacy.html`, `/terms.html` | 자리표시자 | 정식 문구 작성 필요 |

## 기능

- **회원가입 / 로그인**: 이메일 + 비밀번호(10자 이상) + 초대 코드. 로그인하면 HttpOnly 세션 쿠키(14일)가 발급됩니다.
- **초대 코드**: 가입 화면의 "Get code"로 누구나 1회용 일반 코드를 받을 수 있습니다(1시간 유효, IP당 1시간 5개). 관리자는 대시보드에서 일반/관리자 코드를 만들고(7일 유효) 목록에서 지울 수 있습니다.
- **관리자 대시보드**: 오늘·최근 7일 방문 집계, 회원 목록(이메일 검색), 초대코드 관리. IP 주소는 저장하지 않고 날짜가 섞인 해시만 씁니다.
- **난독화기**: 호환성 모드(문자열·주석 암호화, 구조 유지) / VM 모드(실험적, 바이트코드 실행) 중 선택. 지역 변수 이름 바꾸기 옵션(호환성 모드 전용)과 Lua/Luau 구분을 지원합니다. 원본은 저장하지 않습니다.

## 배포

1. `wrangler.jsonc`의 `database_id`가 내 D1 데이터베이스 ID와 같은지 확인합니다.
2. 관리자 계정 만들기: `npx wrangler secret put ADMIN_INVITE_CODE`로 고정 코드를 정하고, 가입 화면의 초대 코드 칸에 넣어 가입하면 관리자 계정이 됩니다. 이후 `npx wrangler secret delete ADMIN_INVITE_CODE`로 지우는 것을 권장합니다. 기존 계정을 바꾸려면 D1 콘솔에서 `UPDATE accounts SET role='admin' WHERE email='내이메일';`을 실행하세요.
3. 선택: `npx wrangler secret put INVITE_CODE`로 여러 번 쓸 수 있는 일반 코드를 설정할 수 있습니다.
4. `npm install` → `npm test` → `npm run deploy`

테이블(`accounts`, `account_sessions`, `signup_codes`, `visits`)은 첫 요청 때 Worker가 스스로 만들므로 마이그레이션 명령은 필요 없습니다.
배포 후 `https://jinhyuk.xyz/api/health`에서 `"database":true,"schema":true`인지 확인하세요.

## API

- `POST /api/auth/signup` `{ email, password, inviteCode }` → 201, 세션 쿠키 발급
- `POST /api/auth/login` `{ email, password }` → `{ user: { id, email, role } }`
- `POST /api/auth/logout`
- `GET /api/me` → `{ authenticated, id, email, role }` (로그인하지 않으면 401)
- `POST /api/invites` → 일반 1회용 초대 코드 (로그인 불필요, IP 제한)
- `GET|POST /api/admin/invites`, `DELETE /api/admin/invites/:id` (관리자)
- `GET /api/admin/overview` (관리자): 방문 집계, 회원 목록
- `POST /api/obfuscate` `{ source, language: "lua"|"luau", mode: "compatibility"|"vm", renameLocals?: boolean }` (로그인 불필요)
- `GET /api/health`

## 로컬 개발

```sh
npm install
npm test
npm run dev
```

## 알아둘 점

- 난독화는 비밀을 보장하지 못하는 실험적 기능입니다. 실제 실행 환경에서 꼭 테스트하세요.
- VM 모드는 Luau 타입 문법을 지원하지 않습니다. 타입이 있는 Luau는 호환성 모드를 쓰세요.
- Workers Free 플랜은 요청당 CPU 시간이 짧아 가입·로그인에서 오류 1102가 날 수 있습니다. 운영에는 Workers Paid를 권장합니다.
- 로그인/가입 실패 제한(IP당 15분에 5회)은 Worker 메모리에 있는 보조 장치입니다. 확실히 막으려면 Cloudflare Rate limiting rules로 `/api/auth/*`를 제한하세요.
- 시안에 있던 기능 중 아직 서버에 없는 것(Google/Discord 로그인, 비밀번호 재설정, API 키, 스크립트 로더, 제품 라이브러리, 파일 업로드)은 화면에서 "연결되지 않음" 안내만 나오거나 제외했습니다.
