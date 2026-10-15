import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import worker from "./index.js";

// D1 흉내: 진짜 SQLite(node:sqlite)에 SQL을 그대로 실행하므로 스키마와 쿼리까지 함께 검증됩니다.
function fakeD1(db) {
  // D1처럼 SQL은 실행하는 순간에 컴파일합니다(batch 안에서 앞 문장이 만든 테이블을 뒤 문장이 쓸 수 있도록).
  const wrap = (sql, args) => ({
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => ({ meta: { changes: Number(db.prepare(sql).run(...args).changes) } })
  });
  return {
    prepare: (sql) => ({ ...wrap(sql, []), bind: (...args) => wrap(sql, args) }),
    batch: async (stmts) => { for (const s of stmts) await s.run(); return []; }
  };
}
const newEnv = (extra = {}) => {
  const raw = new DatabaseSync(":memory:");
  return { raw, DB: fakeD1(raw), INVITE_CODE: "invite-code", ASSETS: { fetch: async () => new Response("asset") }, ...extra };
};
let ipCounter = 0;
const nextIp = () => `203.0.113.${++ipCounter % 250}`;
const req = (path, { method = "GET", ip = nextIp(), headers = {}, body } = {}) =>
  new Request("https://jinhyuk.xyz" + path, {
    method,
    headers: { "cf-connecting-ip": ip, ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined
  });
const call = (env, path, opts) => worker.fetch(req(path, opts), env);
const PASSWORD = "correct-horse-battery";
const signup = (env, email = "a@example.com", extra = {}, ip) =>
  call(env, "/api/auth/signup", { method: "POST", ip, body: { email, password: PASSWORD, inviteCode: "invite-code", ...extra } });
const login = (env, email = "a@example.com", password = PASSWORD, ip) =>
  call(env, "/api/auth/login", { method: "POST", ip, body: { email, password } });
const cookieOf = (res) => res.headers.get("set-cookie").split(";")[0];

test("signup with the right invite code creates an account, logs in, and /api/me works", async () => {
  const env = newEnv();
  const res = await signup(env, "New@Example.com");
  assert.equal(res.status, 201);
  assert.match(res.headers.get("set-cookie"), /HttpOnly; Secure; SameSite=Lax/);
  assert.equal((await res.json()).user.email, "new@example.com");
  const me = await call(env, "/api/me", { headers: { Cookie: cookieOf(res) } });
  assert.equal(me.status, 200);
  assert.equal((await me.json()).email, "new@example.com");
});

test("signup errors are specific: wrong invite 403, duplicate 409, bad input 400", async () => {
  const env = newEnv();
  assert.equal((await signup(env, "a@example.com", { inviteCode: "nope" })).status, 403);
  assert.equal((await signup(env, "a@example.com")).status, 201);
  assert.equal((await signup(env, "A@EXAMPLE.COM")).status, 409);
  assert.equal((await signup(env, "not-an-email")).status, 400);
  assert.equal((await signup(env, "b@example.com", { password: "short" })).status, 400);
});

test("without the INVITE_CODE secret, a wrong invite code is simply rejected with 403", async () => {
  const env = newEnv({ INVITE_CODE: undefined });
  assert.equal((await signup(env)).status, 403);
  assert.equal((await signup(env, "a@example.com", { inviteCode: "" })).status, 403);
});

test("login works with the right password and fails with a generic 401 otherwise", async () => {
  const env = newEnv();
  await signup(env);
  const ok = await login(env);
  assert.equal(ok.status, 200);
  assert.match(ok.headers.get("set-cookie"), /lm_session=/);
  assert.equal((await login(env, "a@example.com", "wrong-password-123")).status, 401);
  assert.equal((await login(env, "nobody@example.com")).status, 401);
});

test("logout removes the session", async () => {
  const env = newEnv();
  const cookie = cookieOf(await signup(env));
  assert.equal((await call(env, "/api/me", { headers: { Cookie: cookie } })).status, 200);
  const out = await call(env, "/api/auth/logout", { method: "POST", headers: { Cookie: cookie } });
  assert.equal(out.status, 200);
  assert.match(out.headers.get("set-cookie"), /Max-Age=0/);
  assert.equal((await call(env, "/api/me", { headers: { Cookie: cookie } })).status, 401);
});

test("an IP is locked out after 5 failed logins or wrong invite codes", async () => {
  const env = newEnv();
  await signup(env);
  for (let i = 0; i < 5; i++) assert.equal((await login(env, "a@example.com", "wrong-password-123", "198.51.100.7")).status, 401);
  assert.equal((await login(env, "a@example.com", PASSWORD, "198.51.100.7")).status, 429);
  for (let i = 0; i < 5; i++) assert.equal((await signup(env, "x@example.com", { inviteCode: "bad" }, "198.51.100.8")).status, 403);
  assert.equal((await signup(env, "x@example.com", {}, "198.51.100.8")).status, 429);
});

test("/dashboard needs a login (server-side), and /auth bounces logged-in users to it", async () => {
  const env = newEnv();
  for (const path of ["/dashboard", "/dashboard.html", "/dashboard/"]) {
    const res = await call(env, path);
    assert.equal(res.status, 302, path);
    assert.equal(res.headers.get("location"), "/auth");
  }
  const cookie = cookieOf(await signup(env));
  const page = await call(env, "/dashboard", { headers: { Cookie: cookie } });
  assert.equal(page.status, 200);
  assert.match(page.headers.get("cache-control"), /no-store/);
  const auth = await call(env, "/auth", { headers: { Cookie: cookie } });
  assert.equal(auth.status, 302);
  assert.equal(auth.headers.get("location"), "/dashboard");
  assert.equal((await call(env, "/auth")).status, 200);
});

test("a database that is missing the tables (or has an old users table) fixes itself on the first request", async () => {
  const env = newEnv();
  env.raw.exec("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT); CREATE TABLE api_keys (id TEXT); CREATE TABLE scripts (id TEXT);");
  const res = await signup(env);
  assert.equal(res.status, 201);
  const tables = env.raw.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name);
  assert.ok(tables.includes("accounts") && tables.includes("account_sessions"));
});

test("health reports database, schema and invite-code status", async () => {
  const body = await (await call(newEnv(), "/api/health")).json();
  assert.deepEqual([body.ok, body.database, body.schema, body.inviteCodeSet], [true, true, true, true]);
  const none = await (await call(newEnv({ DB: undefined, INVITE_CODE: undefined }), "/api/health")).json();
  assert.deepEqual([none.database, none.schema, none.inviteCodeSet], [false, false, false]);
});

test("without a DB binding the auth API answers 503 JSON instead of crashing", async () => {
  const res = await login(newEnv({ DB: undefined }));
  assert.equal(res.status, 503);
  assert.match((await res.json()).error, /DB/);
});

test("a malformed session cookie does not crash the API", async () => {
  const res = await call(newEnv(), "/api/me", { headers: { Cookie: "lm_session=%E0%A4%A" } });
  assert.equal(res.status, 401);
  assert.equal((await res.json()).authenticated, false);
});

test("unexpected errors return JSON 500 for API routes", async () => {
  const env = newEnv();
  await signup(env);
  env.DB.prepare = () => { throw new Error("boom"); };
  env.DB.batch = async () => {};
  const res = await login(env);
  assert.equal(res.status, 500);
  assert.equal((await res.json()).error, "서버 내부 오류가 발생했습니다.");
});

test("PBKDF2 stays within the 100,000 iteration cap Cloudflare Workers enforce", () => {
  const src = readFileSync(new URL("./index.js", import.meta.url), "utf8");
  const n = Number(src.match(/const PBKDF2_ITERATIONS = (\d+)/)[1]);
  assert.ok(n <= 100000, `PBKDF2_ITERATIONS is ${n}`);
  assert.equal(/iterations:\s*\d{4,}/.test(src), false, "no hard-coded iteration count may bypass the constant");
});

test("cross-origin state-changing requests are rejected", async () => {
  const env = newEnv();
  const evil = await call(env, "/api/auth/login", { method: "POST", headers: { Origin: "https://evil.example" }, body: { email: "a@example.com", password: PASSWORD } });
  assert.equal(evil.status, 403);
  const same = await call(env, "/api/auth/login", { method: "POST", headers: { Origin: "https://jinhyuk.xyz" }, body: { email: "a@example.com", password: PASSWORD } });
  assert.equal(same.status, 401);
});

test("every response carries security headers, and HTML also gets a CSP with Google Fonts", async () => {
  const env = newEnv({ ASSETS: { fetch: async () => new Response("<html></html>", { headers: { "Content-Type": "text/html; charset=utf-8" } }) } });
  const page = await call(env, "/auth.html");
  const csp = page.headers.get("content-security-policy");
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /style-src [^;]*https:\/\/fonts\.googleapis\.com/);
  assert.match(csp, /font-src [^;]*https:\/\/fonts\.gstatic\.com/);
  assert.equal(page.headers.get("x-frame-options"), "DENY");
  const api = await call(env, "/api/health");
  assert.equal(api.headers.get("x-content-type-options"), "nosniff");
  assert.equal(api.headers.get("content-security-policy"), null);
});

test("obfuscation still works without any database, and its size limits depend on the mode", async () => {
  const env = newEnv({ DB: undefined });
  const post = (ip, body) => call(env, "/api/obfuscate", { method: "POST", ip, body });
  const big = "print(1)\n".repeat(20000); // ~176 KiB
  assert.equal((await post("198.51.100.101", { source: big, mode: "vm" })).status, 413);
  assert.equal((await post("198.51.100.102", { source: "x".repeat(3 * 1024 * 1024), mode: "compatibility" })).status, 413);
  const ok = await post("198.51.100.103", { source: "print('hi')", mode: "vm" });
  assert.equal(ok.status, 200);
  assert.equal(typeof (await ok.json()).output, "string");
});

test("oversized JSON bodies return 413", async () => {
  const res = await call(newEnv(), "/api/obfuscate", { method: "POST", body: { source: "x".repeat(4_500_000) } });
  assert.equal(res.status, 413);
});

// ---- 메인화면에서 자동 생성하는 초대 코드 ----
const getInvite = (env, ip) => call(env, "/api/invites", { method: "POST", ip });

test("anyone can get a one-time invite code from the main page, and it works exactly once", async () => {
  const env = newEnv({ INVITE_CODE: undefined });
  const res = await getInvite(env);
  assert.equal(res.status, 201);
  const { code, expiresAt } = await res.json();
  assert.match(code, /^[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}$/);
  assert.ok(expiresAt > Date.now() + 50 * 60000 && expiresAt <= Date.now() + 61 * 60000);
  assert.equal((await signup(env, "a@example.com", { inviteCode: code })).status, 201);
  assert.equal((await signup(env, "b@example.com", { inviteCode: code })).status, 403);
  // 코드 원문은 DB에 저장되지 않습니다.
  assert.equal(env.raw.prepare("SELECT COUNT(*) AS n FROM signup_codes WHERE code_hash=?").get(code).n, 0);
});

test("invite codes are accepted regardless of case, spaces and dashes", async () => {
  const env = newEnv();
  const { code } = await (await getInvite(env)).json();
  assert.equal((await signup(env, "a@example.com", { inviteCode: ` ${code.toLowerCase().replaceAll("-", " ")} ` })).status, 201);
});

test("the fixed INVITE_CODE secret keeps working alongside generated codes", async () => {
  const env = newEnv();
  assert.equal((await signup(env, "a@example.com")).status, 201);
  assert.equal((await signup(env, "b@example.com")).status, 201);
});

test("an expired invite code is rejected", async () => {
  const env = newEnv();
  const { code } = await (await getInvite(env)).json();
  env.raw.prepare("UPDATE signup_codes SET expires_at=?").run(Date.now() - 1000);
  assert.equal((await signup(env, "late@example.com", { inviteCode: code })).status, 403);
});

test("a failed signup (duplicate email) does not burn the invite code", async () => {
  const env = newEnv();
  assert.equal((await signup(env, "a@example.com")).status, 201);
  const { code } = await (await getInvite(env)).json();
  assert.equal((await signup(env, "a@example.com", { inviteCode: code })).status, 409);
  assert.equal((await signup(env, "b@example.com", { inviteCode: code })).status, 201);
});

test("each IP can get at most 5 invite codes per hour", async () => {
  const env = newEnv();
  for (let i = 0; i < 5; i++) assert.equal((await getInvite(env, "198.51.100.1")).status, 201);
  const res = await getInvite(env, "198.51.100.1");
  assert.equal(res.status, 429);
  assert.equal(res.headers.get("retry-after"), "3600");
  assert.equal((await getInvite(env, "198.51.100.2")).status, 201);
  // 1시간이 지나면 다시 받을 수 있습니다.
  env.raw.prepare("UPDATE signup_codes SET created_at=created_at-?").run(3601000);
  assert.equal((await getInvite(env, "198.51.100.1")).status, 201);
});

test("generation stops when too many unused codes exist, and old expired codes get cleaned up", async () => {
  const env = newEnv();
  await getInvite(env); // 테이블 생성
  const ins = env.raw.prepare("INSERT INTO signup_codes (id,code_hash,hint,ip_hash,created_at,expires_at) VALUES (?,?,?,?,?,?)");
  for (let i = 0; i < 500; i++) ins.run("i" + i, "h" + i, "abcd", "x" + i, Date.now(), Date.now() + 60000);
  assert.equal((await getInvite(env, "198.51.100.9")).status, 503);
  ins.run("old", "stale", "abcd", "y", Date.now() - 3 * 86400000, Date.now() - 2 * 86400000);
  await getInvite(env, "198.51.100.9");
  assert.equal(env.raw.prepare("SELECT COUNT(*) AS n FROM signup_codes WHERE code_hash='stale'").get().n, 0);
});

test("generated codes are unique and use only unambiguous characters", async () => {
  const env = newEnv(), codes = new Set();
  for (let i = 0; i < 20; i++) codes.add((await (await getInvite(env, `198.51.100.${i + 10}`)).json()).code);
  assert.equal(codes.size, 20);
  for (const c of codes) assert.doesNotMatch(c, /[ILO01]/);
});

// ---- 권한(일반/관리자)과 관리자 대시보드 ----
const ADMIN_CODE = "admin-secret-code";
const adminEnv = (extra = {}) => newEnv({ ADMIN_INVITE_CODE: ADMIN_CODE, ...extra });
const as = (cookie, opts = {}) => ({ ...opts, headers: { Cookie: cookie, ...(opts.headers || {}) } });
async function adminSession(env, email = "boss@example.com") {
  const res = await signup(env, email, { inviteCode: ADMIN_CODE });
  assert.equal(res.status, 201);
  return cookieOf(res);
}
const roleOf = async (env, cookie) => (await (await call(env, "/api/me", as(cookie))).json()).role;
const adminInvite = async (env, cookie, role) => (await call(env, "/api/admin/invites", as(cookie, { method: "POST", body: { role } }))).json();

test("ADMIN_INVITE_CODE makes an admin account; the normal code and public codes make regular users", async () => {
  const env = adminEnv();
  assert.equal(await roleOf(env, await adminSession(env)), "admin");
  assert.equal(await roleOf(env, cookieOf(await signup(env, "u1@example.com"))), "user");
  // 요청에 role을 담아 보내도 로그인 없이 받는 코드는 항상 일반 권한입니다.
  const res = await call(env, "/api/invites", { method: "POST", body: { role: "admin" } });
  const { code, role } = await res.json();
  assert.equal(role, "user");
  assert.equal(await roleOf(env, cookieOf(await signup(env, "u2@example.com", { inviteCode: code }))), "user");
});

test("an admin can create a regular code or an admin code, and the new account gets that role", async () => {
  const env = adminEnv(), cookie = await adminSession(env);
  const reg = await adminInvite(env, cookie, "user"), adm = await adminInvite(env, cookie, "admin");
  assert.deepEqual([reg.role, adm.role], ["user", "admin"]);
  assert.ok(adm.expiresAt > Date.now() + 6 * 86400000);
  assert.equal(await roleOf(env, cookieOf(await signup(env, "u@example.com", { inviteCode: reg.code }))), "user");
  assert.equal(await roleOf(env, cookieOf(await signup(env, "a2@example.com", { inviteCode: adm.code }))), "admin");
  assert.equal((await signup(env, "x@example.com", { inviteCode: adm.code })).status, 403);
  assert.equal((await call(env, "/api/admin/invites", as(cookie, { method: "POST", body: { role: "root" } }))).status, 400);
});

test("admin APIs reject anonymous visitors (401) and regular users (403)", async () => {
  const env = adminEnv();
  await adminSession(env);
  const userCookie = cookieOf(await signup(env, "u@example.com"));
  const id = crypto.randomUUID();
  for (const [path, method] of [["/api/admin/invites", "GET"], ["/api/admin/invites", "POST"], ["/api/admin/overview", "GET"], [`/api/admin/invites/${id}`, "DELETE"]]) {
    assert.equal((await call(env, path, { method })).status, 401, `${method} ${path} anonymous`);
    assert.equal((await call(env, path, as(userCookie, { method }))).status, 403, `${method} ${path} user`);
  }
});

test("/admin is only served to admins; others are redirected", async () => {
  const env = adminEnv(), adminCookie = await adminSession(env), userCookie = cookieOf(await signup(env, "u@example.com"));
  for (const path of ["/admin", "/admin/", "/admin.html"]) {
    const anon = await call(env, path);
    assert.deepEqual([anon.status, anon.headers.get("location")], [302, "/auth"]);
    const user = await call(env, path, as(userCookie));
    assert.deepEqual([user.status, user.headers.get("location")], [302, "/dashboard"]);
    const admin = await call(env, path, as(adminCookie));
    assert.equal(admin.status, 200);
    assert.match(admin.headers.get("cache-control"), /no-store/);
  }
});

test("admins can list, see who used a code, and revoke unused codes", async () => {
  const env = adminEnv(), cookie = await adminSession(env);
  const used = await adminInvite(env, cookie, "user"), spare = await adminInvite(env, cookie, "admin");
  await signup(env, "friend@example.com", { inviteCode: used.code });
  const { invites } = await (await call(env, "/api/admin/invites", as(cookie))).json();
  const byId = Object.fromEntries(invites.map((i) => [i.id, i]));
  assert.deepEqual([byId[used.id].status, byId[used.id].usedEmail, byId[used.id].role], ["used", "friend@example.com", "user"]);
  assert.deepEqual([byId[spare.id].status, byId[spare.id].role, byId[spare.id].hint], ["active", "admin", spare.code.slice(-4)]);
  assert.equal((await call(env, `/api/admin/invites/${used.id}`, as(cookie, { method: "DELETE" }))).status, 404);
  assert.equal((await call(env, `/api/admin/invites/${spare.id}`, as(cookie, { method: "DELETE" }))).status, 200);
  assert.equal((await signup(env, "late@example.com", { inviteCode: spare.code })).status, 403);
});

test("public invite codes do not use up the admins' invite quota, and admins cannot exceed 100 unused codes", async () => {
  const env = adminEnv(), cookie = await adminSession(env);
  await call(env, "/api/invites", { method: "POST" });
  for (let i = 0; i < 100; i++) assert.equal((await call(env, "/api/admin/invites", as(cookie, { method: "POST", body: { role: "user" } }))).status, 201);
  assert.equal((await call(env, "/api/admin/invites", as(cookie, { method: "POST", body: { role: "user" } }))).status, 429);
});

test("visitors are counted per day without storing IP addresses, and only admins can read the numbers", async () => {
  const env = adminEnv(), cookie = await adminSession(env);
  await call(env, "/", { ip: "198.51.100.1" });
  await call(env, "/", { ip: "198.51.100.1" });
  await call(env, "/obfuscator.html", { ip: "198.51.100.2" });
  await call(env, "/api/health", { ip: "198.51.100.3" }); // API 호출은 방문으로 세지 않음
  await call(env, "/", { method: "HEAD", ip: "198.51.100.4" }); // HEAD도 세지 않음
  const body = await (await call(env, "/api/admin/overview", as(cookie))).json();
  const todayRow = body.days[0];
  assert.deepEqual([todayRow.visits, todayRow.uniqueVisitors], [3, 2]);
  assert.equal(body.days.length, 7);
  assert.deepEqual(body.today, todayRow);
  assert.equal(body.days[1].visits, 0);
  const dump = JSON.stringify(env.raw.prepare("SELECT * FROM visits").all());
  assert.doesNotMatch(dump, /198\.51\.100/);
  assert.equal(body.memberCount, 1);
  assert.deepEqual(body.members.map((m) => [m.email, m.role]), [["boss@example.com", "admin"]]);
});

test("old visit rows are pruned after 90 days", async () => {
  const env = adminEnv(), cookie = await adminSession(env);
  await call(env, "/");
  env.raw.prepare("INSERT INTO visits (day,visitor,hits) VALUES ('2020-01-01','v',5)").run();
  await call(env, "/api/admin/overview", as(cookie));
  assert.equal(env.raw.prepare("SELECT COUNT(*) AS n FROM visits WHERE day='2020-01-01'").get().n, 0);
});

test("a database created before roles existed is upgraded automatically, and old accounts become regular users", async () => {
  const env = newEnv();
  env.raw.exec("CREATE TABLE accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL)");
  env.raw.prepare("INSERT INTO accounts VALUES ('old-id','old@example.com','00','00',1)").run();
  const res = await signup(env, "new@example.com");
  assert.equal(res.status, 201);
  assert.equal(env.raw.prepare("SELECT role FROM accounts WHERE id='old-id'").get().role, "user");
  assert.equal(await roleOf(env, cookieOf(res)), "user");
});

test("health reports whether the admin invite code is configured", async () => {
  assert.equal((await (await call(adminEnv(), "/api/health")).json()).adminCodeSet, true);
  assert.equal((await (await call(newEnv(), "/api/health")).json()).adminCodeSet, false);
});
