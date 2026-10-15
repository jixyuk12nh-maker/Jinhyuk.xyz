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

test("signup says so clearly when INVITE_CODE is not configured", async () => {
  const env = newEnv({ INVITE_CODE: undefined });
  const res = await signup(env);
  assert.equal(res.status, 503);
  assert.match((await res.json()).error, /INVITE_CODE/);
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
