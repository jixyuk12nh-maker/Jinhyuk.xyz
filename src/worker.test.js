import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import worker from "./index.js";

const SECRET = "setup-secret";

// Minimal fake D1: `first(sql, args)` lets a test decide what a SELECT returns.
function fakeEnv({ first = () => null, ...extra } = {}) {
  const writes = [], reads = [];
  const statement = (sql) => {
    const make = (args) => ({
      first: async () => { reads.push({ sql, args }); return first(sql, args); },
      run: async () => { writes.push({ sql, args }); return { meta: { changes: 1 } }; },
      all: async () => ({ results: [] })
    });
    return { ...make([]), bind: (...args) => make(args) };
  };
  return {
    DB: { prepare: statement, batch: async () => [] },
    ASSETS: { fetch: async () => new Response("asset") },
    INVITE_CODE: "invite-code",
    writes, reads,
    ...extra
  };
}
const req = (path, { method = "GET", ip = "203.0.113.1", headers = {}, body } = {}) =>
  new Request("https://jinhyuk.xyz" + path, {
    method,
    headers: { "cf-connecting-ip": ip, ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined
  });
const signup = (env, email, extra = {}, ip = "203.0.113.10") =>
  worker.fetch(req("/api/auth/signup", { method: "POST", ip, body: { email, password: "correct-horse-battery", inviteCode: "invite-code", ...extra } }), env);
const login = (env, ip, email = "x@example.com") =>
  worker.fetch(req("/api/auth/login", { method: "POST", ip, body: { email, password: "wrong-password" } }), env);

// A logged-in session (cookie lm_session=abc) with the given role; extra() can override any SELECT.
const asUser = (role, extra = () => undefined) => (sql, args) => {
  const r = extra(sql, args);
  if (r !== undefined) return r;
  if (/FROM sessions JOIN users/.test(sql)) return { id: "OWN01", email: "o@example.com", role, status: "active" };
  if (/COUNT\(\*\)/.test(sql)) return { count: 0 };
  return null;
};
const SESSION = "lm_session=abc";
async function unlock(env, ip = "203.0.113.1", cookie = SESSION) {
  const res = await worker.fetch(req("/api/admin/unlock", { method: "POST", ip, headers: { Cookie: cookie }, body: { code: SECRET } }), env);
  assert.equal(res.status, 200);
  return `${cookie}; lm_dev=${res.headers.get("set-cookie").match(/lm_dev=([^;]+)/)[1]}`;
}
const adminEnv = (role, extra) => fakeEnv({ first: asUser(role, extra), OWNER_SETUP_CODE: SECRET });

// ---------- basics ----------
test("a malformed session cookie does not crash the API", async () => {
  const res = await worker.fetch(req("/api/me", { headers: { Cookie: "lm_session=%E0%A4%A" } }), fakeEnv());
  assert.equal(res.status, 401);
  assert.equal((await res.json()).authenticated, false);
});

test("unexpected errors return JSON 500 for API routes", async () => {
  const env = fakeEnv();
  env.DB.prepare = () => { throw new Error("boom"); };
  const res = await login(env, "198.51.100.88");
  assert.equal(res.status, 500);
  assert.equal((await res.json()).error, "서버 내부 오류가 발생했습니다.");
});

test("PBKDF2 stays within the 100,000 iteration cap Cloudflare Workers enforce", () => {
  const src = readFileSync(new URL("./index.js", import.meta.url), "utf8");
  const n = Number(src.match(/const PBKDF2_ITERATIONS = (\d+)/)[1]);
  assert.ok(n <= 100000, `PBKDF2_ITERATIONS is ${n}`);
  assert.equal(/iterations:\s*\d{4,}/.test(src), false, "no hard-coded iteration count may bypass the constant");
});

// ---------- signup / owner code ----------
test("the very first signup bootstraps an owner account without an invite code", async () => {
  const env = fakeEnv({ first: (sql) => (/COUNT\(\*\)/.test(sql) ? { count: 0 } : null) });
  const res = await signup(env, "first@example.com", { inviteCode: "" }, "203.0.113.40");
  assert.equal(res.status, 201);
  const insert = env.writes.find((w) => /INSERT INTO users/.test(w.sql));
  assert.ok(insert, "expected an INSERT INTO users");
  assert.equal(insert.args[5], "owner");
});

test("once any account exists, signup requires the invite code again (bootstrap window is closed)", async () => {
  const env = fakeEnv({ first: (sql) => (/COUNT\(\*\)/.test(sql) ? { count: 1 } : null) });
  const res = await signup(env, "second@example.com", { inviteCode: "" }, "203.0.113.41");
  assert.equal(res.status, 403);
  assert.equal(env.writes.some((w) => /INSERT INTO users/.test(w.sql)), false);
});

test("if the user-count check itself fails, bootstrap stays off and the invite code is still required", async () => {
  const env = fakeEnv({ first: (sql) => { if (/COUNT\(\*\) AS count FROM users/.test(sql)) throw new Error("boom"); return /COUNT\(\*\)/.test(sql) ? { count: 0 } : null; } });
  const res = await signup(env, "third@example.com", { inviteCode: "" }, "203.0.113.42");
  assert.equal(res.status, 403);
});

test("the owner email cannot be registered without the owner code", async () => {
  const env = fakeEnv({ OWNER_EMAIL: "Owner@Example.com", OWNER_SETUP_CODE: SECRET });
  const res = await signup(env, "owner@example.com");
  assert.equal(res.status, 403);
  assert.equal(env.writes.some((w) => /INSERT INTO users/.test(w.sql)), false);
});

test("the owner email wrong code and non-owner emails with a code all get the same generic error", async () => {
  const env = fakeEnv({ OWNER_EMAIL: "owner@example.com", OWNER_SETUP_CODE: SECRET });
  const a = await signup(env, "owner@example.com", { ownerSetupCode: "wrong" }, "203.0.113.20");
  const b = await signup(env, "someone@example.com", { ownerSetupCode: SECRET }, "203.0.113.21");
  const c = await signup(env, "someone@example.com", { inviteCode: "wrong" }, "203.0.113.22");
  for (const res of [a, b, c]) { assert.equal(res.status, 403); assert.equal((await res.json()).error, "초대 코드 또는 설정 코드가 올바르지 않습니다."); }
  assert.equal(env.writes.some((w) => /INSERT INTO users/.test(w.sql)), false);
});

test("the owner email with the correct owner code becomes owner", async () => {
  const env = fakeEnv({ OWNER_EMAIL: "owner@example.com", OWNER_SETUP_CODE: SECRET });
  const res = await signup(env, "owner@example.com", { ownerSetupCode: SECRET }, "203.0.113.11");
  assert.equal(res.status, 201);
  assert.ok(env.writes.find((w) => /INSERT INTO users/.test(w.sql)).args.includes("owner"));
});

test("an ordinary signup (no owner code) creates a normal user", async () => {
  const env = fakeEnv({ OWNER_EMAIL: "owner@example.com", OWNER_SETUP_CODE: SECRET });
  const res = await signup(env, "someone@example.com", {}, "203.0.113.12");
  assert.equal(res.status, 201);
  const insert = env.writes.find((w) => /INSERT INTO users/.test(w.sql));
  assert.ok(insert.args.includes("user") && !insert.args.includes("owner"));
});

test("signup locks an IP after repeated failures (shared across Worker instances via D1)", async () => {
  const env = fakeEnv({ first: (sql) => (/COUNT\(\*\)/.test(sql) ? { count: 5 } : null) });
  assert.equal((await signup(env, "a@example.com", {}, "203.0.113.30")).status, 429);
});

// ---------- login ----------
test("login locks an IP after 5 failed attempts in 15 minutes", async () => {
  const env = fakeEnv({ first: (sql) => (/COUNT\(\*\)/.test(sql) ? { count: 5 } : null) });
  const res = await login(env, "198.51.100.77");
  assert.equal(res.status, 429);
  assert.equal(res.headers.get("retry-after"), "900");
});

test("a failed login below the limit is a plain 401 and is recorded", async () => {
  const env = fakeEnv({ first: (sql) => (/COUNT\(\*\)/.test(sql) ? { count: 4 } : null) });
  const res = await login(env, "198.51.100.78");
  assert.equal(res.status, 401);
  assert.ok(env.writes.some((w) => /INSERT INTO access_logs/.test(w.sql) && w.args.includes("failed")));
});

test("an account is locked after 10 failures even when they come from many IPs", async () => {
  const user = { id: "U0001", email: "x@example.com", password_salt: "00", password_hash: "bad", role: "user", status: "active" };
  const env = fakeEnv({ first: (sql) => (/FROM users WHERE email=/.test(sql) ? user : /COUNT\(\*\)/.test(sql) ? { count: /reason=\?/.test(sql) ? 10 : 0 } : null) });
  assert.equal((await login(env, "198.51.100.79")).status, 429);
});

test("a blocked account is only revealed to someone who knows the password", async () => {
  const user = { id: "U0002", email: "x@example.com", password_salt: "00", password_hash: "bad", role: "user", status: "blocked" };
  const env = fakeEnv({ first: (sql) => (/FROM users WHERE email=/.test(sql) ? user : /COUNT\(\*\)/.test(sql) ? { count: 0 } : null) });
  assert.equal((await login(env, "198.51.100.80")).status, 401);
});

test("logout clears both the session and the developer unlock cookies", async () => {
  const res = await worker.fetch(req("/api/auth/logout", { method: "POST", headers: { Cookie: SESSION } }), fakeEnv());
  const cookies = res.headers.getSetCookie().join("\n");
  assert.match(cookies, /lm_session=;/);
  assert.match(cookies, /lm_dev=;/);
});

// ---------- IP blacklist ----------
test("blacklisted IPs are blocked on extensionless pages and on API routes", async () => {
  const env = fakeEnv({ first: (sql) => (/FROM ip_blacklist/.test(sql) ? { ip: "x" } : null) });
  assert.equal((await worker.fetch(req("/dashboard", { ip: "192.0.2.50" }), env)).status, 403);
  assert.equal((await worker.fetch(req("/api/me", { ip: "192.0.2.50" }), env)).status, 403);
  assert.equal((await worker.fetch(req("/api/health", { ip: "192.0.2.50" }), env)).status, 200);
});

test("static files bypass the database", async () => {
  const env = fakeEnv();
  const res = await worker.fetch(req("/style.css"), env);
  assert.equal(await res.text(), "asset");
  assert.equal(env.reads.length + env.writes.length, 0);
});

test("page-view logging is throttled per IP so page floods cannot burn D1 writes", async () => {
  const env = fakeEnv();
  for (let i = 0; i < 5; i++) await worker.fetch(req("/", { ip: "192.0.2.99" }), env);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(env.writes.filter((w) => /INSERT INTO access_logs/.test(w.sql)).length, 1);
});

// ---------- Developer Studio ----------
test("/developer requires an owner/admin session", async () => {
  for (const path of ["/developer", "/developer.html"]) {
    const res = await worker.fetch(req(path), fakeEnv());
    assert.equal(res.status, 302);
    assert.match(res.headers.get("location"), /\/auth\.html$/);
  }
});

test("admin APIs need the developer code even for a signed-in owner", async () => {
  const env = adminEnv("owner");
  const noCode = await worker.fetch(req("/api/admin/overview", { headers: { Cookie: SESSION } }), env);
  assert.equal(noCode.status, 403);
  assert.equal((await noCode.json()).needsUnlock, true);

  const wrong = await worker.fetch(req("/api/admin/unlock", { method: "POST", headers: { Cookie: SESSION }, body: { code: "nope" } }), env);
  assert.equal(wrong.status, 403);
  assert.equal(wrong.headers.get("set-cookie"), null);

  const cookie = await unlock(env);
  assert.equal((await worker.fetch(req("/api/admin/overview", { headers: { Cookie: cookie } }), env)).status, 200);
  assert.equal((await (await worker.fetch(req("/api/admin/status", { headers: { Cookie: cookie } }), env)).json()).unlocked, true);
});

test("the developer unlock cookie is bound to the session and cannot be tampered with", async () => {
  const env = adminEnv("owner");
  const cookie = await unlock(env);
  const dev = cookie.split("lm_dev=")[1];
  const otherSession = await worker.fetch(req("/api/admin/overview", { headers: { Cookie: `lm_session=zzz; lm_dev=${dev}` } }), env);
  assert.equal(otherSession.status, 403);
  const forged = await worker.fetch(req("/api/admin/overview", { headers: { Cookie: `${SESSION}; lm_dev=${Date.now() + 3600000}.${"0".repeat(64)}` } }), env);
  assert.equal(forged.status, 403);
  const expired = await worker.fetch(req("/api/admin/overview", { headers: { Cookie: `${SESSION}; lm_dev=${Date.now() - 1000}.${dev.split(".")[1]}` } }), env);
  assert.equal(expired.status, 403);
});

test("unlock is refused when the server has no OWNER_SETUP_CODE, and failures are throttled", async () => {
  const none = fakeEnv({ first: asUser("owner") });
  assert.equal((await worker.fetch(req("/api/admin/unlock", { method: "POST", headers: { Cookie: SESSION }, body: { code: "x" } }), none)).status, 503);
  const locked = fakeEnv({ first: asUser("owner", (sql) => (/COUNT\(\*\)/.test(sql) ? { count: 5 } : undefined)), OWNER_SETUP_CODE: SECRET });
  assert.equal((await worker.fetch(req("/api/admin/unlock", { method: "POST", headers: { Cookie: SESSION }, body: { code: SECRET } }), locked)).status, 429);
});

test("admins cannot block other admins; only the owner can", async () => {
  const env = adminEnv("admin", (sql) => (/SELECT id,role FROM users WHERE id=\?/.test(sql) ? { id: "ADM02", role: "admin" } : undefined));
  const cookie = await unlock(env);
  const res = await worker.fetch(req("/api/admin/users/ADM02/block", { method: "POST", headers: { Cookie: cookie }, body: {} }), env);
  assert.equal(res.status, 403);
  assert.match((await res.json()).error, /소유자/);
});

// ---------- owner-only account creation (no invite code) ----------
test("the owner can create an account directly from the admin panel without an invite code", async () => {
  const env = adminEnv("owner");
  const cookie = await unlock(env);
  const res = await worker.fetch(req("/api/admin/users", { method: "POST", headers: { Cookie: cookie }, body: { email: "new@example.com", password: "correct-horse-battery", role: "user" } }), env);
  assert.equal(res.status, 201);
  const body = await res.json();
  assert.equal(body.user.email, "new@example.com");
  assert.equal(body.user.role, "user");
  assert.ok(env.writes.some((w) => /INSERT INTO users/.test(w.sql)));
});

test("an admin (not owner) cannot create accounts", async () => {
  const env = adminEnv("admin");
  const cookie = await unlock(env);
  const res = await worker.fetch(req("/api/admin/users", { method: "POST", headers: { Cookie: cookie }, body: { email: "new@example.com", password: "correct-horse-battery" } }), env);
  assert.equal(res.status, 403);
  assert.match((await res.json()).error, /소유자/);
});

test("owner-created accounts still reject a duplicate email or a too-short password", async () => {
  const env = adminEnv("owner");
  const cookie = await unlock(env);
  const short = await worker.fetch(req("/api/admin/users", { method: "POST", headers: { Cookie: cookie }, body: { email: "new@example.com", password: "short" } }), env);
  assert.equal(short.status, 400);
  const taken = fakeEnv({ first: asUser("owner", (sql) => (/SELECT id FROM users WHERE email=\?/.test(sql) ? { id: "EXIST1" } : undefined)), OWNER_SETUP_CODE: SECRET });
  const takenCookie = await unlock(taken);
  const dup = await worker.fetch(req("/api/admin/users", { method: "POST", headers: { Cookie: takenCookie }, body: { email: "taken@example.com", password: "correct-horse-battery" } }), taken);
  assert.equal(dup.status, 409);
});

test("blacklist: bad %-encoding gives 400, and the owner cannot block their own IP", async () => {
  const env = adminEnv("owner");
  const cookie = await unlock(env, "203.0.113.1");
  assert.equal((await worker.fetch(req("/api/admin/blacklist/%E0%A4%A", { method: "DELETE", headers: { Cookie: cookie } }), env)).status, 400);
  assert.equal((await worker.fetch(req("/api/admin/blacklist", { method: "POST", headers: { Cookie: cookie }, body: { ip: "203.0.113.1" } }), env)).status, 400);
  assert.equal((await worker.fetch(req("/api/admin/blacklist", { method: "POST", headers: { Cookie: cookie }, body: { ip: "198.51.100.9" } }), env)).status, 201);
});

// ---------- misc hardening ----------
test("cross-origin state-changing requests are rejected", async () => {
  const env = fakeEnv({ first: asUser("user") });
  const res = await worker.fetch(req("/api/keys", { method: "POST", headers: { Cookie: SESSION, Origin: "https://evil.example" }, body: {} }), env);
  assert.equal(res.status, 403);
  const same = await worker.fetch(req("/api/keys", { method: "POST", headers: { Cookie: SESSION, Origin: "https://jinhyuk.xyz" }, body: {} }), env);
  assert.equal(same.status, 201);
});

test("every response carries security headers, and HTML also gets a CSP", async () => {
  const env = fakeEnv({ ASSETS: { fetch: async () => new Response("<html></html>", { headers: { "Content-Type": "text/html; charset=utf-8" } }) } });
  const page = await worker.fetch(req("/auth.html"), env);
  assert.match(page.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.equal(page.headers.get("x-frame-options"), "DENY");
  const api = await worker.fetch(req("/api/health"), env);
  assert.equal(api.headers.get("x-content-type-options"), "nosniff");
  assert.equal(api.headers.get("content-security-policy"), null);
});

test("saved scripts are capped per user", async () => {
  const env = fakeEnv({ first: asUser("user", (sql) => (/FROM scripts WHERE user_id=\?/.test(sql) ? { count: 30 } : undefined)) });
  const res = await worker.fetch(req("/api/scripts", { method: "POST", headers: { Cookie: SESSION }, body: { name: "a.lua", source: "print(1)" } }), env);
  assert.equal(res.status, 409);
});

test("obfuscation size limits depend on the mode and are enforced before compiling", async () => {
  const post = (ip, body) => worker.fetch(req("/api/obfuscate", { method: "POST", ip, body }), fakeEnv());
  const big = "print(1)\n".repeat(20000); // ~176 KiB
  assert.equal((await post("198.51.100.101", { source: big, mode: "vm" })).status, 413);
  assert.equal((await post("198.51.100.102", { source: "x".repeat(3 * 1024 * 1024), mode: "compatibility" })).status, 413);
  const ok = await post("198.51.100.103", { source: "print('hi')", mode: "vm" });
  assert.equal(ok.status, 200);
  assert.equal(typeof (await ok.json()).output, "string");
});

test("accounts created before the 5-character ID change can still be managed by admins", async () => {
  const legacyId = "9f2c1a7e4b6d8031a5c7e9f0";
  const env = adminEnv("owner", (sql) => (/SELECT id,role FROM users WHERE id=\?/.test(sql) ? { id: legacyId, role: "user" } : undefined));
  const cookie = await unlock(env);
  const res = await worker.fetch(req(`/api/admin/users/${legacyId}/block`, { method: "POST", headers: { Cookie: cookie }, body: {} }), env);
  assert.equal(res.status, 200);
});

test("oversized JSON bodies still return 413 after the error messages were localised", async () => {
  const env = fakeEnv({ first: asUser("user") });
  const res = await worker.fetch(req("/api/scripts", { method: "POST", headers: { Cookie: SESSION }, body: { name: "a.lua", source: "x".repeat(1_200_000) } }), env);
  assert.equal(res.status, 413);
});

test("the CSP allows the Google Fonts used by the home page", async () => {
  const env = fakeEnv({ ASSETS: { fetch: async () => new Response("<html></html>", { headers: { "Content-Type": "text/html; charset=utf-8" } }) } });
  const csp = (await worker.fetch(req("/"), env)).headers.get("content-security-policy");
  assert.match(csp, /style-src [^;]*https:\/\/fonts\.googleapis\.com/);
  assert.match(csp, /font-src [^;]*https:\/\/fonts\.gstatic\.com/);
});
