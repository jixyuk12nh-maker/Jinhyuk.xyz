import test from "node:test";
import assert from "node:assert/strict";
import worker from "./index.js";

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

test("a malformed session cookie does not crash the API", async () => {
  const res = await worker.fetch(req("/api/me", { headers: { Cookie: "lm_session=%E0%A4%A" } }), fakeEnv());
  assert.equal(res.status, 401);
  assert.equal((await res.json()).authenticated, false);
});

test("the owner email cannot be registered as a normal user without the setup code", async () => {
  const env = fakeEnv({ OWNER_EMAIL: "Owner@Example.com", OWNER_SETUP_CODE: "setup-secret" });
  const res = await signup(env, "owner@example.com");
  assert.equal(res.status, 403);
  assert.equal(env.writes.some((w) => /INSERT INTO users/.test(w.sql)), false);
});

test("the owner email with the correct setup code becomes owner", async () => {
  const env = fakeEnv({ OWNER_EMAIL: "owner@example.com", OWNER_SETUP_CODE: "setup-secret" });
  const res = await signup(env, "owner@example.com", { ownerSetupCode: "setup-secret" }, "203.0.113.11");
  assert.equal(res.status, 201);
  const insert = env.writes.find((w) => /INSERT INTO users/.test(w.sql));
  assert.ok(insert.args.includes("owner"));
});

test("an ordinary email never gets the owner role", async () => {
  const env = fakeEnv({ OWNER_EMAIL: "owner@example.com", OWNER_SETUP_CODE: "setup-secret" });
  const res = await signup(env, "someone@example.com", { ownerSetupCode: "setup-secret" }, "203.0.113.12");
  assert.equal(res.status, 201);
  const insert = env.writes.find((w) => /INSERT INTO users/.test(w.sql));
  assert.ok(insert.args.includes("user") && !insert.args.includes("owner"));
});

test("login attempts are rate limited per IP", async () => {
  const env = fakeEnv();
  let last;
  for (let i = 0; i < 11; i++) last = await worker.fetch(req("/api/auth/login", { method: "POST", ip: "198.51.100.77", body: { email: "x@example.com", password: "wrong-password" } }), env);
  assert.equal(last.status, 429);
});

test("blacklisted IPs are blocked on extensionless page URLs too", async () => {
  const env = fakeEnv({ first: (sql) => (/FROM ip_blacklist/.test(sql) ? { ip: "x" } : null) });
  const res = await worker.fetch(req("/dashboard", { ip: "192.0.2.50" }), env);
  assert.equal(res.status, 403);
});

test("static files bypass the database", async () => {
  const env = fakeEnv();
  const res = await worker.fetch(req("/style.css"), env);
  assert.equal(await res.text(), "asset");
  assert.equal(env.reads.length + env.writes.length, 0);
});

test("/developer requires an owner/admin session", async () => {
  for (const path of ["/developer", "/developer.html"]) {
    const res = await worker.fetch(req(path), fakeEnv());
    assert.equal(res.status, 302);
    assert.match(res.headers.get("location"), /\/auth\.html$/);
  }
});

test("admins cannot block other admins; only the owner can", async () => {
  const first = (sql) => {
    if (/FROM sessions JOIN users/.test(sql)) return { id: "ADM01", email: "a@example.com", role: "admin", status: "active" };
    if (/SELECT id,role FROM users WHERE id=\?/.test(sql)) return { id: "ADM02", role: "admin" };
    return null;
  };
  const res = await worker.fetch(req("/api/admin/users/ADM02/block", { method: "POST", headers: { Cookie: "lm_session=abc" }, body: {} }), fakeEnv({ first }));
  assert.equal(res.status, 403);
});

test("a malformed blacklist IP in the URL returns 400, not a crash", async () => {
  const first = (sql) => (/FROM sessions JOIN users/.test(sql) ? { id: "OWN01", email: "o@example.com", role: "owner", status: "active" } : null);
  const res = await worker.fetch(req("/api/admin/blacklist/%E0%A4%A", { method: "DELETE", headers: { Cookie: "lm_session=abc" } }), fakeEnv({ first }));
  assert.equal(res.status, 400);
});

test("unexpected errors return JSON 500 for API routes", async () => {
  const env = fakeEnv();
  env.DB.prepare = () => { throw new Error("boom"); };
  const res = await worker.fetch(req("/api/auth/login", { method: "POST", ip: "198.51.100.88", body: { email: "x@example.com", password: "whatever-password" } }), env);
  assert.equal(res.status, 500);
  assert.equal((await res.json()).error, "Internal server error.");
});
