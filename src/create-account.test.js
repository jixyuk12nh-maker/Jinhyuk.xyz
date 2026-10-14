import test from "node:test";
import assert from "node:assert/strict";
import worker from "./index.js";
import { buildAccountSql } from "../scripts/create-account.mjs";

test("a script-created account can log in through the Worker", async () => {
  const { sql, email } = buildAccountSql("Owner@Example.com", "correct-horse-battery", "owner");
  const [, id, em, salt, hash, , role] = sql.match(/VALUES \('([^']+)','([^']+)','([^']+)','([^']+)',(\d+),'([^']+)'/);
  assert.equal(em, email); assert.equal(role, "owner");
  const user = { id, email: em, password_salt: salt, password_hash: hash, role, status: "active" };
  const stmt = (sql2) => { const mk = (args) => ({ first: async () => (/FROM users WHERE email=/.test(sql2) ? user : /COUNT\(\*\)/.test(sql2) ? { count: 0 } : null), run: async () => ({ meta: { changes: 1 } }), all: async () => ({ results: [] }) }); return { ...mk([]), bind: (...a) => mk(a) }; };
  const env = { DB: { prepare: stmt, batch: async () => [] }, ASSETS: { fetch: async () => new Response("") } };
  const call = (password) => worker.fetch(new Request("https://jinhyuk.xyz/api/auth/login", { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.50" }, body: JSON.stringify({ email: em, password }) }), env);
  assert.equal((await call("correct-horse-battery")).status, 200);
  assert.equal((await call("wrong-password-123")).status, 401);
});

test("account script rejects weak passwords and bad emails", () => {
  assert.throws(() => buildAccountSql("a@b.co", "short"));
  assert.throws(() => buildAccountSql("not-an-email", "correct-horse-battery"));
  assert.throws(() => buildAccountSql("a@b.co", "correct-horse-battery", "root"));
});
