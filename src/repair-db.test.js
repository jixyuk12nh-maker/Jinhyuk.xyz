import test from "node:test";
import assert from "node:assert/strict";
import { buildRepairPlan, EXPECTED } from "../scripts/repair-db.mjs";

const BASE_USERS = ["id", "email", "password_salt", "password_hash", "created_at"];
const full = () => Object.fromEntries(Object.entries(EXPECTED).map(([t, c]) => [t, [...c]]));

test("partial manual schema: adds missing tables and users columns, no problems", () => {
  const { problems, actions, sql } = buildRepairPlan({ users: BASE_USERS, api_keys: EXPECTED.api_keys, scripts: EXPECTED.scripts });
  assert.deepEqual(problems, []);
  for (const t of ["sessions", "access_logs", "ip_blacklist"]) assert.ok(actions.includes(`테이블 만들기: ${t}`), t);
  for (const c of ["role", "status", "last_ip", "last_login_at"]) assert.match(sql, new RegExp(`ALTER TABLE users ADD COLUMN ${c} `));
});

test("complete schema: no ALTER statements and no problems", () => {
  const { problems, sql } = buildRepairPlan(full());
  assert.deepEqual(problems, []);
  assert.doesNotMatch(sql, /ALTER TABLE/);
});

test("empty database: creates everything and adds all four users columns", () => {
  const { problems, sql } = buildRepairPlan({});
  assert.deepEqual(problems, []);
  assert.equal((sql.match(/ALTER TABLE users ADD COLUMN/g) || []).length, 4);
});

test("users missing a required base column is reported and not auto-fixed", () => {
  const { problems } = buildRepairPlan({ ...full(), users: ["id", "email", "created_at"] });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /password_salt, password_hash/);
});

test("repair SQL runs on a real SQLite database, is idempotent, and keeps existing rows", async () => {
  let DatabaseSync;
  try { ({ DatabaseSync } = await import("node:sqlite")); } catch { return; }
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
    CREATE TABLE api_keys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, label TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER);
    INSERT INTO users VALUES ('Ab123','a@b.co','s','h',1);`);
  const cols = (t) => db.prepare(`PRAGMA table_info(${t})`).all().map((r) => r.name);
  const existing = Object.fromEntries(Object.keys(EXPECTED).map((t) => [t, cols(t)]));
  db.exec(buildRepairPlan(existing).sql);
  const after = Object.fromEntries(Object.keys(EXPECTED).map((t) => [t, cols(t)]));
  for (const [t, expected] of Object.entries(EXPECTED)) for (const c of expected) assert.ok(after[t].includes(c), `${t}.${c}`);
  assert.equal(db.prepare("SELECT role, status FROM users WHERE id='Ab123'").get().role, "user");
  assert.deepEqual(buildRepairPlan(after).problems, []);
  assert.doesNotMatch(buildRepairPlan(after).sql, /ALTER TABLE/);
  db.exec(buildRepairPlan(after).sql);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM d1_migrations").get().n, 3);
});
