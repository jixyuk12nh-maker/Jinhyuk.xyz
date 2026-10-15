#!/usr/bin/env node
// 수동으로 만들어져 일부 테이블/컬럼이 빠진 D1 데이터베이스를 복구합니다.
// 여러 번 실행해도 안전합니다(없는 것만 만들고, 있는 데이터는 건드리지 않습니다).
//
//   npm run repair-db                         # jinhyuk_xyz 원격 DB
//   npm run repair-db -- 다른DB이름 --local   # 로컬 DB
//
// 하는 일: 빠진 테이블(sessions, access_logs, ip_blacklist 등) 생성, users에 빠진 컬럼 추가,
// 인덱스 생성, 그리고 wrangler 마이그레이션 기록(d1_migrations)을 맞춰 두어
// 이후 `wrangler d1 migrations apply`가 중복 실행으로 실패하지 않게 합니다.
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const EXPECTED = {
  users: ["id", "email", "password_salt", "password_hash", "created_at", "role", "status", "last_ip", "last_login_at"],
  sessions: ["token_hash", "user_id", "created_at", "expires_at"],
  api_keys: ["id", "user_id", "key_hash", "label", "created_at", "last_used_at", "revoked_at"],
  scripts: ["id", "user_id", "name", "source", "size", "created_at", "updated_at"],
  access_logs: ["id", "ip", "event", "outcome", "reason", "user_agent", "created_at"],
  ip_blacklist: ["ip", "reason", "created_at", "created_by"]
};

// migrations/0002 에서 users 에 추가되는 컬럼들 (기존 행이 있어도 안전한 DEFAULT 포함)
const USER_ADDABLE = {
  role: "TEXT NOT NULL DEFAULT 'user'",
  status: "TEXT NOT NULL DEFAULT 'active'",
  last_ip: "TEXT",
  last_login_at: "INTEGER"
};

const CREATE_TABLES = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS scripts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  source TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS access_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  event TEXT NOT NULL,
  outcome TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_blacklist (
  ip TEXT PRIMARY KEY,
  reason TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL
);`;

const CREATE_INDEXES = `
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS api_keys_user_idx ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS scripts_user_idx ON scripts(user_id);
CREATE INDEX IF NOT EXISTS users_role_status_idx ON users(role,status);
CREATE INDEX IF NOT EXISTS access_logs_created_idx ON access_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS access_logs_ip_idx ON access_logs(ip,created_at DESC);
CREATE INDEX IF NOT EXISTS access_logs_event_reason_idx ON access_logs(event, reason, created_at DESC);
CREATE INDEX IF NOT EXISTS access_logs_outcome_created_idx ON access_logs(outcome, created_at DESC);`;

const MIGRATION_RECORD = `
CREATE TABLE IF NOT EXISTS d1_migrations(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO d1_migrations (name) VALUES ('0001_init.sql'), ('0002_admin_and_visitors.sql'), ('0003_access_logs_perf.sql');`;

// existing: { 테이블이름: [현재 컬럼 이름들] } (테이블이 없으면 빈 배열)
export function buildRepairPlan(existing) {
  const problems = [], actions = [], alters = [];
  for (const [table, expected] of Object.entries(EXPECTED)) {
    const have = existing[table] || [];
    if (!have.length) { actions.push(`테이블 만들기: ${table}`); continue; }
    const missing = expected.filter((c) => !have.includes(c));
    if (table === "users") {
      const base = missing.filter((c) => !(c in USER_ADDABLE));
      if (base.length) problems.push(`users 테이블에 필수 컬럼이 없습니다: ${base.join(", ")}`);
      for (const c of missing.filter((c) => c in USER_ADDABLE)) actions.push(`users 컬럼 추가: ${c}`);
    } else if (missing.length) {
      problems.push(`${table} 테이블 모양이 다릅니다. 없는 컬럼: ${missing.join(", ")}`);
    }
  }
  const usersHave = existing.users || [];
  for (const [col, def] of Object.entries(USER_ADDABLE)) {
    if (!usersHave.includes(col)) {
      alters.push(`ALTER TABLE users ADD COLUMN ${col} ${def};`);
      if (!usersHave.length) actions.push(`users 컬럼 추가: ${col}`);
    }
  }
  const sql = [CREATE_TABLES, alters.join("\n"), CREATE_INDEXES, MIGRATION_RECORD].join("\n").trim() + "\n";
  return { problems, actions, sql };
}

function wrangler(args, { capture = false } = {}) {
  return spawnSync("npx", ["wrangler", ...args], capture ? { encoding: "utf8" } : { stdio: "inherit" });
}

function parseResults(stdout) {
  const start = stdout.indexOf("[");
  const data = JSON.parse(stdout.slice(start));
  return data?.[0]?.results || [];
}

function main() {
  const args = process.argv.slice(2);
  const flags = args.filter((a) => a.startsWith("--")), pos = args.filter((a) => !a.startsWith("--"));
  const db = pos[0] || "jinhyuk_xyz";
  const target = flags.includes("--local") ? "--local" : "--remote";
  console.log(`대상 DB: ${db} (${target.slice(2)})\n현재 테이블 구조를 확인하는 중…`);
  const existing = {};
  for (const table of Object.keys(EXPECTED)) {
    const r = wrangler(["d1", "execute", db, target, "--json", "--command", `PRAGMA table_info(${table})`], { capture: true });
    if (r.status !== 0) { console.error(r.stderr || r.stdout || "wrangler 실행에 실패했습니다."); process.exit(1); }
    try { existing[table] = parseResults(r.stdout).map((row) => row.name); }
    catch { console.error(`${table} 구조를 읽지 못했습니다:\n${r.stdout}`); process.exit(1); }
  }
  const { problems, actions, sql } = buildRepairPlan(existing);
  if (problems.length) {
    console.error("\n자동으로 고칠 수 없는 문제가 있어 아무것도 변경하지 않았습니다:\n- " + problems.join("\n- "));
    process.exit(1);
  }
  console.log(actions.length ? "\n적용할 변경:\n- " + actions.join("\n- ") : "\n빠진 테이블이나 컬럼은 없습니다. 인덱스와 마이그레이션 기록만 맞춥니다.");
  const dir = mkdtempSync(join(tmpdir(), "repair-db-"));
  const file = join(dir, "repair.sql");
  try {
    writeFileSync(file, sql);
    const r = wrangler(["d1", "execute", db, target, "--file", file]);
    if (r.status !== 0) process.exit(r.status ?? 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
  console.log("\n복구 후 테이블 목록:");
  wrangler(["d1", "execute", db, target, "--command", "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"]);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
