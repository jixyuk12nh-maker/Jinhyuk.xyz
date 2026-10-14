#!/usr/bin/env node
// 처음 사용할 계정을 직접 만드는 스크립트입니다.
// 비밀번호는 저장소에 남기지 않도록 환경변수(ACCOUNT_PASSWORD) 또는 입력창으로만 받습니다.
//
//   ACCOUNT_PASSWORD='원하는비밀번호(10자 이상)' node scripts/create-account.mjs 내이메일@example.com owner --remote
//
// 인자:  <이메일> [owner|admin|user (기본 owner)] [--remote | --local | (없으면 SQL만 출력)]
import { pbkdf2Sync, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline";

const DB_NAME = "jinhyuk.xyz";
const ITERATIONS = 100000; // src/index.js 의 PBKDF2_ITERATIONS 와 반드시 같아야 로그인됩니다.
const ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

export function buildAccountSql(email, password, role = "owner", now = Date.now()) {
  email = String(email || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw new Error("올바른 이메일 주소를 입력하세요.");
  if (password.length < 10 || password.length > 200) throw new Error("비밀번호는 10~200자여야 합니다.");
  if (!["owner", "admin", "user"].includes(role)) throw new Error("권한은 owner, admin, user 중 하나여야 합니다.");
  const salt = randomBytes(16).toString("hex");
  const hash = pbkdf2Sync(Buffer.from(password, "utf8"), Buffer.from(salt, "utf8"), ITERATIONS, 32, "sha256").toString("hex");
  const id = [...randomBytes(5)].map((b) => ID_ALPHABET[b % ID_ALPHABET.length]).join("");
  const q = (v) => `'${String(v).replace(/'/g, "''")}'`;
  const sql = `INSERT INTO users (id,email,password_salt,password_hash,created_at,role,status) VALUES (${q(id)},${q(email)},${q(salt)},${q(hash)},${now},${q(role)},'active');`;
  return { id, email, role, sql };
}

function askPassword() {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes("비밀번호")) process.stdout.write(s); };
    rl.question("비밀번호 (10자 이상, 화면에 표시되지 않음): ", (a) => { rl.close(); process.stdout.write("\n"); resolve(a); });
  });
}

async function main() {
  const args = process.argv.slice(2);
  const flags = args.filter((a) => a.startsWith("--")), pos = args.filter((a) => !a.startsWith("--"));
  const [email, role = "owner"] = pos;
  if (!email) { console.error("사용법: node scripts/create-account.mjs <이메일> [owner|admin|user] [--remote|--local]"); process.exit(1); }
  const password = process.env.ACCOUNT_PASSWORD || (await askPassword());
  const acct = buildAccountSql(email, password, role);
  const target = flags.includes("--remote") ? "--remote" : flags.includes("--local") ? "--local" : null;
  if (!target) { console.log(acct.sql); console.error("\n(비밀번호 해시가 담긴 SQL입니다. 직접 실행하려면 --remote 또는 --local 을 붙이세요.)"); return; }
  const r = spawnSync("npx", ["wrangler", "d1", "execute", DB_NAME, target, "--command", acct.sql], { stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
  console.log(`\n계정을 만들었어요. 이메일: ${acct.email} · 권한: ${acct.role} · ID: ${acct.id}`);
}

import { fileURLToPath } from "node:url";
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch((e) => { console.error(e.message); process.exit(1); });
