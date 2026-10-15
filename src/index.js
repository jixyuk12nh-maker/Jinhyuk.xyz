import { compileLuaSubset, compileLuaVm } from "./compiler.js";

// ---------------------------------------------------------------------------
// jinhyuk.xyz Worker: 계정(회원가입/로그인/세션) + 난독화 API.
// 계정 테이블은 첫 요청 때 스스로 만들어지므로 별도 마이그레이션이 필요 없습니다.
// ---------------------------------------------------------------------------

// A Worker isolate has ~128 MB of memory. Compatibility mode needs roughly 50x the input size
// and VM mode several hundred x, so these limits keep each request inside it.
const MAX_SOURCE_BYTES = { compatibility: 2 * 1024 * 1024, vm: 128 * 1024 };
const MAX_REQUEST_BYTES = 4 * 1024 * 1024;
// Cloudflare Workers reject PBKDF2 with more than 100,000 iterations (NotSupportedError).
const PBKDF2_ITERATIONS = 100000;
const SESSION_MS = 14 * 86400000;
const MAX_SESSIONS_PER_ACCOUNT = 10;
const FAIL_WINDOW_MS = 15 * 60_000;
const MAX_FAILS_PER_IP = 5;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const rateBuckets = new Map();

function isRateLimited(key, max = RATE_LIMIT_MAX_REQUESTS) {
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.start > RATE_LIMIT_WINDOW_MS) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(key, bucket);
  }
  bucket.count++;
  if (rateBuckets.size > 10000) for (const [k, v] of rateBuckets) if (now - v.start > RATE_LIMIT_WINDOW_MS) rateBuckets.delete(k);
  return bucket.count > max;
}

async function readBoundedText(request, maxBytes) {
  if (!request.body) return await request.text();
  const reader = request.body.getReader(), chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) { const e = new Error("Request too large."); e.tooLarge = true; throw e; }
      chunks.push(value);
    }
  } finally { try { reader.releaseLock(); } catch {} }
  const buffer = new Uint8Array(total); let offset = 0;
  for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(buffer);
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...headers } });
}

async function bodyJson(request, max = 2_000_000) {
  try { return JSON.parse(await readBoundedText(request, max) || "{}"); }
  catch (e) { const err = new Error(e?.tooLarge ? "요청 본문이 너무 큽니다." : "JSON 형식이 올바르지 않습니다."); err.tooLarge = Boolean(e?.tooLarge); throw err; }
}

function formatLimit(bytes) { return bytes >= 1048576 ? `${bytes / 1048576} MiB` : `${bytes / 1024} KiB`; }

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }

function randomToken(bytes = 32) { return [...crypto.getRandomValues(new Uint8Array(bytes))].map((x) => x.toString(16).padStart(2, "0")).join(""); }
async function sha256(value) { const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)); return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join(""); }
async function passwordHash(password, salt = randomToken(16)) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key, 256);
  return { salt, hash: [...new Uint8Array(bits)].map((x) => x.toString(16).padStart(2, "0")).join("") };
}
function safeEqual(a, b) {
  const x = new TextEncoder().encode(String(a)), y = new TextEncoder().encode(String(b));
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}
function cookieValue(request, name) {
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) { try { return decodeURIComponent(part.slice(i + 1).trim()); } catch { return ""; } }
  }
  return "";
}
const sessionCookie = (token, maxAge = SESSION_MS / 1000) => `lm_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const clientIp = (request) => String(request.headers.get("cf-connecting-ip") || "").trim().slice(0, 64).toLowerCase() || "unknown";
const validEmail = (e) => typeof e === "string" && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const DUMMY_SALT = "0".repeat(32);

// Failed signup/login attempts per IP (best effort: kept in this isolate's memory).
const failures = new Map();
function failCount(ip) { const f = failures.get(ip); return f && Date.now() - f.start < FAIL_WINDOW_MS ? f.count : 0; }
function addFailure(ip) {
  const now = Date.now();
  let f = failures.get(ip);
  if (!f || now - f.start >= FAIL_WINDOW_MS) { f = { start: now, count: 0 }; failures.set(ip, f); }
  f.count++;
  if (failures.size > 10000) for (const [k, v] of failures) if (now - v.start >= FAIL_WINDOW_MS) failures.delete(k);
}
const tooMany = () => json({ error: "실패 횟수가 너무 많습니다. 15분 후 다시 시도하세요." }, 429, { "Retry-After": "900" });

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS account_sessions (token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS account_sessions_account_idx ON account_sessions(account_id)",
  "CREATE INDEX IF NOT EXISTS account_sessions_expiry_idx ON account_sessions(expires_at)"
];
const schemaReady = new WeakMap();
function ensureSchema(db) {
  let p = schemaReady.get(db);
  if (!p) {
    p = db.batch(SCHEMA.map((sql) => db.prepare(sql))).catch((e) => { schemaReady.delete(db); throw e; });
    schemaReady.set(db, p);
  }
  return p;
}
async function getDb(env) {
  if (!env.DB) throw new HttpError(503, "데이터베이스(DB 바인딩)가 연결되어 있지 않습니다.");
  try { await ensureSchema(env.DB); }
  catch (e) { console.error("DB schema setup failed:", e?.message); throw new HttpError(503, "데이터베이스를 준비하지 못했습니다. 잠시 후 다시 시도하세요."); }
  return env.DB;
}

async function currentAccount(request, env) {
  const token = cookieValue(request, "lm_session");
  if (!token || !env.DB) return null;
  const db = await getDb(env);
  return await db.prepare("SELECT accounts.id AS id, accounts.email AS email FROM account_sessions JOIN accounts ON accounts.id=account_sessions.account_id WHERE account_sessions.token_hash=? AND account_sessions.expires_at>? LIMIT 1").bind(await sha256(token), Date.now()).first();
}
async function startSession(db, accountId) {
  const token = randomToken(), now = Date.now();
  await db.prepare("INSERT INTO account_sessions (token_hash,account_id,created_at,expires_at) VALUES (?,?,?,?)").bind(await sha256(token), accountId, now, now + SESSION_MS).run();
  try {
    await db.prepare("DELETE FROM account_sessions WHERE account_id=? AND (expires_at<? OR token_hash NOT IN (SELECT token_hash FROM account_sessions WHERE account_id=? ORDER BY created_at DESC LIMIT ?))").bind(accountId, now, accountId, MAX_SESSIONS_PER_ACCOUNT).run();
  } catch (e) { console.error("session cleanup failed:", e?.message); }
  return token;
}
async function credentials(request) {
  let data;
  try { data = await bodyJson(request, 12000); } catch (e) { throw new HttpError(400, e.message); }
  return { email: String(data.email ?? "").trim().toLowerCase(), password: String(data.password ?? ""), invite: String(data.inviteCode ?? "").trim() };
}

async function api(request, env, url) {
  const path = url.pathname, method = request.method;
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && path !== "/api/obfuscate") {
    const origin = request.headers.get("Origin");
    if (origin && origin !== url.origin) return json({ error: "다른 출처의 요청은 허용되지 않습니다." }, 403);
  }

  if (path === "/api/health" && method === "GET") {
    let schema = false;
    if (env.DB) { try { await ensureSchema(env.DB); schema = true; } catch (e) { console.error("health: schema setup failed:", e?.message); } }
    return json({ ok: true, service: "jinhyuk.xyz", database: Boolean(env.DB), schema, inviteCodeSet: Boolean(String(env.INVITE_CODE || "").trim()) });
  }

  if (path === "/api/auth/signup" && method === "POST") {
    const db = await getDb(env), ip = clientIp(request);
    if (failCount(ip) >= MAX_FAILS_PER_IP) return tooMany();
    const { email, password, invite } = await credentials(request);
    if (!validEmail(email)) return json({ error: "올바른 이메일 주소를 입력하세요." }, 400);
    if (password.length < 10 || password.length > 200) return json({ error: "비밀번호는 10~200자여야 합니다." }, 400);
    const expected = String(env.INVITE_CODE || "").trim();
    if (!expected) return json({ error: "가입이 아직 열려 있지 않습니다. 서버에 INVITE_CODE가 설정되지 않았습니다." }, 503);
    if (!safeEqual(invite, expected)) { addFailure(ip); return json({ error: "초대 코드가 올바르지 않습니다." }, 403); }
    const taken = () => json({ error: "이미 가입된 이메일입니다." }, 409);
    if (await db.prepare("SELECT id FROM accounts WHERE email=? LIMIT 1").bind(email).first()) return taken();
    const { salt, hash } = await passwordHash(password), id = crypto.randomUUID();
    try {
      await db.prepare("INSERT INTO accounts (id,email,password_salt,password_hash,created_at) VALUES (?,?,?,?,?)").bind(id, email, salt, hash, Date.now()).run();
    } catch (e) {
      if (/UNIQUE|constraint/i.test(String(e?.message))) return taken();
      throw e;
    }
    const token = await startSession(db, id);
    return json({ ok: true, user: { id, email } }, 201, { "Set-Cookie": sessionCookie(token) });
  }

  if (path === "/api/auth/login" && method === "POST") {
    const db = await getDb(env), ip = clientIp(request);
    if (failCount(ip) >= MAX_FAILS_PER_IP) return tooMany();
    const { email, password } = await credentials(request);
    const row = await db.prepare("SELECT id,email,password_salt,password_hash FROM accounts WHERE email=? LIMIT 1").bind(email).first();
    const check = await passwordHash(password, row ? row.password_salt : DUMMY_SALT);
    if (!row || !safeEqual(check.hash, row.password_hash)) { addFailure(ip); return json({ error: "이메일 또는 비밀번호가 올바르지 않습니다." }, 401); }
    const token = await startSession(db, row.id);
    return json({ ok: true, user: { id: row.id, email: row.email } }, 200, { "Set-Cookie": sessionCookie(token) });
  }

  if (path === "/api/auth/logout" && method === "POST") {
    const token = cookieValue(request, "lm_session");
    if (token && env.DB) {
      try { await (await getDb(env)).prepare("DELETE FROM account_sessions WHERE token_hash=?").bind(await sha256(token)).run(); }
      catch (e) { console.error("logout: could not delete session:", e?.message); }
    }
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) });
  }

  if (path === "/api/me" && method === "GET") {
    const account = await currentAccount(request, env);
    return account ? json({ authenticated: true, id: account.id, email: account.email }) : json({ authenticated: false }, 401);
  }

  if (path === "/api/obfuscate" && method === "POST") {
    const clientKey = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "unknown";
    if (isRateLimited(clientKey)) return json({ error: "요청이 너무 많습니다. 잠시 후 다시 시도하세요." }, 429, { "Retry-After": "30" });
    if (!(request.headers.get("content-type") || "").toLowerCase().includes("application/json")) return json({ error: "Content-Type은 application/json이어야 합니다." }, 415);
    const declaredLength = Number(request.headers.get("content-length") || 0);
    if (declaredLength > MAX_REQUEST_BYTES) return json({ error: "요청이 너무 큽니다. 최대 4 MiB까지 가능합니다." }, 413);
    let data; try { data = await bodyJson(request, MAX_REQUEST_BYTES); } catch (e) { return json({ error: e.message }, e.tooLarge ? 413 : 400); }
    if (typeof data.source !== "string" || !data.source.trim()) return json({ error: "먼저 소스 코드를 입력하세요." }, 400);
    if (data.language !== undefined && !["lua", "luau"].includes(data.language)) return json({ error: "language는 lua 또는 luau여야 합니다." }, 400);
    const mode = data.mode === "vm" ? "vm" : "compatibility";
    if (new TextEncoder().encode(data.source).byteLength > MAX_SOURCE_BYTES[mode]) return json({ error: `소스가 너무 큽니다. ${mode === "vm" ? "VM" : "호환성"} 모드 한도는 ${formatLimit(MAX_SOURCE_BYTES[mode])}입니다.` }, 413);
    try {
      const language = data.language === "luau" ? "luau" : "lua";
      const output = mode === "vm" ? compileLuaVm(data.source, { language }) : compileLuaSubset(data.source, { language, renameLocals: true });
      return json({ output, language, mode, note: mode === "vm" ? "실험적 VM 모드입니다. 실제 실행 환경에서 반드시 테스트하세요. 실행이 느려질 수 있고 모든 Luau 기능을 지원하지는 않습니다." : "호환성 모드는 변환 가능한 문자열과 주석을 처리하고 지역 변수 이름을 보수적으로 바꿉니다. 완전한 VM 가상화는 아닙니다." });
    } catch (e) { return json({ error: e?.message || "변환에 실패했습니다." }, 400); }
  }

  return json({ error: "찾을 수 없습니다." }, 404);
}

const PLAIN = { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" };
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
function withSecurityHeaders(response) {
  const res = new Response(response.body, response);
  const h = res.headers;
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "same-origin");
  h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  h.set("Strict-Transport-Security", "max-age=31536000");
  if ((h.get("Content-Type") || "").includes("text/html")) h.set("Content-Security-Policy", CSP);
  return res;
}

// 서버가 직접 접근을 막는 페이지 (로그인하지 않으면 /auth 로 보냅니다).
const DASHBOARD_PATHS = new Set(["/dashboard", "/dashboard/", "/dashboard.html"]);
const AUTH_PATHS = new Set(["/auth", "/auth/", "/auth.html"]);
const redirect = (to) => new Response(null, { status: 302, headers: { Location: to, "Cache-Control": "no-store" } });
async function accountOrNull(request, env) {
  try { return await currentAccount(request, env); }
  catch (e) { console.error("session lookup failed:", e?.message); return null; }
}

async function handle(request, env) {
  const url = new URL(request.url), path = url.pathname;
  if (path.startsWith("/api/")) return api(request, env, url);
  const isRead = request.method === "GET" || request.method === "HEAD";
  if (isRead && DASHBOARD_PATHS.has(path)) {
    if (!(await accountOrNull(request, env))) return redirect("/auth");
    const asset = await env.ASSETS.fetch(request);
    const page = new Response(asset.body, asset);
    page.headers.set("Cache-Control", "private, no-store");
    return page;
  }
  if (isRead && AUTH_PATHS.has(path) && cookieValue(request, "lm_session") && await accountOrNull(request, env)) return redirect("/dashboard");
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env) {
    try { return withSecurityHeaders(await handle(request, env)); }
    catch (e) {
      if (e instanceof HttpError) return withSecurityHeaders(new URL(request.url).pathname.startsWith("/api/") ? json({ error: e.message }, e.status) : new Response(e.message, { status: e.status, headers: PLAIN }));
      console.error("Unhandled error:", e);
      const body = new URL(request.url).pathname.startsWith("/api/")
        ? json({ error: "서버 내부 오류가 발생했습니다." }, 500)
        : new Response("서버 내부 오류가 발생했습니다.", { status: 500, headers: PLAIN });
      return withSecurityHeaders(body);
    }
  }
};
