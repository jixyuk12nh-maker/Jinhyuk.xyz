import { compileLuaSubset, compileLuaVm } from "./compiler.js";

// A Worker isolate has ~128 MB of memory. Measured: compatibility mode needs roughly 50x the
// input size in memory and VM mode several hundred x, so the old 50 MiB limit could never work
// and let one anonymous request crash the isolate. These limits keep each request inside it.
const MAX_SOURCE_BYTES = { compatibility: 2 * 1024 * 1024, vm: 128 * 1024 };
const MAX_REQUEST_BYTES = 4 * 1024 * 1024;
// Cloudflare Workers reject PBKDF2 with more than 100,000 iterations (NotSupportedError).
const PBKDF2_ITERATIONS = 100000;
const FAIL_WINDOW_MS = 15 * 60_000;
const MAX_FAILS_PER_IP = 5;
const MAX_FAILS_PER_ACCOUNT = 10;
const MAX_SESSIONS_PER_USER = 10;
const MAX_SCRIPTS_PER_USER = 30;
const DEV_UNLOCK_MS = 60 * 60_000;
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
function randomToken(bytes = 32) { const b = crypto.getRandomValues(new Uint8Array(bytes)); return [...b].map(x => x.toString(16).padStart(2, "0")).join(""); }
async function sha256(value) { const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)); return [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2, "0")).join(""); }
async function passwordHash(password, salt = randomToken(16)) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key, 256);
  return { salt, hash: [...new Uint8Array(bits)].map(x => x.toString(16).padStart(2, "0")).join("") };
}
async function bodyJson(request, max = 2_000_000) {
  try { return JSON.parse(await readBoundedText(request, max) || "{}"); }
  catch (e) { const err = new Error(e?.tooLarge ? "요청 본문이 너무 큽니다." : "JSON 형식이 올바르지 않습니다."); err.tooLarge = Boolean(e?.tooLarge); throw err; }
}
function cookieValue(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const part of cookies.split(";")) { const i = part.indexOf("="); if (i > 0 && part.slice(0, i).trim() === name) { try { return decodeURIComponent(part.slice(i + 1).trim()); } catch { return ""; } } }
  return "";
}
async function currentUser(request, env) {
  if (!env.DB) return null;
  const token = cookieValue(request, "lm_session");
  if (token) {
    const hash = await sha256(token);
    const row = await env.DB.prepare("SELECT users.id, users.email, users.role, users.status FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>? LIMIT 1").bind(hash, Date.now()).first();
    if (row && row.status !== "blocked") return { ...row, session: true };
  }
  const auth = request.headers.get("Authorization") || "";
  const apiKey = auth.startsWith("Bearer ") ? auth.slice(7) : request.headers.get("x-api-key") || "";
  if (apiKey) {
    const row = await env.DB.prepare("SELECT users.id, users.email, users.role, users.status, api_keys.id AS key_id FROM api_keys JOIN users ON users.id=api_keys.user_id WHERE api_keys.key_hash=? AND api_keys.revoked_at IS NULL LIMIT 1").bind(await sha256(apiKey)).first();
    if (row && row.status !== "blocked") return { ...row, session: false };
  }
  return null;
}
function sessionCookie(token, maxAge = 60 * 60 * 24 * 14) { return `lm_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`; }
const USER_ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
async function newUserId(db) {
  for (let attempt = 0; attempt < 30; attempt++) {
    const bytes = crypto.getRandomValues(new Uint8Array(5));
    let id = "";
    for (const b of bytes) id += USER_ID_ALPHABET[b % USER_ID_ALPHABET.length];
    const found = await db.prepare("SELECT id FROM users WHERE id=? LIMIT 1").bind(id).first();
    if (!found) return id;
  }
  throw new Error("고유 사용자 ID를 만들지 못했습니다. 다시 시도하세요.");
}
function clientIp(request) {
  return String(request.headers.get("cf-connecting-ip") || "").trim().slice(0, 64).toLowerCase() || "unknown";
}
async function logAccess(env, request, event, outcome, reason = "") {
  if (!env.DB) return;
  try {
    await env.DB.prepare("INSERT INTO access_logs (ip,event,outcome,reason,user_agent,created_at) VALUES (?,?,?,?,?,?)")
      .bind(clientIp(request), String(event).slice(0, 80), String(outcome).slice(0, 40), String(reason).slice(0, 300), String(request.headers.get("user-agent") || "").slice(0, 300), Date.now()).run();
  } catch {}
}
function validEmail(email) { return typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
const DUMMY_SALT = "0".repeat(32);
const ACCESS_LOG_RETENTION_MS = 90 * 86400000;
function safeEqual(a, b) {
  const x = new TextEncoder().encode(String(a)), y = new TextEncoder().encode(String(b));
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}
function safeName(name) { return String(name || "script.lua").replace(/[\r\n\\/\0]/g, "_").slice(0, 120) || "script.lua"; }

async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map(x => x.toString(16).padStart(2, "0")).join("");
}
// Developer Studio unlock: a signed, short-lived cookie bound to the current login session.
async function devCookieValue(env, request, exp) {
  const session = await sha256(cookieValue(request, "lm_session"));
  return `${exp}.${await hmacHex("dev-unlock:" + env.OWNER_SETUP_CODE, `${session}.${exp}`)}`;
}
async function devUnlocked(request, env) {
  if (!env.OWNER_SETUP_CODE) return false;
  const raw = cookieValue(request, "lm_dev"), dot = raw.indexOf(".");
  if (dot < 1) return false;
  const exp = Number(raw.slice(0, dot));
  if (!Number.isFinite(exp) || exp < Date.now()) return false;
  return safeEqual(raw, await devCookieValue(env, request, exp));
}
// Failed attempts are counted from access_logs, so the limit is shared by every Worker instance.
async function countFailures(env, event, { ip, reason }) {
  try {
    const since = Date.now() - FAIL_WINDOW_MS;
    const row = reason
      ? await env.DB.prepare("SELECT COUNT(*) AS count FROM access_logs WHERE event=? AND outcome='failed' AND reason=? AND created_at>?").bind(event, reason, since).first()
      : await env.DB.prepare("SELECT COUNT(*) AS count FROM access_logs WHERE ip=? AND event=? AND outcome='failed' AND created_at>?").bind(ip, event, since).first();
    return Number(row?.count) || 0;
  } catch { return 0; }
}
const tooManyAttempts = () => json({ error: "실패 횟수가 너무 많습니다. 15분 후 다시 시도하세요." }, 429, { "Retry-After": "900" });
async function isIpBlacklisted(env, ip) {
  try { return Boolean(await env.DB.prepare("SELECT ip FROM ip_blacklist WHERE ip=? LIMIT 1").bind(ip).first()); } catch { return false; }
}
async function createSession(env, userId, now = Date.now()) {
  const token = randomToken();
  await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)").bind(await sha256(token), userId, now, now + 14 * 86400000).run();
  try { await env.DB.prepare("DELETE FROM sessions WHERE user_id=? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC LIMIT ?)").bind(userId, userId, MAX_SESSIONS_PER_USER).run(); } catch {}
  return token;
}
function formatLimit(bytes) { return bytes >= 1048576 ? `${bytes / 1048576} MiB` : `${bytes / 1024} KiB`; }

async function api(request, env, url) {
  const path = url.pathname, method = request.method;
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && path !== "/api/obfuscate") {
    const origin = request.headers.get("Origin");
    if (origin && origin !== url.origin) return json({ error: "다른 출처의 요청은 허용되지 않습니다." }, 403);
  }
  if (path === "/api/health" && method === "GET") return json({ ok: true, service: "jinhyuk.xyz", database: Boolean(env.DB) });

  if (path === "/api/auth/signup" && method === "POST") {
    if (!env.DB) return json({ error: "데이터베이스가 설정되지 않았습니다. D1을 만들어 DB로 연결하세요." }, 503);
    const ip = clientIp(request);
    if (await countFailures(env, "signup", { ip }) >= MAX_FAILS_PER_IP) return tooManyAttempts();
    let data; try { data = await bodyJson(request, 12000); } catch (e) { return json({ error: e.message }, 400); }
    const email = String(data.email || "").trim().toLowerCase(), password = String(data.password || "");
    if (!validEmail(email)) return json({ error: "올바른 이메일 주소를 입력하세요." }, 400);
    if (password.length < 10 || password.length > 200) return json({ error: "비밀번호는 10~200자여야 합니다." }, 400);
    const exists = await env.DB.prepare("SELECT id FROM users WHERE email=? LIMIT 1").bind(email).first();
    if (exists) { await logAccess(env, request, "signup", "failed", "Email already exists"); return json({ error: "이미 가입된 이메일입니다." }, 409); }
    const { salt, hash } = await passwordHash(password), id = await newUserId(env.DB), now = Date.now();
    try {
      await env.DB.prepare("INSERT INTO users (id,email,password_salt,password_hash,created_at,role,status,last_ip,last_login_at) SELECT ?,?,?,?,?,CASE WHEN EXISTS (SELECT 1 FROM users) THEN 'user' ELSE 'owner' END,'active',?,?").bind(id, email, salt, hash, now, ip, now).run();
    } catch (e) {
      if (/UNIQUE|constraint/i.test(String(e?.message))) { await logAccess(env, request, "signup", "failed", "Email already exists"); return json({ error: "이미 가입된 이메일입니다." }, 409); }
      throw e;
    }
    await logAccess(env, request, "signup", "success", `user_id=${id}`);
    const token = await createSession(env, id, now);
    return json({ ok: true, user: { id, email } }, 201, { "Set-Cookie": sessionCookie(token) });
  }

  if (path === "/api/auth/login" && method === "POST") {
    if (!env.DB) return json({ error: "데이터베이스가 설정되지 않았습니다." }, 503);
    const ip = clientIp(request);
    if (await countFailures(env, "login", { ip }) >= MAX_FAILS_PER_IP) return tooManyAttempts();
    let data; try { data = await bodyJson(request, 12000); } catch (e) { return json({ error: e.message }, 400); }
    const email = String(data.email || "").trim().toLowerCase(), password = String(data.password || "");
    const user = await env.DB.prepare("SELECT id,email,password_salt,password_hash,role,status FROM users WHERE email=? LIMIT 1").bind(email).first();
    if (!user) { await passwordHash(password, DUMMY_SALT); await logAccess(env, request, "login", "failed", "Email not found"); return json({ error: "이메일 또는 비밀번호가 올바르지 않습니다." }, 401); }
    const failReason = `Incorrect password;user_id=${user.id}`;
    if (await countFailures(env, "login", { reason: failReason }) >= MAX_FAILS_PER_ACCOUNT) return tooManyAttempts();
    const check = await passwordHash(password, user.password_salt);
    if (!safeEqual(check.hash, user.password_hash)) { await logAccess(env, request, "login", "failed", failReason); return json({ error: "이메일 또는 비밀번호가 올바르지 않습니다." }, 401); }
    // Only someone who knows the password learns that the account is blocked.
    if (user.status === "blocked") { await logAccess(env, request, "login", "blocked", `user_id=${user.id}`); return json({ error: "차단된 계정입니다." }, 403); }
    const now = Date.now();
    await env.DB.prepare("UPDATE users SET last_ip=?,last_login_at=? WHERE id=?").bind(ip, now, user.id).run();
    await logAccess(env, request, "login", "success", `user_id=${user.id}`);
    const token = await createSession(env, user.id, now);
    return json({ ok: true, user: { id: user.id, email: user.email } }, 200, { "Set-Cookie": sessionCookie(token) });
  }

  if (path === "/api/auth/logout" && method === "POST") {
    const token = cookieValue(request, "lm_session");
    if (env.DB && token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
    const res = json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) });
    res.headers.append("Set-Cookie", "lm_dev=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
    return res;
  }

  const publicLoaderMatch = path.match(/^\/api\/loader\/([a-f0-9]+)$/);
  if (publicLoaderMatch && method === "GET") {
    if (!env.DB) return json({ error: "데이터베이스가 설정되지 않았습니다." }, 503);
    const auth = request.headers.get("Authorization") || "";
    const apiKey = auth.startsWith("Bearer ") ? auth.slice(7) : request.headers.get("x-api-key") || "";
    if (!apiKey) return json({ error: "API 키가 필요합니다." }, 401);
    const keyRow = await env.DB.prepare("SELECT api_keys.user_id AS user_id, api_keys.id AS id FROM api_keys JOIN users ON users.id=api_keys.user_id WHERE api_keys.key_hash=? AND api_keys.revoked_at IS NULL AND users.status<>'blocked' LIMIT 1").bind(await sha256(apiKey)).first();
    if (!keyRow) return json({ error: "API 키가 올바르지 않습니다." }, 401);
    const script = await env.DB.prepare("SELECT name,source FROM scripts WHERE id=? AND user_id=? LIMIT 1").bind(publicLoaderMatch[1], keyRow.user_id).first();
    if (!script) return json({ error: "스크립트를 찾을 수 없습니다." }, 404);
    await env.DB.prepare("UPDATE api_keys SET last_used_at=? WHERE id=?").bind(Date.now(), keyRow.id).run();
    return new Response(script.source, { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  }

  const user = await currentUser(request, env);
  if (path === "/api/me" && method === "GET") return user ? json({ authenticated: true, id: user.id, email: user.email, role: user.role || "user", isAdmin: ["owner", "admin"].includes(user.role), isOwner: user.role === "owner", session: Boolean(user.session) }) : json({ authenticated: false }, 401);

  if (path === "/api/admin" || path.startsWith("/api/admin/")) {
    if (!user || !user.session) return json({ error: "먼저 계정으로 로그인하세요." }, 401);
    if (!env.DB) return json({ error: "데이터베이스가 설정되지 않았습니다." }, 503);
    if (!["owner", "admin"].includes(user.role)) return json({ error: "개발자 스튜디오 접근이 거부되었습니다." }, 403);
    if (path === "/api/admin/status" && method === "GET") return json({ unlocked: await devUnlocked(request, env), configured: Boolean(env.OWNER_SETUP_CODE) });
    if (path === "/api/admin/unlock" && method === "POST") {
      if (!env.OWNER_SETUP_CODE) return json({ error: "서버에 OWNER_SETUP_CODE가 설정되어 있지 않습니다." }, 503);
      const ip = clientIp(request), reason = `user_id=${user.id}`;
      if (await countFailures(env, "dev_unlock", { ip }) >= MAX_FAILS_PER_IP || await countFailures(env, "dev_unlock", { reason }) >= MAX_FAILS_PER_IP) return tooManyAttempts();
      let data; try { data = await bodyJson(request, 4000); } catch (e) { return json({ error: e.message }, 400); }
      if (!safeEqual(String(data.code || ""), env.OWNER_SETUP_CODE)) { await logAccess(env, request, "dev_unlock", "failed", reason); return json({ error: "개발자 코드가 올바르지 않습니다." }, 403); }
      await logAccess(env, request, "dev_unlock", "success", reason);
      const value = await devCookieValue(env, request, Date.now() + DEV_UNLOCK_MS);
      return json({ ok: true }, 200, { "Set-Cookie": `lm_dev=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${DEV_UNLOCK_MS / 1000}` });
    }
    if (!(await devUnlocked(request, env))) return json({ error: "개발자 코드가 필요합니다.", needsUnlock: true }, 403);
    if (path === "/api/admin/overview" && method === "GET") {
      const [users, visitors, blocked, logs] = await Promise.all([
        env.DB.prepare("SELECT COUNT(*) AS count FROM users").first(),
        env.DB.prepare("SELECT COUNT(DISTINCT ip) AS count FROM access_logs WHERE event IN ('page','login','signup')").first(),
        env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE status='blocked'").first(),
        env.DB.prepare("SELECT COUNT(*) AS count FROM access_logs WHERE created_at>? AND outcome='failed'").bind(Date.now()-86400000).first()
      ]);
      return json({ users: users?.count || 0, visitors: visitors?.count || 0, blocked: blocked?.count || 0, failed24h: logs?.count || 0 });
    }
    if (path === "/api/admin/users" && method === "GET") {
      const rows = await env.DB.prepare("SELECT id,email,role,status,created_at,last_login_at,last_ip FROM users ORDER BY created_at DESC LIMIT 500").all();
      return json({ users: rows.results || [] });
    }
    if (path === "/api/admin/visitors" && method === "GET") {
      const rows = await env.DB.prepare("SELECT id,ip,event,outcome,reason,user_agent,created_at FROM access_logs ORDER BY created_at DESC LIMIT 500").all();
      return json({ visitors: rows.results || [] });
    }
    if (path === "/api/admin/blacklist" && method === "GET") {
      const rows = await env.DB.prepare("SELECT ip,reason,created_at,created_by FROM ip_blacklist ORDER BY created_at DESC LIMIT 500").all();
      return json({ blacklist: rows.results || [] });
    }
    const userMatch = path.match(/^\/api\/admin\/users\/([A-Za-z0-9_-]{1,64})\/(block|unblock|promote|demote)$/);
    if (userMatch && method === "POST") {
      const [, targetId, action] = userMatch;
      const target = await env.DB.prepare("SELECT id,role FROM users WHERE id=? LIMIT 1").bind(targetId).first();
      if (!target) return json({ error: "사용자를 찾을 수 없습니다." }, 404);
      if (target.role === "owner") return json({ error: "소유자 계정은 여기서 변경할 수 없습니다." }, 403);
      if (target.role === "admin" && user.role !== "owner") return json({ error: "관리자 계정은 소유자만 변경할 수 있습니다." }, 403);
      if (["promote", "demote"].includes(action) && user.role !== "owner") return json({ error: "관리자 지정·해제는 소유자만 할 수 있습니다." }, 403);
      if (target.id === user.id && ["block", "demote"].includes(action)) return json({ error: "자기 자신을 차단하거나 권한을 해제할 수 없습니다." }, 400);
      // block also revokes sessions; run both statements in one batch so a blocked account
      // can never end up with status='blocked' while an old session is still left valid (or
      // vice versa) if one of the two writes failed on its own.
      if (action === "block") {
        await env.DB.batch([
          env.DB.prepare("UPDATE users SET status='blocked' WHERE id=?").bind(targetId),
          env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(targetId)
        ]);
      }
      if (action === "unblock") await env.DB.prepare("UPDATE users SET status='active' WHERE id=?").bind(targetId).run();
      if (action === "promote") await env.DB.prepare("UPDATE users SET role='admin' WHERE id=? AND role='user'").bind(targetId).run();
      if (action === "demote") await env.DB.prepare("UPDATE users SET role='user' WHERE id=? AND role='admin'").bind(targetId).run();
      await logAccess(env, request, "admin_user_"+action, "success", `actor=${user.id};target=${targetId}`);
      return json({ ok: true });
    }
    if (path === "/api/admin/blacklist" && method === "POST") {
      if (user.role !== "owner") return json({ error: "IP 블랙리스트는 소유자만 변경할 수 있습니다." }, 403);
      let data; try { data = await bodyJson(request, 4000); } catch (e) { return json({ error: e.message }, 400); }
      const ip = String(data.ip || "").trim().toLowerCase();
      if (!ip || ip.length > 64 || !/^[0-9a-fA-F:.]+$/.test(ip) || ip === "unknown") return json({ error: "올바른 IPv4 또는 IPv6 주소를 입력하세요." }, 400);
      if (ip === clientIp(request)) return json({ error: "현재 접속 중인 내 IP는 차단할 수 없습니다." }, 400);
      await env.DB.prepare("INSERT INTO ip_blacklist (ip,reason,created_at,created_by) VALUES (?,?,?,?) ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,created_at=excluded.created_at,created_by=excluded.created_by").bind(ip, String(data.reason || "Manual block").slice(0,200), Date.now(), user.id).run();
      await logAccess(env, request, "admin_ip_block", "success", `actor=${user.id};ip=${ip}`);
      return json({ ok: true }, 201);
    }
    const unblack = path.match(/^\/api\/admin\/blacklist\/(.+)$/);
    if (unblack && method === "DELETE") {
      if (user.role !== "owner") return json({ error: "IP 블랙리스트는 소유자만 변경할 수 있습니다." }, 403);
      let ip; try { ip = decodeURIComponent(unblack[1]); } catch { return json({ error: "올바르지 않은 IP 주소입니다." }, 400); }
      await env.DB.prepare("DELETE FROM ip_blacklist WHERE ip=?").bind(ip).run();
      await logAccess(env, request, "admin_ip_unblock", "success", `actor=${user.id};ip=${ip}`);
      return json({ ok: true });
    }
    return json({ error: "찾을 수 없습니다." }, 404);
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

  if (!user) return json({ error: "먼저 로그인하세요." }, 401);
  if (!user.session) return json({ error: "이 작업은 브라우저 로그인 세션이 필요합니다. API 키로는 계정 관리나 키 발급을 할 수 없습니다." }, 403);
  if (!env.DB) return json({ error: "데이터베이스가 설정되지 않았습니다. D1을 DB로 연결하세요." }, 503);

  if (path === "/api/keys" && method === "GET") {
    const rows = await env.DB.prepare("SELECT id,label,created_at,last_used_at,revoked_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
    return json({ keys: rows.results || [] });
  }
  if (path === "/api/keys" && method === "POST") {
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM api_keys WHERE user_id=? AND revoked_at IS NULL").bind(user.id).first();
    if ((count?.count || 0) >= 5) return json({ error: "활성 API 키는 최대 5개까지 만들 수 있습니다." }, 409);
    let data = {}; try { data = await bodyJson(request, 4000); } catch (e) { return json({ error: e.message }, 400); }
    const key = `lm_${randomToken(24)}`, id = randomToken(12), now = Date.now();
    await env.DB.prepare("INSERT INTO api_keys (id,user_id,key_hash,label,created_at) VALUES (?,?,?,?,?)").bind(id, user.id, await sha256(key), String(data.label || "기본 키").slice(0, 80), now).run();
    return json({ ok: true, key: { id, label: String(data.label || "기본 키").slice(0,80), created_at: now }, secret: key }, 201);
  }
  const keyMatch = path.match(/^\/api\/keys\/([a-f0-9]+)$/);
  if (keyMatch && method === "DELETE") {
    const result = await env.DB.prepare("UPDATE api_keys SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL").bind(Date.now(), keyMatch[1], user.id).run();
    return result.meta?.changes ? json({ ok: true }) : json({ error: "키를 찾을 수 없습니다." }, 404);
  }

  if (path === "/api/scripts" && method === "GET") {
    const rows = await env.DB.prepare("SELECT id,name,size,created_at,updated_at FROM scripts WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
    return json({ scripts: rows.results || [] });
  }
  if (path === "/api/scripts" && method === "POST") {
    let data; try { data = await bodyJson(request, 1_100_000); } catch (e) { return json({ error: e.message }, e.tooLarge ? 413 : 400); }
    if (typeof data.source !== "string" || !data.source.trim()) return json({ error: "소스 코드가 필요합니다." }, 400);
    const size = new TextEncoder().encode(data.source).byteLength;
    if (size > 900_000) return json({ error: "저장 스크립트는 파일당 최대 900 KB입니다." }, 413);
    const owned = await env.DB.prepare("SELECT COUNT(*) AS count FROM scripts WHERE user_id=?").bind(user.id).first();
    if ((Number(owned?.count) || 0) >= MAX_SCRIPTS_PER_USER) return json({ error: `스크립트는 최대 ${MAX_SCRIPTS_PER_USER}개까지 저장할 수 있습니다. 먼저 하나를 삭제하세요.` }, 409);
    const id = randomToken(12), now = Date.now(), name = safeName(data.name);
    await env.DB.prepare("INSERT INTO scripts (id,user_id,name,source,size,created_at,updated_at) VALUES (?,?,?,?,?,?,?)").bind(id, user.id, name, data.source, size, now, now).run();
    return json({ ok: true, script: { id, name, size, created_at: now } }, 201);
  }
  const scriptMatch = path.match(/^\/api\/scripts\/([a-f0-9]+)$/);
  if (scriptMatch && method === "GET") {
    const row = await env.DB.prepare("SELECT id,name,source,size,created_at,updated_at FROM scripts WHERE id=? AND user_id=?").bind(scriptMatch[1], user.id).first();
    return row ? json({ script: row }) : json({ error: "스크립트를 찾을 수 없습니다." }, 404);
  }
  if (scriptMatch && method === "DELETE") {
    const result = await env.DB.prepare("DELETE FROM scripts WHERE id=? AND user_id=?").bind(scriptMatch[1], user.id).run();
    return result.meta?.changes ? json({ ok: true }) : json({ error: "스크립트를 찾을 수 없습니다." }, 404);
  }
  return json({ error: "찾을 수 없습니다." }, 404);
}

const STATIC_FILE = /\.(?!html$)[a-z0-9]+$/i;
function isPageRequest(request, url) {
  if (request.method !== "GET" && request.method !== "HEAD") return false;
  if (url.pathname.startsWith("/api/")) return false;
  return !STATIC_FILE.test(url.pathname);
}
function defer(ctx, promise) {
  const safe = Promise.resolve(promise).catch(() => {});
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(safe);
  return safe;
}
async function maybeMaintain(env) {
  if (Math.random() > 0.01) return;
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires_at<?").bind(now),
    env.DB.prepare("DELETE FROM access_logs WHERE created_at<?").bind(now - ACCESS_LOG_RETENTION_MS)
  ]);
}
const pageLogSeen = new Map();
function shouldLogPage(ip) {
  const now = Date.now(), last = pageLogSeen.get(ip);
  if (last && now - last < 30_000) return false;
  pageLogSeen.set(ip, now);
  if (pageLogSeen.size > 10000) for (const [k, t] of pageLogSeen) if (now - t > 30_000) pageLogSeen.delete(k);
  return true;
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

async function handle(request, env, ctx) {
  const url = new URL(request.url);
  const isApi = url.pathname.startsWith("/api/"), isPage = isPageRequest(request, url);
  const ip = clientIp(request);
  // The IP blacklist applies to pages and to every API route (except the health check).
  if (env.DB && url.pathname !== "/api/health" && (isApi || isPage) && await isIpBlacklisted(env, ip)) {
    if (shouldLogPage(ip)) defer(ctx, logAccess(env, request, url.pathname === "/api/auth/login" ? "login" : url.pathname === "/api/auth/signup" ? "signup" : isApi ? "api" : "page", "blocked", "IP is blacklisted"));
    return isApi ? json({ error: "차단된 IP 주소입니다." }, 403) : new Response("접근이 거부되었습니다.", { status: 403, headers: PLAIN });
  }
  if (isApi) return api(request, env, url);
  if (env.DB && isPage && shouldLogPage(ip)) {
    defer(ctx, logAccess(env, request, "page", "success", url.pathname || "/"));
    defer(ctx, maybeMaintain(env));
  }
  if (["/developer", "/developer/", "/developer.html"].includes(url.pathname)) {
    const user = await currentUser(request, env);
    if (!user || !user.session || !["owner", "admin"].includes(user.role)) return Response.redirect(new URL("/auth.html", url), 302);
    if (url.pathname !== "/developer.html") return Response.redirect(new URL("/developer.html", url), 302);
  }
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env, ctx) {
    try { return withSecurityHeaders(await handle(request, env, ctx)); }
    catch (e) {
      console.error("Unhandled error:", e);
      const body = new URL(request.url).pathname.startsWith("/api/")
        ? json({ error: "서버 내부 오류가 발생했습니다." }, 500)
        : new Response("서버 내부 오류가 발생했습니다.", { status: 500, headers: PLAIN });
      return withSecurityHeaders(body);
    }
  }
};
