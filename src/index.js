import { compileLuaSubset, compileLuaVm } from "./compiler.js";

const MAX_SOURCE_BYTES = 50 * 1024 * 1024;
const MAX_REQUEST_BYTES = 55 * 1024 * 1024;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const rateBuckets = new Map();

function isRateLimited(key) {
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.start > RATE_LIMIT_WINDOW_MS) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(key, bucket);
  }
  bucket.count++;
  if (rateBuckets.size > 10000) for (const [k, v] of rateBuckets) if (now - v.start > RATE_LIMIT_WINDOW_MS) rateBuckets.delete(k);
  return bucket.count > RATE_LIMIT_MAX_REQUESTS;
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
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations: 150000, hash: "SHA-256" }, key, 256);
  return { salt, hash: [...new Uint8Array(bits)].map(x => x.toString(16).padStart(2, "0")).join("") };
}
async function bodyJson(request, max = 2_000_000) {
  try { return JSON.parse(await readBoundedText(request, max) || "{}"); }
  catch (e) { throw new Error(e?.tooLarge ? "Request body too large." : "Invalid JSON."); }
}
function cookieValue(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const part of cookies.split(";")) { const i = part.indexOf("="); if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim()); }
  return "";
}
async function currentUser(request, env) {
  if (!env.DB) return null;
  const token = cookieValue(request, "lm_session");
  if (token) {
    const hash = await sha256(token);
    const row = await env.DB.prepare("SELECT users.id, users.email FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>? LIMIT 1").bind(hash, Date.now()).first();
    if (row) return { ...row, session: true };
  }
  const auth = request.headers.get("Authorization") || "";
  const apiKey = auth.startsWith("Bearer ") ? auth.slice(7) : request.headers.get("x-api-key") || "";
  if (apiKey) {
    const row = await env.DB.prepare("SELECT users.id, users.email, api_keys.id AS key_id FROM api_keys JOIN users ON users.id=api_keys.user_id WHERE api_keys.key_hash=? AND api_keys.revoked_at IS NULL LIMIT 1").bind(await sha256(apiKey)).first();
    if (row) return { ...row, session: false };
  }
  return null;
}
function sessionCookie(token, maxAge = 60 * 60 * 24 * 14) { return `lm_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`; }
function validEmail(email) { return typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function safeName(name) { return String(name || "script.lua").replace(/[\r\n\\/\0]/g, "_").slice(0, 120) || "script.lua"; }

async function api(request, env, url) {
  const path = url.pathname, method = request.method;
  if (path === "/api/health" && method === "GET") return json({ ok: true, service: "LuaMoon", database: Boolean(env.DB) });

  if (path === "/api/auth/signup" && method === "POST") {
    if (!env.DB) return json({ error: "Database is not configured. Create and bind D1 as DB." }, 503);
    let data; try { data = await bodyJson(request, 12000); } catch (e) { return json({ error: e.message }, 400); }
    const email = String(data.email || "").trim().toLowerCase(), password = String(data.password || ""), invite = String(data.inviteCode || "");
    if (!validEmail(email)) return json({ error: "Enter a valid email address." }, 400);
    if (password.length < 10 || password.length > 200) return json({ error: "Password must be 10–200 characters." }, 400);
    if (!env.INVITE_CODE || invite !== env.INVITE_CODE) return json({ error: "Invalid invite code." }, 403);
    const exists = await env.DB.prepare("SELECT id FROM users WHERE email=? LIMIT 1").bind(email).first();
    if (exists) return json({ error: "An account with this email already exists." }, 409);
    const { salt, hash } = await passwordHash(password), id = randomToken(16), now = Date.now();
    await env.DB.prepare("INSERT INTO users (id,email,password_salt,password_hash,created_at) VALUES (?,?,?,?,?)").bind(id, email, salt, hash, now).run();
    const token = randomToken(), tokenHash = await sha256(token);
    await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)").bind(tokenHash, id, now, now + 14 * 86400000).run();
    return json({ ok: true, user: { id, email } }, 201, { "Set-Cookie": sessionCookie(token) });
  }

  if (path === "/api/auth/login" && method === "POST") {
    if (!env.DB) return json({ error: "Database is not configured." }, 503);
    let data; try { data = await bodyJson(request, 12000); } catch (e) { return json({ error: e.message }, 400); }
    const email = String(data.email || "").trim().toLowerCase(), password = String(data.password || "");
    const user = await env.DB.prepare("SELECT id,email,password_salt,password_hash FROM users WHERE email=? LIMIT 1").bind(email).first();
    if (!user) return json({ error: "Email or password is incorrect." }, 401);
    const check = await passwordHash(password, user.password_salt);
    if (check.hash !== user.password_hash) return json({ error: "Email or password is incorrect." }, 401);
    const token = randomToken(), now = Date.now();
    await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)").bind(await sha256(token), user.id, now, now + 14 * 86400000).run();
    return json({ ok: true, user: { id: user.id, email: user.email } }, 200, { "Set-Cookie": sessionCookie(token) });
  }

  if (path === "/api/auth/logout" && method === "POST") {
    const token = cookieValue(request, "lm_session");
    if (env.DB && token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) });
  }

  const publicLoaderMatch = path.match(/^\/api\/loader\/([a-f0-9]+)$/);
  if (publicLoaderMatch && method === "GET") {
    if (!env.DB) return json({ error: "Database is not configured." }, 503);
    const auth = request.headers.get("Authorization") || "";
    const apiKey = auth.startsWith("Bearer ") ? auth.slice(7) : request.headers.get("x-api-key") || "";
    if (!apiKey) return json({ error: "API key required." }, 401);
    const keyRow = await env.DB.prepare("SELECT user_id,id FROM api_keys WHERE key_hash=? AND revoked_at IS NULL LIMIT 1").bind(await sha256(apiKey)).first();
    if (!keyRow) return json({ error: "Invalid API key." }, 401);
    const script = await env.DB.prepare("SELECT name,source FROM scripts WHERE id=? AND user_id=? LIMIT 1").bind(publicLoaderMatch[1], keyRow.user_id).first();
    if (!script) return json({ error: "Script not found." }, 404);
    await env.DB.prepare("UPDATE api_keys SET last_used_at=? WHERE id=?").bind(Date.now(), keyRow.id).run();
    return new Response(script.source, { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  }

  const user = await currentUser(request, env);
  if (path === "/api/me" && method === "GET") return user ? json({ authenticated: true, email: user.email, session: Boolean(user.session) }) : json({ authenticated: false }, 401);

  if (path === "/api/obfuscate" && method === "POST") {
    const clientKey = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "unknown";
    if (isRateLimited(clientKey)) return json({ error: "Too many requests. Please slow down and try again shortly." }, 429, { "Retry-After": "30" });
    if (!(request.headers.get("content-type") || "").toLowerCase().includes("application/json")) return json({ error: "Content-Type must be application/json." }, 415);
    const declaredLength = Number(request.headers.get("content-length") || 0);
    if (declaredLength > MAX_REQUEST_BYTES) return json({ error: "Request too large. Maximum request size is 55 MiB." }, 413);
    let data; try { data = await bodyJson(request, MAX_REQUEST_BYTES); } catch (e) { return json({ error: e.message }, e.message.includes("large") ? 413 : 400); }
    if (typeof data.source !== "string" || !data.source.trim()) return json({ error: "Enter source code first." }, 400);
    if (data.language !== undefined && !["lua", "luau"].includes(data.language)) return json({ error: "Language must be either lua or luau." }, 400);
    if (new TextEncoder().encode(data.source).byteLength > MAX_SOURCE_BYTES) return json({ error: "Source limit is 50 MiB." }, 413);
    try {
      const language = data.language === "luau" ? "luau" : "lua", mode = data.mode === "vm" ? "vm" : "compatibility";
      const output = mode === "vm" ? compileLuaVm(data.source, { language }) : compileLuaSubset(data.source, { language, renameLocals: true });
      return json({ output, language, mode, note: mode === "vm" ? "Experimental VM mode. Validate output in your exact target runtime; it may run slower and does not support every Luau feature." : "Compatibility mode transforms eligible strings/comments and conservatively renames locals. It is not full VM virtualization." });
    } catch (e) { return json({ error: e?.message || "Compilation failed." }, 400); }
  }

  if (!user) return json({ error: "Sign in first." }, 401);
  if (!user.session) return json({ error: "This operation requires a browser session. API keys cannot manage accounts or issue other keys." }, 403);
  if (!env.DB) return json({ error: "Database is not configured. Bind D1 as DB." }, 503);

  if (path === "/api/keys" && method === "GET") {
    const rows = await env.DB.prepare("SELECT id,label,created_at,last_used_at,revoked_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
    return json({ keys: rows.results || [] });
  }
  if (path === "/api/keys" && method === "POST") {
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM api_keys WHERE user_id=? AND revoked_at IS NULL").bind(user.id).first();
    if ((count?.count || 0) >= 5) return json({ error: "You can have up to 5 active API keys." }, 409);
    let data = {}; try { data = await bodyJson(request, 4000); } catch (e) { return json({ error: e.message }, 400); }
    const key = `lm_${randomToken(24)}`, id = randomToken(12), now = Date.now();
    await env.DB.prepare("INSERT INTO api_keys (id,user_id,key_hash,label,created_at) VALUES (?,?,?,?,?)").bind(id, user.id, await sha256(key), String(data.label || "Default key").slice(0, 80), now).run();
    return json({ ok: true, key: { id, label: String(data.label || "Default key").slice(0,80), created_at: now }, secret: key }, 201);
  }
  const keyMatch = path.match(/^\/api\/keys\/([a-f0-9]+)$/);
  if (keyMatch && method === "DELETE") {
    const result = await env.DB.prepare("UPDATE api_keys SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL").bind(Date.now(), keyMatch[1], user.id).run();
    return result.meta?.changes ? json({ ok: true }) : json({ error: "Key not found." }, 404);
  }

  if (path === "/api/scripts" && method === "GET") {
    const rows = await env.DB.prepare("SELECT id,name,size,created_at,updated_at FROM scripts WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
    return json({ scripts: rows.results || [] });
  }
  if (path === "/api/scripts" && method === "POST") {
    let data; try { data = await bodyJson(request, 1_100_000); } catch (e) { return json({ error: e.message }, e.message.includes("large") ? 413 : 400); }
    if (typeof data.source !== "string" || !data.source.trim()) return json({ error: "Source code is required." }, 400);
    const size = new TextEncoder().encode(data.source).byteLength;
    if (size > 900_000) return json({ error: "Saved scripts are limited to 900 KB per file." }, 413);
    const id = randomToken(12), now = Date.now(), name = safeName(data.name);
    await env.DB.prepare("INSERT INTO scripts (id,user_id,name,source,size,created_at,updated_at) VALUES (?,?,?,?,?,?,?)").bind(id, user.id, name, data.source, size, now, now).run();
    return json({ ok: true, script: { id, name, size, created_at: now } }, 201);
  }
  const scriptMatch = path.match(/^\/api\/scripts\/([a-f0-9]+)$/);
  if (scriptMatch && method === "GET") {
    const row = await env.DB.prepare("SELECT id,name,source,size,created_at,updated_at FROM scripts WHERE id=? AND user_id=?").bind(scriptMatch[1], user.id).first();
    return row ? json({ script: row }) : json({ error: "Script not found." }, 404);
  }
  if (scriptMatch && method === "DELETE") {
    const result = await env.DB.prepare("DELETE FROM scripts WHERE id=? AND user_id=?").bind(scriptMatch[1], user.id).run();
    return result.meta?.changes ? json({ ok: true }) : json({ error: "Script not found." }, 404);
  }
  return json({ error: "Not found." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return api(request, env, url);
    return env.ASSETS.fetch(request);
  }
};
