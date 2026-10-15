const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const MAX_REQUEST_BYTES = MAX_SOURCE_BYTES + 16_384;
const SUPPORTED_VERSIONS = new Set(["auto", "14.7", "14.8", "14.9", "15.0"]);
const VERSION_LIST = ["14.7", "14.8", "14.9", "15.0"];

function securityHeaders(extra = {}) {
  return {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    ...extra,
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: securityHeaders({
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    }),
  });
}

async function readJsonLimited(request) {
  const reader = request.body?.getReader();
  if (!reader) return { error: "요청 본문이 비어 있습니다.", status: 400 };

  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_REQUEST_BYTES) {
        await reader.cancel();
        return { error: "요청 크기가 너무 큽니다. Lua 소스는 2 MiB 이하만 지원합니다.", status: 413 };
      }
      chunks.push(value);
    }
  } catch {
    return { error: "요청 본문을 읽지 못했습니다.", status: 400 };
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return { body: JSON.parse(new TextDecoder().decode(bytes)) };
  } catch {
    return { error: "요청 JSON을 읽을 수 없습니다.", status: 400 };
  }
}

function withStaticSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(securityHeaders())) {
    if (!headers.has(key)) headers.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json({ error: "Method not allowed" }, 405, { allow: "GET, HEAD" });
      }
      return json({
        ok: true,
        service: "lua-restore-worker",
        runtime: "cloudflare-workers",
        engineReady: false,
        supportedVersions: VERSION_LIST,
        note: "Worker/API is online, but no compatible recovery engine is bundled. Recovery requests cannot succeed yet.",
      });
    }

    if (url.pathname === "/api/deobfuscate") {
      if (request.method !== "POST") {
        return json({ error: "Method not allowed", code: "METHOD_NOT_ALLOWED" }, 405, { allow: "POST" });
      }

      const suppliedKey = request.headers.get("x-access-key") || "";
      if (typeof env.SITE_ACCESS_KEY !== "string" || env.SITE_ACCESS_KEY.length < 16) {
        return json({ error: "Worker secret SITE_ACCESS_KEY is not configured (minimum 16 characters).", code: "ACCESS_KEY_NOT_CONFIGURED" }, 503);
      }
      if (suppliedKey !== env.SITE_ACCESS_KEY) {
        return json({ error: "접근 키가 올바르지 않습니다.", code: "INVALID_ACCESS_KEY" }, 401);
      }

      const contentType = request.headers.get("content-type") || "";
      if (!contentType.toLowerCase().includes("application/json")) {
        return json({ error: "Content-Type은 application/json이어야 합니다.", code: "UNSUPPORTED_MEDIA_TYPE" }, 415);
      }

      const contentLengthHeader = request.headers.get("content-length");
      if (contentLengthHeader && Number(contentLengthHeader) > MAX_REQUEST_BYTES) {
        return json({ error: "요청 크기가 너무 큽니다. Lua 소스는 2 MiB 이하만 지원합니다.", code: "REQUEST_TOO_LARGE" }, 413);
      }

      const parsed = await readJsonLimited(request);
      if (parsed.error) return json({ error: parsed.error, code: parsed.status === 413 ? "REQUEST_TOO_LARGE" : "INVALID_JSON" }, parsed.status);
      const body = parsed.body;

      const source = typeof body?.source === "string" ? body.source : "";
      const version = String(body?.version || "auto");
      if (!source.trim()) return json({ error: "Lua 소스가 비어 있습니다.", code: "EMPTY_SOURCE" }, 400);
      if (new TextEncoder().encode(source).byteLength > MAX_SOURCE_BYTES) {
        return json({ error: "소스는 2 MiB 이하만 지원합니다.", code: "SOURCE_TOO_LARGE" }, 413);
      }
      if (!SUPPORTED_VERSIONS.has(version)) {
        return json({ error: "지원 버전은 auto, 14.7, 14.8, 14.9, 15.0입니다.", code: "UNSUPPORTED_VERSION" }, 400);
      }

      // Do not report success until a real compatible recovery engine is integrated.
      return json({
        ok: false,
        code: "ENGINE_NOT_BUNDLED",
        message: "복원 엔진이 아직 연결되지 않았습니다. Worker와 UI는 실행되지만 실제 복원은 불가능합니다.",
        requestedVersion: version,
        supportedVersions: VERSION_LIST,
      }, 503);
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return json({ error: "Not found", code: "NOT_FOUND" }, 404);
    }

    if (!env.ASSETS) return new Response("Static asset binding ASSETS is missing.", { status: 500, headers: securityHeaders() });
    return withStaticSecurityHeaders(await env.ASSETS.fetch(request));
  },
};
