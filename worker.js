const MAX_SOURCE_BYTES = 2 * 1024 * 1024;

const reply = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
});

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: {
        "access-control-allow-origin": env.SITE_ORIGIN || url.origin,
        "access-control-allow-methods": "POST, GET, OPTIONS",
        "access-control-allow-headers": "content-type, x-access-key",
        "access-control-max-age": "600",
        "vary": "Origin",
      }});
    }

    if (url.pathname === "/health" && request.method === "GET") {
      return reply({ ok: true, service: "lua-restore-api" });
    }
    if (url.pathname !== "/api/deobfuscate" || request.method !== "POST") {
      return reply({ error: "Not found" }, 404);
    }

    const origin = request.headers.get("Origin") || "";
    const allowedOrigins = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
    if (origin && !allowedOrigins.includes(origin)) return reply({ error: "Origin not allowed" }, 403);

    const suppliedKey = request.headers.get("x-access-key") || "";
    if (!env.SITE_ACCESS_KEY || suppliedKey.length < 16 || suppliedKey !== env.SITE_ACCESS_KEY) {
      return reply({ error: "유효한 사이트 접근 키가 필요합니다." }, 401);
    }
    const length = Number(request.headers.get("content-length") || "0");
    if (length > MAX_SOURCE_BYTES + 16_384) return reply({ error: "소스는 2 MiB 이하만 지원합니다." }, 413);

    let body;
    try { body = await request.json(); } catch { return reply({ error: "Invalid JSON" }, 400); }
    const source = typeof body.source === "string" ? body.source : "";
    const version = String(body.version || "auto");
    if (!source.trim()) return reply({ error: "Lua 소스가 비어 있습니다." }, 400);
    if (new TextEncoder().encode(source).byteLength > MAX_SOURCE_BYTES) return reply({ error: "소스는 2 MiB 이하만 지원합니다." }, 413);
    if (!["auto", "14.7", "14.8", "14.9", "15.0"].includes(version)) return reply({ error: "지원 버전은 auto, 14.7, 14.8, 14.9, 15.0입니다." }, 400);
    if (!env.ENGINE_URL || !env.ENGINE_TOKEN) return reply({ error: "엔진 서버 설정이 완료되지 않았습니다." }, 503);

    try {
      const upstream = await fetch(`${env.ENGINE_URL.replace(/\/+$/, "")}/v1/deobfuscate`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-internal-token": env.ENGINE_TOKEN },
        body: JSON.stringify({ source, version }),
        signal: AbortSignal.timeout(200_000),
      });
      const data = await upstream.json().catch(() => ({ error: "Invalid engine response" }));
      if (!upstream.ok) return reply({ error: data.detail || data.error || "Engine request failed" }, upstream.status >= 500 ? 502 : upstream.status);
      return reply(data);
    } catch {
      return reply({ error: "복원 엔진에 연결할 수 없습니다." }, 502);
    }
  },
};
