const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const SUPPORTED_VERSIONS = new Set(["auto", "14.7", "14.8", "14.9", "15.0"]);

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...extraHeaders,
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      return json({
        ok: true,
        service: "lua-restore-worker",
        runtime: "cloudflare-workers",
        engineReady: false,
        supportedVersions: ["14.7", "14.8", "14.9", "15.0"],
        note: "Worker/API is online; a compatible recovery engine has not been bundled.",
      });
    }

    if (url.pathname === "/api/deobfuscate") {
      if (request.method !== "POST") {
        return json({ error: "Method not allowed" }, 405, { allow: "POST" });
      }

      const suppliedKey = request.headers.get("x-access-key") || "";
      if (typeof env.SITE_ACCESS_KEY !== "string" || env.SITE_ACCESS_KEY.length < 16) {
        return json({ error: "Worker secret SITE_ACCESS_KEY is not configured (minimum 16 characters)." }, 503);
      }
      if (suppliedKey !== env.SITE_ACCESS_KEY) {
        return json({ error: "접근 키가 올바르지 않습니다." }, 401);
      }

      const contentLength = Number(request.headers.get("content-length") || 0);
      if (contentLength > MAX_SOURCE_BYTES + 16_384) {
        return json({ error: "소스는 2 MiB 이하만 지원합니다." }, 413);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "요청 JSON을 읽을 수 없습니다." }, 400);
      }

      const source = typeof body?.source === "string" ? body.source : "";
      const version = String(body?.version || "auto");
      if (!source.trim()) return json({ error: "Lua 소스가 비어 있습니다." }, 400);
      if (new TextEncoder().encode(source).byteLength > MAX_SOURCE_BYTES) {
        return json({ error: "소스는 2 MiB 이하만 지원합니다." }, 413);
      }
      if (!SUPPORTED_VERSIONS.has(version)) {
        return json({ error: "지원 버전은 auto, 14.7, 14.8, 14.9, 15.0입니다." }, 400);
      }

      // Deliberately do not pretend to deobfuscate: the Python/Luau engine from
      // the original package cannot run natively inside a standard Worker.
      return json({
        ok: false,
        code: "ENGINE_NOT_BUNDLED",
        message: "Worker와 UI는 정상 실행 중이지만 Luraph 복원 엔진이 아직 Worker용으로 이식되지 않았습니다. 복원 성공을 가장하지 않고 요청을 중단했습니다.",
        requestedVersion: version,
        supportedVersions: ["14.7", "14.8", "14.9", "15.0"],
      }, 503);
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return json({ error: "Not found" }, 404);
    }

    if (!env.ASSETS) return new Response("Static asset binding ASSETS is missing.", { status: 500 });
    return env.ASSETS.fetch(request);
  },
};
