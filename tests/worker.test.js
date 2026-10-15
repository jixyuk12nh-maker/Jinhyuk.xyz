import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";

const env = { SITE_ACCESS_KEY: "test-access-key-1234567890" };
const ctx = {};

async function call(path, init = {}, bindings = env) {
  const request = new Request(`https://example.test${path}`, init);
  return worker.fetch(request, bindings, ctx);
}

test("health reports Worker online without claiming engine readiness", async () => {
  const response = await call("/health");
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.ok, true);
  assert.equal(body.engineReady, false);
  assert.deepEqual(body.supportedVersions, ["14.7", "14.8", "14.9", "15.0"]);
});

test("API rejects wrong access key", async () => {
  const response = await call("/api/deobfuscate", {
    method: "POST",
    headers: { "content-type": "application/json", "x-access-key": "wrong" },
    body: JSON.stringify({ source: "return 1", version: "14.7" }),
  });
  assert.equal(response.status, 401);
});

test("API rejects unsupported version", async () => {
  const response = await call("/api/deobfuscate", {
    method: "POST",
    headers: { "content-type": "application/json", "x-access-key": env.SITE_ACCESS_KEY },
    body: JSON.stringify({ source: "return 1", version: "13.0" }),
  });
  assert.equal(response.status, 400);
});

test("API does not fake successful recovery without an engine", async () => {
  const response = await call("/api/deobfuscate", {
    method: "POST",
    headers: { "content-type": "application/json", "x-access-key": env.SITE_ACCESS_KEY },
    body: JSON.stringify({ source: "return 1", version: "14.7" }),
  });
  assert.equal(response.status, 503);
  const body = await response.json();
  assert.equal(body.ok, false);
  assert.equal(body.code, "ENGINE_NOT_BUNDLED");
});

test("API rejects empty source", async () => {
  const response = await call("/api/deobfuscate", {
    method: "POST",
    headers: { "content-type": "application/json", "x-access-key": env.SITE_ACCESS_KEY },
    body: JSON.stringify({ source: "   ", version: "14.7" }),
  });
  assert.equal(response.status, 400);
});


test("health rejects non-GET methods", async () => {
  const response = await call("/health", { method: "POST" });
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "GET, HEAD");
});

test("API requires JSON content type", async () => {
  const response = await call("/api/deobfuscate", {
    method: "POST",
    headers: { "x-access-key": env.SITE_ACCESS_KEY, "content-type": "text/plain" },
    body: "source=return%201",
  });
  assert.equal(response.status, 415);
});

test("API rejects a source larger than 2 MiB", async () => {
  const source = "a".repeat(2 * 1024 * 1024 + 1);
  const response = await call("/api/deobfuscate", {
    method: "POST",
    headers: { "content-type": "application/json", "x-access-key": env.SITE_ACCESS_KEY },
    body: JSON.stringify({ source, version: "14.7" }),
  });
  assert.equal(response.status, 413);
  const body = await response.json();
  assert.equal(body.code, "SOURCE_TOO_LARGE");
});
