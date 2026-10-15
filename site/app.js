(() => {
  // The site is served on the same origin as the Worker route /api/deobfuscate.
  // Configure a reverse proxy or replace API_BASE with your Worker URL if needed.
  const API_BASE = "";
  const $ = (selector) => document.querySelector(selector);
  const fileInput = $("#file");
  const sourceInput = $("#source");
  const fileName = $("#file-name");
  const count = $("#char-count");
  const run = $("#run");
  const resultSection = $("#result-section");
  const output = $("#output");
  const download = $("#download");
  const status = $("#result-summary");
  const badge = $("#result-badge");
  const log = $("#engine-log");
  let downloadName = "recovered.lua";
  const MAX_BYTES = 2 * 1024 * 1024;

  function updateCount() { count.textContent = `${sourceInput.value.length.toLocaleString()} characters`; }
  sourceInput.addEventListener("input", updateCount);

  async function loadFile(file) {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      fileName.textContent = "File too large (max 2 MiB)";
      fileInput.value = "";
      return;
    }
    sourceInput.value = await file.text();
    downloadName = file.name.replace(/\.(lua|luau|txt)$/i, "") + ".recovered.lua";
    fileName.textContent = `${file.name} · ${file.size.toLocaleString()} bytes`;
    updateCount();
  }
  fileInput.addEventListener("change", () => loadFile(fileInput.files?.[0]));

  const dropzone = $("#dropzone");
  ["dragenter", "dragover"].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
    event.preventDefault(); dropzone.classList.add("dragover");
  }));
  ["dragleave", "drop"].forEach((eventName) => dropzone.addEventListener(eventName, (event) => {
    event.preventDefault(); dropzone.classList.remove("dragover");
  }));
  dropzone.addEventListener("drop", (event) => loadFile(event.dataTransfer?.files?.[0]));

  function showResult(kind, message) {
    resultSection.hidden = false;
    badge.className = `result-badge ${kind}`;
    badge.textContent = kind === "success" ? "Finished · unverified" : "Failed";
    status.textContent = message;
    resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  run.addEventListener("click", async () => {
    const source = sourceInput.value;
    const accessKey = $("#access-key").value.trim();
    if (!source.trim()) { showResult("error", "Lua/Luau 소스를 입력하거나 파일을 선택해 주세요."); return; }
    if (new TextEncoder().encode(source).byteLength > MAX_BYTES) {
      showResult("error", "소스는 2 MiB 이하만 지원합니다."); return;
    }
    if (!accessKey) { showResult("error", "사이트 접근 키를 입력해 주세요."); return; }

    run.disabled = true;
    run.querySelector("span:first-child").textContent = "Analyzing...";
    output.value = ""; log.textContent = ""; download.disabled = true;
    resultSection.hidden = false;
    badge.className = "result-badge"; badge.textContent = "Running";
    status.textContent = "분석 중입니다. 큰 파일은 시간이 걸릴 수 있습니다.";
    try {
      const response = await fetch(`${API_BASE}/api/deobfuscate`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-access-key": accessKey },
        body: JSON.stringify({ source, version: $("#version").value }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || data.detail || `Request failed (${response.status})`);
      log.textContent = data.engine_log || "";
      if (!data.ok || !data.recovered_source) {
        showResult("error", data.message || data.error || "엔진이 복원 가능한 결과를 만들지 못했습니다.");
        if (data.engine_log) log.textContent = data.engine_log;
        return;
      }
      output.value = data.recovered_source;
      download.disabled = false;
      showResult("success", `${data.message || "결과 파일을 생성했습니다."} · 엔진 ${data.engine || "unknown"} · ${Number(data.output_bytes || new TextEncoder().encode(output.value).length).toLocaleString()} bytes · ${data.elapsed_seconds ?? "?"} sec`);
    } catch (error) {
      showResult("error", error.message || "요청에 실패했습니다.");
    } finally {
      run.disabled = false;
      run.querySelector("span:first-child").textContent = "Analyze script";
    }
  });

  download.addEventListener("click", () => {
    const url = URL.createObjectURL(new Blob([output.value], { type: "text/plain;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = downloadName; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
})();
