// Must match the Worker: a Worker isolate has ~128 MB of memory, so VM mode accepts far less.
const SOURCE_LIMITS = { compatibility: 2 * 1024 * 1024, vm: 128 * 1024 };
function sourceLimit() {
    return SOURCE_LIMITS[document.querySelector("#obfuscationMode")?.value === "vm" ? "vm" : "compatibility"];
}

const sourceEl = document.querySelector("#source");
const languageModeEl = document.querySelector("#languageMode");
const obfuscationModeEl = document.querySelector("#obfuscationMode");
const languageHintEl = document.querySelector("#languageHint");
const compileHintEl = document.querySelector("#compileHint");
const outputEl = document.querySelector("#output");
const compileBtn = document.querySelector("#compile");
const copyBtn = document.querySelector("#copy");
const downloadBtn = document.querySelector("#download");
const statusEl = document.querySelector("#status");
const sourceCount = document.querySelector("#sourceCount");
const outputCount = document.querySelector("#outputCount");
const fileInput = document.querySelector("#fileInput");
const uploadBtn = document.querySelector("#uploadFile");
const loadExampleBtn = document.querySelector("#loadExample");
const fileInfo = document.querySelector("#fileInfo");
const fileName = document.querySelector("#fileName");
const fileSize = document.querySelector("#fileSize");
const removeFileBtn = document.querySelector("#removeFile");
const sourceDropzone = document.querySelector("#sourceDropzone");
const dropHint = document.querySelector("#dropHint");
const outputEmpty = document.querySelector("#outputEmpty");

let isCompiling = false;
let loadedFile = null;

const statusDot = statusEl.querySelector(".status-dot");

function setStatus(message, kind = "") {
    statusEl.replaceChildren(
        statusDot,
        document.createTextNode(message)
    );

    statusEl.className = kind;
}

function formatSize(bytes) {
    if (bytes >= 1024 * 1024) {
        return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    }

    if (bytes >= 1024) {
        return `${(bytes / 1024).toFixed(2)} KB`;
    }

    return `${bytes} bytes`;
}

function updateCounts() {
    const sourceBytes = new Blob([sourceEl.value]).size;

    sourceCount.textContent =
        `${sourceEl.value.length.toLocaleString("ko-KR")}자 · ${formatSize(sourceBytes)}`;

    if (outputEl.value) {
        const outputBytes = new Blob([outputEl.value]).size;

        outputCount.textContent =
            `${outputEl.value.length.toLocaleString("ko-KR")}자 · ${formatSize(outputBytes)}`;
    } else {
        outputCount.textContent = "아직 결과 없음";
    }

    outputEmpty.hidden = Boolean(outputEl.value);
}

function checkSourceSize() {
    const bytes = new Blob([sourceEl.value]).size;

    if (bytes > sourceLimit()) {
        setStatus(
            `소스가 이 모드의 한도(${formatSize(sourceLimit())})를 넘었습니다 (${formatSize(bytes)})`,
            "error"
        );

        compileBtn.disabled = true;
        return false;
    }

    compileBtn.disabled = isCompiling;
    return true;
}

function clearOutput() {
    outputEl.value = "";
    copyBtn.disabled = true;
    downloadBtn.disabled = true;
    updateCounts();
}

function resetLoadedFile() {
    loadedFile = null;
    fileInput.value = "";
    fileInfo.hidden = true;
    fileName.textContent = "";
    fileSize.textContent = "";
}

async function loadFile(file) {
    if (!file) return;

    if (file.size > sourceLimit()) {
        setStatus(`파일이 이 모드의 한도(${formatSize(sourceLimit())})를 넘었습니다`, "error");
        return;
    }

    const extensionAllowed = /\.(lua|txt)$/i.test(file.name);

    if (!extensionAllowed && file.type !== "text/plain") {
        setStatus(".lua 또는 .txt 파일을 선택하세요", "error");
        return;
    }

    try {
        const text = await file.text();

        sourceEl.value = text;
        loadedFile = file;

        fileName.textContent = file.name;
        fileSize.textContent = formatSize(file.size);
        fileInfo.hidden = false;

        clearOutput();
        updateCounts();
        checkSourceSize();
        updateLanguageHint();

        setStatus("파일을 불러왔습니다", "success");
    } catch {
        setStatus("파일을 읽을 수 없습니다", "error");
    }
}


sourceEl.addEventListener("input", () => {
    clearOutput();
    updateCounts();

    if (checkSourceSize()) {
        setStatus("준비됨");
    }
});

uploadBtn.addEventListener("click", () => {
    fileInput.click();
});

fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];

    if (file) {
        await loadFile(file);
    }

    fileInput.value = "";
});

removeFileBtn.addEventListener("click", () => {
    resetLoadedFile();
    sourceEl.value = "";

    clearOutput();
    updateCounts();
    checkSourceSize();
    updateLanguageHint();

    setStatus("파일을 제거했습니다");
    sourceEl.focus();
});

loadExampleBtn.addEventListener("click", () => {
    resetLoadedFile();

    sourceEl.value = [
        'local name = "jinhyuk.xyz"',
        "local count = 2",
        "if count > 1 then",
        '    print(name .. " VM ready")',
        "else",
        '    warn("not ready")',
        "end"
    ].join("\n");

    clearOutput();
    updateCounts();
    checkSourceSize();
    updateLanguageHint();

    setStatus("예제를 불러왔습니다", "success");
});

for (const eventName of ["dragenter", "dragover"]) {
    sourceDropzone.addEventListener(eventName, event => {
        event.preventDefault();
        sourceDropzone.classList.add("drag-active");
        dropHint.hidden = false;
    });
}

for (const eventName of ["dragleave", "dragend"]) {
    sourceDropzone.addEventListener(eventName, event => {
        if (
            eventName === "dragleave" &&
            sourceDropzone.contains(event.relatedTarget)
        ) {
            return;
        }

        sourceDropzone.classList.remove("drag-active");
        dropHint.hidden = true;
    });
}

sourceDropzone.addEventListener("drop", async event => {
    event.preventDefault();

    sourceDropzone.classList.remove("drag-active");
    dropHint.hidden = true;

    const file = event.dataTransfer?.files?.[0];

    if (file) {
        await loadFile(file);
    }
});

function detectLuaTarget(source) {
    const masked = source
        .replace(/--\[(=*)\[[\s\S]*?\]\1\]/g, " ")
        .replace(/--[^\r\n]*/g, " ")
        .replace(/\[(=*)\[[\s\S]*?\]\1\]/g, " ")
        .replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, " ");
    const luauHints = [
        /\btype\s+[A-Za-z_]/,
        /\bexport\s+type\b/,
        /\btypeof\s*\(/,
        /::/,
        /\bcontinue\b/,
        /\bgame\s*:/,
        /\bEnum\./,
        /\bInstance\.new\b/,
        /\+=|-=|\*=|\/=|\.\.=|%=/
    ];
    return luauHints.some((r) => r.test(masked)) ? "luau" : "lua";
}

function resolvedLanguage() {
    const selected = languageModeEl.value;
    return selected === "auto" ? detectLuaTarget(sourceEl.value) : selected;
}

function updateLanguageHint() {
    const language = resolvedLanguage();
    if (obfuscationModeEl.value === "vm") {
        languageHintEl.textContent = `${language === "luau" ? "로블록스 Luau" : "표준 Lua"} · 실험적 VM 엔진.`;
        compileHintEl.textContent = language === "luau"
            ? "VM 모드는 일부 Luau 문법만 지원하며 타입 표기는 지원하지 않습니다. 로블록스에서 꼼꼼히 테스트하세요."
            : "VM 모드는 인터프리터를 포함하므로 기본 실행보다 느릴 수 있습니다. 사용 전에 테스트하세요.";
    } else {
        languageHintEl.textContent = `${language === "luau" ? "로블록스 Luau" : "표준 Lua"} · 호환성 모드.`;
        compileHintEl.textContent = language === "luau"
            ? "타입 표기를 포함한 넓은 Luau 문법을 유지하며, 변환 가능한 문자열을 인코딩합니다."
            : "넓은 Lua 문법을 유지하며, 변환 가능한 문자열을 인코딩하고 일반 주석을 제거합니다.";
    }
    clearOutput();
}
sourceEl?.addEventListener("input", updateLanguageHint);
languageModeEl?.addEventListener("change", () => {
    updateLanguageHint();
    setStatus("준비됨");
});
obfuscationModeEl?.addEventListener("change", () => {
    updateLanguageHint();
    setStatus("준비됨");
    checkSourceSize();
});
updateLanguageHint();

compileBtn.addEventListener("click", async () => {
    if (isCompiling || !checkSourceSize()) return;

    if (!sourceEl.value.trim()) {
        setStatus("먼저 Lua 소스 코드를 입력하세요", "error");
        sourceEl.focus();
        return;
    }

    isCompiling = true;
    compileBtn.disabled = true;
    compileBtn.innerHTML = '변환 중… <span aria-hidden="true">⏳</span>';

    setStatus("변환 중");

    try {
        const response = await fetch("/api/obfuscate", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                source: sourceEl.value,
                language: resolvedLanguage(),
                mode: obfuscationModeEl?.value || "compatibility"
            })
        });

        let data;

        try {
            data = await response.json();
        } catch {
            throw new Error("서버 응답이 올바르지 않습니다.");
        }

        if (!response.ok) {
            throw new Error(data.error || "변환에 실패했습니다.");
        }

        if (typeof data.output !== "string") {
            throw new Error("서버가 변환 결과를 반환하지 않았습니다.");
        }

        outputEl.value = data.output;

        copyBtn.disabled = !data.output;
        downloadBtn.disabled = !data.output;

        updateCounts();
        setStatus("변환 완료", "success");
    } catch (error) {
        clearOutput();
        setStatus(error.message || "변환에 실패했습니다", "error");
    } finally {
        isCompiling = false;
        compileBtn.innerHTML = '난독화 <span aria-hidden="true">→</span>';
        checkSourceSize();
    }
});

copyBtn.addEventListener("click", async () => {
    if (!outputEl.value) return;

    try {
        await navigator.clipboard.writeText(outputEl.value);
        setStatus("클립보드에 복사했습니다", "success");
    } catch {
        outputEl.focus();
        outputEl.select();
        setStatus("결과를 선택해서 직접 복사하세요", "error");
    }
});

downloadBtn.addEventListener("click", () => {
    if (!outputEl.value) return;

    const blob = new Blob(
        [outputEl.value],
        { type: "text/plain;charset=utf-8" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "jinhyuk-obfuscated.lua";

    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);
});

updateCounts();
checkSourceSize();
setStatus("준비됨");
