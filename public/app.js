const MAX_FILE_SIZE = 50 * 1024 * 1024;

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
        `${sourceEl.value.length.toLocaleString()} characters · ${formatSize(sourceBytes)}`;

    if (outputEl.value) {
        const outputBytes = new Blob([outputEl.value]).size;

        outputCount.textContent =
            `${outputEl.value.length.toLocaleString()} characters · ${formatSize(outputBytes)}`;
    } else {
        outputCount.textContent = "No output yet";
    }

    outputEmpty.hidden = Boolean(outputEl.value);
}

function checkSourceSize() {
    const bytes = new Blob([sourceEl.value]).size;

    if (bytes > MAX_FILE_SIZE) {
        setStatus(
            `Source exceeds 50 MB (${formatSize(bytes)})`,
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

    if (file.size > MAX_FILE_SIZE) {
        setStatus("File exceeds the 50 MB limit", "error");
        return;
    }

    const extensionAllowed = /\.(lua|txt)$/i.test(file.name);

    if (!extensionAllowed && file.type !== "text/plain") {
        setStatus("Choose a .lua or .txt file", "error");
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

        setStatus("File loaded", "success");
    } catch {
        setStatus("Unable to read this file", "error");
    }
}


sourceEl.addEventListener("input", () => {
    clearOutput();
    updateCounts();

    if (checkSourceSize()) {
        setStatus("Ready");
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

    setStatus("File removed");
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

    setStatus("Example loaded", "success");
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
        languageHintEl.textContent = `${language === "luau" ? "Roblox Luau" : "Standard Lua"} · Experimental VM engine.`;
        compileHintEl.textContent = language === "luau"
            ? "VM mode supports selected Luau syntax, but not type annotations. Test carefully in Roblox."
            : "VM mode embeds an interpreter and may be slower than native execution. Test before use.";
    } else {
        languageHintEl.textContent = `${language === "luau" ? "Roblox Luau" : "Standard Lua"} · Compatibility mode.`;
        compileHintEl.textContent = language === "luau"
            ? "Preserves broad Luau syntax, including type annotations; eligible strings are encoded."
            : "Preserves broad Lua syntax; eligible strings are encoded and ordinary comments are removed.";
    }
    clearOutput();
}
sourceEl?.addEventListener("input", updateLanguageHint);
languageModeEl?.addEventListener("change", () => {
    updateLanguageHint();
    setStatus("Ready");
});
obfuscationModeEl?.addEventListener("change", () => {
    updateLanguageHint();
    setStatus("Ready");
});
updateLanguageHint();

compileBtn.addEventListener("click", async () => {
    if (isCompiling || !checkSourceSize()) return;

    if (!sourceEl.value.trim()) {
        setStatus("Enter Lua source code first", "error");
        sourceEl.focus();
        return;
    }

    isCompiling = true;
    compileBtn.disabled = true;
    compileBtn.innerHTML = 'Compiling… <span aria-hidden="true">⏳</span>';

    setStatus("Compiling");

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
            throw new Error("The server returned an invalid response.");
        }

        if (!response.ok) {
            throw new Error(data.error || "Compilation failed.");
        }

        if (typeof data.output !== "string") {
            throw new Error("The server returned no generated output.");
        }

        outputEl.value = data.output;

        copyBtn.disabled = !data.output;
        downloadBtn.disabled = !data.output;

        updateCounts();
        setStatus("Compilation successful", "success");
    } catch (error) {
        clearOutput();
        setStatus(error.message || "Compilation failed", "error");
    } finally {
        isCompiling = false;
        compileBtn.innerHTML = 'Obfuscate <span aria-hidden="true">→</span>';
        checkSourceSize();
    }
});

copyBtn.addEventListener("click", async () => {
    if (!outputEl.value) return;

    try {
        await navigator.clipboard.writeText(outputEl.value);
        setStatus("Copied to clipboard", "success");
    } catch {
        outputEl.focus();
        outputEl.select();
        setStatus("Select the output and copy it manually", "error");
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
    link.download = "luamoon-obfuscated.lua";

    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);
});

updateCounts();
checkSourceSize();
setStatus("Ready");
