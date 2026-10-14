// Helpers shared by the compatibility transformer and the VM compiler.

export function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6D2B79F5) | 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function shuffleArray(arr, rng) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

export function encodeXorRotateBytes(bytes, rng) {
  const key = Array.from({ length: 4 }, () => 1 + Math.floor(rng() * 254));
  const rot = 1 + Math.floor(rng() * 7);
  const out = new Uint8Array(bytes.length + 5);
  out[0] = rot;
  out.set(key, 1);
  for (let i = 0; i < bytes.length; i++) {
    const x = bytes[i] ^ key[i % 4];
    out[i + 5] = ((x << rot) | (x >>> (8 - rot))) & 0xff;
  }
  return out;
}

export function base64Encode(bytes, alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const hasB = i + 1 < bytes.length;
    const hasC = i + 2 < bytes.length;
    const b = hasB ? bytes[i + 1] : 0;
    const c = hasC ? bytes[i + 2] : 0;
    out += alphabet[a >> 2];
    out += alphabet[((a & 3) << 4) | (b >> 4)];
    out += hasB ? alphabet[((b & 15) << 2) | (c >> 6)] : "=";
    out += hasC ? alphabet[c & 63] : "=";
  }
  return out;
}

export function secureRandom() {
  if (globalThis.crypto?.getRandomValues) {
    const value = new Uint32Array(1);
    globalThis.crypto.getRandomValues(value);
    return value[0] / 4294967296;
  }
  throw new Error("Secure randomness is unavailable; provide an explicit seed only for testing.");
}

export function longBracketOpen(source, start) {
  if (source[start] !== "[") return null;
  let i = start + 1;
  while (source[i] === "=") i++;
  if (source[i] !== "[") return null;
  return { equals: i - start - 1, contentStart: i + 1 };
}

export function decodeLuaStringBytes(raw, kind) {
  if (kind === "long") {
    const open = longBracketOpen(raw, 0);
    if (!open) throw new Error("Invalid long-bracket string.");
    const close = "]" + "=".repeat(open.equals) + "]";
    let value = raw.slice(open.contentStart, raw.length - close.length).replace(/\r\n?/g, "\n");
    if (value.startsWith("\n")) value = value.slice(1);
    return Array.from(new TextEncoder().encode(value));
  }
  const bytes = [];
  const pushText = value => bytes.push(...new TextEncoder().encode(value));
  for (let i = 1; i < raw.length - 1;) {
    let c = raw[i];
    if (c !== "\\") {
      const cp = raw.codePointAt(i);
      const char = String.fromCodePoint(cp);
      pushText(char);
      i += char.length;
      continue;
    }
    i++;
    if (i >= raw.length - 1) throw new Error("Unfinished escape in string literal.");
    c = raw[i];
    const simple = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, "\\": 92, "\"": 34, "'": 39 };
    if (Object.hasOwn(simple, c)) { bytes.push(simple[c]); i++; continue; }
    if (c === "\n") { bytes.push(10); i++; continue; }
    if (c === "\r") { if (raw[i + 1] === "\n") i++; bytes.push(10); i++; continue; }
    if (c === "z") { i++; while (i < raw.length - 1 && /\s/.test(raw[i])) i++; continue; }
    if (c === "x" && /^[0-9a-fA-F]{2}$/.test(raw.slice(i + 1, i + 3))) {
      bytes.push(parseInt(raw.slice(i + 1, i + 3), 16)); i += 3; continue;
    }
    if (c === "u" && raw[i + 1] === "{") {
      const end = raw.indexOf("}", i + 2);
      if (end < 0) throw new Error("Invalid Unicode escape in string literal.");
      const cp = parseInt(raw.slice(i + 2, end), 16);
      if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) throw new Error("Invalid Unicode escape in string literal.");
      pushText(String.fromCodePoint(cp)); i = end + 1; continue;
    }
    if (/[0-9]/.test(c)) {
      let digits = c;
      while (digits.length < 3 && /[0-9]/.test(raw[i + 1] || "")) digits += raw[++i];
      const n = Number(digits);
      if (n > 255) throw new Error("Decimal escape exceeds 255.");
      bytes.push(n); i++; continue;
    }
    pushText(c);
    i++;
  }
  return bytes;
}

// Returns the source with the contents of string literals, long strings and
// comments replaced by spaces (line breaks kept). Pattern checks run on the
// result cannot fire on text that is only inside a literal or a comment.
export function maskStringsAndComments(source) {
  const parts = [];
  let last = 0;
  const blank = (start, end) => {
    parts.push(source.slice(last, start), source.slice(start, end).replace(/[^\r\n]/g, " "));
    last = end;
  };
  const n = source.length;
  let i = 0;
  while (i < n) {
    const c = source[i];
    if (c === "-" && source[i + 1] === "-") {
      const start = i;
      const open = longBracketOpen(source, i + 2);
      let end;
      if (open) {
        const close = "]" + "=".repeat(open.equals) + "]";
        const found = source.indexOf(close, open.contentStart);
        end = found < 0 ? n : found + close.length;
      } else {
        const found = source.indexOf("\n", i);
        end = found < 0 ? n : found;
      }
      blank(start, end);
      i = end;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const start = i++;
      while (i < n && source[i] !== c) i += source[i] === "\\" ? 2 : 1;
      i = Math.min(i + 1, n);
      blank(start, i);
      continue;
    }
    if (c === "[") {
      const open = longBracketOpen(source, i);
      if (open) {
        const start = i;
        const close = "]" + "=".repeat(open.equals) + "]";
        const found = source.indexOf(close, open.contentStart);
        i = found < 0 ? n : found + close.length;
        blank(start, i);
        continue;
      }
    }
    i++;
  }
  parts.push(source.slice(last));
  return parts.join("");
}

export function hasLuauTypeSyntax(source) {
  return /\bexport\s+type\s+[A-Za-z_]|\btype\s+[A-Za-z_][\w]*\s*=|\btypeof\s*\(|::|\b(?:local\s+)?function\s+[\w.:]+\s*\([^)]*:[^)]*\)|\bfunction\s*\([^)]*:[^)]*\)|\blocal\s+[A-Za-z_]\w*\s*:\s*[A-Za-z_{(]/.test(source);
}
