import {
  mulberry32,
  shuffleArray,
  encodeXorRotateBytes,
  base64Encode,
  longBracketOpen,
  decodeLuaStringBytes,
  hasLuauTypeSyntax,
  maskStringsAndComments,
  secureRandom
} from "./shared.js";

export { compileLuaVm } from "./vm.js";

const KEYWORDS = new Set(["local", "function", "return", "if", "then", "elseif", "else", "end", "while", "repeat", "until", "do", "break", "true", "false", "nil", "and", "or", "not", "for"]);
const NUMBER_RE = /0[xX][0-9a-fA-F]*(?:\.[0-9a-fA-F]*)?(?:[pP][+-]?\d+)?|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?/y;
const NAME_RE = /[A-Za-z_][A-Za-z0-9_]*/y;
// How far back the Luau string classifier looks for the start of a line. Keeps
// the per-string cost constant even for minified single-line sources.
const LINE_LOOKBEHIND = 2000;

function luaStringExpression(bytes, rng, decoderName, alphabet) {
  const key = 1 + Math.floor(rng() * 255);
  const stride = 1 + Math.floor(rng() * 255);
  const cipher = bytes.map((byte, index) => byte ^ ((key + index * stride) & 0xff));
  const payload = base64Encode(cipher, alphabet);
  // Parenthesised so the call stays a single expression even where a string
  // literal is allowed without parentheses, e.g. `print "hi"` -> `print (dec(...))`.
  return `(${decoderName}(${JSON.stringify(payload)},${key},${stride}))`;
}

// Applies non-overlapping replacements given in ascending `start` order.
// Builds the output in one pass; repeated String#slice on the full source
// would make large inputs quadratic.
function applyReplacements(source, replacements) {
  const parts = [];
  let last = 0;
  for (const r of replacements) {
    parts.push(source.slice(last, r.start), r.text);
    last = r.end;
  }
  parts.push(source.slice(last));
  return parts.join("");
}

function makeDecoderName(source, rng) {
  const first = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
  const rest = first + "0123456789";
  for (let attempt = 0; attempt < 100; attempt++) {
    let name = "_";
    for (let i = 0; i < 13; i++) name += (i === 0 ? first : rest)[Math.floor(rng() * (i === 0 ? first : rest).length)];
    if (!source.includes(name)) return name;
  }
  throw new Error("Unable to generate a collision-free string decoder name.");
}

function makeStringDecoder(name, alphabet) {
  // One chunk-local helper decodes a per-build alphabet and per-string rolling XOR mask.
  // This raises the cost of casual string extraction but is not cryptographic protection.
  return `local ${name}=(function(A)local M={} for i=1,#A do M[string.sub(A,i,i)]=i-1 end;return function(S,K,R)local O={} local V=0 local B=0 for i=1,#S do local N=M[string.sub(S,i,i)] if N then V=V*64+N B=B+6 if B>=8 then B=B-8 O[#O+1]=math.floor(V/2^B)%256 V=V%2^B end end end;local function X(a,b)local q,p=0,1 for _=1,8 do local c,d=a%2,b%2 if c~=d then q=q+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return q end;for i=1,#O do O[i]=string.char(X(O[i],(K+(i-1)*R)%256)) end;return table.concat(O) end end)(${JSON.stringify(alphabet)});`;
}

function preludeOffset(source) {
  let pos = source.charCodeAt(0) === 0xfeff ? 1 : 0;
  if (source.startsWith("#!", pos)) {
    const end = source.indexOf("\n", pos);
    pos = end < 0 ? source.length : end + 1;
  }
  while (pos < source.length) {
    const end = source.indexOf("\n", pos);
    const lineEnd = end < 0 ? source.length : end;
    const line = source.slice(pos, lineEnd);
    if (/^\s*$/.test(line) || /^\s*--!/.test(line)) {
      pos = end < 0 ? source.length : end + 1;
      continue;
    }
    break;
  }
  return pos;
}

// Positions used to classify Luau string literals in one linear pass:
// the end offset of every multiline `type X =` alias, and the start offset of
// every line that begins a statement (which ends an alias body).
function luauTypeContext(source) {
  const aliasEnds = [];
  for (const m of source.matchAll(/(?:^|\n)[ \t]*(?:export[ \t]+)?type[ \t]+[A-Za-z_]\w*[ \t]*=/g)) {
    aliasEnds.push(m.index + m[0].length);
  }
  const statementStarts = [];
  for (const m of source.matchAll(/^[ \t]*(?:local\b|function\b|return\b|if\b|for\b|while\b|repeat\b|do\b|print[ \t]*\(|warn[ \t]*\(|[A-Za-z_]\w*[ \t]*=)/gm)) {
    statementStarts.push(m.index);
  }
  return { aliasEnds, statementStarts };
}

// Largest element <= x in an ascending array, or -1.
function lastAtMost(sorted, x) {
  let lo = 0, hi = sorted.length - 1, found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (sorted[mid] <= x) { found = mid; lo = mid + 1; } else hi = mid - 1;
  }
  return found < 0 ? -1 : sorted[found];
}

// Smallest element > x in an ascending array, or Infinity.
function firstAbove(sorted, x) {
  let lo = 0, hi = sorted.length - 1, found = Infinity;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (sorted[mid] > x) { found = sorted[mid]; hi = mid - 1; } else lo = mid + 1;
  }
  return found;
}

function lineStartBefore(source, pos) {
  const floor = Math.max(0, pos - LINE_LOOKBEHIND);
  let p = pos;
  while (p > floor && source[p - 1] !== "\n") p--;
  return p;
}

// Decides whether a Luau string literal is part of a type (alias, annotation,
// function parameter or return type) and must stay literal source text.
// Value strings, including method-call arguments such as `obj:Method("x")`,
// are not type literals and are encoded.
// True when the prefix ends inside a call's argument list, e.g. `obj:Method(`
// or `f(a, `. Function parameter lists (`function f(`) are not calls.
function insideCallArguments(prefix) {
  const open = [];
  for (let k = 0; k < prefix.length; k++) {
    if (prefix[k] === "(") open.push(k);
    else if (prefix[k] === ")") open.pop();
  }
  return open.some(k => {
    const before = prefix.slice(0, k);
    return /[\w\])]\s*$/.test(before) && !/\bfunction\s*[\w.:]*\s*$/.test(before);
  });
}

function isLuauTypeStringLiteral(source, start, context) {
  const windowStart = Math.max(0, start - LINE_LOOKBEHIND);
  const segment = source.slice(windowStart, start);
  const prefix = segment.slice(Math.max(segment.lastIndexOf("\n"), segment.lastIndexOf(";")) + 1);
  // A string inside a call, such as `game:GetService("Players")`, is a value
  // even though the text before it looks like `name:` (a method call).
  if (insideCallArguments(prefix)) return false;
  if (/^\s*(?:export\s+)?type\s+[A-Za-z_]\w*\s*=/.test(prefix)) return true;
  if (/^\s*(?:local\s+)?[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s*:\s*[^=]*$/.test(prefix)) return true;
  if (/\bfunction\b[^\n]*\([^)]*:\s*[^=]*$/.test(prefix)) return true;
  if (/\bfunction\b[^\n]*\)\s*:\s*[^=]*$/.test(prefix)) return true;

  // A string that starts a line continuing a multiline `type X =` alias stays
  // literal, unless a statement line intervened.
  const aliasEnd = lastAtMost(context.aliasEnds, start);
  if (aliasEnd < 0) return false;
  if (firstAbove(context.statementStarts, aliasEnd) <= start) return false;
  // Continuation lines of a union or intersection may begin with `|` or `&`.
  return /^\s*[|&]?\s*$/.test(source.slice(lineStartBefore(source, start), start));
}

function identifierTokens(source) {
  const out = [];
  let i = 0;
  while (i < source.length) {
    const c = source[i];
    if (/\s/.test(c)) { i++; continue; }
    if (source.startsWith("--", i)) {
      const open = longBracketOpen(source, i + 2);
      if (open) {
        const close = "]" + "=".repeat(open.equals) + "]";
        const end = source.indexOf(close, open.contentStart);
        if (end < 0) return null;
        i = end + close.length;
      } else {
        const end = source.indexOf("\n", i);
        i = end < 0 ? source.length : end + 1;
      }
      continue;
    }
    if (c === "'" || c === '"') {
      const quote = c;
      i++;
      while (i < source.length) {
        if (source[i] === "\\") { i += 2; continue; }
        if (source[i++] === quote) break;
      }
      continue;
    }
    if (c === "[") {
      const open = longBracketOpen(source, i);
      if (open) {
        const close = "]" + "=".repeat(open.equals) + "]";
        const end = source.indexOf(close, open.contentStart);
        if (end < 0) return null;
        i = end + close.length;
        continue;
      }
    }
    if (c === "`") {
      i++;
      while (i < source.length) {
        if (source[i] === "\\") { i += 2; continue; }
        if (source[i++] === "`") break;
      }
      continue;
    }
    const start = i;
    // Numbers are consumed whole, so that `0x10` or `1e5` never leaves a
    // `x10` / `e5` identifier behind that a local could be renamed into.
    if (/[0-9]/.test(c) || (c === "." && /[0-9]/.test(source[i + 1] || ""))) {
      NUMBER_RE.lastIndex = i;
      const m = NUMBER_RE.exec(source)[0];
      i += m.length;
      out.push({ value: m, start, end: i, type: "number" });
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      NAME_RE.lastIndex = i;
      const m = NAME_RE.exec(source)[0];
      i += m.length;
      out.push({ value: m, start, end: i, type: KEYWORDS.has(m) ? "keyword" : "identifier" });
      continue;
    }
    const op = ["...", "::", "==", "~=", "<=", ">=", "..", "+=", "-=", "*=", "/=", "%=", "^=", "//"].find(x => source.startsWith(x, i));
    if (op) { i += op.length; out.push({ value: op, start, end: i, type: "symbol" }); continue; }
    i++;
    out.push({ value: c, start, end: i, type: "symbol" });
  }
  return out;
}

// For every token: the number of open block frames (function/do/repeat/if
// bodies) and the innermost open bracket or block frame around it.
function analyzeFrames(tokens) {
  const frames = [];
  const depth = new Array(tokens.length);
  const enclosing = new Array(tokens.length);
  let blocks = 0;
  for (let i = 0; i < tokens.length; i++) {
    const v = tokens[i].value;
    depth[i] = blocks;
    enclosing[i] = frames.length ? frames[frames.length - 1] : null;
    if (v === "(" || v === "[" || v === "{") frames.push(v);
    else if (v === ")" || v === "]" || v === "}") frames.pop();
    else if (v === "function" || v === "do" || v === "repeat" || v === "then") { frames.push("block"); blocks++; }
    else if (v === "elseif" || v === "end" || v === "until") { frames.pop(); blocks--; }
  }
  return { depth, enclosing };
}

function makeIdentifier(rng, used) {
  const first = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
  const rest = first + "0123456789";
  for (let tries = 0; tries < 200; tries++) {
    let name = "_";
    const length = 7 + Math.floor(rng() * 5);
    for (let i = 0; i < length; i++) name += (i === 0 ? first : rest)[Math.floor(rng() * (i === 0 ? first : rest).length)];
    if (!used.has(name)) { used.add(name); return name; }
  }
  throw new Error("Unable to generate a unique local identifier.");
}

// True when the identifier at token j names a field, method, label or goto
// target rather than a variable, so it must not follow a local's rename.
function isNonVariableUse(tokens, j, enclosingFrame) {
  const prev = tokens[j - 1]?.value;
  const next = tokens[j + 1]?.value;
  if (prev === "." || prev === ":" || prev === "::" || prev === "goto") return true;
  if (next === "::") return true;
  // `name = value` inside a table constructor is a field key. Outside one it is
  // an assignment to the local itself and must be renamed with it.
  if (next === "=" && enclosingFrame === "{" && (prev === "{" || prev === "," || prev === ";")) return true;
  return false;
}

// Conservative top-level local renaming. If the source contains constructs that
// make scope analysis ambiguous for this lexical pass, renaming is skipped rather
// than risking a semantic change. String encoding still runs in that case.
function renameSafeTopLevelLocals(source, rng, language) {
  if (source.includes("`") || (language === "luau" && hasLuauTypeSyntax(maskStringsAndComments(source)))) return source;
  const tokens = identifierTokens(source);
  if (!tokens || !tokens.length) return source;
  const { depth, enclosing } = analyzeFrames(tokens);

  const occurrences = new Map();   // name -> token indexes of every identifier use
  const firstUse = new Map();      // name -> index of its first identifier use
  const localDecls = new Map();    // name -> token indexes of `local <name>`
  for (let j = 0; j < tokens.length; j++) {
    const t = tokens[j];
    if (t.type === "identifier") {
      if (!occurrences.has(t.value)) { occurrences.set(t.value, []); firstUse.set(t.value, j); }
      occurrences.get(t.value).push(j);
    }
    if (t.value === "local" && tokens[j + 1]?.type === "identifier") {
      const name = tokens[j + 1].value;
      if (!localDecls.has(name)) localDecls.set(name, []);
      localDecls.get(name).push(j);
    }
  }

  const used = new Set(occurrences.keys());
  const candidates = [];
  const declarations = new Map();
  const functionParams = new Set();
  const loopVars = new Set();
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].value === "function") {
      let j = i + 1;
      while (j < tokens.length && tokens[j].value !== "(" && tokens[j].value !== "end") j++;
      if (tokens[j]?.value === "(") {
        for (j++; j < tokens.length && tokens[j].value !== ")"; j++) {
          if (tokens[j].type === "identifier" && (j === i + 2 || tokens[j - 1]?.value === ",")) functionParams.add(tokens[j].value);
        }
      }
    }
    if (tokens[i].value === "for") {
      for (let j = i + 1; j < tokens.length && tokens[j].value !== "do"; j++) {
        if (tokens[j].type === "identifier" && (j === i + 1 || tokens[j - 1]?.value === ",")) loopVars.add(tokens[j].value);
      }
    }
    if (tokens[i].value !== "local" || depth[i] !== 0) continue;
    let nameIndex = i + 1;
    let isFunction = false;
    if (tokens[nameIndex]?.value === "function") { isFunction = true; nameIndex++; }
    const nameToken = tokens[nameIndex];
    if (!nameToken || nameToken.type !== "identifier") continue;
    // Only initialized, single-name locals are handled by this conservative pass.
    if (!isFunction && tokens[nameIndex + 1]?.value !== "=") continue;
    const name = nameToken.value;
    declarations.set(name, [...(declarations.get(name) || []), nameIndex]);
    candidates.push({ name, index: nameIndex });
  }

  const replacements = [];
  for (const { name, index } of candidates) {
    if ((declarations.get(name) || []).length !== 1 || functionParams.has(name) || loopVars.has(name)) continue;
    // An earlier use of the same name could be a global whose meaning must not change.
    if (firstUse.get(name) < index) continue;
    // Avoid redeclarations of the same name later on.
    if ((localDecls.get(name) || []).some(j => j > index)) continue;
    const renamed = makeIdentifier(rng, used);
    for (const j of occurrences.get(name)) {
      if (j < index) continue;
      if (j !== index && isNonVariableUse(tokens, j, enclosing[j])) continue;
      replacements.push({ start: tokens[j].start, end: tokens[j].end, text: renamed });
    }
  }
  if (!replacements.length) return source;
  replacements.sort((a, b) => a.start - b.start);
  return applyReplacements(source, replacements);
}

function universalLexicalObfuscate(source, rng, options = {}) {
  const language = options.language === "luau" ? "luau" : "lua";
  if (options.renameLocals === true) source = renameSafeTopLevelLocals(source, rng, language);
  const typeContext = language === "luau" ? luauTypeContext(source) : null;
  const replacements = [];
  const alphabetChars = Array.from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<>?@[]^_`{|}~");
  shuffleArray(alphabetChars, rng);
  const alphabet = alphabetChars.slice(0, 64).join("");
  const decoderName = makeDecoderName(source, rng);
  let encodedStringCount = 0;
  let i = 0;
  while (i < source.length) {
    const c = source[i];
    if (c === "'" || c === '"') {
      const start = i++;
      let closed = false;
      while (i < source.length) {
        if (source[i] === "\\") { i += 2; continue; }
        if (source[i] === c) { i++; closed = true; break; }
        i++;
      }
      if (!closed) throw new Error(`Unclosed string at character ${start + 1}.`);
      const preserveTypeLiteral = typeContext !== null && isLuauTypeStringLiteral(source, start, typeContext);
      if (!preserveTypeLiteral) {
        const raw = source.slice(start, i);
        replacements.push({ start, end: i, text: luaStringExpression(decodeLuaStringBytes(raw, "quoted"), rng, decoderName, alphabet) });
        encodedStringCount++;
      }
      continue;
    }
    if (c === "[") {
      const open = longBracketOpen(source, i);
      if (open) {
        const start = i;
        const close = "]" + "=".repeat(open.equals) + "]";
        const end = source.indexOf(close, open.contentStart);
        if (end < 0) throw new Error(`Unclosed long-bracket string at character ${start + 1}.`);
        i = end + close.length;
        const preserveTypeLiteral = typeContext !== null && isLuauTypeStringLiteral(source, start, typeContext);
        if (!preserveTypeLiteral) {
          const raw = source.slice(start, i);
          replacements.push({ start, end: i, text: luaStringExpression(decodeLuaStringBytes(raw, "long"), rng, decoderName, alphabet) });
          encodedStringCount++;
        }
        continue;
      }
    }
    if (c === "`") {
      i++;
      let closed = false;
      while (i < source.length) {
        if (source[i] === "\\") { i += 2; continue; }
        if (source[i] === "`") { i++; closed = true; break; }
        i++;
      }
      if (!closed) throw new Error("Unclosed Luau interpolated string.");
      continue;
    }
    if (source.startsWith("--", i)) {
      const start = i;
      const open = longBracketOpen(source, i + 2);
      if (open) {
        const close = "]" + "=".repeat(open.equals) + "]";
        const end = source.indexOf(close, open.contentStart);
        if (end < 0) throw new Error(`Unclosed long comment at character ${start + 1}.`);
        i = end + close.length;
        const comment = source.slice(start, i);
        if (/^--!/.test(comment)) replacements.push({ start, end: i, text: comment });
        else replacements.push({ start, end: i, text: comment.replace(/[^\r\n]/g, " ") });
      } else {
        const end = source.indexOf("\n", i);
        i = end < 0 ? source.length : end;
        const comment = source.slice(start, i);
        if (/^--!/.test(comment)) replacements.push({ start, end: i, text: comment });
        else replacements.push({ start, end: i, text: comment.replace(/[^\r\n]/g, " ") });
      }
      continue;
    }
    i++;
  }
  let output = applyReplacements(source, replacements);
  if (encodedStringCount > 0) {
    const originalOffset = preludeOffset(source);
    let adjustedOffset = originalOffset;
    for (const item of replacements) {
      if (item.end <= originalOffset) adjustedOffset += item.text.length - (item.end - item.start);
    }
    output = output.slice(0, adjustedOffset) + makeStringDecoder(decoderName, alphabet) + output.slice(adjustedOffset);
  }
  return output;
}

export function compileLuaSubset(source, options = {}) {
  if (typeof source !== "string") throw new Error("Source must be a string.");
  const byteLength = new TextEncoder().encode(source).byteLength;
  const maxBytes = 50 * 1024 * 1024;
  if (byteLength > maxBytes) {
    throw new Error(`Input too large (limit 50MB, got ${(byteLength / (1024 * 1024)).toFixed(2)}MB).`);
  }
  const language = options.language === "luau" ? "luau" : "lua";
  const rng = Number.isInteger(options.seed) ? mulberry32(options.seed ^ (language === "luau" ? 0x4c554155 : 0x4c554120)) : secureRandom;

  // Intentionally do not compile input through the prototype VM. A lexical
  // transformer leaves the target language's grammar and runtime semantics in
  // place, so constructs outside the old VM subset (method calls, varargs,
  // multiple returns/assignments, goto, Lua 5.3 operators, Luau types, etc.)
  // are not rejected or rewritten by a partial parser.
  return universalLexicalObfuscate(source, rng, { language, renameLocals: options.renameLocals === true });
}
