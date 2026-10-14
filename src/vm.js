// VM mode: Lua / Luau source -> stack bytecode -> embedded interpreter.
//
// Pipeline: lex() -> Parser (full Lua expression/statement grammar) ->
// Compiler (scope-resolved locals, upvalues, multiple returns, varargs,
// goto/labels) -> emitLua() (shuffled opcodes, masked operands, NOP padding,
// encoded constants, salted integrity checksums).
//
// Runtime model. Each local lives in its own box ({v=value}) created by a
// declaration, so closures capture the right variable (including fresh
// variables per loop iteration). Lua closures are real Lua functions, so
// VM code can be passed to native helpers such as table.sort or pcall.
// Multiple values travel as packed tables {n=count, ...} on the VM stack.

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

// Order defines the opcode numbering before per-build shuffling.
const OPS = [
  "PUSHK", "POP", "DUP", "SWAP", "FIRST", "GETL", "SETL", "NEWL", "GETU", "SETU",
  "GETG", "SETG", "GETT", "SETT", "TABNEW", "TAPPEND", "CLOSURE", "CALL", "CALLX",
  "VARARG", "UNPK", "RET", "RETX", "JMP", "JMPF", "JMPT", "NOP",
  "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "IDIV", "CONCAT",
  "BAND", "BOR", "BXOR", "SHL", "SHR", "BNOT",
  "NEG", "NOT", "LEN", "EQ", "NE", "LT", "LE", "GT", "GE"
];

const BINOP_NAMES = {
  "+": "ADD", "-": "SUB", "*": "MUL", "/": "DIV", "%": "MOD", "^": "POW", "//": "IDIV",
  "..": "CONCAT", "==": "EQ", "~=": "NE", "<": "LT", "<=": "LE", ">": "GT", ">=": "GE",
  "&": "BAND", "|": "BOR", "~": "BXOR", "<<": "SHL", ">>": "SHR"
};
const UNOP_NAMES = { "-": "NEG", "not": "NOT", "#": "LEN", "~": "BNOT" };

// Binding powers as in the reference Lua grammar: [left, right].
const BINARY = {
  or: [1, 1], and: [2, 2],
  "<": [3, 3], ">": [3, 3], "<=": [3, 3], ">=": [3, 3], "~=": [3, 3], "==": [3, 3],
  "|": [4, 4], "~": [5, 5], "&": [6, 6], "<<": [7, 7], ">>": [7, 7],
  "..": [9, 8], "+": [10, 10], "-": [10, 10],
  "*": [11, 11], "/": [11, 11], "//": [11, 11], "%": [11, 11],
  "^": [14, 13]
};
const UNARY_PRIORITY = 12;
const COMPOUND_OPS = { "+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%", "^=": "^", "..=": ".." };

const KEYWORDS = new Set([
  "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in",
  "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while"
]);
const LUAU_COMPOUND = ["..=", "+=", "-=", "*=", "/=", "%=", "^="];
const MULTI_SYMBOLS = ["...", "..", "==", "~=", "<=", ">=", "//", "::", "<<", ">>"];
const SINGLE_SYMBOLS = "+-*/%^#&~|<>=(){}[];:,.";
const DEC_RE = /(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?/y;
const HEX_RE = /0[xX]([0-9a-fA-F]*)(?:\.([0-9a-fA-F]*))?(?:[pP]([+-]?\d+))?/y;
const NAME_RE = /[A-Za-z_][A-Za-z0-9_]*/y;

// A string literal token carries its decoded bytes so that escapes such as
// \xFF survive the round trip exactly (see encodeConstant).
function rawStringConstant(bytes) {
  return { __lmRawString: true, bytes };
}

// Float-valued numeric constant. Wrapped so encodeConstant can keep the
// float subtype (Lua 5.3 prints 1000.0 for 1e3); plain numbers are integers.
function floatConstant(value) {
  return { __lmFloat: true, value };
}

function describeToken(t) {
  if (t.type === "eof") return "<eof>";
  if (t.type === "string") return "string literal";
  return `'${t.value}'`;
}

// ---------------------------------------------------------------- lexer

function lex(source, luau) {
  const tokens = [];
  const n = source.length;
  let i = 0;
  const push = (type, value, pos) => tokens.push({ type, value, pos });
  while (i < n) {
    const c = source[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === "-" && source[i + 1] === "-") {
      const open = longBracketOpen(source, i + 2);
      if (open) {
        const close = "]" + "=".repeat(open.equals) + "]";
        const end = source.indexOf(close, open.contentStart);
        if (end < 0) throw new Error(`Unclosed long comment at character ${i + 1}.`);
        i = end + close.length;
      } else {
        const end = source.indexOf("\n", i);
        i = end < 0 ? n : end + 1;
      }
      continue;
    }
    const start = i;
    if (c === "[") {
      const open = longBracketOpen(source, i);
      if (open) {
        const close = "]" + "=".repeat(open.equals) + "]";
        const end = source.indexOf(close, open.contentStart);
        if (end < 0) throw new Error(`Unclosed long string at character ${start + 1}.`);
        i = end + close.length;
        push("string", rawStringConstant(decodeLuaStringBytes(source.slice(start, i), "long")), start);
        continue;
      }
    }
    if (c === '"' || c === "'") {
      i++;
      let closed = false;
      while (i < n) {
        if (source[i] === "\\") { i += 2; continue; }
        if (source[i] === c) { i++; closed = true; break; }
        i++;
      }
      if (!closed) throw new Error(`Unclosed string at character ${start + 1}.`);
      push("string", rawStringConstant(decodeLuaStringBytes(source.slice(start, i), "quoted")), start);
      continue;
    }
    if (/[0-9]/.test(c) || (c === "." && /[0-9]/.test(source[i + 1] || ""))) {
      if (c === "0" && /[xX]/.test(source[i + 1] || "")) {
        HEX_RE.lastIndex = i;
        const m = HEX_RE.exec(source);
        if (!m || (m[1] === "" && !m[2])) throw new Error(`Invalid hex number at character ${start + 1}.`);
        i += m[0].length;
        let value;
        if (m[2] === undefined && m[3] === undefined) {
          value = parseInt(m[1], 16);
        } else {
          value = parseInt(m[1] || "0", 16);
          const frac = m[2] || "";
          for (let k = 0; k < frac.length; k++) value += parseInt(frac[k], 16) / Math.pow(16, k + 1);
          if (m[3] !== undefined) value *= Math.pow(2, Number(m[3]));
        }
        if (!Number.isFinite(value)) throw new Error(`Hex number out of range at character ${start + 1}.`);
        const isHexFloat = m[2] !== undefined || m[3] !== undefined;
        push("number", isHexFloat ? floatConstant(value) : value, start);
        continue;
      }
      DEC_RE.lastIndex = i;
      const m = DEC_RE.exec(source);
      i += m[0].length;
      const value = Number(m[0]);
      if (!Number.isFinite(value)) throw new Error(`Numeric literal out of range at character ${start + 1}.`);
      // Float literals (with '.' or an exponent) stay floats, as in Lua 5.3.
      const isFloat = /[.eE]/.test(m[0]);
      push("number", isFloat ? floatConstant(value) : value, start);
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      NAME_RE.lastIndex = i;
      const word = NAME_RE.exec(source)[0];
      i += word.length;
      push(KEYWORDS.has(word) ? "keyword" : "identifier", word, start);
      continue;
    }
    const sym = [...(luau ? LUAU_COMPOUND : []), ...MULTI_SYMBOLS].find(s => source.startsWith(s, i));
    if (sym) {
      i += sym.length;
      push("symbol", sym, start);
      continue;
    }
    if (SINGLE_SYMBOLS.includes(c)) {
      i++;
      push("symbol", c, start);
      continue;
    }
    throw new Error(`Unsupported character ${JSON.stringify(c)} at character ${i + 1}.`);
  }
  push("eof", "<eof>", n);
  return tokens;
}

// ---------------------------------------------------------------- parser

class Parser {
  constructor(tokens, luau) {
    this.t = tokens;
    this.i = 0;
    this.luau = luau;
    // The main chunk is a vararg function, as in Lua, so `...` is valid at top level.
    this.varargs = [true];
  }

  peek(k = 0) { return this.t[Math.min(this.i + k, this.t.length - 1)]; }

  is(v, k = 0) {
    const t = this.peek(k);
    return (t.type === "symbol" || t.type === "keyword") && t.value === v;
  }

  take() {
    const t = this.t[this.i];
    if (t.type !== "eof") this.i++;
    return t;
  }

  fail(message, token = this.peek()) {
    throw new Error(`${message} at character ${token.pos + 1}.`);
  }

  expect(v) {
    if (!this.is(v)) this.fail(`Expected '${v}', got ${describeToken(this.peek())}`);
    return this.take();
  }

  name() {
    const t = this.peek();
    if (t.type !== "identifier") this.fail(`Expected name, got ${describeToken(t)}`);
    return this.take().value;
  }

  parse() {
    const body = this.block(new Set());
    if (this.peek().type !== "eof") this.fail(`Unexpected ${describeToken(this.peek())}`);
    return body;
  }

  blockEnds(stops) {
    const t = this.peek();
    return t.type === "eof" || (t.type === "keyword" && stops.has(t.value));
  }

  block(stops) {
    const out = [];
    while (!this.blockEnds(stops)) {
      if (this.is(";")) { this.take(); continue; }
      if (this.is("return")) {
        this.take();
        let exprs = [];
        if (!this.blockEnds(stops) && !this.is(";")) exprs = this.exprList();
        if (this.is(";")) this.take();
        out.push({ type: "return", exprs });
        break;
      }
      out.push(this.statement());
    }
    return out;
  }

  // In Luau, `continue` is a statement unless the next token continues an
  // expression statement (for example `continue()` is a call).
  continuesExpression(t) {
    if (t.type === "string") return true;
    return t.type === "symbol" && ["=", "(", ".", "[", ":", ",", "{"].includes(t.value);
  }

  statement() {
    const t = this.peek();
    if (this.is("if")) return this.ifStat();
    if (this.is("while")) {
      this.take();
      const test = this.expression();
      this.expect("do");
      const body = this.block(new Set(["end"]));
      this.expect("end");
      return { type: "while", test, body };
    }
    if (this.is("do")) {
      this.take();
      const body = this.block(new Set(["end"]));
      this.expect("end");
      return { type: "do", body };
    }
    if (this.is("for")) return this.forStat();
    if (this.is("repeat")) {
      this.take();
      const body = this.block(new Set(["until"]));
      this.expect("until");
      return { type: "repeat", body, test: this.expression() };
    }
    if (this.is("function")) return this.functionStat();
    if (this.is("local")) return this.localStat();
    if (this.is("break")) { this.take(); return { type: "break" }; }
    if (this.is("::")) {
      this.take();
      const name = this.name();
      this.expect("::");
      return { type: "label", name };
    }
    if (t.type === "identifier" && t.value === "goto" && this.peek(1).type === "identifier") {
      this.take();
      return { type: "goto", name: this.name() };
    }
    if (this.luau && t.type === "identifier" && t.value === "continue" && !this.continuesExpression(this.peek(1))) {
      this.take();
      return { type: "continue" };
    }
    return this.exprStat();
  }

  ifStat() {
    this.take();
    const branches = [];
    let test = this.expression();
    this.expect("then");
    branches.push({ test, body: this.block(new Set(["elseif", "else", "end"])) });
    while (this.is("elseif")) {
      this.take();
      test = this.expression();
      this.expect("then");
      branches.push({ test, body: this.block(new Set(["elseif", "else", "end"])) });
    }
    let orelse = null;
    if (this.is("else")) {
      this.take();
      orelse = this.block(new Set(["end"]));
    }
    this.expect("end");
    return { type: "if", branches, orelse };
  }

  forStat() {
    this.take();
    const first = this.name();
    if (this.is("=")) {
      this.take();
      const start = this.expression();
      this.expect(",");
      const stop = this.expression();
      let step = null;
      if (this.is(",")) { this.take(); step = this.expression(); }
      this.expect("do");
      const body = this.block(new Set(["end"]));
      this.expect("end");
      return { type: "numfor", name: first, start, stop, step, body };
    }
    const names = [first];
    while (this.is(",")) { this.take(); names.push(this.name()); }
    this.expect("in");
    const exprs = this.exprList();
    this.expect("do");
    const body = this.block(new Set(["end"]));
    this.expect("end");
    return { type: "genfor", names, exprs, body };
  }

  functionStat() {
    this.take();
    let target = { type: "name", name: this.name() };
    let method = false;
    while (this.is(".") || this.is(":")) {
      const sep = this.take().value;
      target = { type: "index", obj: target, key: { type: "const", value: this.name() } };
      if (sep === ":") { method = true; break; }
    }
    return { type: "funcStat", target, func: this.funcBody(method) };
  }

  localStat() {
    this.take();
    if (this.is("function")) {
      this.take();
      const name = this.name();
      return { type: "localFunction", name, func: this.funcBody(false) };
    }
    const names = [];
    do {
      if (names.length) this.take();
      const name = this.name();
      let attrib = null;
      if (this.is("<")) {
        this.take();
        attrib = this.name();
        this.expect(">");
        if (attrib !== "const" && attrib !== "close") this.fail(`Unknown attribute '${attrib}'`);
      }
      names.push({ name, attrib });
    } while (this.is(","));
    let exprs = [];
    if (this.is("=")) {
      this.take();
      exprs = this.exprList();
    }
    return { type: "local", names, exprs };
  }

  exprStat() {
    const first = this.suffixedExp();
    if (this.is("=") || this.is(",")) {
      const targets = [first];
      while (this.is(",")) {
        this.take();
        targets.push(this.suffixedExp());
      }
      this.expect("=");
      const exprs = this.exprList();
      for (const target of targets) {
        if (target.type !== "name" && target.type !== "index") this.fail("Invalid assignment target");
      }
      return { type: "assign", targets, exprs };
    }
    const t = this.peek();
    if (this.luau && t.type === "symbol" && Object.hasOwn(COMPOUND_OPS, t.value)) {
      this.take();
      if (first.type !== "name" && first.type !== "index") this.fail("Invalid assignment target");
      const rhs = this.expression();
      return { type: "assign", targets: [first], exprs: [{ type: "binop", op: COMPOUND_OPS[t.value], left: first, right: rhs }] };
    }
    if (first.type === "call" || first.type === "method") return { type: "callStat", expr: first };
    this.fail(`Unexpected ${describeToken(this.peek())}, expected assignment or function call`);
  }

  funcBody(method) {
    this.expect("(");
    const params = method ? ["self"] : [];
    let vararg = false;
    if (!this.is(")")) {
      for (;;) {
        if (this.is("...")) { this.take(); vararg = true; break; }
        params.push(this.name());
        if (!this.is(",")) break;
        this.take();
      }
    }
    this.expect(")");
    this.varargs.push(vararg);
    const body = this.block(new Set(["end"]));
    this.expect("end");
    this.varargs.pop();
    return { type: "function", params, vararg, body };
  }

  exprList() {
    const out = [this.expression()];
    while (this.is(",")) {
      this.take();
      out.push(this.expression());
    }
    return out;
  }

  expression(limit = 0) {
    let left;
    if (this.is("not") || this.is("-") || this.is("#") || this.is("~")) {
      const op = this.take().value;
      left = { type: "unop", op, value: this.expression(UNARY_PRIORITY) };
    } else {
      left = this.simpleExp();
    }
    for (;;) {
      const t = this.peek();
      const op = t.type === "symbol" || t.type === "keyword" ? t.value : null;
      const pr = op !== null && Object.hasOwn(BINARY, op) ? BINARY[op] : null;
      if (!pr || pr[0] <= limit) break;
      this.take();
      const right = this.expression(pr[1]);
      left = { type: "binop", op, left, right };
    }
    return left;
  }

  simpleExp() {
    const t = this.peek();
    if (t.type === "number" || t.type === "string") {
      this.take();
      return { type: "const", value: t.value };
    }
    if (this.is("nil")) { this.take(); return { type: "const", value: null }; }
    if (this.is("true")) { this.take(); return { type: "const", value: true }; }
    if (this.is("false")) { this.take(); return { type: "const", value: false }; }
    if (this.is("...")) {
      if (!this.varargs[this.varargs.length - 1]) this.fail("Cannot use '...' outside a vararg function");
      this.take();
      return { type: "vararg" };
    }
    if (this.is("function")) {
      this.take();
      return this.funcBody(false);
    }
    if (this.is("{")) return this.tableCtor();
    return this.suffixedExp();
  }

  primaryExp() {
    const t = this.peek();
    if (t.type === "identifier") {
      this.take();
      return { type: "name", name: t.value };
    }
    if (this.is("(")) {
      this.take();
      const value = this.expression();
      this.expect(")");
      return { type: "paren", value };
    }
    this.fail(`Unexpected ${describeToken(t)}`);
  }

  suffixedExp() {
    let node = this.primaryExp();
    for (;;) {
      if (this.is(".")) {
        this.take();
        node = { type: "index", obj: node, key: { type: "const", value: this.name() } };
      } else if (this.is("[")) {
        this.take();
        const key = this.expression();
        this.expect("]");
        node = { type: "index", obj: node, key };
      } else if (this.is(":")) {
        this.take();
        const name = this.name();
        node = { type: "method", obj: node, name, args: this.callArgs() };
      } else if (this.is("(") || this.is("{") || this.peek().type === "string") {
        node = { type: "call", callee: node, args: this.callArgs() };
      } else {
        return node;
      }
    }
  }

  callArgs() {
    const t = this.peek();
    if (t.type === "string") {
      this.take();
      return [{ type: "const", value: t.value }];
    }
    if (this.is("{")) return [this.tableCtor()];
    this.expect("(");
    let args = [];
    if (!this.is(")")) args = this.exprList();
    this.expect(")");
    return args;
  }

  tableCtor() {
    this.expect("{");
    const fields = [];
    while (!this.is("}")) {
      if (this.is("[")) {
        this.take();
        const key = this.expression();
        this.expect("]");
        this.expect("=");
        fields.push({ key, value: this.expression() });
      } else if (this.peek().type === "identifier" && this.is("=", 1)) {
        const key = { type: "const", value: this.take().value };
        this.take();
        fields.push({ key, value: this.expression() });
      } else {
        fields.push({ key: null, value: this.expression() });
      }
      if (this.is(",") || this.is(";")) this.take();
      else if (!this.is("}")) this.fail(`Expected ',' or '}', got ${describeToken(this.peek())}`);
    }
    this.expect("}");
    return { type: "table", fields };
  }
}

// ---------------------------------------------------------------- compiler

class Proto {
  constructor(parent, vararg) {
    this.parent = parent;
    this.vararg = vararg;
    this.np = 0;
    this.code = [];        // [opName, a, b]; jump targets are 1-based instruction indexes
    this.consts = [];
    this.constMap = new Map();
    this.upvals = [];      // {kind: 1 = slot of enclosing frame, 2 = enclosing upvalue, index}
    this.upvalMap = new Map();
    this.scopes = [];      // {vars: name -> slot, labels: name -> pc, gotos: []}
    this.loops = [];       // {breaks: [], continues: []}
    this.nslots = 0;
  }
}

class Compiler {
  constructor() {
    this.protos = [];      // child prototypes; CLOSURE operands are 1-based indexes here
  }

  emit(fs, op, a = 0, b = 0) {
    fs.code.push([op, a, b]);
    return fs.code.length;
  }

  here(fs) { return fs.code.length + 1; }

  patch(fs, at, target) { fs.code[at - 1][1] = target; }

  constant(fs, value) {
    const key = `${typeof value}:${JSON.stringify(value)}`;
    let idx = fs.constMap.get(key);
    if (idx === undefined) {
      fs.consts.push(value);
      idx = fs.consts.length;
      fs.constMap.set(key, idx);
    }
    return idx;
  }

  openScope(fs) { fs.scopes.push({ vars: new Map(), labels: new Map(), gotos: [] }); }

  closeScope(fs) {
    const scope = fs.scopes.pop();
    for (const jump of scope.gotos) {
      if (scope.labels.has(jump.name)) {
        this.patch(fs, jump.at, scope.labels.get(jump.name));
      } else if (fs.scopes.length) {
        fs.scopes[fs.scopes.length - 1].gotos.push(jump);
      } else {
        throw new Error(`No visible label '${jump.name}' for goto.`);
      }
    }
  }

  declare(fs, name) {
    const slot = ++fs.nslots;
    fs.scopes[fs.scopes.length - 1].vars.set(name, slot);
    return slot;
  }

  newSlot(fs) { return ++fs.nslots; }

  findLocal(fs, name) {
    for (let i = fs.scopes.length - 1; i >= 0; i--) {
      const slot = fs.scopes[i].vars.get(name);
      if (slot !== undefined) return slot;
    }
    return undefined;
  }

  resolve(fs, name) {
    const slot = this.findLocal(fs, name);
    if (slot !== undefined) return { kind: "local", index: slot };
    if (fs.upvalMap.has(name)) return { kind: "upval", index: fs.upvalMap.get(name) };
    if (!fs.parent) return null;
    const outer = this.resolve(fs.parent, name);
    if (!outer) return null;
    fs.upvals.push({ kind: outer.kind === "local" ? 1 : 2, index: outer.index });
    const index = fs.upvals.length;
    fs.upvalMap.set(name, index);
    return { kind: "upval", index };
  }

  nameGet(fs, name) {
    const r = this.resolve(fs, name);
    if (!r) this.emit(fs, "GETG", this.constant(fs, name));
    else if (r.kind === "local") this.emit(fs, "GETL", r.index);
    else this.emit(fs, "GETU", r.index);
  }

  nameSet(fs, name) {
    const r = this.resolve(fs, name);
    if (!r) this.emit(fs, "SETG", this.constant(fs, name));
    else if (r.kind === "local") this.emit(fs, "SETL", r.index);
    else this.emit(fs, "SETU", r.index);
  }

  isMulti(n) { return n.type === "call" || n.type === "method" || n.type === "vararg"; }

  // Pushes exactly one value.
  expr(fs, n) {
    switch (n.type) {
      case "const": this.emit(fs, "PUSHK", this.constant(fs, n.value)); return;
      case "slot": this.emit(fs, "GETL", n.slot); return;
      case "name": this.nameGet(fs, n.name); return;
      case "vararg": this.emit(fs, "VARARG"); this.emit(fs, "FIRST"); return;
      case "paren": this.expr(fs, n.value); return;
      case "index":
        this.expr(fs, n.obj);
        this.expr(fs, n.key);
        this.emit(fs, "GETT");
        return;
      case "call":
      case "method":
        this.callRaw(fs, n);
        this.emit(fs, "FIRST");
        return;
      case "function": this.closure(fs, n); return;
      case "table": this.table(fs, n); return;
      case "unop":
        this.expr(fs, n.value);
        this.emit(fs, UNOP_NAMES[n.op]);
        return;
      case "binop":
        if (n.op === "and" || n.op === "or") {
          this.expr(fs, n.left);
          this.emit(fs, "DUP");
          const skip = this.emit(fs, n.op === "and" ? "JMPF" : "JMPT", 0);
          this.emit(fs, "POP");
          this.expr(fs, n.right);
          this.patch(fs, skip, this.here(fs));
          return;
        }
        this.expr(fs, n.left);
        this.expr(fs, n.right);
        this.emit(fs, BINOP_NAMES[n.op]);
        return;
      default: throw new Error("Internal compiler error: unknown expression.");
    }
  }

  // Pushes a packed table with all values of a call or vararg expression.
  multi(fs, n) {
    if (n.type === "vararg") this.emit(fs, "VARARG");
    else this.callRaw(fs, n);
  }

  // Pushes the packed result of a call (not truncated to one value).
  callRaw(fs, n) {
    if (n.type === "method") {
      this.expr(fs, n.obj);
      this.emit(fs, "DUP");
      this.emit(fs, "PUSHK", this.constant(fs, n.name));
      this.emit(fs, "GETT");
      this.emit(fs, "SWAP");
      const info = this.args(fs, n.args);
      this.emit(fs, info.multi ? "CALLX" : "CALL", info.n + 1);
      return;
    }
    this.expr(fs, n.callee);
    const info = this.args(fs, n.args);
    this.emit(fs, info.multi ? "CALLX" : "CALL", info.n);
  }

  // Pushes an argument list. When the last argument is multi-valued, its
  // packed values are left on the stack for CALLX / RETX to expand.
  args(fs, exprs) {
    const m = exprs.length;
    if (m && this.isMulti(exprs[m - 1])) {
      for (let i = 0; i < m - 1; i++) this.expr(fs, exprs[i]);
      this.multi(fs, exprs[m - 1]);
      return { n: m - 1, multi: true };
    }
    for (const e of exprs) this.expr(fs, e);
    return { n: m, multi: false };
  }

  // Pushes exactly n values from an expression list.
  pushValues(fs, exprs, n) {
    const m = exprs.length;
    for (let i = 0; i < m; i++) {
      const e = exprs[i];
      if (i === m - 1 && this.isMulti(e)) {
        const need = n - i;
        this.multi(fs, e);
        if (need > 0) this.emit(fs, "UNPK", need);
        else this.emit(fs, "POP");
        return;
      }
      this.expr(fs, e);
      if (i >= n) this.emit(fs, "POP");
    }
    for (let i = m; i < n; i++) this.emit(fs, "PUSHK", this.constant(fs, null));
  }

  table(fs, n) {
    this.emit(fs, "TABNEW");
    let pos = 1;
    n.fields.forEach((field, idx) => {
      if (field.key === null) {
        this.emit(fs, "DUP");
        this.emit(fs, "PUSHK", this.constant(fs, pos));
        if (idx === n.fields.length - 1 && this.isMulti(field.value)) {
          this.multi(fs, field.value);
          this.emit(fs, "TAPPEND");
        } else {
          this.expr(fs, field.value);
          this.emit(fs, "SETT");
          pos++;
        }
      } else {
        this.emit(fs, "DUP");
        this.expr(fs, field.key);
        this.expr(fs, field.value);
        this.emit(fs, "SETT");
      }
    });
  }

  closure(fs, n) {
    const index = this.protos.length + 1;
    this.protos.push(null);
    const child = new Proto(fs, n.vararg);
    child.np = n.params.length;
    this.openScope(child);
    for (const p of n.params) this.declare(child, p);
    this.block(child, n.body);
    this.emit(child, "RET", 0);
    this.closeScope(child);
    this.protos[index - 1] = child;
    this.emit(fs, "CLOSURE", index);
  }

  block(fs, stmts) {
    for (const s of stmts) this.stmt(fs, s);
  }

  scopedBlock(fs, stmts) {
    this.openScope(fs);
    this.block(fs, stmts);
    this.closeScope(fs);
  }

  pushLoop(fs) {
    const loop = { breaks: [], continues: [] };
    fs.loops.push(loop);
    return loop;
  }

  popLoop(fs) { fs.loops.pop(); }

  assign(fs, s) {
    if (s.targets.length === 1 && s.exprs.length === 1) {
      const t = s.targets[0];
      if (t.type === "name") {
        this.expr(fs, s.exprs[0]);
        this.nameSet(fs, t.name);
      } else {
        this.expr(fs, t.obj);
        this.expr(fs, t.key);
        this.expr(fs, s.exprs[0]);
        this.emit(fs, "SETT");
      }
      return;
    }
    // Multiple targets: index targets evaluate their table and key first,
    // then all values are evaluated, then stores happen (Lua 5.3 order).
    const n = s.targets.length;
    const pre = s.targets.map(t => {
      if (t.type !== "index") return null;
      this.expr(fs, t.obj);
      const o = this.newSlot(fs);
      this.emit(fs, "NEWL", o);
      this.expr(fs, t.key);
      const k = this.newSlot(fs);
      this.emit(fs, "NEWL", k);
      return { o, k };
    });
    this.pushValues(fs, s.exprs, n);
    const temps = s.targets.map(() => this.newSlot(fs));
    for (let i = n - 1; i >= 0; i--) this.emit(fs, "NEWL", temps[i]);
    s.targets.forEach((t, i) => {
      if (t.type === "name") {
        this.emit(fs, "GETL", temps[i]);
        this.nameSet(fs, t.name);
      } else {
        this.emit(fs, "GETL", pre[i].o);
        this.emit(fs, "GETL", pre[i].k);
        this.emit(fs, "GETL", temps[i]);
        this.emit(fs, "SETT");
      }
    });
  }

  stmt(fs, s) {
    switch (s.type) {
      case "local": {
        this.pushValues(fs, s.exprs, s.names.length);
        const slots = s.names.map(({ name }) => this.declare(fs, name));
        for (let i = slots.length - 1; i >= 0; i--) this.emit(fs, "NEWL", slots[i]);
        return;
      }
      case "localFunction": {
        const slot = this.declare(fs, s.name);
        this.emit(fs, "PUSHK", this.constant(fs, null));
        this.emit(fs, "NEWL", slot);
        this.closure(fs, s.func);
        this.emit(fs, "SETL", slot);
        return;
      }
      case "funcStat": {
        const t = s.target;
        if (t.type === "name") {
          this.closure(fs, s.func);
          this.nameSet(fs, t.name);
        } else {
          this.expr(fs, t.obj);
          this.expr(fs, t.key);
          this.closure(fs, s.func);
          this.emit(fs, "SETT");
        }
        return;
      }
      case "assign": this.assign(fs, s); return;
      case "callStat":
        this.callRaw(fs, s.expr);
        this.emit(fs, "POP");
        return;
      case "return": {
        if (!s.exprs.length) {
          this.emit(fs, "RET", 0);
          return;
        }
        const info = this.args(fs, s.exprs);
        this.emit(fs, info.multi ? "RETX" : "RET", info.n);
        return;
      }
      case "if": {
        const exits = [];
        for (const br of s.branches) {
          this.expr(fs, br.test);
          const skip = this.emit(fs, "JMPF", 0);
          this.scopedBlock(fs, br.body);
          exits.push(this.emit(fs, "JMP", 0));
          this.patch(fs, skip, this.here(fs));
        }
        if (s.orelse) this.scopedBlock(fs, s.orelse);
        for (const j of exits) this.patch(fs, j, this.here(fs));
        return;
      }
      case "while": {
        const start = this.here(fs);
        this.expr(fs, s.test);
        const exit = this.emit(fs, "JMPF", 0);
        const loop = this.pushLoop(fs);
        this.scopedBlock(fs, s.body);
        this.popLoop(fs);
        for (const c of loop.continues) this.patch(fs, c, start);
        this.emit(fs, "JMP", start);
        const end = this.here(fs);
        this.patch(fs, exit, end);
        for (const b of loop.breaks) this.patch(fs, b, end);
        return;
      }
      case "repeat": {
        const start = this.here(fs);
        const loop = this.pushLoop(fs);
        this.openScope(fs);
        this.block(fs, s.body);
        const testAt = this.here(fs);
        for (const c of loop.continues) this.patch(fs, c, testAt);
        this.expr(fs, s.test);
        this.emit(fs, "JMPF", start);
        this.closeScope(fs);
        this.popLoop(fs);
        const end = this.here(fs);
        for (const b of loop.breaks) this.patch(fs, b, end);
        return;
      }
      case "numfor": this.numericFor(fs, s); return;
      case "genfor": this.genericFor(fs, s); return;
      case "do": this.scopedBlock(fs, s.body); return;
      case "break": {
        const loop = fs.loops[fs.loops.length - 1];
        if (!loop) throw new Error("'break' outside loop.");
        loop.breaks.push(this.emit(fs, "JMP", 0));
        return;
      }
      case "continue": {
        const loop = fs.loops[fs.loops.length - 1];
        if (!loop) throw new Error("'continue' outside loop.");
        loop.continues.push(this.emit(fs, "JMP", 0));
        return;
      }
      case "goto": {
        for (let i = fs.scopes.length - 1; i >= 0; i--) {
          if (fs.scopes[i].labels.has(s.name)) {
            this.emit(fs, "JMP", fs.scopes[i].labels.get(s.name));
            return;
          }
        }
        const at = this.emit(fs, "JMP", 0);
        fs.scopes[fs.scopes.length - 1].gotos.push({ name: s.name, at });
        return;
      }
      case "label": {
        const scope = fs.scopes[fs.scopes.length - 1];
        if (scope.labels.has(s.name)) throw new Error(`Label '${s.name}' already defined.`);
        scope.labels.set(s.name, this.here(fs));
        return;
      }
      default: throw new Error("Internal compiler error: unknown statement.");
    }
  }

  // Numeric for: the counter lives in hidden slots, so assigning to the loop
  // variable in the body does not change iteration (Lua semantics).
  numericFor(fs, s) {
    this.expr(fs, s.start);
    this.expr(fs, s.stop);
    if (s.step) this.expr(fs, s.step);
    else this.emit(fs, "PUSHK", this.constant(fs, 1));
    const hs = this.newSlot(fs);
    const he = this.newSlot(fs);
    const hi = this.newSlot(fs);
    this.emit(fs, "NEWL", hi);
    this.emit(fs, "NEWL", he);
    this.emit(fs, "NEWL", hs);

    // A zero step would loop forever; Lua raises an error instead.
    this.emit(fs, "GETL", hi);
    this.emit(fs, "PUSHK", this.constant(fs, 0));
    this.emit(fs, "EQ");
    const stepOk = this.emit(fs, "JMPF", 0);
    this.emit(fs, "GETG", this.constant(fs, "error"));
    this.emit(fs, "PUSHK", this.constant(fs, "LuaMoon VM: 'for' step is zero"));
    this.emit(fs, "CALL", 1);
    this.emit(fs, "POP");
    this.patch(fs, stepOk, this.here(fs));

    const slot = (index) => ({ type: "slot", slot: index });
    const zero = { type: "const", value: 0 };
    const cond = {
      type: "binop", op: "or",
      left: {
        type: "binop", op: "and",
        left: { type: "binop", op: ">", left: slot(hi), right: zero },
        right: { type: "binop", op: "<=", left: slot(hs), right: slot(he) }
      },
      right: {
        type: "binop", op: "and",
        left: { type: "binop", op: "<=", left: slot(hi), right: zero },
        right: { type: "binop", op: ">=", left: slot(hs), right: slot(he) }
      }
    };

    this.openScope(fs);
    const start = this.here(fs);
    this.expr(fs, cond);
    const exit = this.emit(fs, "JMPF", 0);
    const loop = this.pushLoop(fs);
    this.openScope(fs);
    const variable = this.declare(fs, s.name);
    this.emit(fs, "GETL", hs);
    this.emit(fs, "NEWL", variable);
    this.block(fs, s.body);
    this.closeScope(fs);
    for (const c of loop.continues) this.patch(fs, c, this.here(fs));
    this.emit(fs, "GETL", hs);
    this.emit(fs, "GETL", hi);
    this.emit(fs, "ADD");
    this.emit(fs, "SETL", hs);
    this.emit(fs, "JMP", start);
    this.popLoop(fs);
    const end = this.here(fs);
    this.patch(fs, exit, end);
    for (const b of loop.breaks) this.patch(fs, b, end);
    this.closeScope(fs);
  }

  // Generic for: calls the iterator each round with (state, control) and
  // stops when its first result is nil.
  genericFor(fs, s) {
    this.pushValues(fs, s.exprs, 3);
    const hf = this.newSlot(fs);
    const hs = this.newSlot(fs);
    const hc = this.newSlot(fs);
    const hp = this.newSlot(fs);
    this.emit(fs, "NEWL", hc);
    this.emit(fs, "NEWL", hs);
    this.emit(fs, "NEWL", hf);

    this.openScope(fs);
    const start = this.here(fs);
    this.emit(fs, "GETL", hf);
    this.emit(fs, "GETL", hs);
    this.emit(fs, "GETL", hc);
    this.emit(fs, "CALL", 2);
    this.emit(fs, "NEWL", hp);
    this.emit(fs, "GETL", hp);
    this.emit(fs, "PUSHK", this.constant(fs, 1));
    this.emit(fs, "GETT");
    this.emit(fs, "SETL", hc);
    this.emit(fs, "GETL", hc);
    this.emit(fs, "PUSHK", this.constant(fs, null));
    this.emit(fs, "EQ");
    const exit = this.emit(fs, "JMPT", 0);

    const loop = this.pushLoop(fs);
    this.openScope(fs);
    const slots = s.names.map(name => this.declare(fs, name));
    slots.forEach((slot, i) => {
      this.emit(fs, "GETL", hp);
      this.emit(fs, "PUSHK", this.constant(fs, i + 1));
      this.emit(fs, "GETT");
      this.emit(fs, "NEWL", slot);
    });
    this.block(fs, s.body);
    this.closeScope(fs);
    for (const c of loop.continues) this.patch(fs, c, start);
    this.emit(fs, "JMP", start);
    this.popLoop(fs);
    const end = this.here(fs);
    this.patch(fs, exit, end);
    for (const b of loop.breaks) this.patch(fs, b, end);
    this.closeScope(fs);
  }
}

function compileChunk(ast) {
  const compiler = new Compiler();
  const root = new Proto(null, true);
  compiler.openScope(root);
  compiler.block(root, ast);
  compiler.closeScope(root);
  compiler.emit(root, "RET", 0);
  return { root, protos: compiler.protos };
}

// ---------------------------------------------------------------- emitter

function checksum32(str, saltA, saltB) {
  // Adler-32-style rolling checksum, salted per build. Every intermediate
  // value stays well under 2^53, so the Lua-side _cksum agrees bit for bit.
  const MOD = 65521;
  let a = (1 + saltA) % MOD;
  let b = saltB % MOD;
  for (let i = 0; i < str.length; i++) {
    a = (a + str.charCodeAt(i)) % MOD;
    b = (b + a) % MOD;
  }
  return b * 65536 + a;
}

function encodeMaskedText(value, rng, alphabet) {
  const key = 1 + Math.floor(rng() * 255);
  const bytes = new TextEncoder().encode(value);
  for (let i = 0; i < bytes.length; i++) bytes[i] ^= key;
  return { text: base64Encode(bytes, alphabet), key };
}

function encodeConstant(value, rng) {
  if (value === null) return { tag: "z" };
  if (typeof value === "boolean") return { tag: value ? "t" : "f" };
  if (typeof value === "number" || (value && typeof value === "object" && value.__lmFloat)) {
    const n = typeof value === "number" ? value : value.value;
    const float = typeof value !== "number";
    const text = float && Number.isInteger(n) && Math.abs(n) < 1e21 ? n.toFixed(1) : String(n);
    return { tag: "n", bytes: encodeXorRotateBytes(new TextEncoder().encode(text), rng) };
  }
  const raw = value && typeof value === "object" && value.__lmRawString;
  const bytes = raw ? Uint8Array.from(value.bytes) : new TextEncoder().encode(String(value));
  return { tag: "s", bytes: encodeXorRotateBytes(bytes, rng) };
}

function encodeXorRotate(text, rng) {
  return encodeXorRotateBytes(new TextEncoder().encode(text), rng);
}

function bytesToLuaArray(bytes) {
  return bytes.length ? `{${Array.from(bytes).join(",")}}` : "{}";
}

function padControlFlow(code, rng) {
  const jumpOps = new Set(["JMP", "JMPF", "JMPT"]);
  const targetMap = new Map();
  let expandedLength = 0;
  const padding = code.map(() => 1 + Math.floor(rng() * 3));
  for (let i = 0; i < code.length; i++) {
    expandedLength += padding[i];
    targetMap.set(i + 1, expandedLength + 1);
    expandedLength += 1;
  }
  targetMap.set(code.length + 1, expandedLength + 1);
  const expanded = [];
  for (let i = 0; i < code.length; i++) {
    for (let j = 0; j < padding[i]; j++) expanded.push(["NOP", 0, 0]);
    const row = [...code[i]];
    if (jumpOps.has(row[0])) {
      const mapped = targetMap.get(row[1]);
      if (mapped === undefined) throw new Error("Invalid jump target during control-flow encoding.");
      row[1] = mapped;
    }
    expanded.push(row);
  }
  return expanded;
}

// Interpreter source. It is XOR/rotation encoded and loaded at runtime.
// The opcode table is spliced in per build (see emitLua).
function interpreterSource(opnLiteral) {
  return `return function(DATA,G,...)
local _MOD=4294967296
local F=DATA.F
local OPN=${opnLiteral}
local unpack=table.unpack or unpack
local mtype=math.type
local function pack(...) return {n=select("#",...),...} end
local function truth(v) return v~=nil and v~=false end
local function tobit(v) return math.floor(v)%_MOD end
local function bfAnd(a,b) return a==1 and b==1 end
local function bfOr(a,b) return a==1 or b==1 end
local function bfXor(a,b) return a~=b end
local function bitop(x,y,f)
x=tobit(x) y=tobit(y)
local r,p=0,1
for _=1,32 do
if f(x%2,y%2) then r=r+p end
x=math.floor(x/2) y=math.floor(y/2) p=p*2
end
return r
end
local function bx(a,b)
local r,p=0,1
for _=1,8 do
local x,y=a%2,b%2
if x~=y then r=r+p end
a=math.floor(a/2) b=math.floor(b/2) p=p*2
end
return r
end
local function ds(bl)
local rot=bl[1]
local keys={bl[2],bl[3],bl[4],bl[5]}
local out={}
for i=6,#bl do
local b=bl[i]
local m=2^rot
b=math.floor(b/m)+(b%m)*2^(8-rot)
b=bx(b,keys[(i-6)%4+1])
out[#out+1]=string.char(b)
end
return table.concat(out)
end
local function gc(pr,i)
local K=pr.K
if not K then K={} pr.K=K end
local v=K[i]
if v~=nil then return v end
local e=pr.CT[i]
if not e then return nil end
local t=e[1]
if t=="s" then v=ds(e[2])
elseif t=="n" then v=tonumber(ds(e[2]))
elseif t=="t" then v=true
elseif t=="f" then v=false
else return nil end
K[i]=v
return v
end
local run,mkclosure
function mkclosure(pr,B,UPV)
local uv={}
local U=pr.UV
for j=1,pr.NU do
local k,i=U[2*j-1],U[2*j]
if k==1 then
local box=B[i]
if not box then box={} B[i]=box end
uv[j]=box
else
uv[j]=UPV[i]
end
end
return function(...)
local r=run(pr,uv,pack(...))
return unpack(r,1,r.n)
end
end
function run(pr,UPV,args)
local BC,MA,MB=pr.BC,pr.MA,pr.MB
local S,B={},{}
local sp,pc=0,1
local np=pr.NP
local VA={n=0}
for i=1,np do B[i]={v=args[i]} end
if pr.VA then
local m=0
for j=np+1,args.n do m=m+1 VA[m]=args[j] end
VA.n=m
end
local function push(v) sp=sp+1 S[sp]=v end
local function pop() local v=S[sp] S[sp]=nil sp=sp-1 return v end
while true do
local index=pc
local ins=BC[index]
if not ins then return {n=0} end
pc=index+1
local o=OPN[ins[1]]
local a=(ins[2]-((MA+index*65599)%_MOD))%_MOD
local b=(ins[3]-((MB+index*31337)%_MOD))%_MOD
if o=="PUSHK" then push(gc(pr,a))
elseif o=="GETL" then local box=B[a] push(box and box.v)
elseif o=="SETL" then local v=pop() local box=B[a] if box then box.v=v else B[a]={v=v} end
elseif o=="GETT" then local k=pop() local t=pop() push(t[k])
elseif o=="CALL" then
local argv={n=a} for j=a,1,-1 do argv[j]=pop() end
local f=pop()
push(pack(f(unpack(argv,1,a))))
elseif o=="FIRST" then local P=pop() push(P[1])
elseif o=="POP" then pop()
elseif o=="DUP" then push(S[sp])
elseif o=="JMPF" then if not truth(pop()) then pc=a end
elseif o=="JMP" then pc=a
elseif o=="ADD" then local y=pop() local x=pop() push(x+y)
elseif o=="SUB" then local y=pop() local x=pop() push(x-y)
elseif o=="EQ" then local y=pop() local x=pop() push(x==y)
elseif o=="LT" then local y=pop() local x=pop() push(x<y)
elseif o=="LE" then local y=pop() local x=pop() push(x<=y)
elseif o=="GT" then local y=pop() local x=pop() push(x>y)
elseif o=="GE" then local y=pop() local x=pop() push(x>=y)
elseif o=="GETG" then push(G[gc(pr,a)])
elseif o=="NEWL" then B[a]={v=pop()}
elseif o=="RET" then local r={n=a} for j=a,1,-1 do r[j]=pop() end return r
elseif o=="JMPT" then if truth(pop()) then pc=a end
elseif o=="SETT" then local v=pop() local k=pop() local t=pop() t[k]=v
elseif o=="MUL" then local y=pop() local x=pop() push(x*y)
elseif o=="MOD" then local y=pop() local x=pop() push(x%y)
elseif o=="CONCAT" then local y=pop() local x=pop() push(x..y)
elseif o=="NOP" then
elseif o=="NOT" then push(not truth(pop()))
elseif o=="TABNEW" then push({})
elseif o=="TAPPEND" then local P=pop() local k=pop() local t=pop() for j=1,P.n do t[k+j-1]=P[j] end
elseif o=="CLOSURE" then push(mkclosure(F[a],B,UPV))
elseif o=="VARARG" then push(VA)
elseif o=="UNPK" then local P=pop() for j=1,a do push(P[j]) end
elseif o=="RETX" then
local X=pop()
local total=a+X.n
local r={n=total}
for j=a,1,-1 do r[j]=pop() end
for j=1,X.n do r[a+j]=X[j] end
return r
elseif o=="CALLX" then
local X=pop()
local total=a+X.n
local argv={n=total}
for j=a,1,-1 do argv[j]=pop() end
for j=1,X.n do argv[a+j]=X[j] end
local f=pop()
push(pack(f(unpack(argv,1,total))))
elseif o=="GETU" then push(UPV[a].v)
elseif o=="SETU" then UPV[a].v=pop()
elseif o=="SETG" then G[gc(pr,a)]=pop()
elseif o=="DIV" then local y=pop() local x=pop() push(x/y)
elseif o=="POW" then local y=pop() local x=pop() push(x^y)
elseif o=="IDIV" then local y=pop() local x=pop() local q=math.floor(x/y) if mtype and (mtype(x)=="float" or mtype(y)=="float") then q=q+0.0 end push(q)
elseif o=="NE" then local y=pop() local x=pop() push(x~=y)
elseif o=="NEG" then push(-pop())
elseif o=="LEN" then push(#pop())
elseif o=="SWAP" then S[sp],S[sp-1]=S[sp-1],S[sp]
elseif o=="SHL" then local y=pop() local x=pop() push(math.floor((tobit(x)*2^y)%_MOD))
elseif o=="SHR" then local y=pop() local x=pop() push(math.floor(tobit(x)/2^y))
elseif o=="BAND" then local y=pop() local x=pop() push(bitop(x,y,bfAnd))
elseif o=="BOR" then local y=pop() local x=pop() push(bitop(x,y,bfOr))
elseif o=="BXOR" then local y=pop() local x=pop() push(bitop(x,y,bfXor))
elseif o=="BNOT" then local x=pop() push(bitop(x,4294967295,bfXor))
else error("LuaMoon VM: invalid opcode",0)
end
end
end
local r=run(DATA.R,{},pack(...))
return unpack(r,1,r.n)
end`;
}

function emitLua({ root, protos }, rng) {
  const alphabetChars = Array.from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<>?@[]^_`{|}~");
  shuffleArray(alphabetChars, rng);
  const packedAlphabet = alphabetChars.slice(0, 64).join("");
  const shuffledIds = shuffleArray(Array.from({ length: 256 }, (_, i) => i), rng);
  const opIds = new Map(OPS.map((op, i) => [op, shuffledIds[i]]));
  const MOD32 = 4294967296;
  const encodedOperand = (value, base, index, stride) =>
    (value + ((base + index * stride) % MOD32)) % MOD32;

  function encodeProto(p) {
    const maskA = 1 + Math.floor(rng() * 0x7ffffffe);
    const maskB = 1 + Math.floor(rng() * 0x7ffffffe);
    const constants = p.consts.map(value => encodeConstant(value, rng));
    const ct = `{${constants.map(e => (e.tag === "s" || e.tag === "n")
      ? `{${JSON.stringify(e.tag)},${bytesToLuaArray(e.bytes)}}`
      : `{${JSON.stringify(e.tag)}}`).join(",")}}`;
    const code = padControlFlow(p.code, rng);
    const bc = `{${code.map(([op, a, b], i) => {
      const index = i + 1;
      return `{${opIds.get(op)},${encodedOperand(a, maskA, index, 65599)},${encodedOperand(b, maskB, index, 31337)}}`;
    }).join(",")}}`;
    const uv = `{${p.upvals.map(u => `${u.kind},${u.index}`).join(",")}}`;
    return `{BC=${bc},CT=${ct},MA=${maskA},MB=${maskB},UV=${uv},NU=${p.upvals.length},NP=${p.np},VA=${p.vararg ? "true" : "false"}}`;
  }

  const rootEncoded = encodeProto(root);
  const childEncoded = protos.map(encodeProto);
  const payloadSource = `return {R=${rootEncoded},F={${childEncoded.join(",")}}}`;

  const opnLiteral = `{${OPS.map(op => `[${opIds.get(op)}]=${JSON.stringify(op)}`).join(",")}}`;
  const innerVmSource = interpreterSource(opnLiteral);

  const encryptedVm = encodeXorRotate(innerVmSource, rng);
  const payload = encodeMaskedText(payloadSource, rng, packedAlphabet);
  const encodedVm = base64Encode(encryptedVm, packedAlphabet);

  // Tamper-detection checksums over the two raw encoded blobs, taken before
  // any decoding happens. Salts are fresh per build. A mismatch means the
  // shipped text was edited after compilation and the loader refuses to run.
  const vmSaltA = Math.floor(rng() * 65521);
  const vmSaltB = Math.floor(rng() * 65521);
  const dataSaltA = Math.floor(rng() * 65521);
  const dataSaltB = Math.floor(rng() * 65521);
  const vmChecksum = checksum32(encodedVm, vmSaltA, vmSaltB);
  const dataChecksum = checksum32(payload.text, dataSaltA, dataSaltB);

  return `return (function(...)
local _A=${JSON.stringify(packedAlphabet)}
local _KW=${JSON.stringify(encodedVm)}
local _D=${JSON.stringify(payload.text)}
local _Q=${payload.key}
local _VA,_VB,_VC=${vmSaltA},${vmSaltB},${vmChecksum}
local _DA,_DB,_DC=${dataSaltA},${dataSaltB},${dataChecksum}
local function _cksum(s,sa,sb)
local MOD=65521
local a=(1+sa)%MOD
local b=sb%MOD
for i=1,#s do
a=(a+string.byte(s,i))%MOD
b=(b+a)%MOD
end
return b*65536+a
end
if _cksum(_KW,_VA,_VB)~=_VC or _cksum(_D,_DA,_DB)~=_DC then
error("LuaMoon VM: integrity check failed",0)
end
local function _u(s)
local M={}
for i=1,#_A do M[string.sub(_A,i,i)]=i-1 end
local O={} local V=0 local B=0
for i=1,#s do
local c=string.sub(s,i,i)
if c~="=" then
local n=M[c]
if n then
V=V*64+n B=B+6
if B>=8 then B=B-8 local q=math.floor(V/2^B)%256 O[#O+1]=q V=V%2^B end
end
end
end
return O
end
local function _bx(a,b)
local r,p=0,1
for _=1,8 do
local x,y=a%2,b%2
if x~=y then r=r+p end
a=math.floor(a/2) b=math.floor(b/2) p=p*2
end
return r
end
local function _dk(bl)
local rot=bl[1]
local keys={bl[2],bl[3],bl[4],bl[5]}
local out={}
for i=6,#bl do
local b=bl[i]
local m=2^rot
b=math.floor(b/m)+(b%m)*2^(8-rot)
b=_bx(b,keys[(i-6)%4+1])
out[#out+1]=string.char(b)
end
return table.concat(out)
end
local function _un(s,k)
local b=_u(s) local o={}
for i=1,#b do o[i]=string.char(_bx(b[i],k)) end
return table.concat(o)
end
local _loader=loadstring or load
if type(_loader)~="function" then error("LuaMoon VM: dynamic code loading is unavailable",0) end
local _dataChunk,_dataErr=_loader(_un(_D,_Q))
if not _dataChunk then error(_dataErr or "LuaMoon VM: data initialization failed",0) end
local _DATA=_dataChunk()
local _src=_dk(_u(_KW))
local _chunk,_err=_loader(_src)
if not _chunk then error(_err or "LuaMoon VM: failed to initialize",0) end
return _chunk()(_DATA,(getfenv and getfenv() or _G),...)
end)(...)
`;
}

// ---------------------------------------------------------------- entry point

export function compileLuaVm(source, options = {}) {
  if (typeof source !== "string") throw new Error("Source must be a string.");
  const byteLength = new TextEncoder().encode(source).byteLength;
  if (byteLength > 50 * 1024 * 1024) throw new Error("Input too large (limit 50MB).");
  const luau = options.language === "luau";
  // Checked on the masked source so text inside strings or comments (for example
  // "a::b") does not look like Luau type syntax.
  if (luau && hasLuauTypeSyntax(maskStringsAndComments(source))) {
    throw new Error("VM mode does not support Luau type declarations yet. Use Compatibility mode for typed Luau.");
  }
  const rng = Number.isInteger(options.seed)
    ? mulberry32(options.seed ^ (luau ? 0x4c554155 : 0x4c554120))
    : secureRandom;
  const ast = new Parser(lex(source, luau), luau).parse();
  return emitLua(compileChunk(ast), rng);
}
