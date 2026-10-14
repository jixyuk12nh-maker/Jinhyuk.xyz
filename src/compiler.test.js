import test from "node:test";
import assert from "node:assert/strict";
import { compileLuaSubset, compileLuaVm } from "./compiler.js";

const obfuscate = (source, language = "lua", seed = 123) => compileLuaSubset(source, { language, seed });

test("obfuscates ordinary Lua strings without wrapping source in loadstring", () => {
  const source = 'local message = "hello"; print(message)';
  const output = obfuscate(source);
  assert.equal(output.includes('"hello"'), false);
  assert.match(output, /local _[A-Za-z0-9_]+=/);
  assert.match(output, /_[A-Za-z0-9_]+\("[^"]*",\d+,\d+\)/);
  assert.equal(output.includes("hello"), false);
  assert.equal(output.includes("loadstring"), false);
});

test("keeps method calls and table constructors syntactically intact", () => {
  const source = `local Library = loadstring(game:HttpGet("https://example.test/Library.lua"))()\nlocal Window = Library:CreateWindow({Title="Obsidian", Footer="", Center=true, AutoShow=true})`;
  const output = obfuscate(source);
  assert.match(output, /game:HttpGet\(/);
  assert.match(output, /Library:CreateWindow\(\{Title=/);
  assert.equal(output.includes("https://example.test/Library.lua"), false);
  assert.equal(output.includes('Title="Obsidian"'), false);
});

test("supports Lua syntax outside the old VM subset without rejecting it", () => {
  const source = `local function f(...) local a,b=... for i=1,3 do print(i,a,b) end return a,b end\n::again::\nlocal n = 1 << 2\nif n ~= 0 then goto again end`;
  const output = obfuscate(source, "lua", 77);
  for (const fragment of ["function f(...) ", "local a,b=...", "for i=1,3 do", "return a,b", "::again::", "1 << 2", "goto again"]) assert.ok(output.includes(fragment), fragment);
});

test("handles quoted and long-bracket strings", () => {
  const source = `local a = 'single\\nline'\nlocal b = [=[long\ntext]=]\nprint(a,b)`;
  const output = obfuscate(source, "lua", 8);
  assert.equal(output.includes("single"), false);
  assert.equal(output.includes("long"), false);
  assert.match(output, /print\(a,b\)/);
});

test("removes ordinary comments but preserves directives and line positions", () => {
  const source = `--!strict\nlocal a = "x" -- remove me\n--[[ block comment ]]\nprint(a)`;
  const output = obfuscate(source, "luau", 10);
  assert.match(output, /^--!strict/);
  assert.equal(output.includes("remove me"), false);
  assert.equal(output.includes("block comment"), false);
  assert.match(output, /print\(a\)/);
  assert.equal(output.split("\n").length, source.split("\n").length);
});

test("preserves Luau type declarations and string literal types while encoding value strings", () => {
  const source = `--!strict\ntype State = "Idle" | "Running"\nlocal state: State = "Idle"\nlocal message = "hello"\nlocal function greet(name: string): string\n return ` + '`hello, {name}`' + `\nend`;
  const output = obfuscate(source, "luau", 11);
  assert.match(output, /^--!strict/);
  assert.match(output, /type State = "Idle" \| "Running"/);
  assert.match(output, /local state: State =/);
  assert.equal(output.includes('local message = "hello"'), false);
  assert.match(output, /name: string/);
  assert.match(output, /`hello, \{name\}`/);
});

test("preserves Luau-specific syntax such as compound assignment, continue, and type functions", () => {
  const source = `type Box<T> = { value: T }\nlocal x: number = 0\nwhile x < 3 do x += 1 if x == 2 then continue end end\nlocal y = x :: number`;
  const output = obfuscate(source, "luau", 12);
  for (const fragment of ["type Box<T>", "value: T", "x += 1", "continue", "x :: number"]) assert.ok(output.includes(fragment), fragment);
});

test("uses runtime decoding with per-string rolling masks and randomized alphabets", () => {
  const source = 'local first = "secret-one"\nlocal second = "secret-two"\nprint(first, second)';
  const output = obfuscate(source, "lua", 9001);
  assert.equal(output.includes("secret-one"), false);
  assert.equal(output.includes("secret-two"), false);
  assert.match(output, /local _[A-Za-z0-9_]+=/);
  assert.equal((output.match(/_[A-Za-z0-9_]+\("/g) || []).length, 2);
  assert.match(output, /,\d+,\d+\)/);
});

test("keeps Luau directives before the injected decoder", () => {
  const output = obfuscate('--!strict\nlocal message = "private"', "luau", 31337);
  assert.ok(output.startsWith("--!strict\n"));
  assert.ok(output.indexOf("local _") > output.indexOf("--!strict"));
  assert.equal(output.includes("private"), false);
});

test("supports randomized string encoding across builds", () => {
  const source = 'print("marker")';
  const a = obfuscate(source, "lua", 100);
  const b = obfuscate(source, "lua", 101);
  assert.notEqual(a, b);
  assert.equal(a.includes("marker"), false);
  assert.equal(b.includes("marker"), false);
});

test("does not transform strings inside Luau type aliases or annotations", () => {
  const source = `type Mode = "A" | "B"\nlocal mode: "A" | "B" = "A"`;
  const output = obfuscate(source, "luau", 99);
  assert.match(output, /type Mode = "A" \| "B"/);
  assert.match(output, /local mode: "A" \| "B" =/);
});

test("enforces the 50 MiB source limit", () => {
  assert.throws(() => compileLuaSubset("a".repeat(50 * 1024 * 1024 + 1)), /limit 50MB/i);
});

test("rejects an unterminated quoted string", () => {
  assert.throws(() => obfuscate('print("broken)'), /Unclosed string/i);
});

test("does not parse or rewrite broad Lua grammar constructs", () => {
  const source = `local a, b = 1, 2
local function f(x, ...)
  local t = {x, key = "value", ["dynamic"] = ...}
  for k, v in pairs(t) do
    if k == "key" then a = a + 1 elseif k == "dynamic" then b = b / 2 end
  end
  repeat a = a - 1 until a <= 0
  return a, b, ...
end
::again::
if a ~= b then goto again end
return f(a, b)`;
  const output = obfuscate(source, "lua", 1234);
  for (const fragment of ["local a, b = 1, 2", "local function f(x, ...)", "for k, v in pairs(t) do", "repeat a = a - 1 until a <= 0", "return a, b, ...", "::again::", "goto again"]) {
    assert.ok(output.includes(fragment), fragment);
  }
  assert.equal(output.includes('"value"'), false);
});

test("preserves complex Luau syntax while obfuscating ordinary value strings", () => {
  const source = `--!strict
export type Node<T> = { value: T, next: Node<T>?, callback: (T) -> string }
local function build<T>(value: T): Node<T>
  local result: Node<T> = {value = value, next = nil, callback = function(x: T): string return tostring(x) end}
  local count = 0
  while count < 2 do
    count += 1
    if count == 1 then continue end
  end
  local text = \`hello, {value}!\`
  local raw = "visible-secret"
  return result
end`;
  const output = obfuscate(source, "luau", 4321);
  for (const fragment of ["--!strict", "export type Node<T>", "callback: (T) -> string", "function build<T>(value: T): Node<T>", "count += 1", "continue", "\`hello, {value}!\`"]) {
    assert.ok(output.includes(fragment), fragment);
  }
  assert.equal(output.includes('"visible-secret"'), false);
});

test("preserves multiline comments and source line count", () => {
  const source = `local x = "safe"
--[=[ first
second
third ]=]
print(x)`;
  const output = obfuscate(source, "lua", 9);
  assert.equal(output.split("\n").length, source.split("\n").length);
  assert.equal(output.includes("second"), false);
  assert.match(output, /print\(x\)/);
});


test("renames eligible top-level locals without changing method names or table keys", () => {
  const source = `local Library = loadstring(game:HttpGet("https://example.test/Library.lua"))()
local Window = Library:CreateWindow({Title = "Obsidian"})
Window:Notify({Content = "ready"})`;
  const output = compileLuaSubset(source, { language: "luau", seed: 876, renameLocals: true });
  assert.equal(output.includes("local Library"), false);
  assert.equal(output.includes("local Window"), false);
  assert.match(output, /:CreateWindow\(/);
  assert.match(output, /:Notify\(/);
  assert.match(output, /\{Title =/);
  assert.match(output, /\{Content =/);
  assert.equal(output.includes("https://example.test/Library.lua"), false);
});

test("conservatively skips local renaming when Luau type syntax is present", () => {
  const source = `--!strict
local state: string = "ready"
print(state)`;
  const output = compileLuaSubset(source, { language: "luau", seed: 877, renameLocals: true });
  assert.match(output, /local state: string =/);
  assert.match(output, /print\(state\)/);
  assert.equal(output.includes('"ready"'), false);
});


test("VM mode emits encoded bytecode wrapper instead of the original source", () => {
  const source = `local message = "VM_SECRET_MARKER"
local count = 2
if count > 1 then print(message .. "!") else warn("no") end`;
  const output = compileLuaVm(source, { language: "lua", seed: 900 });
  assert.match(output, /^return \(function\(/);
  assert.equal(output.includes("VM_SECRET_MARKER"), false);
  assert.equal(output.includes('local message ='), false);
  assert.ok(output.length > source.length * 2);
});

test("VM mode parses colon method calls and preserves method semantics in bytecode", () => {
  const source = `local obj = game:GetService("Players")
obj:FindFirstChild("Player")`;
  const output = compileLuaVm(source, { language: "luau", seed: 901 });
  assert.equal(output.includes("FindFirstChild"), false);
  assert.equal(output.includes("Players"), false);
  assert.match(output, /local _KW=/);
  assert.match(output, /local _D=/);
});

test("VM mode rejects unsupported typed Luau rather than silently claiming virtualization", () => {
  assert.throws(() => compileLuaVm('local value: string = "x"', { language: "luau", seed: 902 }), /type declarations/i);
});

test("VM mode decodes decimal, hex, and unicode string escapes instead of corrupting them", () => {
  // Regression test: the old VM-mode lexer only understood \n \r \t \\ \' \" \0
  // and silently mangled every other escape (dropping the backslash and
  // re-emitting the following characters as literal text) instead of erroring.
  const output = compileLuaVm('local a = "\\065\\x41\\u{1F600}"\nprint(a)', { language: "lua", seed: 950 });
  assert.match(output, /^return \(function\(/);
  assert.equal(output.includes("065"), false);
  assert.equal(output.includes("x41"), false);
});

test("VM mode supports hex integer and hex float literals", () => {
  const output = compileLuaVm("local a = 0x1F + 0xA\nlocal b = 0x1p4\nprint(a, b)", { language: "lua", seed: 951 });
  assert.match(output, /^return \(function\(/);
  assert.doesNotThrow(() => compileLuaVm("local a = 0x1.8p1", { language: "lua", seed: 951 }));
});

test("VM mode rejects non-finite numeric literals instead of embedding Infinity/NaN", () => {
  assert.throws(() => compileLuaVm("local a = 1e400", { language: "lua", seed: 952 }), /out of range/i);
});

test("VM mode compiles numeric for loops (ascending, descending, and break)", () => {
  const output = compileLuaVm(
    "local sum = 0\nfor i = 1, 10 do sum = sum + i end\nfor j = 10, 1, -2 do print(j) end\nfor k = 1, 100 do if k == 5 then break end end",
    { language: "lua", seed: 953 }
  );
  assert.match(output, /^return \(function\(/);
});

test("VM mode compiles generic 'for ... in' loops", () => {
  const output = compileLuaVm("for k, v in pairs(t) do print(k, v) end", { language: "lua", seed: 954 });
  assert.match(output, /^return \(function\(/);
});

test("VM mode numeric for loop compiles a zero-step guard instead of hanging", () => {
  // Regression test: with a zero step, the desugared loop condition
  // ("step<=0 and start>=stop") stayed true forever once start===stop,
  // which hung the Lua runtime executing the obfuscated output. The guard
  // calls Lua's own error(), so the message is an encoded string constant
  // like any other literal -- not visible in the compiled output -- and is
  // verified by actually running the generated Lua under a real interpreter
  // (see docs/VM-HARDENING.md for the manual verification transcript).
  const output = compileLuaVm("for i = 1, 1, 0 do end", { language: "lua", seed: 955 });
  assert.match(output, /^return \(function\(/);
  assert.doesNotThrow(() => compileLuaVm("for i = 1, 1, 0 do end", { language: "lua", seed: 955 }));
});

test("VM mode compiles varargs, multiple returns, goto, bitwise ops, and float literals", () => {
  const source = `local function f(...) local a, b = ... return select("#", ...), a, b end
local x, y = f(1, 2)
for i = 1, 3 do if i == 2 then goto skip end print(i) ::skip:: end
print(5 & 3, 5 | 3, 5 ~ 3, ~0, 1 << 4, 7 // 2, 1e3)
local t = {f(1), n = 1}`;
  const output = compileLuaVm(source, { language: "lua", seed: 960 });
  assert.match(output, /^return \(function\(/);
  assert.equal(output.includes("skip"), false);
});

test("VM mode compiles Luau compound assignment and continue", () => {
  const output = compileLuaVm("local n = 1\nn += 2\nfor i = 1, 3 do if i == 2 then continue end end", { language: "luau", seed: 961 });
  assert.match(output, /^return \(function\(/);
});

test("VM mode reports vararg use outside a vararg function and undefined goto labels", () => {
  assert.throws(() => compileLuaVm("local function f() return ... end", { language: "lua", seed: 962 }), /vararg function/i);
  assert.throws(() => compileLuaVm("goto nowhere", { language: "lua", seed: 963 }), /no visible label/i);
});
