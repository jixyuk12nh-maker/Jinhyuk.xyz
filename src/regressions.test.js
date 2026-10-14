import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compileLuaSubset, compileLuaVm } from "./compiler.js";

const renamed = (source, language = "lua") => compileLuaSubset(source, { language, seed: 42, renameLocals: true });

test("renaming a top-level local also renames its assignments", () => {
  const output = renamed("local count = 0\ncount = count + 1\nprint(count)");
  assert.equal(/\bcount\b/.test(output), false, "no reference to the original name may survive");
  // The assignment target must be the same local as the reads.
  const name = output.match(/local (_\w+) =/)[1];
  assert.match(output, new RegExp(`${name} = \\(?${name}`));
});

test("renaming does not treat table keys as variables but does rename assignments in functions", () => {
  const output = renamed("local y = 5\nlocal holder = { y = y, f = function() local a = 1; a, y = 2, 3 end }\nholder.f()\nprint(holder.y, y)");
  // The field key `y` keeps its name; the assignment `a, y = 2, 3` inside the
  // function targets the renamed top-level local.
  assert.match(output, /\{ y = _\w+, f = /);
  assert.equal(/, y = 2, 3/.test(output), false);
  assert.match(output, /, _\w+ = 2, 3/);
});

test("numeric literals are not split into identifiers during renaming", () => {
  const output = renamed("local x10 = 5\nlocal e5 = 7\nprint(0x10, 1e5, x10, e5)");
  assert.match(output, /print\(0x10, 1e5, /);
  assert.equal(/\b0_/.test(output) || /\b1_/.test(output), false);
});

test("string call sugar stays valid Lua after encoding", () => {
  const output = compileLuaSubset('print "hello"\nrequire "module"', { seed: 3 });
  assert.equal(/\bprint _/.test(output), false);
  assert.match(output, /print \(_[A-Za-z0-9_]+\(/);
});

test("Luau method-call string arguments are encoded, not treated as type literals", () => {
  const output = compileLuaSubset('script.Parent:WaitForChild("Gui")\ngame:GetService("Players")', { language: "luau", seed: 4 });
  assert.equal(output.includes("Gui"), false);
  assert.equal(output.includes("Players"), false);
});

test("Luau union continuation lines in multiline type aliases stay literal", () => {
  const source = 'type Mode =\n  "fast"\n  | "slow"\nlocal m: Mode = "fast"\nprint(m)';
  const output = compileLuaSubset(source, { language: "luau", seed: 5 });
  assert.match(output, /\n  \| "slow"\n/);
  assert.match(output, /\n  "fast"\n/);
});

test("compatibility transform stays fast on large inputs", () => {
  const source = Array.from({ length: 8000 }, (_, i) => `local v${i} = "s${i}" .. tostring(${i})\nprint(v${i})`).join("\n");
  const started = Date.now();
  compileLuaSubset(source, { seed: 9, renameLocals: true });
  assert.ok(Date.now() - started < 5000, "transform of 8000 lines should take seconds, not minutes");
});

test("VM mode accepts '...' in the main chunk, as Lua does", () => {
  const output = compileLuaVm("local n = select('#', ...)\nprint(n, ...)", { language: "lua", seed: 6 });
  assert.match(output, /^return \(function\(/);
});

test("VM mode does not mistake '::' inside a Luau string for type syntax", () => {
  const output = compileLuaVm('print("a::b")', { language: "luau", seed: 7 });
  assert.match(output, /^return \(function\(/);
});

// Runs generated code under a real Lua interpreter when one is installed and
// compares its output with the original program. Skipped otherwise.
const LUA = ["lua5.4", "lua5.3", "lua", "texlua"].find(bin => {
  try { execFileSync(bin, ["-v"], { stdio: "ignore" }); return true; } catch { return false; }
});

function runLua(code) {
  const dir = mkdtempSync(join(tmpdir(), "luamoon-"));
  try {
    const file = join(dir, "chunk.lua");
    writeFileSync(file, code);
    return execFileSync(LUA, [file], { encoding: "utf8" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const PROGRAM = `local count = 0
count = count + 1
local w = 0x10
local e5 = 2
print(count, w, 1e2, e5)
local holder = { k = 1, f = function() local a = 1; a, count = 2, 9 end }
holder.f()
print(holder.k, count)
for i = 1, 3 do if i == 2 then goto continue end print("i", i) ::continue:: end
print("str \\65\\x42", ("ab"):upper())
print(select("#", (function(...) return ... end)(1, nil, 3)))
`;

test("obfuscated Lua runs with the same output as the original (compatibility mode)", { skip: !LUA && "no Lua interpreter on PATH" }, () => {
  const expected = runLua(PROGRAM);
  assert.equal(runLua(compileLuaSubset(PROGRAM, { seed: 17, renameLocals: true })), expected);
});

test("obfuscated Lua runs with the same output as the original (VM mode)", { skip: !LUA && "no Lua interpreter on PATH" }, () => {
  const expected = runLua(PROGRAM);
  assert.equal(runLua(compileLuaVm(PROGRAM, { language: "lua", seed: 18 })), expected);
});
