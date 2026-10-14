import test from "node:test";
import assert from "node:assert/strict";
import { compileLuaSubset } from "../src/compiler.js";

test("preserves Lua source syntax and encodes string constants", () => {
  const source = [
    'local name = "LuaMoon"',
    "local count = 2",
    "if count > 1 then",
    '  print(name .. " VM ready")',
    "elseif count == 1 then",
    '  print("one")',
    "else",
    '  warn("not ready")',
    "end"
  ].join("\n");
  const output = compileLuaSubset(source, { seed: 1234 });
  assert.equal(output.includes('"LuaMoon"'), false);
  assert.match(output, /local count = 2/);
  assert.match(output, /if count > 1 then/);
  assert.match(output, /elseif count == 1 then/);
});

test("encodes numeric and escaped string constants", () => {
  const output = compileLuaSubset('local n = -12.5\nprint("hello\\nworld", n)', { seed: 1 });
  assert.equal(output.includes("hello"), false);
  assert.match(output, /local n = -12.5/);
});

test("preserves nested table constructors and index assignment", () => {
  const source = 'local t = {child={value="secret"}} t.child.value="changed" print(t.child.value)';
  const output = compileLuaSubset(source, { seed: 23 });
  assert.match(output, /local t = \{child=\{value=/);
  assert.match(output, /t\.child\.value=/);
  assert.equal(output.includes('"secret"'), false);
  assert.equal(output.includes('"changed"'), false);
});
