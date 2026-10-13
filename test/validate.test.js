import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { validateArgs, checkRequiredWhen } from "../src/validate.js";

const schema = {
  type: "object",
  properties: {
    name: { type: "string", pattern: "^[a-z]+$" },
    count: { type: "integer", minimum: 1 },
    ratio: { type: "number" },
    flag: { type: "boolean" },
    mode: { type: "string", enum: ["a", "b"] },
    extra: { type: "object" },
  },
  required: ["name"],
};

test("accepts valid arguments", () => {
  assert.deepEqual(validateArgs(schema, { name: "abc", count: 2, ratio: 1.5, flag: true, mode: "a", extra: {} }), []);
});

test("arguments must be an object", () => {
  for (const bad of [null, undefined, "x", 5, [], [{ name: "abc" }]]) {
    assert.deepEqual(validateArgs(schema, bad), ["arguments must be an object"], JSON.stringify(bad));
  }
});

test("reports missing required arguments", () => {
  assert.deepEqual(validateArgs(schema, {}), ["name is required"]);
});

test("rejects arguments the schema does not declare", () => {
  assert.deepEqual(validateArgs(schema, { name: "abc", nope: 1 }), ["nope is not a recognised argument"]);
});

test("does not treat inherited names as declared arguments", () => {
  assert.ok(validateArgs(schema, { name: "abc", constructor: "x" }).length);
});

test("type checks", () => {
  assert.ok(validateArgs(schema, { name: 5 }).length);
  assert.ok(validateArgs(schema, { name: "abc", count: 1.5 }).length);
  assert.ok(validateArgs(schema, { name: "abc", count: "2" }).length);
  assert.ok(validateArgs(schema, { name: "abc", ratio: NaN }).length);
  assert.ok(validateArgs(schema, { name: "abc", ratio: Infinity }).length);
  assert.ok(validateArgs(schema, { name: "abc", flag: "true" }).length);
  assert.ok(validateArgs(schema, { name: "abc", extra: [] }).length);
  assert.ok(validateArgs(schema, { name: "abc", extra: null }).length);
});

test("enum, pattern and minimum", () => {
  assert.ok(validateArgs(schema, { name: "abc", mode: "c" }).length);
  assert.ok(validateArgs(schema, { name: "ABC" }).length);
  assert.ok(validateArgs(schema, { name: "abc", count: 0 }).length);
});

test("undefined optional values are ignored", () => {
  assert.deepEqual(validateArgs(schema, { name: "abc", count: undefined }), []);
});

test("checkRequiredWhen enforces conditional requirements", () => {
  const rules = [{ field: "action", values: ["delete"], required: ["pos"] }];
  assert.deepEqual(checkRequiredWhen(rules, { action: "delete" }), ["pos is required when action is delete"]);
  assert.deepEqual(checkRequiredWhen(rules, { action: "delete", pos: 0 }), []);
  assert.deepEqual(checkRequiredWhen(rules, { action: "list" }), []);
  assert.deepEqual(checkRequiredWhen(undefined, { action: "delete" }), []);
});
