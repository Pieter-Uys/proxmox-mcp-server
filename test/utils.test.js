import test from "node:test";
import assert from "node:assert/strict";
import { forLog } from "../src/utils.js";

test("forLog turns line breaks and control characters into spaces", () => {
  assert.equal(forLog("a\nb\r\nc\td\u0000e f"), "a b  c d e f");
});

test("forLog JSON-encodes non-strings and handles missing values", () => {
  assert.equal(forLog({ id: 1 }), '{"id":1}');
  assert.equal(forLog(7), "7");
  assert.equal(forLog(undefined), "undefined");
  assert.equal(forLog(null), "null");
});

test("forLog cuts long values to maxLength", () => {
  assert.equal(forLog("x".repeat(500)).length, 200);
  assert.equal(forLog("abcdef", 3), "abc");
});

test("forLog can't be used to forge a second log line", () => {
  const forged = forLog("tools/list\nAUDIT {\"user\":\"admin\"}");
  assert.equal(forged.includes("\n"), false);
});
