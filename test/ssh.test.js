import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { shellQuote } from "../src/ssh.js";

test("shellQuote wraps a value in single quotes", () => {
  assert.equal(shellQuote("hello world"), "'hello world'");
  assert.equal(shellQuote(42), "'42'");
});

test("shellQuote escapes every embedded single quote", () => {
  assert.equal(shellQuote("it's"), String.raw`'it'\''s'`);
  assert.equal(shellQuote("''"), String.raw`''\'''\'''`);
});

test("shellQuote leaves shell metacharacters inert", () => {
  assert.equal(shellQuote("$(rm -rf /); `id` \\ x"), "'$(rm -rf /); `id` \\ x'");
});
