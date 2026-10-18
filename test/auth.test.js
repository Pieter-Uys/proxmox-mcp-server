import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { readBearerToken } from "../src/auth.js";

const tokenFrom = (authorization) => readBearerToken({ headers: { authorization } });

test("readBearerToken extracts the token after the Bearer scheme", () => {
  assert.equal(tokenFrom("Bearer abc.def.ghi"), "abc.def.ghi");
  assert.equal(tokenFrom("bearer abc"), "abc");
  assert.equal(tokenFrom("BEARER   abc"), "abc");
  assert.equal(tokenFrom("Bearer\tabc"), "abc");
});

test("readBearerToken rejects anything that isn't a Bearer token", () => {
  for (const header of [undefined, "", "Bearer", "Bearer ", "Bearer     ", "Basic abc", "Bearerabc", "Token abc"]) {
    assert.equal(tokenFrom(header), null, JSON.stringify(header));
  }
});

test("readBearerToken stays fast on very long runs of whitespace", () => {
  assert.equal(tokenFrom("Bearer" + " ".repeat(200_000)), null);
  assert.equal(tokenFrom("Bearer" + " ".repeat(200_000) + "x"), "x");
});
