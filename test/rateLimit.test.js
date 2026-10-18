import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createRateLimiter } from "../src/rateLimit.js";

test("rate limiter allows up to the limit then returns 429", async () => {
  const app = express();
  app.use(createRateLimiter(2));
  app.get("/", (_req, res) => res.json({ ok: true }));
  const server = app.listen(0);
  try {
    const url = `http://127.0.0.1:${server.address().port}/`;
    const statuses = [];
    for (let i = 0; i < 3; i++) statuses.push((await fetch(url)).status);
    assert.deepEqual(statuses, [200, 200, 429]);
    const blocked = await fetch(url);
    assert.deepEqual(await blocked.json(), { error: "rate_limited" });
  } finally {
    server.close();
  }
});
