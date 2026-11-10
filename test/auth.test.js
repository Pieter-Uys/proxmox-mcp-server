import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readBearerToken, verifyBearerToken, clientIp, authTestHooks } from "../src/auth.js";
import { AUTHENTIK } from "../src/authentik.js";
import { CONFIG, SECURITY } from "../src/config.js";

// ─── Helpers: real RS256 JWTs signed with a key made for this run ──────────
const KEY_ID = "test-key";
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const nowSeconds = () => Math.floor(Date.now() / 1000);
const base64UrlJson = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

function validClaims(overrides = {}) {
  return {
    iss: AUTHENTIK.issuer,
    aud: "proxmox-mcp-client",
    sub: "subject-123",
    preferred_username: "alice",
    email: "alice@example.com",
    iat: nowSeconds(),
    exp: nowSeconds() + 600,
    ...overrides,
  };
}

// Signs `claims` with `key` (RS256 unless the header says otherwise).
function signJwt(claims, { header = {}, key = privateKey } = {}) {
  const fullHeader = { alg: "RS256", typ: "JWT", kid: KEY_ID, ...header };
  const signedPart = `${base64UrlJson(fullHeader)}.${base64UrlJson(claims)}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signedPart), key).toString("base64url");
  return `${signedPart}.${signature}`;
}

const verify = (token) => verifyBearerToken({ headers: { authorization: `Bearer ${token}` } });

// Runs fn with settings temporarily overridden on `target`, then restores them.
async function withSettings(target, overrides, fn) {
  const previous = Object.fromEntries(Object.keys(overrides).map((key) => [key, target[key]]));
  Object.assign(target, overrides);
  try {
    return await fn();
  } finally {
    Object.assign(target, previous);
  }
}

// Every test starts with an empty cache and only the test key installed.
test.beforeEach(() => {
  authTestHooks.reset();
  authTestHooks.setSigningKeys({ [KEY_ID]: publicKey });
});

// Stands in for Authentik's userinfo endpoint. Any other request fails the
// test, so nothing here can reach the network.
async function withUserinfo(claims, fn) {
  const realFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(url);
    assert.equal(url, AUTHENTIK.userinfoUrl, "only userinfo may be fetched");
    if (!claims) return { ok: false, status: 401, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => claims };
  };
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = realFetch;
  }
}

// ─── readBearerToken ────────────────────────────────────────────────────────

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

// ─── Audience (AUTHENTIK_AUDIENCE) ──────────────────────────────────────────
test("audience: unset accepts any aud, as before", async () => {
  await withSettings(CONFIG.authentik, { audience: undefined }, async () => {
    assert.equal((await verify(signJwt(validClaims({ aud: "some-other-app" })))).ok, true);
  });
});

test("audience: when set, aud must name it, as a string or in an array", async () => {
  await withSettings(CONFIG.authentik, { audience: "proxmox-mcp-client" }, async () => {
    assert.equal((await verify(signJwt(validClaims({ aud: "proxmox-mcp-client" })))).ok, true);
    assert.equal((await verify(signJwt(validClaims({ aud: ["other", "proxmox-mcp-client"] })))).ok, true);
    for (const aud of ["some-other-app", ["other", "another"], [], undefined, "proxmox-mcp-client-2"]) {
      const result = await verify(signJwt(validClaims({ aud })));
      assert.equal(result.ok, false, JSON.stringify(aud));
      assert.equal(result.reason, "wrong audience", JSON.stringify(aud));
    }
  });
});

// ─── User allowlist (ALLOWED_USERS) ─────────────────────────────────────────
test("allowlist: unset lets in anyone Authentik signs in, as before", async () => {
  await withSettings(SECURITY, { allowedUsers: null }, async () => {
    assert.equal((await verify(signJwt(validClaims({ preferred_username: "mallory" })))).ok, true);
  });
});

test("allowlist: a JWT user matches by username, email or sub, ignoring case", async () => {
  for (const allowedUsers of [["alice"], ["alice@example.com"], ["subject-123"], ["bob", "alice"]]) {
    await withSettings(SECURITY, { allowedUsers }, async () => {
      authTestHooks.reset();
      authTestHooks.setSigningKeys({ [KEY_ID]: publicKey });
      const result = await verify(signJwt(validClaims({ preferred_username: "Alice" })));
      assert.equal(result.ok, true, JSON.stringify(allowedUsers));
    });
  }
});

test("allowlist: a verified JWT user who isn't listed is rejected", async () => {
  await withSettings(SECURITY, { allowedUsers: ["bob", "carol@example.com"] }, async () => {
    const result = await verify(signJwt(validClaims()));
    assert.equal(result.ok, false);
    assert.equal(result.reason, "user not allowed");
  });
});

test("allowlist: an opaque token user who isn't listed is rejected", async () => {
  await withSettings(SECURITY, { allowedUsers: ["bob"] }, async () => {
    await withUserinfo({ preferred_username: "alice", email: "alice@example.com", sub: "s1" }, async () => {
      const result = await verify("opaque-token-value");
      assert.equal(result.ok, false);
      assert.equal(result.reason, "user not allowed");
    });
  });
  await withSettings(SECURITY, { allowedUsers: ["alice"] }, async () => {
    await withUserinfo({ preferred_username: "alice" }, async () => {
      assert.equal((await verify("another-opaque-token")).ok, true);
    });
  });
});

test("allowlist: also applies to tokens already in the verified-token cache", async () => {
  const token = signJwt(validClaims());
  await withSettings(SECURITY, { allowedUsers: null }, async () => {
    assert.deepEqual(await verify(token), { ok: true, user: "alice", scope: undefined, cached: false });
    assert.equal((await verify(token)).cached, true);
  });
  await withSettings(SECURITY, { allowedUsers: ["bob"] }, async () => {
    const result = await verify(token);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "user not allowed");
  });
});

test("allowlist: cached opaque tokens are re-checked too", async () => {
  await withUserinfo({ preferred_username: "alice" }, async (calls) => {
    await withSettings(SECURITY, { allowedUsers: ["alice"] }, async () => {
      assert.equal((await verify("opaque-cached")).ok, true);
    });
    await withSettings(SECURITY, { allowedUsers: ["bob"] }, async () => {
      assert.equal((await verify("opaque-cached")).reason, "user not allowed");
    });
    assert.equal(calls.length, 1, "second check came from the cache");
  });
});

// ─── Client IP for the audit log ────────────────────────────────────────────
test("clientIp ignores cf-connecting-ip unless the server trusts a proxy", async () => {
  const req = { ip: "203.0.113.7", headers: { "cf-connecting-ip": "198.51.100.1" } };
  await withSettings(SECURITY, { trustProxyHops: 0 }, () => {
    assert.equal(clientIp(req), "203.0.113.7");
  });
  await withSettings(SECURITY, { trustProxyHops: 1 }, () => {
    assert.equal(clientIp(req), "198.51.100.1");
    assert.equal(clientIp({ ip: "203.0.113.7", headers: {} }), "203.0.113.7");
  });
});
