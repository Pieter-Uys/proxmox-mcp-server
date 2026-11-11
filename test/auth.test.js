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

// Replaces fetch for the duration of fn. `respond(url)` returns the reply, or
// throws to fail the test; the default fails on any request, so a test proves
// it made none.
async function withFetch(respond, fn) {
  const realFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    return respond(String(url));
  };
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = realFetch;
  }
}
const noNetwork = (url) => assert.fail(`unexpected request to ${url}`);

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

test("allowlist: typed entries match their own claim, untyped ones the username, ignoring case", async () => {
  for (const allowedUsers of [["alice"], ["user:alice"], ["email:alice@example.com"], ["sub:subject-123"], ["bob", "alice"]]) {
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

// ─── Client IP for the audit log ────────────────────────────────────────────
test("allowlist: an entry never matches a different claim (second audit R9)", async () => {
  // Someone who sets their email to a listed username must not get in, nor
  // match a listed email or subject by username.
  const cases = [
    [["bob"], { preferred_username: "mallory", email: "bob" }],
    [["bob"], { preferred_username: "mallory", sub: "bob" }],
    [["alice@example.com"], { preferred_username: "mallory", email: "alice@example.com" }],
    [["subject-123"], { preferred_username: "mallory", sub: "subject-123" }],
    [["email:bob@example.com"], { preferred_username: "bob@example.com", email: "mallory@example.com" }],
    [["sub:abc"], { preferred_username: "abc", sub: "other" }],
    [["user:abc"], { preferred_username: "other", email: "abc", sub: "abc" }],
  ];
  for (const [allowedUsers, claims] of cases) {
    await withSettings(SECURITY, { allowedUsers }, async () => {
      authTestHooks.reset();
      authTestHooks.setSigningKeys({ [KEY_ID]: publicKey });
      const result = await verify(signJwt(validClaims({ email: undefined, sub: "s-default", ...claims })));
      assert.equal(result.reason, "user not allowed", JSON.stringify([allowedUsers, claims]));
    });
  }
});

test("clientIp ignores cf-connecting-ip unless the server trusts a proxy", async () => {
  const req = { ip: "203.0.113.7", headers: { "cf-connecting-ip": "198.51.100.1" } };
  await withSettings(SECURITY, { trustProxyHops: 0 }, () => {
    assert.equal(clientIp(req), "203.0.113.7");
  });
  // Behind a proxy that isn't Cloudflare, a client can still send the header,
  // so it needs TRUST_CLOUDFLARE_HEADER as well (second audit R8).
  await withSettings(SECURITY, { trustProxyHops: 1, trustCloudflareHeader: false }, () => {
    assert.equal(clientIp(req), "203.0.113.7");
  });
  await withSettings(SECURITY, { trustProxyHops: 1, trustCloudflareHeader: true }, () => {
    assert.equal(clientIp(req), "198.51.100.1");
    assert.equal(clientIp({ ip: "203.0.113.7", headers: {} }), "203.0.113.7");
  });
  await withSettings(SECURITY, { trustProxyHops: 0, trustCloudflareHeader: true }, () => {
    assert.equal(clientIp(req), "203.0.113.7", "never without a trusted proxy hop");
  });
});

// ─── JWT verification ───────────────────────────────────────────────────────
const reasonFor = async (token) => (await verify(token)).reason;
const otherKeys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

test("jwt: a valid RS256 token is accepted", async () => {
  assert.deepEqual(await verify(signJwt(validClaims({ scope: "openid" }))), {
    ok: true,
    user: "alice",
    scope: "openid",
    cached: false,
  });
});

test("jwt: a signature from another key is rejected", async () => {
  assert.equal(await reasonFor(signJwt(validClaims(), { key: otherKeys.privateKey })), "bad signature");
});

test("jwt: tampered claims break the signature", async () => {
  const [header, , signature] = signJwt(validClaims()).split(".");
  const forged = base64UrlJson(validClaims({ preferred_username: "root" }));
  assert.equal(await reasonFor(`${header}.${forged}.${signature}`), "bad signature");
});

test("jwt: an unknown kid is rejected without fetching keys", async () => {
  assert.equal(await reasonFor(signJwt(validClaims(), { header: { kid: "nope" } })), "unknown signing key");
});

test("jwt: algorithms other than RS256 are rejected, including none and HS256", async () => {
  const claims = base64UrlJson(validClaims());
  const none = `${base64UrlJson({ alg: "none", kid: KEY_ID })}.${claims}.`;
  assert.equal(await reasonFor(none), "unsupported alg none");
  // HS256 keyed with the public key: the classic algorithm-confusion forgery.
  const hsHeader = base64UrlJson({ alg: "HS256", kid: KEY_ID });
  const hmacKey = publicKey.export({ type: "spki", format: "pem" });
  const hsSig = crypto.createHmac("sha256", hmacKey).update(`${hsHeader}.${claims}`).digest("base64url");
  assert.equal(await reasonFor(`${hsHeader}.${claims}.${hsSig}`), "unsupported alg HS256");
  for (const alg of ["RS512", "ES256", "PS256", "rs256"]) {
    assert.equal(await reasonFor(signJwt(validClaims(), { header: { alg } })), `unsupported alg ${alg}`);
  }
});

test("jwt: wrong issuer is rejected", async () => {
  assert.equal(await reasonFor(signJwt(validClaims({ iss: "https://evil.test/application/o/proxmox-mcp/" }))), "wrong issuer");
  assert.equal(await reasonFor(signJwt(validClaims({ iss: undefined }))), "wrong issuer");
});

test("jwt: expired, missing exp and not-yet-valid tokens are rejected", async () => {
  assert.equal(await reasonFor(signJwt(validClaims({ exp: nowSeconds() - 120 }))), "token expired");
  assert.equal(await reasonFor(signJwt(validClaims({ exp: undefined }))), "token expired");
  assert.equal(await reasonFor(signJwt(validClaims({ exp: String(nowSeconds() + 600) }))), "token expired");
  assert.equal(await reasonFor(signJwt(validClaims({ nbf: nowSeconds() + 600 }))), "token not yet valid");
});

test("jwt: malformed tokens are rejected", async () => {
  assert.equal(await reasonFor("a.b.c"), "malformed JWT");
});

test("cache: a verified token is never reused past its own exp", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const exp = nowSeconds() + 60; // well inside the 5 minute cache TTL
  const token = signJwt(validClaims({ exp }));
  assert.equal((await verify(token)).cached, false);
  assert.equal((await verify(token)).cached, true);
  // Just past exp: the cache entry is gone, so the token is checked afresh
  // (still inside the 30 second clock skew, so it passes once more).
  t.mock.timers.setTime(exp * 1000 + 1000);
  assert.equal((await verify(token)).cached, false);
  // Past the clock skew: rejected, not served from the cache.
  t.mock.timers.setTime(exp * 1000 + 31_000);
  assert.equal(await reasonFor(token), "token expired");
});


// ─── Opaque tokens (audit M5) ───────────────────────────────────────────────
// Authentik's access tokens are JWTs (only refresh tokens are opaque), so a
// non-JWT bearer value is refused here without asking Authentik anything.
test("opaque: a non-JWT token is rejected locally, with no request to Authentik", async () => {
  await withFetch(noNetwork, async (calls) => {
    for (const token of ["opaque-token-value", "a.b", "a.b.c.d", "x".repeat(64)]) {
      assert.equal(await reasonFor(token), "not a JWT access token", token);
    }
    assert.equal(calls.length, 0);
  });
});

// ─── Group allowlist (audit M4) ─────────────────────────────────────────────
test("groups: ALLOWED_GROUPS admits a member of a listed group", async () => {
  await withSettings(SECURITY, { allowedUsers: null, allowedGroups: ["proxmox-admins"] }, async () => {
    assert.equal((await verify(signJwt(validClaims({ groups: ["staff", "Proxmox-Admins"] })))).ok, true);
    for (const groups of [["staff"], [], undefined, "proxmox-admins"]) {
      authTestHooks.reset();
      authTestHooks.setSigningKeys({ [KEY_ID]: publicKey });
      assert.equal(await reasonFor(signJwt(validClaims({ groups }))), "user not allowed", JSON.stringify(groups));
    }
  });
});

test("groups: with both lists set, a match on either admits the user", async () => {
  await withSettings(SECURITY, { allowedUsers: ["bob"], allowedGroups: ["proxmox-admins"] }, async () => {
    assert.equal((await verify(signJwt(validClaims({ preferred_username: "bob", groups: [] })))).ok, true);
    assert.equal((await verify(signJwt(validClaims({ groups: ["proxmox-admins"] })))).ok, true);
    assert.equal(await reasonFor(signJwt(validClaims({ groups: ["staff"] }))), "user not allowed");
  });
});

test("groups: membership is re-checked for cached tokens", async () => {
  const token = signJwt(validClaims({ groups: ["proxmox-admins"] }));
  await withSettings(SECURITY, { allowedGroups: ["proxmox-admins"] }, async () => {
    assert.equal((await verify(token)).ok, true);
  });
  await withSettings(SECURITY, { allowedGroups: ["other"] }, async () => {
    const result = await verify(token);
    assert.equal(result.reason, "user not allowed");
  });
});

// ─── JWKS with keys this server can't use (audit M7) ────────────────────────
test("jwks: unusable keys are skipped instead of breaking every login", async () => {
  authTestHooks.reset(); // no keys installed, so the next check fetches the JWKS
  const rsaJwk = { ...publicKey.export({ format: "jwk" }), kid: KEY_ID, use: "sig", alg: "RS256" };
  const ecJwk = { ...crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" }), kid: "ec-key" };
  const jwks = {
    keys: [
      { kty: "oct", kid: "hmac-key", k: "c2VjcmV0" },
      { kty: "RSA", kid: "broken", n: "not base64!", e: "AQAB" },
      ecJwk,
      { kty: "RSA", kid: "enc-key", use: "enc", ...publicKey.export({ format: "jwk" }) },
      rsaJwk,
    ],
  };
  await withFetch(
    (url) => {
      assert.equal(url, AUTHENTIK.jwksUrl);
      return { ok: true, status: 200, json: async () => jwks };
    },
    async (calls) => {
      assert.equal((await verify(signJwt(validClaims()))).ok, true);
      assert.equal(calls.length, 1);
      assert.equal(await reasonFor(signJwt(validClaims(), { header: { kid: "ec-key" } })), "unknown signing key");
      assert.equal(await reasonFor(signJwt(validClaims(), { header: { kid: "enc-key" } })), "unknown signing key");
    },
  );
});
