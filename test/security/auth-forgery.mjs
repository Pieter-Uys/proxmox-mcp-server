// Token-forgery suite against the real JWT verification path.
//
// This is the internet-facing boundary: a forged token that verifies is full
// root on the Proxmox host. The verification is hand-rolled, so it is probed
// with real signatures: valid tokens must pass, and every forgery must fail,
// with no network call. Uses the server's own authTestHooks to install a
// signing key, exactly as test/auth.test.js does.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";

// Config must be in place before importing auth.js.
Object.assign(process.env, {
  PROXMOX_HOST: "pve.test",
  PROXMOX_TOKEN_ID: "t@pam!t",
  PROXMOX_TOKEN_SECRET: "s",
  PROXMOX_SSH_HOST: "pve.test",
  MCP_BASE_URL: "https://mcp.test",
  AUTHENTIK_URL: "https://auth.test",
  AUTHENTIK_AUDIENCE: "mcp-client", // the audience check is under test
  AUDIT_LOG: path.join(os.tmpdir(), "pmcp-auth", "audit.jsonl"),
  SHELL_MODE: "off", // no SSH host key needed
  ALLOW_ANY_AUDIENCE: "yes", // ignored: audience is set, so the check runs
});

const { verifyBearerToken, authTestHooks } = await import("../../src/auth.js");

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const KID = "test-kid";
authTestHooks.reset();
authTestHooks.setSigningKeys({ [KID]: publicKey });

const ISSUER = "https://auth.test/application/o/proxmox-mcp/";
const now = () => Math.floor(Date.now() / 1000);
const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

// A valid signer, and knobs to forge each part.
function makeToken({ header = {}, claims = {}, signWith = privateKey, alg = "RS256", overridePayload } = {}) {
  const fullHeader = { alg, kid: KID, typ: "JWT", ...header };
  const fullClaims = { iss: ISSUER, aud: "mcp-client", exp: now() + 3600, preferred_username: "alice", scope: "openid", ...claims };
  const headPart = b64(fullHeader);
  const payloadPart = overridePayload ?? b64(fullClaims);
  const signingInput = `${headPart}.${payloadPart}`;
  let sig = "";
  if (alg === "RS256") sig = crypto.sign("RSA-SHA256", Buffer.from(signingInput), signWith).toString("base64url");
  else if (alg === "HS256") sig = crypto.createHmac("sha256", signWith).update(signingInput).digest("base64url");
  // alg "none": empty signature.
  return `${signingInput}.${sig}`;
}

const verify = (token) => verifyBearerToken({ headers: { authorization: `Bearer ${token}` } });

const failures = [];
async function expectResult(label, token, shouldPass) {
  const res = await verify(token);
  const got = res.ok ? "accept" : "reject (" + res.reason + ")";
  if (res.ok !== shouldPass)
    failures.push(`${label}: expected ${shouldPass ? "accept" : "REJECT"}, got ${got}`);
}

// The public key in PEM, for the algorithm-confusion attack (sign HS256 with
// the public key as the shared secret, hoping the verifier treats it as HMAC).
const publicPem = publicKey.export({ type: "spki", format: "pem" });

// ── Valid token must pass ────────────────────────────────────────────────────
await expectResult("valid RS256", makeToken(), true);

// ── Forgeries must all fail ──────────────────────────────────────────────────
await expectResult("alg:none", makeToken({ alg: "none" }), false);
await expectResult("alg confusion HS256 w/ public key", makeToken({ alg: "HS256", signWith: publicPem }), false);
await expectResult("unsigned (empty sig, RS256 header)", `${b64({ alg: "RS256", kid: KID })}.${b64({ iss: ISSUER, aud: "mcp-client", exp: now() + 3600 })}.`, false);
await expectResult("wrong issuer", makeToken({ claims: { iss: "https://evil.test/" } }), false);
await expectResult("wrong audience", makeToken({ claims: { aud: "other-app" } }), false);
await expectResult("missing audience", makeToken({ claims: { aud: undefined } }), false);
await expectResult("expired", makeToken({ claims: { exp: now() - 120 } }), false);
await expectResult("missing exp", makeToken({ claims: { exp: undefined } }), false);
await expectResult("nbf in the future", makeToken({ claims: { nbf: now() + 600 } }), false);
await expectResult("unknown kid", makeToken({ header: { kid: "attacker-kid" } }), false);
await expectResult("signed by a different key", makeToken({ signWith: crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey }), false);

// Tampered payload: a valid signature over claims A, but payload swapped to B
// (admin, longer expiry). Signature no longer matches the payload.
const good = makeToken();
const [h, , s] = good.split(".");
const forgedPayload = b64({ iss: ISSUER, aud: "mcp-client", exp: now() + 999999, preferred_username: "root", groups: ["admins"] });
await expectResult("tampered payload", `${h}.${forgedPayload}.${s}`, false);

// Opaque / non-JWT must be refused locally, with no network call.
await expectResult("opaque token", "not-a-jwt-value", false);
await expectResult("two-segment token", "aaa.bbb", false);

// ── Report ───────────────────────────────────────────────────────────────────
console.log(`\nAuth-forgery suite: ${16} token checks\n`);
if (failures.length) {
  console.log(`!!! ${failures.length} FAILURE(S):`);
  for (const f of failures) console.log(`  ${f}`);
} else {
  console.log("All forgeries rejected and the valid token accepted.");
}
console.log("");
assert.equal(failures.length, 0, `${failures.length} auth-forgery failure(s)`);
