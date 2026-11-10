import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import { shellQuote, createHostVerifier, hostKeyFingerprint, collectOutput, formatCommandResult } from "../src/ssh.js";
import { HOST_KEY_FINGERPRINT } from "../src/constants.js";

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

// ─── Host key pinning (audit H3) ────────────────────────────────────────────

const hostKey = crypto.randomBytes(51); // stands in for a raw ssh-ed25519 public key blob
const otherKey = crypto.randomBytes(51);

test("hostKeyFingerprint matches OpenSSH's SHA256 form", () => {
  const fingerprint = hostKeyFingerprint(hostKey);
  assert.match(fingerprint, HOST_KEY_FINGERPRINT);
  const expected = crypto.createHash("sha256").update(hostKey).digest("base64").replace(/=+$/, "");
  assert.equal(fingerprint, `SHA256:${expected}`);
});

test("the host verifier accepts only the pinned key", () => {
  const verify = createHostVerifier(hostKeyFingerprint(hostKey));
  assert.equal(verify(hostKey), true);
  assert.equal(verify(otherKey), false);
  assert.equal(verify(Buffer.alloc(0)), false);
});

test("the host verifier accepts a pinned fingerprint written with base64 padding", () => {
  const verify = createHostVerifier(`${hostKeyFingerprint(hostKey)}=`);
  assert.equal(verify(hostKey), true);
});

// ─── Output collection (audit H4) ───────────────────────────────────────────
// A stand-in for an ssh2 channel: emits data on itself and on .stderr.
function fakeStream() {
  const stream = new EventEmitter();
  stream.stderr = new EventEmitter();
  stream.setEncoding = () => {};
  stream.stderr.setEncoding = () => {};
  stream.closed = false;
  stream.close = () => {
    stream.closed = true;
  };
  return stream;
}

test("collectOutput returns all output and the exit code under the cap", async () => {
  const stream = fakeStream();
  const pending = collectOutput(stream, 100);
  stream.emit("data", "hello ");
  stream.emit("data", "world\n");
  stream.stderr.emit("data", "warn\n");
  stream.emit("close", 0);
  assert.deepEqual(await pending, { stdout: "hello world", stderr: "warn", code: 0, signal: null, truncated: false });
});

test("collectOutput stops at the byte cap across stdout and stderr and closes the channel", async () => {
  const stream = fakeStream();
  const pending = collectOutput(stream, 10);
  stream.emit("data", "123456");
  stream.stderr.emit("data", "abcdef");
  stream.emit("data", "never kept");
  stream.emit("close", 0);
  const result = await pending;
  assert.equal(result.stdout, "123456");
  assert.equal(result.stderr, "abcd");
  assert.equal(result.truncated, true);
  assert.equal(result.code, null, "a cut-off command has no exit code");
  assert.equal(stream.closed, true);
});

test("collectOutput counts bytes, not characters", async () => {
  const stream = fakeStream();
  const pending = collectOutput(stream, 4);
  stream.emit("data", "ééé"); // 6 bytes
  const result = await pending;
  assert.equal(result.truncated, true);
  assert.equal(result.stdout, "éé");
});

test("an exception inside a stream handler rejects the call instead of crashing the process", async () => {
  const stream = fakeStream();
  const pending = collectOutput(stream, 100);
  stream.emit("data", { toString: null }); // Buffer.byteLength throws on this
  await assert.rejects(pending, TypeError);
});

test("a truncated result says so, so the model can't mistake it for complete output", () => {
  const text = formatCommandResult({ stdout: "x", stderr: "", code: null, signal: null, truncated: true });
  assert.match(text, /^Exit: none \(output cut off; the command may still be running\)/);
  assert.match(text, /output truncated at \d+ bytes/);
  // Closing the channel doesn't kill the remote process, so never claim it stopped.
  assert.doesNotMatch(text, /stopped/);
  assert.match(text, /may still be running on the host; check its state before retrying/);
});

test("fingerprint padding is stripped without a backtracking regex", () => {
  const verify = createHostVerifier(`${hostKeyFingerprint(hostKey)}${"=".repeat(3)}`);
  assert.equal(verify(hostKey), true);
  // A long run of = that isn't at the end must still be handled in linear time.
  const started = process.hrtime.bigint();
  createHostVerifier(`SHA256:${"=".repeat(50_000)}x`);
  assert.ok(process.hrtime.bigint() - started < 200_000_000n, "took too long");
});
