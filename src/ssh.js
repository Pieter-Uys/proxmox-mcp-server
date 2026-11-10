import crypto from "node:crypto";
import { Client } from "ssh2";
import { CONFIG } from "./config.js";
import { SSH_COMMAND_TIMEOUT_MS, SSH_CONNECT_TIMEOUT_MS, SSH_MAX_OUTPUT_BYTES } from "./constants.js";
import { withTimeout } from "./utils.js";

// ─── SSH ────────────────────────────────────────────────────────────────────
// Runs a command over SSH and resolves with { stdout, stderr, code, signal, truncated }.
// `code` is null if the command didn't exit normally (killed, or the connection
// closed first); `signal` then names the signal if there was one.
// Connects to the Proxmox host unless `target` overrides
// host/port/username/password/hostKey. `timeoutMs` covers connect plus run.
export async function sshExec(command, target = {}, { timeoutMs = SSH_COMMAND_TIMEOUT_MS } = {}) {
  const connection = new Client();
  const connectAndRun = async () => {
    await openConnection(connection, buildConnectOptions(target));
    return runCommand(connection, command);
  };
  try {
    return await withTimeout(connectAndRun(), timeoutMs, {
      // The channel is torn down, but nothing on the host is told to stop, so
      // say so: the model must not assume the command was undone.
      message: `SSH timeout after ${Math.round(timeoutMs / 1000)}s. The command may still be running on the remote host; check its state before retrying.`,
      onTimeout: () => connection.destroy(),
    });
  } finally {
    connection.end();
  }
}

// Where and how to connect: the Proxmox host by default, or the given target.
function buildConnectOptions(target) {
  // The Proxmox host is checked against PROXMOX_SSH_HOST_KEY; another target
  // only against the fingerprint given for it, if any.
  const fingerprint = target.host ? target.hostKey : CONFIG.ssh.hostKey;
  return {
    host: target.host || CONFIG.ssh.host,
    port: target.port || CONFIG.ssh.port,
    username: target.username || CONFIG.ssh.username,
    readyTimeout: SSH_CONNECT_TIMEOUT_MS,
    ...(fingerprint && { hostVerifier: createHostVerifier(fingerprint) }),
    ...chooseCredentials(target),
  };
}

// A password given for this call wins; otherwise use the configured key.
function chooseCredentials(target) {
  if (target.password) return { password: target.password };
  if (CONFIG.ssh.privateKey) return { privateKey: CONFIG.ssh.privateKey };
  return {};
}

// ─── Host key pinning ───────────────────────────────────────────────────────
// ssh2 accepts any host key unless told otherwise, so anyone who can intercept
// the connection would see every command and could forge its output. The
// fingerprint is the OpenSSH "SHA256:<base64>" form printed by
// `ssh-keyscan host | ssh-keygen -lf -`.

export function hostKeyFingerprint(rawKey) {
  const digest = crypto.createHash("sha256").update(rawKey).digest("base64");
  return `SHA256:${digest.replace(/=+$/, "")}`;
}

// Returns ssh2's hostVerifier: true only for a key with exactly this
// fingerprint. ssh2 aborts the connection before authenticating on false, so a
// password or key signature never reaches the wrong host.
export function createHostVerifier(expectedFingerprint) {
  const expected = Buffer.from(expectedFingerprint.replace(/=+$/, ""));
  return (rawKey) => {
    const actual = Buffer.from(hostKeyFingerprint(rawKey));
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  };
}

// Resolves once the connection is ready to run commands.
function openConnection(connection, connectOptions) {
  return new Promise((resolve, reject) => {
    connection.on("ready", resolve);
    connection.on("error", reject);
    connection.connect(connectOptions);
  });
}

// Runs one command on a ready connection and collects its output.
function runCommand(connection, command) {
  return new Promise((resolve, reject) => {
    connection.on("error", reject); // e.g. the connection drops mid-command
    connection.exec(command, (error, stream) => {
      if (error) return reject(error);
      collectOutput(stream).then(resolve, reject);
    });
  });
}

// ─── Output collection ──────────────────────────────────────────────────────
// Collects a channel's stdout and stderr, at most `maxBytes` across both. Past
// that the channel is closed and the result is marked truncated, so output
// such as `cat /dev/zero` can't exhaust memory or hit V8's string limit.
// Exported for tests, which pass a fake stream.
export function collectOutput(stream, maxBytes = SSH_MAX_OUTPUT_BYTES) {
  return new Promise((resolve, reject) => {
    const output = { stdout: "", stderr: "" };
    let bytes = 0;
    let truncated = false;
    let settled = false;
    const finish = (settle, value) => {
      if (settled) return;
      settled = true;
      settle(value);
    };
    const result = (exitCode, signal) => ({
      stdout: output.stdout.trim(),
      stderr: output.stderr.trim(),
      code: exitCode ?? null,
      signal: signal ?? null,
      truncated,
    });

    // A throw inside an event handler would otherwise be an uncaught
    // exception and take the whole server down; reject this call instead.
    const guard = (handler) => (...args) => {
      try {
        handler(...args);
      } catch (error) {
        finish(reject, error);
      }
    };

    const append = (field, chunk) => {
      if (truncated) return;
      const room = maxBytes - bytes;
      const size = Buffer.byteLength(chunk);
      if (size <= room) {
        output[field] += chunk;
        bytes += size;
        return;
      }
      // Keep what fits. A character cut in half decodes as U+FFFD, which is
      // fine for output that is marked incomplete anyway.
      output[field] += Buffer.from(chunk).subarray(0, room).toString("utf8");
      bytes = maxBytes;
      truncated = true;
      stream.close?.(); // stop the remote side sending more
      finish(resolve, result(null, null));
    };

    // Decode as a stream so a character split across two chunks stays intact.
    stream.setEncoding?.("utf8");
    stream.stderr.setEncoding?.("utf8");
    stream.on("data", guard((chunk) => append("stdout", chunk)));
    stream.stderr.on("data", guard((chunk) => append("stderr", chunk)));
    // Output is kept even if the command was killed, since it may explain why.
    stream.on("close", guard((exitCode, signal) => finish(resolve, result(exitCode, signal))));
    stream.on("error", (error) => finish(reject, error));
  });
}

// Wraps a value in single quotes so the shell passes it through literally.
const ESCAPED_SINGLE_QUOTE = String.raw`'\''`;
export function shellQuote(value) {
  const escaped = String(value).replaceAll("'", ESCAPED_SINGLE_QUOTE);
  return `'${escaped}'`;
}

export function formatCommandResult(result) {
  const truncationNote = result.truncated
    ? `\n[output truncated at ${SSH_MAX_OUTPUT_BYTES} bytes; the command was stopped and this output is incomplete]`
    : "";
  const stderr = result.stderr ? "\nSTDERR:\n" + result.stderr : "";
  return `Exit: ${describeExit(result)}\n${result.stdout}${stderr}${truncationNote}`;
}

// The exit code, or a plain statement of why there isn't one, so a killed or
// cut-off command is never mistaken for a successful run.
function describeExit({ code, signal, truncated }) {
  if (code !== null) return String(code);
  if (truncated) return "none (stopped after too much output)";
  if (signal) return `none (killed by signal ${signal})`;
  return "none (connection closed before the command finished)";
}

export async function runOnHost(command, options) {
  return formatCommandResult(await sshExec(command, {}, options));
}
