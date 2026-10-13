import { Client } from "ssh2";
import { CONFIG } from "./config.js";
import { SSH_COMMAND_TIMEOUT_MS, SSH_CONNECT_TIMEOUT_MS } from "./constants.js";
import { withTimeout } from "./utils.js";

// ─── SSH ────────────────────────────────────────────────────────────────────
// Runs a command over SSH and resolves with { stdout, stderr, code, signal }.
// `code` is null if the command didn't exit normally (killed, or the connection
// closed first); `signal` then names the signal if there was one.
// Connects to the Proxmox host unless `target` overrides
// host/port/username/password.
export async function sshExec(command, target = {}) {
  const connection = new Client();
  const connectAndRun = async () => {
    await openConnection(connection, buildConnectOptions(target));
    return runCommand(connection, command);
  };
  try {
    return await withTimeout(connectAndRun(), SSH_COMMAND_TIMEOUT_MS, {
      message: "SSH timeout",
      onTimeout: () => connection.destroy(),
    });
  } finally {
    connection.end();
  }
}

// Where and how to connect: the Proxmox host by default, or the given target.
function buildConnectOptions(target) {
  return {
    host: target.host || CONFIG.ssh.host,
    port: target.port || CONFIG.ssh.port,
    username: target.username || CONFIG.ssh.username,
    readyTimeout: SSH_CONNECT_TIMEOUT_MS,
    ...chooseCredentials(target),
  };
}

// A password given for this call wins; otherwise use the configured key.
function chooseCredentials(target) {
  if (target.password) return { password: target.password };
  if (CONFIG.ssh.privateKey) return { privateKey: CONFIG.ssh.privateKey };
  return {};
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
      let stdout = "";
      let stderr = "";
      // Decode as a stream so a character split across two chunks stays intact.
      stream.setEncoding("utf8");
      stream.stderr.setEncoding("utf8");
      stream.on("data", (chunk) => (stdout += chunk));
      stream.stderr.on("data", (chunk) => (stderr += chunk));
      // Output is kept even if the command was killed, since it may explain why.
      stream.on("close", (exitCode, signal) =>
        resolve({
          stdout: stdout.trim(),
          stderr: stderr.trim(),
          code: exitCode ?? null,
          signal: signal ?? null,
        }),
      );
    });
  });
}

// Wraps a value in single quotes so the shell passes it through literally.
export function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

export function formatCommandResult(result) {
  return `Exit: ${describeExit(result)}\n${result.stdout}${result.stderr ? "\nSTDERR:\n" + result.stderr : ""}`;
}

// The exit code, or a plain statement of why there isn't one, so a killed or
// cut-off command is never mistaken for a successful run.
function describeExit({ code, signal }) {
  if (code !== null) return String(code);
  if (signal) return `none (killed by signal ${signal})`;
  return "none (connection closed before the command finished)";
}

export async function runOnHost(command) {
  return formatCommandResult(await sshExec(command));
}
