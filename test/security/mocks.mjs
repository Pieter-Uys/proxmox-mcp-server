// Instrumented mock backends for the high-yield rig.
//
// These stand in for the Proxmox host (SSH) and the Proxmox REST API. They do
// not emulate Proxmox; they RECORD exactly what the server sends, so a test can
// assert on the real command string that reached the host or the real method,
// path and body that reached the API. That recorded traffic is the oracle: a
// crafted tool call that produces `zfs destroy` or `/etc/shadow` on a backend
// is a proven bypass, with no real host involved.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import ssh2 from "ssh2";

const { Server: SshServer } = ssh2;

// Generates a throwaway self-signed cert for 127.0.0.1 once, under a temp dir,
// so the rig needs no pre-made files. PROXMOX_CA_CERT points at the cert, so
// the server trusts this and only this certificate for the mock API.
export function ensureCert() {
  const dir = path.join(os.tmpdir(), "pmcp-rig-ca");
  const cert = path.join(dir, "cert.pem");
  const key = path.join(dir, "key.pem");
  if (!fs.existsSync(cert) || !fs.existsSync(key)) {
    fs.mkdirSync(dir, { recursive: true });
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", key, "-out", cert, "-days", "2",
      "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
    ], { stdio: "ignore" });
  }
  return { cert, key };
}

// ─── Mock SSH host ──────────────────────────────────────────────────────────
// Accepts any authentication, records every exec command, returns canned
// output. `commands` is the list of exact strings the server asked it to run.
export async function startMockSsh() {
  const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const hostKey = privateKey.export({ type: "pkcs1", format: "pem" });
  const commands = [];
  const server = new SshServer({ hostKeys: [hostKey] }, (client) => {
    client.on("authentication", (ctx) => ctx.accept());
    client.on("ready", () => {
      client.on("session", (acceptSession) => {
        const session = acceptSession();
        session.on("exec", (acceptExec, _reject, info) => {
          commands.push(info.command);
          const stream = acceptExec();
          stream.write("MOCK_OUTPUT\n");
          stream.exit(0);
          stream.end();
        });
      });
    });
    client.on("error", () => {});
  });
  const port = await listen(server, 0);
  return { port, commands, close: () => new Promise((r) => server.close(r)) };
}

// ─── Mock Proxmox REST API ──────────────────────────────────────────────────
// HTTPS (proxmox.js refuses plain HTTP). Records { method, path, body } for
// every request, returns a canned Proxmox-shaped body. `cert`/`key` are the
// throwaway pair under /tmp/mockca; PROXMOX_CA_CERT must point at the cert.
export async function startMockProxmox(certPath, keyPath) {
  const requests = [];
  const server = https.createServer(
    { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) },
    (req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        requests.push({ method: req.method, path: req.url, body });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ data: { mock: true } }));
      });
    },
  );
  const port = await listen(server, 0);
  return { port, requests, close: () => new Promise((r) => server.close(r)) };
}

// ─── Mock Authentik JWKS + userinfo (for the auth-forgery suite) ─────────────
export async function startMockAuthentik() {
  const hits = [];
  const server = http.createServer((req, res) => {
    hits.push(req.url);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ keys: [] }));
  });
  const port = await listen(server, 0);
  return { port, hits, close: () => new Promise((r) => server.close(r)) };
}

function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server.address().port));
  });
}
