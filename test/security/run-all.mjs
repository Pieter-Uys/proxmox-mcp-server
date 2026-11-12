// Runs every security harness as its own process and summarises the result,
// so one failure doesn't hide the others. Non-zero exit if any harness fails.
//
//   node test/security/run-all.mjs
//
// Each harness is self-contained (its own mock backends and signing keys) and
// makes no network call or real Proxmox connection.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const harnesses = [
  ["attack-pass", "curated adversarial corpus against the policy gate"],
  ["fuzz-pass", "generated inputs (metachars, option abbreviations, path obfuscation)"],
  ["backend-truth", "real tool calls vs instrumented mock SSH host and Proxmox API"],
  ["auth-forgery", "forged JWTs against the real verification path"],
  ["sudoers-match", "deploy/sudoers.proxmox-mcp vs the commands the server sends under sudo"],
];

let failed = 0;
for (const [name, blurb] of harnesses) {
  const file = path.join(here, `${name}.mjs`);
  const run = spawnSync(process.execPath, [file], { encoding: "utf8" });
  const out = (run.stdout || "") + (run.stderr || "");
  const ok = run.status === 0;
  if (!ok) failed++;
  // Keep the harness's own summary line(s), drop the server's RPC noise.
  const summary = out
    .split("\n")
    .filter((l) => l && !l.startsWith("RPC:") && !l.startsWith("Tool error") && !/^\s+at /.test(l))
    .slice(-6)
    .join("\n      ");
  console.log(`\n${ok ? "PASS" : "FAIL"}  ${name}  (${blurb})\n      ${summary}`);
}

const verdict = failed === 0 ? "All security harnesses passed." : failed + " harness(es) FAILED.";
console.log(`\n${verdict}`);
process.exit(failed === 0 ? 0 : 1);
