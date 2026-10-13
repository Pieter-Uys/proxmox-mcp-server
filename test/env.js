// Imported first by every test file. src/config.js refuses to start without
// these settings, so provide throwaway values before any src/ module loads.
// They are assigned unconditionally so a test run can never pick up real
// infrastructure settings from the developer's shell.
import os from "os";
import path from "path";

Object.assign(process.env, {
  PROXMOX_HOST: "pve.test",
  PROXMOX_TOKEN_ID: "test@pam!test",
  PROXMOX_TOKEN_SECRET: "test-secret",
  PROXMOX_SSH_HOST: "pve.test",
  MCP_BASE_URL: "https://mcp.test",
  AUTHENTIK_URL: "https://auth.test",
  AUDIT_LOG: path.join(os.tmpdir(), "proxmox-mcp-test", "audit.jsonl"),
});

// Start every file from the default (secure) modes.
delete process.env.AUTH_MODE;
delete process.env.SHELL_MODE;
delete process.env.PROXMOX_CA_CERT;
delete process.env.PROXMOX_SSH_KEY;
