import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { assertSafeApiPath, proxmoxRequest } from "../src/proxmox.js";

test("assertSafeApiPath accepts the paths the tools build", () => {
  for (const path of [
    "/version",
    "/nodes/pve/qemu/100/status/current",
    "/cluster/resources?type=vm",
    "/access/users/root@pam",
    "/storage/local:iso",
    "/nodes/pve/lxc/101/firewall/rules/3",
    "/nodes/pve/storage/my.store-1/content",
  ]) {
    assert.doesNotThrow(() => assertSafeApiPath(path), path);
  }
});

test("assertSafeApiPath rejects paths that could leave /api2/json", () => {
  for (const path of [
    "",
    "nodes",
    "//evil.test/x",
    "/../etc",
    "/nodes/../../x",
    "/nodes/./x",
    "/%2e%2e/x",
    "/%2E%2E/x",
    "/nodes/a%2fb",
    "/nodes/a%5cb",
    "/nodes\\x",
    "/nodes/x#frag",
    "/nodes/x y",
    "/nodes/x\nHost: evil",
    "/nodes/%zz",
    undefined,
    42,
  ]) {
    assert.throws(() => assertSafeApiPath(path), /Invalid Proxmox API path/, String(path));
  }
});

test("proxmoxRequest refuses an unsafe path before sending anything", async () => {
  await assert.rejects(proxmoxRequest("GET", "/../x"), /Invalid Proxmox API path/);
});
