import "./env.js";
import test from "node:test";
import assert from "node:assert/strict";
import { ipVersion, parseCidrList, cidrListIncludes } from "../src/cidr.js";

test("ipVersion accepts literal IPv4 and IPv6 addresses only", () => {
  assert.equal(ipVersion("10.0.0.5"), 4);
  assert.equal(ipVersion("192.168.1.254"), 4);
  assert.equal(ipVersion("fd00::5"), 6);
  assert.equal(ipVersion("::ffff:10.0.0.5"), 6);
  for (const value of [
    "example.com",
    "vm1",
    "localhost",
    "10.0.0.5 ",
    " 10.0.0.5",
    "010.0.0.5",
    "10.0.0",
    "10.0.0.256",
    "10.0.0.5:22",
    "fe80::1%eth0",
    "",
    undefined,
    42,
  ]) {
    assert.equal(ipVersion(value), 0, JSON.stringify(value));
  }
});

test("parseCidrList matches addresses inside the listed ranges", () => {
  const list = parseCidrList("192.168.0.0/16, 10.0.0.0/8,fd00::/8, 172.16.5.9");
  for (const ip of ["192.168.1.10", "10.255.0.1", "fd12::1", "172.16.5.9", "::ffff:10.0.0.5"]) {
    assert.equal(cidrListIncludes(list, ip), true, ip);
  }
  for (const ip of ["192.169.0.1", "11.0.0.1", "172.16.5.10", "8.8.8.8", "fe80::1", "::1", "127.0.0.1"]) {
    assert.equal(cidrListIncludes(list, ip), false, ip);
  }
});

test("parseCidrList refuses malformed entries instead of skipping them", () => {
  for (const text of [
    "",
    " , ",
    "10.0.0.0/33",
    "fd00::/129",
    "10.0.0.0/",
    "10.0.0.0/8/8",
    "10.0.0.0/x",
    "10.0.0.0/-1",
    "example.com/24",
    "10.0.0/8",
    "192.168.0.0/16,bogus",
  ]) {
    assert.throws(() => parseCidrList(text), JSON.stringify(text));
  }
});
