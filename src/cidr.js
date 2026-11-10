import net from "node:net";

// ─── IP addresses and CIDR allowlists ───────────────────────────────────────
// Built on node:net (isIP and BlockList), so no dependency is needed.

// 4 or 6 for a literal IPv4 or IPv6 address, otherwise 0. Host names are not
// addresses, and neither is an IPv6 address with a zone (fe80::1%eth0), since
// the zone picks an interface on this machine rather than naming a host.
export function ipVersion(value) {
  if (typeof value !== "string" || value.includes("%")) return 0;
  return net.isIP(value);
}

// Parses "192.168.0.0/16, 10.0.0.0/8, fd00::/8" into a BlockList. A bare
// address counts as a single host (/32 or /128). Throws on anything else, so a
// typo can't quietly widen or empty the list.
export function parseCidrList(text) {
  const entries = String(text)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (!entries.length) throw new Error("no CIDR ranges given");
  const list = new net.BlockList();
  for (const entry of entries) addCidr(list, entry);
  return list;
}

function addCidr(list, entry) {
  const [address, prefixText, extra] = entry.split("/");
  const version = ipVersion(address);
  const maxPrefix = version === 4 ? 32 : 128;
  const prefix = prefixText === undefined ? maxPrefix : Number(prefixText);
  const validPrefix = prefixText === undefined || (/^\d+$/.test(prefixText) && prefix <= maxPrefix);
  if (!version || extra !== undefined || !validPrefix)
    throw new Error(`"${entry}" is not an IPv4 or IPv6 CIDR range`);
  list.addSubnet(address, prefix, version === 4 ? "ipv4" : "ipv6");
}

// True if `ip` (already known to be an address) falls inside one of the ranges.
// An IPv4-mapped IPv6 address (::ffff:10.0.0.5) is matched against IPv4 ranges.
export function cidrListIncludes(list, ip) {
  return list.check(ip, ipVersion(ip) === 4 ? "ipv4" : "ipv6");
}
