// ─── Proxmox GETs that read more than status ───────────────────────────────
// GET calls run without confirmation, but a few return data the shell tools
// would gate: files inside a guest, cloud-init secrets, files from backups, or
// make the host probe network targets the caller names. This is a list of
// known cases, not a guarantee; the API token's role is the real limit.
//
// Each rule matches a run of path segments anywhere in the path, after
// percent-decoding, so /qemu/100/%61gent is the same as /qemu/100/agent.
// "*" matches any one segment.
const SENSITIVE_GET_RULES = [
  {
    segments: ["nodes", "*", "qemu", "*", "agent"],
    reason: "This GET reads data inside the VM through the QEMU guest agent (files, users, system details).",
  },
  {
    segments: ["nodes", "*", "qemu", "*", "cloudinit", "dump"],
    reason: "This GET returns the VM's cloud-init data, which can include password hashes and SSH keys.",
  },
  {
    segments: ["nodes", "*", "scan"],
    reason: "This GET makes the Proxmox host probe network or storage targets the caller names.",
  },
  {
    // Behind "Download from URL": the host fetches the URL to report its size
    // and type, so it can reach addresses only the host can (SSRF).
    segments: ["nodes", "*", "query-url-metadata"],
    reason: "This GET makes the Proxmox host contact the URL the caller names (it can reach addresses only the host can).",
  },
  {
    segments: ["nodes", "*", "storage", "*", "file-restore"],
    reason: "This GET lists or downloads files from inside a backup.",
  },
];

// Why this GET needs confirmation, or null for an ordinary read.
export function sensitiveGetReason(apiPath) {
  const segments = decodedSegments(apiPath);
  if (segments === null)
    return "This GET path can't be checked (malformed % escape).";
  const rule = SENSITIVE_GET_RULES.find(({ segments: pattern }) =>
    segments.some((_, start) => matchesAt(segments, start, pattern)),
  );
  return rule?.reason ?? null;
}

function decodedSegments(apiPath) {
  const [pathname] = String(apiPath).split("?");
  try {
    return pathname.split("/").filter(Boolean).map((segment) => decodeURIComponent(segment));
  } catch {
    return null;
  }
}

function matchesAt(segments, start, pattern) {
  return pattern.every((expected, offset) => {
    const actual = segments[start + offset];
    return actual !== undefined && (expected === "*" || expected === actual);
  });
}
