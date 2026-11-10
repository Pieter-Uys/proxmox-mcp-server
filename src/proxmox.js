import https from "node:https";
import { CONFIG } from "./config.js";
import { PROXMOX_REQUEST_TIMEOUT_MS, PROXMOX_MAX_RESPONSE_BYTES } from "./constants.js";

// ─── Proxmox API ────────────────────────────────────────────────────────────
// Uses https.request rather than fetch: fetch ignores the `agent` option, so
// TLS settings for Proxmox would silently not apply.

// One connection pool for all Proxmox calls. With PROXMOX_CA_CERT set, Proxmox
// requests trust that certificate (and only it); otherwise the system CAs apply.
const proxmoxAgent = new https.Agent({
  keepAlive: true,
  ...(CONFIG.proxmox.caCert && { ca: CONFIG.proxmox.caCert }),
});

// Throws unless `apiPath` stays under /api2/json once the URL is parsed. A path
// like /../x, or one with an encoded slash or dot segment, would otherwise
// reach other endpoints on the Proxmox host. Query strings are allowed.
export function assertSafeApiPath(apiPath) {
  const reject = (why) => {
    throw new Error(`Invalid Proxmox API path: ${why}`);
  };
  if (typeof apiPath !== "string" || !apiPath.startsWith("/") || apiPath.startsWith("//"))
    reject("it must start with a single /");
  if (/[\s\\#]|\p{Cc}/u.test(apiPath)) reject("it contains whitespace, a backslash, # or a control character");
  const [pathname] = apiPath.split("?");
  for (const segment of pathname.split("/")) {
    let decoded;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      return reject("it contains a malformed % escape");
    }
    if (decoded === "." || decoded === "..") reject("it contains a dot segment");
    if (/[/\\]/.test(decoded)) reject("it contains an encoded slash or backslash");
  }
}

// Calls the Proxmox REST API and returns the response's `data`.
export async function proxmoxRequest(method, apiPath, body = null) {
  assertSafeApiPath(apiPath);
  const response = await sendRequest(buildRequest(method, apiPath, body));
  if (response.status < 200 || response.status >= 300)
    throw new Error(`Proxmox ${response.status}: ${response.text}`);
  return parseProxmoxBody(response.text);
}

function buildRequest(method, apiPath, body) {
  const payload = body ? JSON.stringify(body) : null;
  const origin = `https://${CONFIG.proxmox.host}:${CONFIG.proxmox.port}`;
  const url = new URL(`/api2/json${apiPath}`, origin);
  // Defense in depth: the parsed URL must still be on the configured host and under /api2/json/.
  if (url.origin !== new URL(origin).origin || !url.pathname.startsWith("/api2/json/"))
    throw new Error("Invalid Proxmox API path: it resolves outside /api2/json");
  return {
    url,
    options: {
      method,
      agent: proxmoxAgent,
      headers: {
        Authorization: `PVEAPIToken=${CONFIG.proxmox.tokenId}=${CONFIG.proxmox.tokenSecret}`,
        "Content-Type": "application/json",
        ...(payload && { "Content-Length": Buffer.byteLength(payload) }),
      },
    },
    payload,
  };
}

// Sends the request and resolves with { status, text } once the body is read.
// The whole exchange, including a slow trickle of body bytes, must finish
// within `timeoutMs`, and the body may not exceed `maxBytes`. `request` is
// https.request; tests pass http.request to talk to a local stand-in.
export function sendRequest(
  { url, options, payload },
  { timeoutMs = PROXMOX_REQUEST_TIMEOUT_MS, maxBytes = PROXMOX_MAX_RESPONSE_BYTES, request: send = https.request } = {},
) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      request.destroy();
      reject(error);
    };
    const request = send(url, options, (response) => {
      const chunks = [];
      let bytes = 0;
      response.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > maxBytes)
          return fail(new Error(`Proxmox reply is larger than ${maxBytes} bytes. Narrow the query (a more specific path or filter) and try again.`));
        chunks.push(chunk);
      });
      response.on("end", () => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        resolve({ status: response.statusCode, text: Buffer.concat(chunks).toString("utf8") });
      });
      response.on("error", fail);
    });
    const deadline = setTimeout(
      () => fail(new Error(`Proxmox API did not answer within ${timeoutMs / 1000}s.`)),
      timeoutMs,
    );
    request.on("error", fail);
    request.end(payload ?? undefined);
  });
}

// Proxmox wraps results as { data: ... }. Non-JSON replies are returned as text.
function parseProxmoxBody(text) {
  try {
    const parsed = JSON.parse(text);
    return parsed.data !== undefined ? parsed.data : parsed;
  } catch {
    return text;
  }
}
