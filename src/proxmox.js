import https from "https";
import { CONFIG } from "./config.js";

// ─── Proxmox API ────────────────────────────────────────────────────────────
// Uses https.request rather than fetch: fetch ignores the `agent` option, so
// TLS settings for Proxmox would silently not apply.

// One connection pool for all Proxmox calls. With PROXMOX_CA_CERT set, Proxmox
// requests trust that certificate (and only it); otherwise the system CAs apply.
const proxmoxAgent = new https.Agent({
  keepAlive: true,
  ...(CONFIG.proxmox.caCert && { ca: CONFIG.proxmox.caCert }),
});

// Calls the Proxmox REST API and returns the response's `data`.
export async function proxmoxRequest(method, apiPath, body = null) {
  const response = await sendRequest(buildRequest(method, apiPath, body));
  if (response.status < 200 || response.status >= 300)
    throw new Error(`Proxmox ${response.status}: ${response.text}`);
  return parseProxmoxBody(response.text);
}

function buildRequest(method, apiPath, body) {
  const payload = body ? JSON.stringify(body) : null;
  return {
    url: `https://${CONFIG.proxmox.host}:${CONFIG.proxmox.port}/api2/json${apiPath}`,
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
function sendRequest({ url, options, payload }) {
  return new Promise((resolve, reject) => {
    const request = https.request(url, options, (response) => {
      let text = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => (text += chunk));
      response.on("end", () => resolve({ status: response.statusCode, text }));
      response.on("error", reject);
    });
    request.on("error", reject);
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
