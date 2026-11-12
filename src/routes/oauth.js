import express from "express";
import { CONFIG } from "../config.js";
import { AUTHENTIK, OAUTH_SCOPES, authentikFetch } from "../authentik.js";
import { oauthErrorHandler } from "./middleware.js";

// OAuth discovery and a thin proxy to Authentik, so MCP clients can log in via this server.
export const oauthRouter = express.Router();

// Tells MCP clients which authorization server to log in with.
oauthRouter.get("/.well-known/oauth-protected-resource", (_, res) =>
  res.json({
    resource: CONFIG.server.baseUrl,
    authorization_servers: [AUTHENTIK.baseUrl],
    scopes_supported: OAUTH_SCOPES,
  }),
);

oauthRouter.get("/.well-known/oauth-authorization-server", (_, res) =>
  proxyToAuthentik(res, "discovery", AUTHENTIK.discoveryUrl),
);

// Both proxies forward what the client sent, byte for byte. Rebuilding it
// from the parsed form would change it: a repeated parameter (RFC 8707 lets
// resource repeat) was joined with commas, and a[b]=c became [object Object].
oauthRouter.get("/authorize", (req, res) => {
  console.log("Authorize redirect");
  res.redirect(`${AUTHENTIK.authorizeUrl}?${rawQuery(req)}`);
});

// Token requests are form-encoded (RFC 6749 section 4.1.3). The body is read
// raw, so anything else arrives unparsed and is refused.
const rawForm = express.raw({ type: "application/x-www-form-urlencoded" });

oauthRouter.post("/token", rawForm, (req, res) => {
  if (!Buffer.isBuffer(req.body))
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Token requests must be application/x-www-form-urlencoded",
    });
  return proxyToAuthentik(res, "token", AUTHENTIK.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: req.body, // the raw bytes: decoding could replace invalid UTF-8
  });
});

// The query string as the client sent it, without the leading "?".
function rawQuery(req) {
  const start = req.originalUrl.indexOf("?");
  return start === -1 ? "" : req.originalUrl.slice(start + 1);
}

oauthRouter.use(oauthErrorHandler);

// Forwards a request to Authentik and relays its status and JSON body.
// Failures (unreachable, timed out, non-JSON reply) become an OAuth 502.
async function proxyToAuthentik(res, label, url, init) {
  try {
    const response = await authentikFetch(url, init);
    const body = await response.json();
    console.log(`Authentik ${label}:`, response.status);
    res.status(response.status).json(body);
  } catch (error) {
    console.error(`Authentik ${label} request failed:`, error.message);
    res
      .status(502)
      .json({ error: "server_error", error_description: "Authentik request failed" });
  }
}
