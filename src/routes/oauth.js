import express from "express";
import { CONFIG } from "../config.js";
import { AUTHENTIK, OAUTH_SCOPES, authentikFetch } from "../authentik.js";
import { parseBody, oauthErrorHandler } from "./middleware.js";

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

oauthRouter.get("/authorize", (req, res) => {
  console.log("Authorize redirect");
  res.redirect(`${AUTHENTIK.authorizeUrl}?${new URLSearchParams(req.query)}`);
});

oauthRouter.post("/token", parseBody, (req, res) =>
  proxyToAuthentik(res, "token", AUTHENTIK.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(req.body).toString(),
  }),
);

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
