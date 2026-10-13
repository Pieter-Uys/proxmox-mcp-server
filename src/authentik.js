import { CONFIG } from "./config.js";
import { AUTHENTIK_REQUEST_TIMEOUT_MS } from "./constants.js";

// ─── Authentik endpoints ────────────────────────────────────────────────────
const baseUrl = CONFIG.authentik.url;
const appUrl = `${baseUrl}/application/o/${CONFIG.authentik.slug}`;

export const AUTHENTIK = {
  baseUrl,
  issuer: `${appUrl}/`,
  jwksUrl: `${appUrl}/jwks/`,
  discoveryUrl: `${appUrl}/.well-known/openid-configuration`,
  authorizeUrl: `${baseUrl}/application/o/authorize/`,
  tokenUrl: `${baseUrl}/application/o/token/`,
  userinfoUrl: `${baseUrl}/application/o/userinfo/`,
};

// Scopes MCP clients should request when logging in. `offline_access` makes
// Authentik issue a refresh token, so clients can renew an expired access
// token themselves instead of making the user sign in again.
export const OAUTH_SCOPES = ["openid", "profile", "email", "offline_access"];

// Every request to Authentik goes through here, so none can hang forever:
// a stalled Authentik would otherwise stall every login and token check.
export function authentikFetch(url, init = {}) {
  return fetch(url, { ...init, signal: AbortSignal.timeout(AUTHENTIK_REQUEST_TIMEOUT_MS) });
}
