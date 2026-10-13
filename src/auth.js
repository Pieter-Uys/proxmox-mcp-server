import crypto from "crypto";
import { CONFIG, SECURITY } from "./config.js";
import { audit } from "./audit.js";
import { AUTHENTIK, OAUTH_SCOPES, authentikFetch } from "./authentik.js";
import {
  TOKEN_CACHE_TTL_MS,
  MAX_CACHED_TOKENS,
  JWT_CLOCK_SKEW_SECONDS,
  JWKS_TTL_MS,
  JWKS_MIN_REFETCH_MS,
} from "./constants.js";
import { singleFlight } from "./utils.js";

// ─── Express middleware ─────────────────────────────────────────────────────
// Verifies the bearer token and sets req.ctx = { ip, user }. What happens to a
// bad token depends on AUTH_MODE: enforce rejects it, log lets it through.
export async function requireAuth(req, res, next) {
  const ip = req.headers["cf-connecting-ip"] || req.ip;
  req.ctx = { ip, user: "anonymous" };
  if (SECURITY.authMode === "off") return next();

  const authResult = await verifyBearerToken(req);
  auditAuthResult(req, ip, authResult);
  if (authResult.ok) {
    req.ctx.user = authResult.user;
    return next();
  }
  if (SECURITY.authMode === "log") {
    console.warn("AUTH (log-only) would reject:", authResult.reason);
    req.ctx.user = "unverified";
    return next();
  }
  rejectUnauthorized(res, authResult.reason);
}

// Logs every failure, and successes only when freshly verified (not cache hits).
function auditAuthResult(req, ip, authResult) {
  const requestInfo = { ip, path: req.path, mode: SECURITY.authMode };
  if (authResult.ok) {
    // `scope` shows what the client was granted, e.g. whether offline_access
    // (refresh tokens) is in effect. Not recorded for opaque tokens.
    if (!authResult.cached)
      audit({ event: "auth_ok", user: authResult.user, scope: authResult.scope, ...requestInfo });
    return;
  }
  audit({
    event: "auth_fail",
    reason: authResult.reason,
    detail: authResult.detail,
    shape: authResult.tokenShape,
    ...requestInfo,
  });
}

function rejectUnauthorized(res, reason) {
  res.setHeader(
    "WWW-Authenticate",
    // `scope` tells the client which scopes to request (MCP clients check this first).
    `Bearer resource_metadata="${CONFIG.server.baseUrl}/.well-known/oauth-protected-resource", scope="${OAUTH_SCOPES.join(" ")}"`,
  );
  res.status(401).json({ error: "unauthorized", error_description: reason });
}

// ─── Bearer token verification ──────────────────────────────────────────────
// Returns { ok: true, user, cached, scope? } or { ok: false, reason, detail?, tokenShape? }.
async function verifyBearerToken(req) {
  const token = readBearerToken(req);
  if (!token) return { ok: false, reason: "missing bearer token" };
  const cachedUser = getCachedUser(token);
  if (cachedUser !== undefined) return { ok: true, user: cachedUser, cached: true };
  try {
    const verification = looksLikeJwt(token)
      ? await verifyJwt(token)
      : await verifyOpaqueToken(token);
    if (!verification.ok) return verification;
    cacheVerifiedUser(token, verification);
    return { ok: true, user: verification.user, scope: verification.scope, cached: false };
  } catch (error) {
    // Keep internal details (e.g. JWKS fetch failures) out of the 401 response.
    console.error("Token verification error:", error);
    return { ok: false, reason: "token verification failed", detail: error.message };
  }
}

function readBearerToken(req) {
  const match = (req.headers.authorization || "").match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

const looksLikeJwt = (token) => token.split(".").length === 3;

function usernameFromClaims(claims) {
  return claims.preferred_username || claims.email || claims.sub || "unknown";
}

// ─── Verified-token cache ───────────────────────────────────────────────────
const verifiedTokenCache = new Map(); // sha256(token) -> { user, expiresAt }
const cacheKeyFor = (token) => crypto.createHash("sha256").update(token).digest("hex");

function getCachedUser(token) {
  const entry = verifiedTokenCache.get(cacheKeyFor(token));
  return entry && entry.expiresAt > Date.now() ? entry.user : undefined;
}

// Caps the lifetime so long-lived JWTs are still re-verified periodically.
function cacheVerifiedUser(token, verification) {
  if (verifiedTokenCache.size > MAX_CACHED_TOKENS) verifiedTokenCache.clear();
  verifiedTokenCache.set(cacheKeyFor(token), {
    user: verification.user,
    expiresAt: Math.min(verification.expiresAt, Date.now() + TOKEN_CACHE_TTL_MS),
  });
}

// ─── Opaque tokens: only Authentik can check them ───────────────────────────
async function verifyOpaqueToken(token) {
  const response = await authentikFetch(AUTHENTIK.userinfoUrl, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok)
    return { ok: false, reason: `opaque token, userinfo returned ${response.status}` };
  return {
    ok: true,
    user: usernameFromClaims(await response.json()),
    expiresAt: Date.now() + TOKEN_CACHE_TTL_MS,
  };
}

// ─── JWTs: verified locally against Authentik's signing keys ────────────────
async function verifyJwt(token) {
  const jwt = decodeJwt(token);
  if (!jwt) return { ok: false, reason: "malformed JWT" };
  const tokenShape = summarizeToken(jwt);
  const failure = (await checkSignature(jwt)) || checkClaims(jwt.claims);
  if (failure) return { ok: false, reason: failure, tokenShape };
  return {
    ok: true,
    user: usernameFromClaims(jwt.claims),
    scope: jwt.claims.scope,
    expiresAt: jwt.claims.exp * 1000,
  };
}

// Splits and decodes a JWT, or returns null if it isn't well-formed.
function decodeJwt(token) {
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  try {
    return {
      header: decodeBase64UrlJson(encodedHeader),
      claims: decodeBase64UrlJson(encodedPayload),
      signedPart: `${encodedHeader}.${encodedPayload}`,
      signature: Buffer.from(encodedSignature, "base64url"),
    };
  } catch {
    return null;
  }
}

function decodeBase64UrlJson(segment) {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}

// Non-secret claims recorded in the audit log to help diagnose rejected tokens.
function summarizeToken({ header, claims }) {
  return { alg: header.alg, iss: claims.iss, aud: claims.aud, scope: claims.scope, exp: claims.exp };
}

// Returns why the signature can't be trusted, or null if it's valid.
async function checkSignature({ header, signedPart, signature }) {
  if (header.alg !== "RS256") return `unsupported alg ${header.alg}`;
  const publicKey = await getSigningKey(header.kid);
  if (!publicKey) return "unknown signing key";
  const valid = crypto.verify("RSA-SHA256", Buffer.from(signedPart), publicKey, signature);
  return valid ? null : "bad signature";
}

// Checked in order; the first rule that fails is the reason reported.
const CLAIM_RULES = [
  { reason: "wrong issuer", fails: (claims) => claims.iss !== AUTHENTIK.issuer },
  {
    reason: "token expired",
    fails: (claims, nowSeconds) =>
      typeof claims.exp !== "number" || claims.exp < nowSeconds - JWT_CLOCK_SKEW_SECONDS,
  },
  {
    reason: "token not yet valid",
    fails: (claims, nowSeconds) =>
      typeof claims.nbf === "number" && claims.nbf > nowSeconds + JWT_CLOCK_SKEW_SECONDS,
  },
];

function checkClaims(claims) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  return CLAIM_RULES.find((rule) => rule.fails(claims, nowSeconds))?.reason ?? null;
}

// ─── Authentik signing keys (JWKS) ──────────────────────────────────────────
/** @type {{ keysById: Map<string, import("crypto").KeyObject>, fetchedAt: number }} */
const jwks = { keysById: new Map(), fetchedAt: 0 };

async function getSigningKey(keyId) {
  if (shouldRefreshJwks(keyId)) await refreshJwks();
  return jwks.keysById.get(keyId);
}

// Refresh hourly, or sooner for an unknown key id (at most every JWKS_MIN_REFETCH_MS).
function shouldRefreshJwks(keyId) {
  const ageMs = Date.now() - jwks.fetchedAt;
  return ageMs > JWKS_TTL_MS || (!jwks.keysById.has(keyId) && ageMs > JWKS_MIN_REFETCH_MS);
}

// Concurrent requests that all need fresh keys share a single fetch.
const refreshJwks = singleFlight(async () => {
  const response = await authentikFetch(AUTHENTIK.jwksUrl);
  if (!response.ok) throw new Error(`jwks fetch ${response.status}`);
  const { keys = [] } = await response.json();
  jwks.keysById = new Map(
    keys.map((jwk) => [jwk.kid, crypto.createPublicKey({ key: jwk, format: "jwk" })]),
  );
  jwks.fetchedAt = Date.now();
});
