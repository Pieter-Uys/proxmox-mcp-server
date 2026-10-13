// ─── Tunable timeouts, TTLs and limits ─────────────────────────────────────

// SSH
export const SSH_COMMAND_TIMEOUT_MS = 60 * 1000;
export const SSH_CONNECT_TIMEOUT_MS = 15 * 1000;

// Bearer token verification
export const TOKEN_CACHE_TTL_MS = 5 * 60 * 1000;
export const MAX_CACHED_TOKENS = 1000;
export const JWT_CLOCK_SKEW_SECONDS = 30;
export const JWKS_TTL_MS = 60 * 60 * 1000;
export const JWKS_MIN_REFETCH_MS = 30 * 1000; // throttle refetches triggered by unknown key ids

// Authentik
export const AUTHENTIK_REQUEST_TIMEOUT_MS = 10 * 1000;

// SSE
export const SSE_KEEPALIVE_INTERVAL_MS = 15 * 1000;
