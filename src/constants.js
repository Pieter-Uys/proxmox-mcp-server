// ─── Tunable timeouts, TTLs and limits ─────────────────────────────────────

// SSH
export const SSH_COMMAND_TIMEOUT_MS = 60 * 1000;
export const SSH_CONNECT_TIMEOUT_MS = 15 * 1000;
// Community script installs download packages and build containers, which
// takes minutes, so they get their own limit.
export const COMMUNITY_SCRIPT_TIMEOUT_MS = 20 * 60 * 1000;
// Output kept per command, stdout and stderr together. Past it the channel is
// closed and the output cut off, so `cat /dev/zero` can't exhaust the server's
// memory. The remote command is not killed and may keep running.
export const SSH_MAX_OUTPUT_BYTES = 1024 * 1024;
// An OpenSSH host key fingerprint, as printed by `ssh-keygen -lf`.
export const HOST_KEY_FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}=?$/;

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
