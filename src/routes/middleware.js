import express from "express";
import { rpcError, RPC_ERROR_CODES } from "../rpc.js";
import { forLog } from "../utils.js";

// Request body parsing, applied per route so that a malformed body is reported
// by the error handler of the router that received it.
export const parseBody = [express.json(), express.urlencoded({ extended: true })];

// Express 4 doesn't catch errors from async handlers; this passes them on to
// the router's error handler instead of leaving an unhandled rejection.
export function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

// ─── Error responses per route type ─────────────────────────────────────────
// Express passes errors it catches itself (e.g. malformed or oversized request
// bodies) to these handlers. Each logs the error and replies in the format its
// clients expect, never with a stack trace.
function createErrorHandler(formatBody) {
  return (error, req, res, next) => {
    if (res.headersSent) return next(error);
    const status = error.status || error.statusCode || 500;
    const isClientError = status >= 400 && status < 500;
    if (isClientError) console.warn(`Rejected request to ${forLog(req.path)}: ${forLog(error.message)}`);
    else console.error(`Unhandled error on ${forLog(req.path)}:`, error);
    res.status(status).json(formatBody(error, isClientError));
  };
}

// JSON-RPC 2.0 errors, for MCP clients.
export const jsonRpcErrorHandler = createErrorHandler((error, isClientError) => {
  if (error.type === "entity.parse.failed")
    return rpcError(null, RPC_ERROR_CODES.PARSE_ERROR, "Parse error");
  if (isClientError) return rpcError(null, RPC_ERROR_CODES.INVALID_REQUEST, "Invalid request");
  return rpcError(null, RPC_ERROR_CODES.INTERNAL_ERROR, "Internal error");
});

// OAuth 2.0 error responses (RFC 6749 section 5.2), for the login flow.
export const oauthErrorHandler = createErrorHandler((error, isClientError) =>
  isClientError
    ? {
        error: "invalid_request",
        error_description: error.expose ? error.message : "Invalid request",
      }
    : { error: "server_error", error_description: "Internal error" },
);

// Anything that fails outside the routers.
export const fallbackErrorHandler = createErrorHandler((error, isClientError) => ({
  error: isClientError ? "invalid_request" : "internal_error",
}));
