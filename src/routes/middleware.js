import express from "express";
import { rpcError, RPC_ERROR_CODES } from "../rpc.js";
import { forLog } from "../utils.js";

// Request body parsing, applied per route so that a malformed body is reported
// by the error handler of the router that received it.
export const parseBody = [express.json(), express.urlencoded({ extended: true })];

// Passes errors from async handlers to the router's error handler. Express 5
// does this itself; the wrapper is kept so the handlers don't depend on it.
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
    const status = errorStatus(error);
    const isClientError = status >= 400 && status < 500;
    // A JSON parse error quotes part of the body, which can hold secrets.
    const summary = error.type === "entity.parse.failed" ? "malformed JSON body" : error.message;
    if (isClientError) console.warn(`Rejected request to ${forLog(req.path)}: ${forLog(summary)}`);
    else console.error(`Unhandled error on ${forLog(req.path)}:`, error);
    res.status(status).json(formatBody(error, isClientError));
  };
}

// The HTTP status an error asks for, or 500. Express 5's res.status() throws
// on anything but an integer from 100 to 999, and a status outside 4xx/5xx
// would not be an error response, so only those are passed through.
function errorStatus(error) {
  const status = error.status ?? error.statusCode;
  return Number.isInteger(status) && status >= 400 && status <= 599 ? status : 500;
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
