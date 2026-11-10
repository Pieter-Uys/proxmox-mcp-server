import express from "express";
import { requireAuth } from "../auth.js";
import { handleJsonRpc } from "../jsonrpc.js";
import { SSE_KEEPALIVE_INTERVAL_MS } from "../constants.js";
import { parseBody, asyncRoute, jsonRpcErrorHandler } from "./middleware.js";
import { rpcError, RPC_ERROR_CODES } from "../rpc.js";
import { forLog } from "../utils.js";

// MCP Streamable HTTP transport: JSON-RPC over POST /mcp, plus a keepalive
// stream for clients that open GET /mcp. The legacy /sse and /messages routes
// were removed: they never tracked a session or replied on the stream.
export const mcpRouter = express.Router();
const authenticate = asyncRoute(requireAuth);

// JSON-RPC endpoint: one request per POST. Batches (a JSON array) were
// dropped from MCP in revision 2025-06-18, and here would let one HTTP request
// fan out into many tool calls (each its own SSH session) while counting once
// against the rate limiter, so they are refused.
mcpRouter.post(
  "/mcp",
  parseBody,
  authenticate,
  asyncRoute(async (req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Cache-Control", "no-store");
    if (Array.isArray(req.body)) {
      console.log("MCP POST: batch refused");
      return res
        .status(400)
        .json(rpcError(null, RPC_ERROR_CODES.INVALID_REQUEST, "Batch requests are not supported; send one request per POST"));
    }
    const response = await handleJsonRpc(req.body, req.ctx);
    if (response === null) return res.status(202).end(); // a notification
    // Only the outcome is logged, never result text, which can carry command output.
    console.log("MCP response:", `id=${forLog(response.id, 40)}`, response.error ? `error=${response.error.code}` : "ok");
    res.json(response);
  }),
);

// GET /mcp: a keepalive-only stream for clients that open one.
mcpRouter.get("/mcp", authenticate, (req, res) => {
  console.log("MCP GET (SSE stream)");
  openEventStream(req, res);
  res.write(": keepalive\n\n");
});

mcpRouter.delete("/mcp", (_, res) => res.status(204).end());

mcpRouter.use(jsonRpcErrorHandler);

// Starts a Server-Sent Events stream and keeps it alive until the client leaves.
function openEventStream(req, res) {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");
  const keepaliveTimer = setInterval(
    () => res.write(": keepalive\n\n"),
    SSE_KEEPALIVE_INTERVAL_MS,
  );
  req.on("close", () => clearInterval(keepaliveTimer));
}
