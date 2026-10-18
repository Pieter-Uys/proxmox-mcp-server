import crypto from "node:crypto";
import express from "express";
import { requireAuth } from "../auth.js";
import { handleJsonRpc } from "../jsonrpc.js";
import { SSE_KEEPALIVE_INTERVAL_MS } from "../constants.js";
import { parseBody, asyncRoute, jsonRpcErrorHandler } from "./middleware.js";
import { forLog } from "../utils.js";

// MCP transports: JSON-RPC over POST /mcp, plus SSE streams for clients that open one.
export const mcpRouter = express.Router();
const authenticate = asyncRoute(requireAuth);

// JSON-RPC endpoint: a single request or a batch (array) of them.
mcpRouter.post(
  "/mcp",
  parseBody,
  authenticate,
  asyncRoute(async (req, res) => {
    console.log("MCP POST:", forLog(req.body, 60));
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Cache-Control", "no-store");
    const response = Array.isArray(req.body)
      ? await handleBatch(req.body, req.ctx)
      : await handleJsonRpc(req.body, req.ctx);
    if (response === null) return res.status(202).end(); // a notification
    console.log("MCP response:", forLog(response, 80));
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

// Legacy SSE transport: tells the client where to POST its messages.
mcpRouter.get("/sse", authenticate, (req, res) => {
  console.log("SSE connection");
  openEventStream(req, res);
  res.write(`event: endpoint\ndata: /messages?sessionId=${crypto.randomUUID()}\n\n`);
});

mcpRouter.post(
  "/messages",
  parseBody,
  authenticate,
  asyncRoute(async (req, res) => {
    console.log("SSE message:", forLog(req.body, 60));
    const response = await handleJsonRpc(req.body, req.ctx);
    res.json(response || {});
  }),
);

mcpRouter.use(jsonRpcErrorHandler);

// Runs each request in a batch; notifications produce no entry in the reply.
async function handleBatch(rpcRequests, caller) {
  const responses = await Promise.all(
    rpcRequests.map((rpcRequest) => handleJsonRpc(rpcRequest, caller)),
  );
  return responses.filter(Boolean);
}

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
