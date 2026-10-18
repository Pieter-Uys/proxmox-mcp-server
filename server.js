#!/usr/bin/env node
import express from "express";
import { CONFIG, SECURITY } from "./src/config.js";
import { TOOL_LIST } from "./src/tools.js";
import { oauthRouter } from "./src/routes/oauth.js";
import { mcpRouter } from "./src/routes/mcp.js";
import { fallbackErrorHandler } from "./src/routes/middleware.js";

// ─── Express ─────────────────────────────────────────────────────────────────
const app = express();
app.disable("x-powered-by");

// CORS
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Accept, Authorization, Mcp-Session-Id, Last-Event-ID",
  );
  res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// Health
app.get("/health", (_, res) => res.json({ status: "ok", tools: TOOL_LIST.length }));

app.use(oauthRouter);
app.use(mcpRouter);

app.use((req, res) => res.status(404).json({ error: "not_found" }));

// Each router formats its own errors; this catches anything outside them.
app.use(fallbackErrorHandler);

app.listen(CONFIG.server.port, () => {
  console.log(`Proxmox MCP running on :${CONFIG.server.port}`);
  console.log(`Tools: ${TOOL_LIST.length}`);
  console.log(`Authentik: ${CONFIG.authentik.url}`);
  console.log(
    `Security: AUTH_MODE=${SECURITY.authMode} SHELL_MODE=${SECURITY.shellMode} AUDIT_LOG=${SECURITY.auditLog}`,
  );
});
