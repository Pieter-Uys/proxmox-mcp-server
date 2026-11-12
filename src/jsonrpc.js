import fs from "node:fs";
import { audit, redactSecrets } from "./audit.js";
import { getPolicyBlockReason } from "./policy.js";
import { rpcResult, rpcError, RPC_ERROR_CODES } from "./rpc.js";
import { TOOL_LIST, callTool, findTool } from "./tools.js";
import { validateArgs, checkRequiredWhen } from "./validate.js";
import { forLog, withTimeout } from "./utils.js";
import { SECURITY } from "./config.js";

// ─── MCP JSON-RPC handler ───────────────────────────────────────────────────
// `caller` is req.ctx from requireAuth: { ip, user }. Returns the response to
// send, or null for notifications (which get no response).
export async function handleJsonRpc(rpcRequest, caller = {}) {
  if (!rpcRequest || typeof rpcRequest !== "object" || Array.isArray(rpcRequest))
    return rpcError(null, RPC_ERROR_CODES.INVALID_REQUEST, "Invalid request");
  const { method, params, id } = rpcRequest;
  // A request without an id is a notification: JSON-RPC forbids answering
  // one, even with an error.
  const isNotification = !Object.hasOwn(rpcRequest, "id");
  console.log("RPC:", forLog(method, 60), describeRpcTarget(rpcRequest), isNotification ? "(notification)" : `id=${forLog(id, 40)}`);
  // A tool call sent as a notification would run with nobody to receive the
  // result. Nothing legitimate does that, so it is recorded and not run.
  if (isNotification && method === "tools/call") {
    audit({ event: "tool_call", user: caller.user, ip: caller.ip, tool: params?.name, outcome: "refused_notification" });
    return null;
  }
  if (!Object.hasOwn(METHODS, method))
    return isNotification
      ? null
      : rpcError(id, RPC_ERROR_CODES.METHOD_NOT_FOUND, "Method not found: " + forLog(method, 100));
  const response = await METHODS[method](id, params, caller);
  return isNotification ? null : response;
}

// The tool a tools/call names, for logs. Arguments are never logged: they can
// hold passwords and other secrets.
function describeRpcTarget({ method, params }) {
  return method === "tools/call" ? `tool=${forLog(params?.name, 60)}` : "";
}

// The version clients see, read from package.json so it has one source.
export const SERVER_VERSION = JSON.parse(
  fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"),
).version;

// Newest first. Tool annotations were introduced in 2025-03-26.
const SUPPORTED_PROTOCOL_VERSIONS = ["2025-03-26", "2024-11-05"];

// Use the client's version if we support it, otherwise our newest (the client
// then decides whether it can talk to us).
export function negotiateProtocolVersion(requested) {
  return SUPPORTED_PROTOCOL_VERSIONS.includes(requested)
    ? requested
    : SUPPORTED_PROTOCOL_VERSIONS[0];
}

const METHODS = {
  initialize: (id, params) =>
    rpcResult(id, {
      protocolVersion: negotiateProtocolVersion(params?.protocolVersion),
      capabilities: { tools: {} },
      serverInfo: { name: "proxmox-mcp", version: SERVER_VERSION },
    }),
  "notifications/initialized": () => null,
  ping: (id) => rpcResult(id, {}),
  "tools/list": (id) => rpcResult(id, { tools: TOOL_LIST }),
  "tools/call": handleToolCall,
};

// ─── tools/call ─────────────────────────────────────────────────────────────
// Validate, check policy, then run. Every outcome is audited.
async function handleToolCall(id, params, caller) {
  const toolName = params?.name;
  const args = params?.arguments || {};
  const auditToolCall = (outcomeFields) =>
    audit({
      event: "tool_call",
      user: caller.user,
      ip: caller.ip,
      tool: toolName,
      args: redactSecrets(args),
      ...outcomeFields,
    });

  // An unknown tool is a protocol error (MCP: -32602), not a tool result.
  if (!findTool(toolName)) {
    auditToolCall({ outcome: "unknown_tool" });
    return rpcError(id, RPC_ERROR_CODES.INVALID_PARAMS, `Unknown tool: ${forLog(toolName, 100)}`);
  }
  const refusal = checkToolCall(toolName, args);
  if (refusal) {
    auditToolCall({ outcome: refusal.outcome, reason: refusal.reason });
    return toolErrorResult(id, refusal.message);
  }
  return runTool(id, toolName, args, auditToolCall);
}

// Returns why the server won't run this call, or null if it may run.
function checkToolCall(toolName, args) {
  const tool = findTool(toolName);
  const toolSchema = TOOL_LIST.find((listed) => listed.name === toolName)?.inputSchema;
  const problems = toolSchema
    ? [...validateArgs(toolSchema, args), ...checkRequiredWhen(tool.requiredWhen, args)]
    : [];
  if (problems.length) {
    const reason = problems.join("; ");
    return { outcome: "invalid", reason, message: `Invalid arguments: ${reason}` };
  }
  const blockReason = getPolicyBlockReason(tool, args);
  if (blockReason) {
    return { outcome: "blocked", reason: blockReason, message: `Blocked by server policy: ${blockReason}` };
  }
  return null;
}

async function runTool(id, toolName, args, auditToolCall) {
  // Recorded before running, so a call that hangs or crashes the server still
  // leaves a trace, and a call whose record can't be written doesn't run.
  const recorded = auditToolCall({ outcome: "started" });
  if (!recorded && SECURITY.auditRequired === "true")
    return toolErrorResult(id, "Refused: the audit log can't be written (AUDIT_REQUIRED=true). Fix AUDIT_LOG on the server.");
  const startedAt = Date.now();
  try {
    const seconds = SECURITY.toolTimeoutMs / 1000;
    const result = await withTimeout(callTool(toolName, args), SECURITY.toolTimeoutMs, {
      message: `The tool call took longer than ${seconds}s (TOOL_TIMEOUT_SECONDS), so the server stopped waiting. What it started may still be running on the host; check its state before retrying.`,
    });
    auditToolCall({ outcome: "ok", ms: Date.now() - startedAt });
    return rpcResult(id, result);
  } catch (error) {
    console.error(`Tool error (${forLog(toolName)}):`, error);
    auditToolCall({ outcome: "error", error: error.message, ms: Date.now() - startedAt });
    // A tool that failed while running is a result the model should see and
    // react to; JSON-RPC errors are for protocol faults.
    return toolErrorResult(id, `Tool failed: ${error.message}`);
  }
}

// A call the server refused to run, reported to the model as a tool error.
function toolErrorResult(id, text) {
  return rpcResult(id, { isError: true, content: [{ type: "text", text }] });
}
