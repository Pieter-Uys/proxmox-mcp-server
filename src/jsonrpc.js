import { audit, redactSecrets } from "./audit.js";
import { getPolicyBlockReason } from "./policy.js";
import { rpcResult, rpcError, RPC_ERROR_CODES } from "./rpc.js";
import { TOOL_LIST, callTool, findTool } from "./tools.js";
import { validateArgs, checkRequiredWhen } from "./validate.js";
import { forLog } from "./utils.js";

// ─── MCP JSON-RPC handler ───────────────────────────────────────────────────
// `caller` is req.ctx from requireAuth: { ip, user }. Returns the response to
// send, or null for notifications (which get no response).
export async function handleJsonRpc(rpcRequest, caller = {}) {
  if (!rpcRequest || typeof rpcRequest !== "object" || Array.isArray(rpcRequest))
    return rpcError(null, RPC_ERROR_CODES.INVALID_REQUEST, "Invalid request");
  const { method, params, id } = rpcRequest;
  console.log("RPC:", forLog(method), forLog(id));
  if (!Object.hasOwn(METHODS, method))
    return rpcError(id, RPC_ERROR_CODES.METHOD_NOT_FOUND, "Method not found: " + method);
  return METHODS[method](id, params, caller);
}

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
      serverInfo: { name: "proxmox-mcp", version: "1.1.0" },
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
  const startedAt = Date.now();
  try {
    const result = await callTool(toolName, args);
    auditToolCall({ outcome: "ok", ms: Date.now() - startedAt });
    return rpcResult(id, result);
  } catch (error) {
    console.error(`Tool error (${toolName}):`, error);
    auditToolCall({ outcome: "error", error: error.message, ms: Date.now() - startedAt });
    return rpcError(id, RPC_ERROR_CODES.SERVER_ERROR, error.message);
  }
}

// A call the server refused to run, reported to the model as a tool error.
function toolErrorResult(id, text) {
  return rpcResult(id, { isError: true, content: [{ type: "text", text }] });
}
