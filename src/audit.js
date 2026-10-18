import fs from "node:fs";
import path from "node:path";
import { SECURITY } from "./config.js";

// ─── Audit log (JSON Lines) ─────────────────────────────────────────────────
try {
  fs.mkdirSync(path.dirname(SECURITY.auditLog), { recursive: true });
} catch (error) {
  console.warn(
    `Cannot create audit log directory: ${error.message}. Audit entries will not be written.`,
  );
}

const SECRET_FIELD_NAME = /pass(word)?|secret|token|private.?key/i;
export function redactSecrets(value) {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (value && typeof value === "object") {
    const redacted = {};
    for (const [fieldName, fieldValue] of Object.entries(value)) {
      redacted[fieldName] = SECRET_FIELD_NAME.test(fieldName)
        ? "[redacted]"
        : redactSecrets(fieldValue);
    }
    return redacted;
  }
  return value;
}
export function audit(entry) {
  try {
    fs.appendFileSync(
      SECURITY.auditLog,
      JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n",
    );
  } catch (error) {
    console.error("Audit write failed:", error.message);
  }
}
