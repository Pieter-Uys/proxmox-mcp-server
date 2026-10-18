// Makes a value safe to write on one log line: strings pass through, anything
// else is JSON-encoded, and line breaks and other control characters become
// spaces so request data can't forge extra log entries. Cut to `maxLength`.
export function forLog(value, maxLength = 200) {
  const text = typeof value === "string" ? value : String(JSON.stringify(value));
  return text.replaceAll(/[\p{Cc}\u2028\u2029]/gu, " ").slice(0, maxLength);
}

// Looks up `key` in `table`, throwing a helpful error for unknown values.
export function pick(table, key, label) {
  if (!Object.hasOwn(table, key)) {
    throw new Error(
      `Unknown ${label} "${forLog(key, 100)}". Expected one of: ${Object.keys(table).join(", ")}`,
    );
  }
  return table[key];
}

// Rejects with `message` if `promise` hasn't settled within `ms`. `onTimeout`
// runs first so the caller can abort the work (close a socket, cancel a request).
export async function withTimeout(promise, ms, { message = "Operation timed out", onTimeout } = {}) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      onTimeout?.();
      reject(new Error(message));
    }, ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

// Wraps an async function so concurrent callers share one in-flight run
// instead of each starting their own. The next call after it settles starts fresh.
export function singleFlight(task) {
  let inFlight = null;
  return () => {
    inFlight ??= task().finally(() => {
      inFlight = null;
    });
    return inFlight;
  };
}
