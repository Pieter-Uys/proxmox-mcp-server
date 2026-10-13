// Looks up `key` in `table`, throwing a helpful error for unknown values.
export function pick(table, key, label) {
  if (!Object.hasOwn(table, key)) {
    throw new Error(
      `Unknown ${label} "${key}". Expected one of: ${Object.keys(table).join(", ")}`,
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
