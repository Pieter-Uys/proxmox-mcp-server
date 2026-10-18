import rateLimit from "express-rate-limit";

// Per-IP request limiter. Over-limit callers get HTTP 429 in the same JSON
// error shape the rest of the server uses.
export function createRateLimiter(limitPerMinute) {
  return rateLimit({
    windowMs: 60 * 1000,
    limit: limitPerMinute,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: (_req, res) => res.status(429).json({ error: "rate_limited" }),
  });
}
