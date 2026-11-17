"use strict";

const buckets = new Map();

export function checkRateLimit(key, { limit = 120, windowMs = 60_000 } = {}) {
  const now = Date.now();
  let bucket = buckets.get(key);

  if (!bucket || now >= bucket.resetAt) {
    bucket = {
      count: 0,
      resetAt: now + windowMs
    };
  }

  bucket.count += 1;
  buckets.set(key, bucket);

  // Periodic cleanup to prevent unbounded memory growth
  if (buckets.size > 5000) {
    for (const [k, v] of buckets.entries()) {
      if (now >= v.resetAt) {
        buckets.delete(k);
      }
    }
  }

  const remaining = Math.max(0, limit - bucket.count);
  return {
    allowed: bucket.count <= limit,
    limit,
    remaining,
    resetAt: Math.ceil(bucket.resetAt / 1000)
  };
}

export function rateLimitHeaders(result) {
  return {
    "X-RateLimit-Limit": String(result.limit),
    "X-RateLimit-Remaining": String(result.remaining),
    "X-RateLimit-Reset": String(result.resetAt)
  };
}
