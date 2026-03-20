import type { RateLimiter, RateLimitResult } from '@argus/core';

export class MemoryRateLimiter implements RateLimiter {
  private store: Map<string, number[]> = new Map();

  async check(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult> {
    const now = Date.now();
    const windowMs = windowSeconds * 1000;
    const windowStart = now - windowMs;

    // Get existing timestamps and filter out expired ones
    let timestamps = this.store.get(key) ?? [];
    timestamps = timestamps.filter((t) => t > windowStart);

    if (timestamps.length < limit) {
      // Allowed: add this request's timestamp
      timestamps.push(now);
      this.store.set(key, timestamps);

      return {
        allowed: true,
        limit,
        remaining: limit - timestamps.length,
        resetAt: Math.ceil((now + windowMs) / 1000),
      };
    }

    // Blocked: over limit
    this.store.set(key, timestamps);
    const oldestTimestamp = timestamps[0];
    const retryAfterMs = oldestTimestamp + windowMs - now;

    return {
      allowed: false,
      limit,
      remaining: 0,
      resetAt: Math.ceil((oldestTimestamp + windowMs) / 1000),
      retryAfter: Math.ceil(retryAfterMs / 1000),
    };
  }

  async reset(key: string): Promise<void> {
    this.store.delete(key);
  }
}
