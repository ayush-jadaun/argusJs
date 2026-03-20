import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { MemoryRateLimiter } from '../memory-rate-limiter.js';

describe('MemoryRateLimiter', () => {
  let limiter: MemoryRateLimiter;

  beforeEach(() => {
    vi.useFakeTimers();
    limiter = new MemoryRateLimiter();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should allow requests under limit', async () => {
    const r = await limiter.check('ip:1.2.3.4', 5, 60);
    expect(r.allowed).toBe(true);
    expect(r.remaining).toBe(4);
    expect(r.limit).toBe(5);
  });

  it('should block requests over limit', async () => {
    for (let i = 0; i < 5; i++) {
      await limiter.check('ip:x', 5, 60);
    }
    const r = await limiter.check('ip:x', 5, 60);
    expect(r.allowed).toBe(false);
    expect(r.remaining).toBe(0);
    expect(r.retryAfter).toBeDefined();
  });

  it('should reset after window expires', async () => {
    for (let i = 0; i < 5; i++) {
      await limiter.check('ip:x', 5, 10);
    }
    const blocked = await limiter.check('ip:x', 5, 10);
    expect(blocked.allowed).toBe(false);

    vi.advanceTimersByTime(11000);

    const allowed = await limiter.check('ip:x', 5, 10);
    expect(allowed.allowed).toBe(true);
    expect(allowed.remaining).toBe(4);
  });

  it('should track separate keys independently', async () => {
    for (let i = 0; i < 5; i++) {
      await limiter.check('key-a', 5, 60);
    }
    const ra = await limiter.check('key-a', 5, 60);
    expect(ra.allowed).toBe(false);

    const rb = await limiter.check('key-b', 5, 60);
    expect(rb.allowed).toBe(true);
  });

  it('should reset a key', async () => {
    for (let i = 0; i < 5; i++) {
      await limiter.check('ip:x', 5, 60);
    }
    await limiter.reset('ip:x');
    const r = await limiter.check('ip:x', 5, 60);
    expect(r.allowed).toBe(true);
    expect(r.remaining).toBe(4);
  });

  it('should return correct resetAt timestamp', async () => {
    const now = Date.now();
    const r = await limiter.check('ip:x', 5, 60);
    expect(r.resetAt).toBeGreaterThanOrEqual(Math.ceil((now + 60000) / 1000));
  });
});
