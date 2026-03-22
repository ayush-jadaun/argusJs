import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { RedisRateLimiter } from '../redis-rate-limiter.js';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6381';

describe('RedisRateLimiter (integration)', () => {
  let limiter: RedisRateLimiter;
  let connected = false;

  beforeAll(async () => {
    try {
      limiter = new RedisRateLimiter({ url: REDIS_URL, keyPrefix: 'test:rl:' });
      await limiter.init();
      connected = true;
    } catch (_err) {
      console.warn('Redis not available, skipping rate limiter integration tests');
    }
  }, 10000);

  afterAll(async () => {
    if (connected) await limiter.shutdown();
  });

  beforeEach(async () => {
    if (!connected) return;
    const Redis = (await import('ioredis')).default;
    const client = new Redis(REDIS_URL);
    await client.flushdb();
    await client.quit();
  });

  it('should allow requests under limit', async () => {
    if (!connected) return;
    const r = await limiter.check('ip:1', 5, 60);
    expect(r.allowed).toBe(true);
    expect(r.remaining).toBe(4);
  });

  it('should block requests over limit', async () => {
    if (!connected) return;
    for (let i = 0; i < 5; i++) {
      await limiter.check('ip:x', 5, 60);
    }
    const r = await limiter.check('ip:x', 5, 60);
    expect(r.allowed).toBe(false);
    expect(r.remaining).toBe(0);
    expect(r.retryAfter).toBe(60);
  });

  it('should track keys independently', async () => {
    if (!connected) return;
    for (let i = 0; i < 3; i++) {
      await limiter.check('key-a', 3, 60);
    }
    expect((await limiter.check('key-a', 3, 60)).allowed).toBe(false);
    expect((await limiter.check('key-b', 3, 60)).allowed).toBe(true);
  });

  it('should reset a key', async () => {
    if (!connected) return;
    for (let i = 0; i < 5; i++) {
      await limiter.check('ip:y', 5, 60);
    }
    await limiter.reset('ip:y');
    const r = await limiter.check('ip:y', 5, 60);
    expect(r.allowed).toBe(true);
  });

  it('should allow after window expires', async () => {
    if (!connected) return;
    for (let i = 0; i < 3; i++) {
      await limiter.check('ip:z', 3, 1);
    }
    expect((await limiter.check('ip:z', 3, 1)).allowed).toBe(false);
    await new Promise(r => setTimeout(r, 1500));
    expect((await limiter.check('ip:z', 3, 1)).allowed).toBe(true);
  });

  it('should return correct resetAt', async () => {
    if (!connected) return;
    const before = Math.ceil(Date.now() / 1000) + 60;
    const r = await limiter.check('ip:ts', 5, 60);
    expect(r.resetAt).toBeGreaterThanOrEqual(before - 1);
  });
});
