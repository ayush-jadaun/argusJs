import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { RedisCacheAdapter } from '../redis-cache-adapter.js';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6381';

describe('RedisCacheAdapter (integration)', () => {
  let cache: RedisCacheAdapter;
  let connected = false;

  beforeAll(async () => {
    try {
      cache = new RedisCacheAdapter({ url: REDIS_URL, keyPrefix: 'test:' });
      await cache.init();
      connected = true;
    } catch (_err) {
      console.warn('Redis not available, skipping integration tests');
    }
  }, 10000);

  afterAll(async () => {
    if (connected) await cache.shutdown();
  });

  beforeEach(async () => {
    if (!connected) return;
    const Redis = (await import('ioredis')).default;
    const client = new Redis(REDIS_URL);
    await client.flushdb();
    await client.quit();
  });

  it('should set and get values', async () => {
    if (!connected) return;
    await cache.set('key1', 'value1', 60);
    expect(await cache.get('key1')).toBe('value1');
  });

  it('should return null for missing keys', async () => {
    if (!connected) return;
    expect(await cache.get('missing')).toBeNull();
  });

  it('should delete keys', async () => {
    if (!connected) return;
    await cache.set('key1', 'val', 60);
    await cache.del('key1');
    expect(await cache.get('key1')).toBeNull();
  });

  it('should check existence', async () => {
    if (!connected) return;
    await cache.set('key1', 'val', 60);
    expect(await cache.exists('key1')).toBe(true);
    expect(await cache.exists('nope')).toBe(false);
  });

  it('should increment atomically', async () => {
    if (!connected) return;
    expect(await cache.incr('counter', 60)).toBe(1);
    expect(await cache.incr('counter', 60)).toBe(2);
    expect(await cache.incr('counter', 60)).toBe(3);
  });

  it('should manage sets', async () => {
    if (!connected) return;
    await cache.sadd('myset', 'a');
    await cache.sadd('myset', 'b');
    await cache.sadd('myset', 'a'); // dup
    expect(await cache.sismember('myset', 'a')).toBe(true);
    expect(await cache.sismember('myset', 'c')).toBe(false);
    const members = await cache.smembers('myset');
    expect(members.sort()).toEqual(['a', 'b']);
  });

  it('should pass health check', async () => {
    if (!connected) return;
    expect(await cache.healthCheck()).toBe(true);
  });

  it('should handle TTL expiry', async () => {
    if (!connected) return;
    await cache.set('expire-me', 'val', 1);
    expect(await cache.get('expire-me')).toBe('val');
    await new Promise(r => setTimeout(r, 1500));
    expect(await cache.get('expire-me')).toBeNull();
  });
});
