import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { RedisCacheAdapter } from '../redis-cache-adapter.js';

describe('RedisCacheAdapter (integration)', () => {
  let cache: RedisCacheAdapter;

  beforeAll(async () => {
    cache = new RedisCacheAdapter({ host: 'localhost', port: 6381, keyPrefix: 'test:' });
    await cache.init();
  });

  afterAll(async () => {
    await cache.shutdown();
  });

  beforeEach(async () => {
    // Flush test keys — use a new adapter instance to run FLUSHDB
    const Redis = (await import('ioredis')).default;
    const client = new Redis({ host: 'localhost', port: 6381 });
    await client.flushdb();
    await client.quit();
  });

  it('should set and get values', async () => {
    await cache.set('key1', 'value1', 60);
    expect(await cache.get('key1')).toBe('value1');
  });

  it('should return null for missing keys', async () => {
    expect(await cache.get('missing')).toBeNull();
  });

  it('should delete keys', async () => {
    await cache.set('key1', 'val', 60);
    await cache.del('key1');
    expect(await cache.get('key1')).toBeNull();
  });

  it('should check existence', async () => {
    await cache.set('key1', 'val', 60);
    expect(await cache.exists('key1')).toBe(true);
    expect(await cache.exists('nope')).toBe(false);
  });

  it('should increment atomically', async () => {
    expect(await cache.incr('counter', 60)).toBe(1);
    expect(await cache.incr('counter', 60)).toBe(2);
    expect(await cache.incr('counter', 60)).toBe(3);
  });

  it('should manage sets', async () => {
    await cache.sadd('myset', 'a');
    await cache.sadd('myset', 'b');
    await cache.sadd('myset', 'a'); // dup
    expect(await cache.sismember('myset', 'a')).toBe(true);
    expect(await cache.sismember('myset', 'c')).toBe(false);
    const members = await cache.smembers('myset');
    expect(members.sort()).toEqual(['a', 'b']);
  });

  it('should pass health check', async () => {
    expect(await cache.healthCheck()).toBe(true);
  });

  it('should handle TTL expiry', async () => {
    await cache.set('expire-me', 'val', 1);
    expect(await cache.get('expire-me')).toBe('val');
    await new Promise(r => setTimeout(r, 1500));
    expect(await cache.get('expire-me')).toBeNull();
  });
});
