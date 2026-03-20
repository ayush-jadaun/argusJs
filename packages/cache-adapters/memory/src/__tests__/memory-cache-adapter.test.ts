import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { MemoryCacheAdapter } from '../memory-cache-adapter.js';

describe('MemoryCacheAdapter', () => {
  let cache: MemoryCacheAdapter;

  beforeEach(() => {
    vi.useFakeTimers();
    cache = new MemoryCacheAdapter();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should get and set values', async () => {
    await cache.set('key1', 'value1', 60);
    expect(await cache.get('key1')).toBe('value1');
  });

  it('should return null for missing keys', async () => {
    expect(await cache.get('missing')).toBeNull();
  });

  it('should delete keys', async () => {
    await cache.set('key1', 'value1', 60);
    await cache.del('key1');
    expect(await cache.get('key1')).toBeNull();
  });

  it('should check existence', async () => {
    await cache.set('key1', 'value1', 60);
    expect(await cache.exists('key1')).toBe(true);
    expect(await cache.exists('missing')).toBe(false);
  });

  it('should expire keys after TTL', async () => {
    await cache.set('key1', 'value1', 10);
    expect(await cache.get('key1')).toBe('value1');
    vi.advanceTimersByTime(11000);
    expect(await cache.get('key1')).toBeNull();
  });

  it('should increment atomically', async () => {
    const v1 = await cache.incr('counter', 60);
    expect(v1).toBe(1);
    const v2 = await cache.incr('counter', 60);
    expect(v2).toBe(2);
    const v3 = await cache.incr('counter', 60);
    expect(v3).toBe(3);
  });

  it('should expire incremented keys', async () => {
    await cache.incr('counter', 5);
    vi.advanceTimersByTime(6000);
    const v = await cache.incr('counter', 5);
    expect(v).toBe(1); // reset after expiry
  });

  it('should add to sets', async () => {
    await cache.sadd('myset', 'a');
    await cache.sadd('myset', 'b');
    await cache.sadd('myset', 'a'); // duplicate
    const members = await cache.smembers('myset');
    expect(members.sort()).toEqual(['a', 'b']);
  });

  it('should check set membership', async () => {
    await cache.sadd('myset', 'a');
    expect(await cache.sismember('myset', 'a')).toBe(true);
    expect(await cache.sismember('myset', 'b')).toBe(false);
  });

  it('should return empty array for non-existent set', async () => {
    expect(await cache.smembers('missing')).toEqual([]);
  });

  it('should return false for sismember on non-existent set', async () => {
    expect(await cache.sismember('missing', 'a')).toBe(false);
  });

  it('should pass health check', async () => {
    expect(await cache.healthCheck()).toBe(true);
  });

  it('should handle init and shutdown', async () => {
    await expect(cache.init()).resolves.toBeUndefined();
    await expect(cache.shutdown()).resolves.toBeUndefined();
  });
});
