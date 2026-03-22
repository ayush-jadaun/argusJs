import type { CacheAdapter } from '@argusjs/core';

interface CacheEntry {
  value: string;
  expiresAt: number;
}

export class MemoryCacheAdapter implements CacheAdapter {
  private store = new Map<string, CacheEntry>();
  private sets = new Map<string, Set<string>>();

  async init(): Promise<void> {
    // No-op for in-memory adapter
  }

  async shutdown(): Promise<void> {
    this.store.clear();
    this.sets.clear();
  }

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() >= entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    this.store.set(key, {
      value,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  }

  async del(key: string): Promise<void> {
    this.store.delete(key);
    this.sets.delete(key);
  }

  async exists(key: string): Promise<boolean> {
    const entry = this.store.get(key);
    if (!entry) return this.sets.has(key);
    if (Date.now() >= entry.expiresAt) {
      this.store.delete(key);
      return false;
    }
    return true;
  }

  async incr(key: string, ttlSeconds: number): Promise<number> {
    const entry = this.store.get(key);

    if (!entry || Date.now() >= entry.expiresAt) {
      // Key doesn't exist or is expired — start fresh at 1
      if (entry) this.store.delete(key);
      this.store.set(key, {
        value: '1',
        expiresAt: Date.now() + ttlSeconds * 1000,
      });
      return 1;
    }

    const current = parseInt(entry.value, 10);
    const next = current + 1;
    entry.value = String(next);
    return next;
  }

  async sadd(key: string, member: string): Promise<void> {
    let set = this.sets.get(key);
    if (!set) {
      set = new Set<string>();
      this.sets.set(key, set);
    }
    set.add(member);
  }

  async sismember(key: string, member: string): Promise<boolean> {
    const set = this.sets.get(key);
    if (!set) return false;
    return set.has(member);
  }

  async smembers(key: string): Promise<string[]> {
    const set = this.sets.get(key);
    if (!set) return [];
    return Array.from(set);
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }
}
