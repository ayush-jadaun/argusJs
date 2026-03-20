import { Redis } from 'ioredis';
import type { CacheAdapter } from '@argus/core';

export interface RedisCacheConfig {
  url?: string;
  host?: string;
  port?: number;
  password?: string;
  db?: number;
  keyPrefix?: string;
}

export class RedisCacheAdapter implements CacheAdapter {
  private client: Redis;
  private prefix: string;

  constructor(config: RedisCacheConfig) {
    this.prefix = config.keyPrefix ?? 'argus:';
    if (config.url) {
      this.client = new Redis(config.url);
    } else {
      this.client = new Redis({
        host: config.host ?? 'localhost',
        port: config.port ?? 6379,
        password: config.password,
        db: config.db ?? 0,
      });
    }
  }

  private key(k: string): string { return this.prefix + k; }

  async init(): Promise<void> { await this.client.ping(); }
  async shutdown(): Promise<void> { await this.client.quit(); }

  async get(key: string): Promise<string | null> {
    return this.client.get(this.key(key));
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    await this.client.setex(this.key(key), ttlSeconds, value);
  }

  async del(key: string): Promise<void> {
    await this.client.del(this.key(key));
  }

  async exists(key: string): Promise<boolean> {
    return (await this.client.exists(this.key(key))) === 1;
  }

  async incr(key: string, ttlSeconds: number): Promise<number> {
    const k = this.key(key);
    const val = await this.client.incr(k);
    if (val === 1) {
      await this.client.expire(k, ttlSeconds);
    }
    return val;
  }

  async sadd(key: string, member: string): Promise<void> {
    await this.client.sadd(this.key(key), member);
  }

  async sismember(key: string, member: string): Promise<boolean> {
    return (await this.client.sismember(this.key(key), member)) === 1;
  }

  async smembers(key: string): Promise<string[]> {
    return this.client.smembers(this.key(key));
  }

  async healthCheck(): Promise<boolean> {
    try {
      return (await this.client.ping()) === 'PONG';
    } catch {
      return false;
    }
  }
}
