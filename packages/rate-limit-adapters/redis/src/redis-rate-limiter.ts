import { Redis } from 'ioredis';
import type { RateLimiter, RateLimitResult } from '@argus/core';

export interface RedisRateLimiterConfig {
  url?: string;
  host?: string;
  port?: number;
  password?: string;
  keyPrefix?: string;
  maxRetriesPerRequest?: number;
  connectTimeout?: number;
}

const LUA_SCRIPT = `
  local key = KEYS[1]
  local now = tonumber(ARGV[1])
  local window_start = tonumber(ARGV[2])
  local limit = tonumber(ARGV[3])
  local window_seconds = tonumber(ARGV[4])

  redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
  local count = redis.call('ZCARD', key)

  if count < limit then
    redis.call('ZADD', key, now, now .. ':' .. math.random(1000000))
    redis.call('EXPIRE', key, window_seconds)
    return {1, limit - count - 1}
  else
    return {0, 0}
  end
`;

export class RedisRateLimiter implements RateLimiter {
  private client: Redis;
  private prefix: string;

  constructor(config: RedisRateLimiterConfig) {
    this.prefix = config.keyPrefix ?? 'argus:rl:';
    const commonOpts = {
      lazyConnect: true,
      maxRetriesPerRequest: config.maxRetriesPerRequest ?? 3,
      connectTimeout: config.connectTimeout ?? 5000,
    };
    if (config.url) {
      this.client = new Redis(config.url, commonOpts);
    } else {
      this.client = new Redis({
        host: config.host ?? 'localhost',
        port: config.port ?? 6379,
        password: config.password,
        ...commonOpts,
      });
    }
  }

  async init(): Promise<void> {
    await this.client.connect();
    await this.client.ping();
  }
  async shutdown(): Promise<void> { await this.client.quit(); }

  async check(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = now - windowSeconds * 1000;
    const resetAt = Math.ceil((now + windowSeconds * 1000) / 1000);

    const result = await this.client.eval(
      LUA_SCRIPT, 1, this.prefix + key,
      now, windowStart, limit, windowSeconds,
    ) as [number, number];

    const allowed = result[0] === 1;
    const remaining = result[1];

    return {
      allowed,
      limit,
      remaining,
      resetAt,
      retryAfter: allowed ? undefined : windowSeconds,
    };
  }

  async reset(key: string): Promise<void> {
    await this.client.del(this.prefix + key);
  }
}
