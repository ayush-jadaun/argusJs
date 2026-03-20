// Increase libuv thread pool BEFORE any imports — argon2's native addon uses
// libuv threads, and the default pool size of 4 is a major bottleneck under load.
import { cpus } from 'node:os';
process.env.UV_THREADPOOL_SIZE = String(Math.max(16, cpus().length * 2));

import { createApp } from './app.js';
import { Argus } from '@argus/core';
import { PostgresAdapter } from '@argus/db-postgres';
import { RedisCacheAdapter } from '@argus/cache-redis';
import { Argon2Hasher } from '@argus/hash-argon2';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { MemoryEmailProvider } from '@argus/email-memory';
import { RedisRateLimiter } from '@argus/ratelimit-redis';

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  const redisUrl = process.env.REDIS_URL;

  if (!databaseUrl) {
    console.error('DATABASE_URL is required');
    process.exit(1);
  }

  const db = new PostgresAdapter({ connectionString: databaseUrl });
  const cache = redisUrl
    ? new RedisCacheAdapter({ url: redisUrl })
    : await (async () => {
        console.warn('No REDIS_URL — using in-memory cache (not for production)');
        const { MemoryCacheAdapter } = await import('@argus/cache-memory');
        return new MemoryCacheAdapter();
      })();

  // Use lightweight Argon2 params in dev/test for fast iteration;
  // production uses secure defaults (64MB, 3 iterations, 4 parallelism).
  const isDev = process.env.NODE_ENV !== 'production';
  const hasher = new Argon2Hasher(isDev ? {
    memoryCost: 4096,    // 4MB instead of 64MB
    timeCost: 2,         // 2 instead of 3
    parallelism: 1,      // 1 instead of 4
  } : undefined);        // production uses defaults

  const argus = new Argus({
    db: db,
    cache: cache,
    hasher,
    token: new RS256TokenProvider({
      privateKey: process.env.JWT_PRIVATE_KEY || undefined,
      issuer: process.env.JWT_ISSUER || 'argus',
      audience: process.env.JWT_AUDIENCE ? process.env.JWT_AUDIENCE.split(',') : ['argus'],
    }),
    email: new MemoryEmailProvider(), // swap with SendGrid/SES/SMTP in production
    rateLimiter: redisUrl ? new RedisRateLimiter({ url: redisUrl }) : undefined,
    password: { minLength: 8, maxLength: 128, historyCount: 5 },
    session: { maxPerUser: 5, absoluteTimeout: 2592000 },
    lockout: { maxAttempts: 10, duration: 1800, captchaThreshold: 3 },
    emailVerification: { required: true, tokenTTL: 86400 },
    audit: { enabled: true },
  });

  await argus.init();

  const app = await createApp({ argus });
  const port = parseInt(process.env.PORT || '3100', 10);
  const host = process.env.HOST || '0.0.0.0';

  await app.listen({ port, host });
  console.log(`ArgusJS server running on http://${host}:${port}`);

  const shutdown = async () => {
    console.log('Shutting down...');
    await app.close();
    await argus.shutdown();
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  console.error('Failed to start:', err);
  process.exit(1);
});
