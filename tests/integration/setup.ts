import { Argus } from '@argus/core';
import { PostgresAdapter } from '@argus/db-postgres';
import { RedisCacheAdapter } from '@argus/cache-redis';
import { Argon2Hasher } from '@argus/hash-argon2';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { MemoryEmailProvider } from '@argus/email-memory';
import { MemoryRateLimiter } from '@argus/ratelimit-memory';

export async function createIntegrationArgus() {
  const db = new PostgresAdapter({
    connectionString: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5434/postgres',
  });
  const cache = new RedisCacheAdapter({
    url: process.env.REDIS_URL || 'redis://localhost:6381',
  });
  const email = new MemoryEmailProvider();

  const argus = new Argus({
    db,
    cache,
    hasher: new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 }), // fast for tests (timeCost min is 2)
    token: new RS256TokenProvider({ issuer: 'test', audience: ['test'] }),
    email,
    rateLimiter: new MemoryRateLimiter(),
    password: { minLength: 8, maxLength: 128, historyCount: 5 },
    session: { maxPerUser: 5, absoluteTimeout: 86400 },
    lockout: { maxAttempts: 5, duration: 60, captchaThreshold: 3 },
    emailVerification: { required: true, tokenTTL: 86400 },
    audit: { enabled: true },
  });

  await argus.init();

  // Clean tables
  if ('truncateAll' in db) {
    await (db as any).truncateAll();
  }

  return { argus, db, cache, email };
}
