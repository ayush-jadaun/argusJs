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

  const argus = new Argus({
    db: db,
    cache: cache,
    hasher: new Argon2Hasher(),
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
