// Production setup with PostgreSQL + Redis + full Argon2
import { Argus } from '@argus/core';
import { PostgresAdapter } from '@argus/db-postgres';
import { RedisCacheAdapter } from '@argus/cache-redis';
import { Argon2Hasher } from '@argus/hash-argon2';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { SendGridEmailProvider } from '@argus/email-sendgrid';
import { RedisRateLimiter } from '@argus/ratelimit-redis';

async function main() {
  const argus = new Argus({
    db: new PostgresAdapter({
      connectionString: process.env.DATABASE_URL!,
      max: 20,
      idleTimeout: 30,
      connectTimeout: 10,
    }),
    cache: new RedisCacheAdapter({ url: process.env.REDIS_URL! }),
    hasher: new Argon2Hasher(), // production defaults: 64MB, 3 iterations
    token: new RS256TokenProvider({
      privateKey: process.env.JWT_PRIVATE_KEY!,
      keyId: 'prod-key-2026',
      issuer: 'auth.myplatform.com',
      audience: ['api.myplatform.com'],
      accessTokenTTL: 900,
      mfaTokenTTL: 300,
    }),
    email: new SendGridEmailProvider({
      apiKey: process.env.SENDGRID_API_KEY!,
      from: 'noreply@myplatform.com',
    }),
    rateLimiter: new RedisRateLimiter({ url: process.env.REDIS_URL! }),
    password: {
      minLength: 10,
      maxLength: 128,
      historyCount: 5,
    },
    session: {
      maxPerUser: 5,
      absoluteTimeout: 2592000, // 30 days
      inactivityTimeout: 86400, // 24 hours
    },
    lockout: {
      maxAttempts: 10,
      duration: 1800, // 30 min
      captchaThreshold: 3,
    },
    emailVerification: { required: true, tokenTTL: 86400 },
    audit: { enabled: true, retentionDays: 730 },
  });

  await argus.init();
  console.log('ArgusJS initialized with PostgreSQL + Redis');

  // Example: register, login, refresh
  const reg = await argus.register({
    email: 'user@example.com',
    password: 'MySecurePassword!123',
    displayName: 'New User',
    ipAddress: '1.2.3.4',
    userAgent: 'Mozilla/5.0',
  });
  console.log('User registered:', reg.user.id);

  await argus.shutdown();
}

main().catch(console.error);
