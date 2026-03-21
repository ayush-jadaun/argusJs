// Profile 2: Balanced (Recommended for most apps)
// Best for: SaaS, e-commerce, social platforms
// Refresh p50: ~12ms | Login p50: ~120ms | Registration p50: ~500ms

import { Argus } from '@argus/core';
import { PostgresAdapter } from '@argus/db-postgres';
import { RedisCacheAdapter } from '@argus/cache-redis';
import { Argon2Hasher } from '@argus/hash-argon2';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { MemoryEmailProvider } from '@argus/email-memory';

async function main() {
  const argus = new Argus({
    db: new PostgresAdapter({ connectionString: process.env.DATABASE_URL! }),
    cache: new RedisCacheAdapter({ url: process.env.REDIS_URL! }),

    // Argon2 at OWASP minimum — still GPU-resistant, 3x faster
    hasher: new Argon2Hasher({
      memoryCost: 19456,  // 19MB (OWASP minimum for Argon2id)
      timeCost: 2,
      parallelism: 1,
    }),

    // RS256 — keeps microservice compatibility
    token: new RS256TokenProvider({
      issuer: 'auth.myapp.com',
      audience: ['api.myapp.com'],
      accessTokenTTL: 900,   // 15 min
    }),

    email: new MemoryEmailProvider(),

    session: {
      maxPerUser: 5,
      absoluteTimeout: 2592000,          // 30 days
      rotateRefreshTokens: true,         // still rotating (security)
      cacheRefreshTokens: true,          // cache in Redis for speed
      refreshTokenCacheTTL: 10,          // 10s window — acceptable trade-off
    },

    password: { minLength: 10, maxLength: 128, historyCount: 5 },
    lockout: { maxAttempts: 10, duration: 1800, captchaThreshold: 3 },
    audit: { enabled: true, retentionDays: 730 },
  });

  await argus.init();
  console.log('Balanced profile active');
  console.log('  Argon2: 19MB, 2 iterations (OWASP minimum)');
  console.log('  Tokens: RS256 with JWKS');
  console.log('  Rotation: ON');
  console.log('  Token cache: ON (10s TTL — 10s revocation delay window)');
  console.log('  Session limit: 5 per user');

  await argus.shutdown();
}

main().catch(console.error);
