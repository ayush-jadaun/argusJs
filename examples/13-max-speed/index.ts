// Profile 3: Maximum Speed
// Best for: Internal tools, MVPs, prototypes, monoliths
// Refresh p50: ~5ms | Login p50: ~80ms | Registration p50: ~125ms

import { Argus } from '@argusjs/core';
import { PostgresAdapter } from '@argusjs/db-postgres';
import { RedisCacheAdapter } from '@argusjs/cache-redis';
import { Argon2Hasher } from '@argusjs/hash-argon2';
import { HS256TokenProvider } from '@argusjs/token-jwt-hs256';
import { MemoryEmailProvider } from '@argusjs/email-memory';

async function main() {
  const argus = new Argus({
    db: new PostgresAdapter({ connectionString: process.env.DATABASE_URL! }),
    cache: new RedisCacheAdapter({ url: process.env.REDIS_URL! }),

    // Argon2 with light params — still better than bcrypt
    hasher: new Argon2Hasher({
      memoryCost: 4096,   // 4MB
      timeCost: 2,
      parallelism: 1,
    }),

    // HS256 — symmetric, fastest signing (~0.1ms vs RS256's ~5ms)
    // WARNING: No JWKS endpoint. All services need the shared secret.
    token: new HS256TokenProvider({
      secret: process.env.JWT_SECRET || 'change-me-to-a-real-secret-at-least-32-chars-long!!',
      issuer: 'myapp',
      audience: ['myapp'],
      accessTokenTTL: 3600,   // 1 hour (longer = fewer refreshes needed)
    }),

    email: new MemoryEmailProvider(),

    session: {
      maxPerUser: 10,
      absoluteTimeout: 7776000,           // 90 days
      rotateRefreshTokens: false,         // no rotation — reuse until expiry
      cacheRefreshTokens: true,           // cache everything
      refreshTokenCacheTTL: 60,           // 60s window
    },

    password: { minLength: 8, maxLength: 128, historyCount: 0 },
    lockout: { maxAttempts: 20, duration: 300, captchaThreshold: 5 },
    audit: { enabled: false },            // skip audit for speed
  });

  await argus.init();
  console.log('Maximum Speed profile active');
  console.log('  Argon2: 4MB, 2 iterations');
  console.log('  Tokens: HS256 (symmetric, no JWKS)');
  console.log('  Rotation: OFF (token reused until expiry)');
  console.log('  Token cache: ON (60s TTL)');
  console.log('  Audit: OFF');
  console.log('  Session limit: 10 per user');
  console.log('');
  console.log('  WARNING: This profile trades security for speed.');
  console.log('  Do NOT use for apps handling sensitive user data.');

  await argus.shutdown();
}

main().catch(console.error);
