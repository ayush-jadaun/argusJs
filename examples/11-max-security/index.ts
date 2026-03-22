// Profile 1: Maximum Security
// Best for: Banking, healthcare, fintech
// Refresh p50: ~21ms | Login p50: ~159ms | Registration p50: ~1,328ms

import { Argus } from '@argusjs/core';
import { PostgresAdapter } from '@argusjs/db-postgres';
import { RedisCacheAdapter } from '@argusjs/cache-redis';
import { Argon2Hasher } from '@argusjs/hash-argon2';
import { RS256TokenProvider } from '@argusjs/token-jwt-rs256';
import { MemoryEmailProvider } from '@argusjs/email-memory';
import { RedisRateLimiter } from '@argusjs/ratelimit-redis';
import { DefaultSecurityEngine } from '@argusjs/security-engine';

async function main() {
  const db = new PostgresAdapter({ connectionString: process.env.DATABASE_URL! });
  const cache = new RedisCacheAdapter({ url: process.env.REDIS_URL! });

  const argus = new Argus({
    db,
    cache,

    // Argon2id with full production params — GPU-resistant
    hasher: new Argon2Hasher({
      memoryCost: 65536,  // 64MB per hash
      timeCost: 3,        // 3 iterations
      parallelism: 4,     // 4 threads per hash
    }),

    // RS256 — asymmetric keys, JWKS endpoint for microservice verification
    token: new RS256TokenProvider({
      issuer: 'auth.securecorp.com',
      audience: ['api.securecorp.com', 'internal.securecorp.com'],
      accessTokenTTL: 300,   // 5 min (short-lived for security)
      mfaTokenTTL: 120,      // 2 min MFA challenge window
    }),

    email: new MemoryEmailProvider(),
    rateLimiter: new RedisRateLimiter({ url: process.env.REDIS_URL! }),

    // Full security engine
    security: new DefaultSecurityEngine({
      cache,
      db,
      config: {
        bruteForce: { maxAttempts: 5, lockoutDuration: 3600 },  // 1 hour lockout
        sharing: { maxConcurrentIPs: 2, action: 'block' },      // block sharing
        risk: { challengeThreshold: 40, blockThreshold: 60 },   // aggressive
      },
    }),

    session: {
      maxPerUser: 3,                    // strict limit
      absoluteTimeout: 86400,           // 24 hours max
      rotateRefreshTokens: true,        // rotate every refresh (detect theft)
      cacheRefreshTokens: false,        // always hit DB (instant revocation)
    },

    password: { minLength: 12, maxLength: 128, historyCount: 10 },
    lockout: { maxAttempts: 5, duration: 3600, captchaThreshold: 2 },
    audit: { enabled: true, retentionDays: 2555 },  // 7 year retention
  });

  await argus.init();
  console.log('Maximum Security profile active');
  console.log('  Argon2: 64MB, 3 iterations');
  console.log('  Tokens: RS256 with JWKS, 5-min access tokens');
  console.log('  Rotation: ON (reuse detection)');
  console.log('  Token cache: OFF (instant revocation)');
  console.log('  Session limit: 3 per user');
  console.log('  Lockout: 5 attempts, 1 hour');

  await argus.shutdown();
}

main().catch(console.error);
