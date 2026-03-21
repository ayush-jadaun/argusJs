// Demonstrates pluggability — swap ANY adapter with one line

import { Argus } from '@argus/core';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';
import { MemoryEmailProvider } from '@argus/email-memory';

// === SWAP HASHING ALGORITHM ===
// Option A: Argon2id (recommended for production)
import { Argon2Hasher } from '@argus/hash-argon2';
const hasherA = new Argon2Hasher();

// Option B: bcrypt (legacy compatibility)
import { BcryptHasher } from '@argus/hash-bcrypt';
const hasherB = new BcryptHasher({ rounds: 12 });

// Option C: scrypt (no native dependencies)
import { ScryptHasher } from '@argus/hash-scrypt';
const hasherC = new ScryptHasher({ cost: 16384 });

// === SWAP TOKEN SIGNING ===
// Option A: RS256 (asymmetric — recommended, supports JWKS)
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
const tokenA = new RS256TokenProvider({ issuer: 'my-app', audience: ['my-app'] });

// Option B: ES256 (ECDSA — smaller tokens, faster signing)
import { ES256TokenProvider } from '@argus/token-jwt-es256';
const tokenB = new ES256TokenProvider({ issuer: 'my-app', audience: ['my-app'] });

// Option C: HS256 (symmetric — simplest, no JWKS)
import { HS256TokenProvider } from '@argus/token-jwt-hs256';
const tokenC = new HS256TokenProvider({ secret: 'my-secret-at-least-32-chars-long!!', issuer: 'my-app', audience: ['my-app'] });

// === SWAP REFRESH TOKEN BEHAVIOR ===
// Token rotation is also configurable — pass rotateRefreshTokens: false in the session
// config to reuse the same refresh token (Keycloak-style) instead of rotating on every refresh.
// See docs/TRADEOFFS.md for security implications.

async function main() {
  // Mix and match — use bcrypt with ES256 tokens:
  const argus = new Argus({
    db: new MemoryDbAdapter(),
    cache: new MemoryCacheAdapter(),
    hasher: hasherB,    // bcrypt
    token: tokenB,      // ES256
    email: new MemoryEmailProvider(),
  });

  await argus.init();

  const result = await argus.register({
    email: 'test@example.com',
    password: 'SwapDemo123!',
    displayName: 'Swap Demo',
    ipAddress: '127.0.0.1',
    userAgent: 'example',
  });

  console.log('Registered with bcrypt + ES256:', result.user.email);
  console.log('Token algorithm: ES256 (ECDSA)');

  await argus.shutdown();
}

main().catch(console.error);
