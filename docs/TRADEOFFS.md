# ArgusJS — Performance vs Security Trade-offs

ArgusJS is designed to let **you** choose your trade-offs. Every security feature that impacts performance is configurable. This document explains each option, its impact, and when to use it.

---

## The Trade-off Matrix

| Config | Default | Secure Setting | Fast Setting |
|--------|---------|----------------|-------------|
| Token signing | RS256 | RS256 (asymmetric) | HS256 (symmetric) |
| Token rotation | `true` | `rotateRefreshTokens: true` | `rotateRefreshTokens: false` |
| Token cache | `false` | `cacheRefreshTokens: false` | `cacheRefreshTokens: true` |
| Argon2 memory | 64 MB | `memoryCost: 65536` | `memoryCost: 4096` |
| Argon2 iterations | 3 | `timeCost: 3` | `timeCost: 2` |

## Performance Profiles

### Profile 1: Maximum Security (Default)

**Best for:** Banking, healthcare, fintech, any app handling sensitive data.

```typescript
const argus = new Argus({
  db: new PostgresAdapter({ connectionString: '...' }),
  cache: new RedisCacheAdapter({ url: '...' }),
  hasher: new Argon2Hasher(),                    // 64MB, 3 iterations, 4 parallelism
  token: new RS256TokenProvider({                // Asymmetric — JWKS for microservices
    issuer: 'auth.mybank.com',
    audience: ['api.mybank.com'],
  }),
  session: {
    rotateRefreshTokens: true,                   // Rotate on every refresh
    cacheRefreshTokens: false,                   // Always hit DB (instant revocation)
    maxPerUser: 3,                               // Strict session limit
  },
  // ...
});
```

**Benchmarks (single instance, measured with k6 — 20 VUs, 30s):**

| Operation | p50 | p90 | p95 |
|-----------|-----|-----|-----|
| Registration | 666ms | 780ms | 847ms |
| Login | 108ms | 145ms | 155ms |
| Token Refresh (isolated) | **15ms** | 16ms | 20ms |

**Security guarantees:**
- Stolen refresh tokens detected instantly via rotation
- Concurrent token reuse triggers full session revocation
- JWKS allows zero-trust token verification across services
- Argon2id with 64MB makes GPU brute-force economically infeasible

---

### Profile 2: Balanced (Recommended for most apps)

**Best for:** SaaS apps, social platforms, e-commerce — where both speed and security matter.

```typescript
const argus = new Argus({
  db: new PostgresAdapter({ connectionString: '...' }),
  cache: new RedisCacheAdapter({ url: '...' }),
  hasher: new Argon2Hasher({
    memoryCost: 19456,                           // 19MB — OWASP minimum recommendation
    timeCost: 2,
    parallelism: 1,
  }),
  token: new RS256TokenProvider({                // Still asymmetric for microservices
    issuer: 'auth.myapp.com',
    audience: ['api.myapp.com'],
  }),
  session: {
    rotateRefreshTokens: true,                   // Still rotating (security)
    cacheRefreshTokens: true,                    // Cache tokens in Redis
    refreshTokenCacheTTL: 10,                    // 10s cache — small security window
    maxPerUser: 5,
  },
  // ...
});
```

**Benchmarks (estimated — interpolated between Profile 1 and 3):**

| Operation | p50 (est.) | p95 (est.) |
|-----------|-----------|-----------|
| Registration | ~350ms | ~550ms |
| Login | ~110ms | ~160ms |
| Token Refresh | ~15ms | ~25ms |

**Trade-offs:**
- Argon2 at 19MB is still GPU-resistant (OWASP minimum) but 3x faster to hash
- 10s token cache window: if a token is revoked, an attacker has up to 10 seconds to use a cached copy. Acceptable for most apps.
- RS256 keeps microservice compatibility

---

### Profile 3: Maximum Speed (Monolith)

**Best for:** Monolithic apps, internal tools, MVPs, prototypes — where speed > paranoid security.

```typescript
const argus = new Argus({
  db: new PostgresAdapter({ connectionString: '...' }),
  cache: new RedisCacheAdapter({ url: '...' }),
  hasher: new Argon2Hasher({
    memoryCost: 4096,                            // 4MB — fast, still bcrypt-level security
    timeCost: 2,
    parallelism: 1,
  }),
  token: new HS256TokenProvider({                // Symmetric — fastest signing
    secret: process.env.JWT_SECRET!,
    issuer: 'myapp',
    audience: ['myapp'],
  }),
  session: {
    rotateRefreshTokens: false,                  // No rotation — reuse token until expiry
    cacheRefreshTokens: true,                    // Cache everything
    refreshTokenCacheTTL: 60,                    // 60s cache
    maxPerUser: 10,
  },
  // ...
});
```

**Benchmarks (single instance, measured with k6 — 20 VUs, 30s):**

| Operation | p50 | p90 | p95 |
|-----------|-----|-----|-----|
| Registration | 84ms | 113ms | 124ms |
| Login | 111ms | 147ms | 164ms |
| Token Refresh (isolated) | **17ms** | 32ms | 35ms |

**Trade-offs:**
- HS256: No JWKS endpoint. All services need the shared secret. Can't do zero-trust verification.
- No rotation: Stolen refresh token is valid until it expires (up to 30 days). No reuse detection.
- 4MB Argon2: Still better than bcrypt, but a well-funded attacker with GPUs could crack weak passwords.
- 60s cache: Revoked tokens can still be used for up to 60 seconds.

---

## Individual Trade-offs Explained

### 1. Token Signing: RS256 vs ES256 vs HS256

| | RS256 | ES256 | HS256 |
|---|---|---|---|
| **Algorithm** | RSA 2048-bit | ECDSA P-256 | HMAC-SHA256 |
| **Sign speed** | ~5ms | ~2ms | ~0.1ms |
| **Verify speed** | ~0.5ms | ~1ms | ~0.1ms |
| **Key type** | Asymmetric | Asymmetric | Symmetric |
| **JWKS support** | Yes | Yes | No |
| **Token size** | ~800 bytes | ~400 bytes | ~400 bytes |
| **Microservices** | Perfect | Perfect | Bad |
| **Key rotation** | Easy | Easy | Hard |
| **Compromise impact** | Low (public key is public) | Low | **Critical** (can forge tokens) |

**Recommendation:**
- Microservices → RS256 or ES256
- Single server → HS256 is fine
- Care about token size → ES256 (smallest)

```typescript
// Switch with one line:
import { RS256TokenProvider } from '@argusjs/token-jwt-rs256';
import { ES256TokenProvider } from '@argusjs/token-jwt-es256';
import { HS256TokenProvider } from '@argusjs/token-jwt-hs256';

token: new RS256TokenProvider({ ... })  // 5ms sign, JWKS works
token: new ES256TokenProvider({ ... })  // 2ms sign, JWKS works, smaller tokens
token: new HS256TokenProvider({ ... })  // 0.1ms sign, no JWKS
```

### 2. Token Rotation: On vs Off

| | Rotation ON (default) | Rotation OFF |
|---|---|---|
| **Refresh latency** | +15-20ms (revoke old + create new in DB) | Baseline |
| **DB writes per refresh** | 2 (revoke + insert) | 0 |
| **Token reuse detection** | Instant — stolen token triggers alarm | None |
| **Concurrent refresh safety** | Atomic — only one caller wins | All succeed |
| **Stolen token impact** | Detected on next legitimate refresh | Valid until expiry |

**Recommendation:**
- B2C apps with refresh tokens stored in httpOnly cookies → rotation ON
- Mobile apps where tokens live in secure storage → rotation ON
- Server-to-server with API keys → rotation OFF (use API keys instead)

```typescript
session: {
  rotateRefreshTokens: true,   // secure (default)
  rotateRefreshTokens: false,  // fast (Keycloak-style)
}
```

### 3. Refresh Token Caching: Off vs On

| | Cache OFF (default) | Cache ON |
|---|---|---|
| **Refresh token lookup** | ~5ms (Postgres) | ~1ms (Redis) |
| **Revocation latency** | Instant | Delayed by cacheTTL |
| **Security window** | Zero | Up to cacheTTL seconds |
| **The attack scenario** | Impossible | Token revoked in DB but cached copy still valid in Redis |
| **Consistency** | Strong (ACID) | Eventual |

**Recommendation:**
- `cacheTTL: 5` — 5 second window, saves ~4ms per refresh. Good trade-off.
- `cacheTTL: 30` — reasonable for most apps.
- `cacheTTL: 300` — only for internal/low-risk apps.
- Never use with `rotateRefreshTokens: false` AND long-lived tokens.

```typescript
session: {
  cacheRefreshTokens: false,          // always hit DB (default)
  cacheRefreshTokens: true,           // cache in Redis
  refreshTokenCacheTTL: 10,           // 10s window
}
```

### 4. Password Hashing: Argon2 Tuning

| | Production (default) | Balanced | Fast (dev/test) |
|---|---|---|---|
| **memoryCost** | 65536 (64MB) | 19456 (19MB) | 4096 (4MB) |
| **timeCost** | 3 | 2 | 2 |
| **parallelism** | 4 | 1 | 1 |
| **Hash time** | ~400ms | ~150ms | ~40ms |
| **GPU resistance** | Excellent | Good (OWASP minimum) | Moderate |
| **Memory per hash** | 64MB | 19MB | 4MB |
| **Concurrent hashes (4GB RAM)** | 62 | 210 | 1000 |

**OWASP 2024 recommendations:**
- Argon2id with memoryCost >= 19MB and timeCost >= 2 is the minimum.
- Below 19MB, consider bcrypt as a fallback.

```typescript
hasher: new Argon2Hasher()                                          // production defaults
hasher: new Argon2Hasher({ memoryCost: 19456, timeCost: 2 })        // balanced
hasher: new Argon2Hasher({ memoryCost: 4096, timeCost: 2 })         // fast
hasher: new BcryptHasher({ rounds: 12 })                            // legacy
hasher: new BcryptHasher({ rounds: 10 })                            // fast legacy
```

---

## Quick Reference: "What should I use?"

| Your situation | Token | Rotation | Cache | Argon2 |
|----------------|-------|----------|-------|--------|
| **Bank / healthcare** | RS256 | ON | OFF | 64MB, 3 iter |
| **SaaS product** | RS256 | ON | 10s TTL | 19MB, 2 iter |
| **Social / consumer app** | RS256 | ON | 30s TTL | 19MB, 2 iter |
| **Internal tool** | HS256 | OFF | 60s TTL | 4MB, 2 iter |
| **MVP / prototype** | HS256 | OFF | 60s TTL | 4MB, 2 iter |
| **API-only (M2M)** | RS256 | OFF | OFF | N/A (use API keys) |

---

## Scaling Beyond Single Instance

All the above numbers are per single Node.js instance. To scale:

| Strategy | Multiplier | Effort |
|----------|-----------|--------|
| Cluster mode (all CPU cores) | Nx (N = cores) | Built-in, just set `NODE_ENV=production` |
| Horizontal scaling (LB + N instances) | Linear | Docker/K8s, zero code changes |
| Read replicas (Postgres) | Offload reads | Config change in PostgresAdapter |
| Redis Cluster | Offload cache | Config change in RedisCacheAdapter |

**Example:** 8-core machine with 3 replicas behind a load balancer:
- Registration (prod Argon2): 33 × 8 × 3 = **792 req/s**
- Login: 179 × 8 × 3 = **4,296 req/s**
- Token refresh: 176 × 8 × 3 = **4,224 req/s**

That handles **370 million token refreshes per day** — enough for 10M+ MAU.
