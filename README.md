<p align="center">
  <h1 align="center">ArgusJS</h1>
  <p align="center">Enterprise-grade, fully pluggable authentication platform for Node.js</p>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build Status" /></a>
  <a href="#"><img src="https://img.shields.io/badge/tests-282%20passed-brightgreen" alt="Tests" /></a>
  <a href="#"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License" /></a>
  <a href="#"><img src="https://img.shields.io/badge/node-%3E%3D20-green" alt="Node" /></a>
  <a href="#"><img src="https://img.shields.io/badge/typescript-5.7-blue" alt="TypeScript" /></a>
</p>

---

## What is ArgusJS

ArgusJS is a complete, self-hosted authentication and authorization platform built for teams that need full control over their auth infrastructure. It provides everything from basic email/password login to MFA, OAuth, RBAC, organizations, and advanced security features -- all through a pluggable adapter architecture where every component can be swapped without changing application code. Whether you are building a SaaS product, an internal tool, or a platform with strict compliance requirements, ArgusJS gives you production-grade auth without vendor lock-in.

## Features

### Core Authentication
- Email/password registration with configurable validation
- Login with session creation and device tracking
- Logout (single session or all devices)
- Token rotation with automatic reuse detection (TOCTOU-safe)
- Password reset via time-limited email tokens
- Email verification with token-based flow
- Password change with history enforcement

### Security
- **Argon2id hashing** -- GPU-resistant, memory-hard password hashing (64 MB default)
- **Brute force protection** -- progressive lockout after configurable failed attempts
- **Account lockout** -- time-based lockout with automatic unlock
- **Rate limiting** -- sliding window rate limiter (Redis or in-memory)
- **Anomaly detection** -- new device, new location, unusual time scoring
- **Device trust** -- fingerprint and trust management
- **Account sharing prevention** -- concurrent IP and device monitoring
- **Impossible travel detection** -- geo-based login velocity checks

### Enterprise
- **Organizations** -- multi-tenant workspaces with member roles and invites
- **RBAC + ABAC** -- hierarchical roles, granular permissions, access policies
- **API keys** -- scoped API key management with expiry
- **Webhooks** -- event-driven webhook subscriptions with HMAC signing
- **Admin impersonation** -- impersonate users for support (fully audited)
- **Audit logging** -- every security-relevant action logged with retention policies
- **Configurable security/performance trade-offs** -- toggle token rotation, caching, Argon2 tuning per deployment
- **GDPR compliance** -- data export, account deletion, right to be forgotten

### Multi-Factor Authentication
- **TOTP** -- Google Authenticator, Authy, 1Password (via `@argus/mfa-totp`)
- **WebAuthn/FIDO2** -- hardware keys, biometrics, passkeys (via `@argus/mfa-webauthn`)
- **SMS** -- Twilio-powered OTP codes (via `@argus/mfa-sms`)
- **Backup codes** -- one-time recovery codes generated on MFA setup

### OAuth / Social Login
- Google, GitHub, Apple, Microsoft, Discord
- Custom OIDC provider for any standards-compliant identity provider
- Automatic account linking by verified email

### Pluggable Architecture
Every component is swappable -- database, cache, hashing, tokens, MFA, OAuth, email, rate limiting, security engine, and password policy. Implement the TypeScript interface, pass it to the constructor, done.

## Quick Start

```bash
npm install @argus/core @argus/server @argus/db-memory @argus/cache-memory \
            @argus/hash-argon2 @argus/token-jwt-rs256 @argus/email-memory
```

```typescript
import { Argus } from '@argus/core';
import { createApp } from '@argus/server';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';
import { Argon2Hasher } from '@argus/hash-argon2';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { MemoryEmailProvider } from '@argus/email-memory';

const argus = new Argus({
  db: new MemoryDbAdapter(),
  cache: new MemoryCacheAdapter(),
  hasher: new Argon2Hasher(),
  token: new RS256TokenProvider({ issuer: 'my-app', audience: ['my-app'] }),
  email: new MemoryEmailProvider(),
});

await argus.init();
const app = await createApp({ argus });
await app.listen({ port: 3100, host: '0.0.0.0' });
```

Server is now running at `http://localhost:3100`. Try it:

```bash
# Register
curl -X POST http://localhost:3100/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"SecurePass123!","displayName":"Alice"}'

# Login
curl -X POST http://localhost:3100/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"SecurePass123!"}'
```

## Architecture

```mermaid
graph TB
    Client["Client App / SDK<br/><code>@argus/client</code>"]
    Dashboard["Admin Dashboard<br/><code>@argus/dashboard</code> (Next.js)"]
    Server["REST API Server<br/><code>@argus/server</code> (Fastify 5)"]
    Core["Auth Engine<br/><code>@argus/core</code>"]

    subgraph "Required Adapters"
        direction LR
        DB["Database<br/><code>postgres</code> | <code>memory</code>"]
        Cache["Cache<br/><code>redis</code> | <code>memory</code>"]
        Hash["Hashing<br/><code>argon2</code> | <code>bcrypt</code> | <code>scrypt</code>"]
        Token["Token Signing<br/><code>rs256</code> | <code>es256</code> | <code>hs256</code>"]
    end

    subgraph "Optional Adapters"
        direction LR
        Email["Email<br/><code>sendgrid</code> | <code>ses</code> | <code>smtp</code> | <code>memory</code>"]
        RL["Rate Limiter<br/><code>redis</code> | <code>memory</code>"]
        MFA["MFA<br/><code>totp</code> | <code>sms</code> | <code>webauthn</code>"]
        OAuth["OAuth<br/><code>google</code> | <code>github</code> | <code>apple</code><br/><code>microsoft</code> | <code>discord</code> | <code>custom</code>"]
        Policy["Password Policy<br/><code>zxcvbn</code> | <code>hibp</code>"]
        Security["Security Engine<br/>brute force | anomaly<br/>device trust | sharing"]
    end

    Client -->|HTTP| Server
    Dashboard -->|HTTP| Server
    Server --> Core
    Core --> DB
    Core --> Cache
    Core --> Hash
    Core --> Token
    Core -.-> Email
    Core -.-> RL
    Core -.-> MFA
    Core -.-> OAuth
    Core -.-> Policy
    Core -.-> Security
```

## Packages

| Package | Description | Status |
|---------|-------------|--------|
| `@argus/core` | Core authentication engine, types, interfaces, and utilities | Stable |
| `@argus/server` | Fastify 5 HTTP server with 60+ REST API routes | Stable |
| `@argus/client` | Browser/Node SDK with React hooks (`AuthProvider`, `useAuth`) | Stable |
| `@argus/dashboard` | Next.js admin dashboard for user management | Stable |
| `@argus/db-postgres` | PostgreSQL adapter using Drizzle ORM | Stable |
| `@argus/db-mongodb` | MongoDB adapter using native driver | Stable |
| `@argus/db-memory` | In-memory database adapter (dev/test) | Stable |
| `@argus/cache-redis` | Redis cache adapter using ioredis | Stable |
| `@argus/cache-memory` | In-memory cache adapter (dev/test) | Stable |
| `@argus/hash-argon2` | Argon2id password hashing (recommended) | Stable |
| `@argus/hash-bcrypt` | bcrypt password hashing | Stable |
| `@argus/hash-scrypt` | Node.js built-in scrypt hashing (no native deps) | Stable |
| `@argus/token-jwt-rs256` | JWT signing with RS256 (RSA, supports JWKS) | Stable |
| `@argus/token-jwt-es256` | JWT signing with ES256 (ECDSA, smaller tokens) | Stable |
| `@argus/token-jwt-hs256` | JWT signing with HS256 (HMAC, symmetric) | Stable |
| `@argus/email-sendgrid` | Email delivery via SendGrid API | Stable |
| `@argus/email-ses` | Email delivery via AWS SES | Stable |
| `@argus/email-smtp` | Email delivery via SMTP (Nodemailer) | Stable |
| `@argus/email-memory` | In-memory email adapter (dev/test) | Stable |
| `@argus/ratelimit-redis` | Redis-backed sliding window rate limiter | Stable |
| `@argus/ratelimit-memory` | In-memory rate limiter (dev/test) | Stable |
| `@argus/mfa-totp` | TOTP multi-factor auth (Google Authenticator, Authy) | Stable |
| `@argus/mfa-sms` | SMS-based MFA via Twilio | Stable |
| `@argus/mfa-webauthn` | WebAuthn/FIDO2 passkey MFA (SimpleWebAuthn) | Stable |
| `@argus/oauth-google` | Google OAuth 2.0 provider | Stable |
| `@argus/oauth-github` | GitHub OAuth 2.0 provider | Stable |
| `@argus/oauth-apple` | Apple Sign In provider | Stable |
| `@argus/oauth-microsoft` | Microsoft/Azure AD OAuth provider | Stable |
| `@argus/oauth-discord` | Discord OAuth 2.0 provider | Stable |
| `@argus/oauth-custom` | Custom OAuth/OIDC provider for any IdP | Stable |
| `@argus/policy-zxcvbn` | Password strength estimation via zxcvbn | Stable |
| `@argus/policy-hibp` | Breach check via Have I Been Pwned API | Stable |
| `@argus/security-engine` | Brute force, anomaly detection, device trust, sharing detection | Stable |

## Installation

Install the core and only the adapters you need:

```bash
# Core + Server (always required)
pnpm add @argus/core @argus/server

# Database (pick one)
pnpm add @argus/db-postgres      # PostgreSQL via Drizzle ORM
pnpm add @argus/db-memory        # In-memory (dev/test only)

# Cache (pick one)
pnpm add @argus/cache-redis      # Redis via ioredis
pnpm add @argus/cache-memory     # In-memory (dev/test only)

# Password hashing (pick one)
pnpm add @argus/hash-argon2      # Argon2id (recommended)
pnpm add @argus/hash-bcrypt      # bcrypt (legacy compat)
pnpm add @argus/hash-scrypt      # scrypt (no native deps)

# JWT signing (pick one)
pnpm add @argus/token-jwt-rs256  # RS256 asymmetric (recommended)
pnpm add @argus/token-jwt-es256  # ES256 ECDSA (smaller tokens)
pnpm add @argus/token-jwt-hs256  # HS256 symmetric (simplest)

# Email (pick one)
pnpm add @argus/email-sendgrid   # SendGrid
pnpm add @argus/email-ses        # AWS SES
pnpm add @argus/email-smtp       # SMTP (Nodemailer)
pnpm add @argus/email-memory     # In-memory (dev/test only)

# Rate limiting (pick one, optional)
pnpm add @argus/ratelimit-redis  # Redis sliding window
pnpm add @argus/ratelimit-memory # In-memory

# MFA (optional, pick any)
pnpm add @argus/mfa-totp         # TOTP (Google Authenticator)
pnpm add @argus/mfa-sms          # SMS via Twilio
pnpm add @argus/mfa-webauthn     # WebAuthn/FIDO2 passkeys

# OAuth (optional, pick any)
pnpm add @argus/oauth-google
pnpm add @argus/oauth-github
pnpm add @argus/oauth-apple
pnpm add @argus/oauth-microsoft
pnpm add @argus/oauth-discord
pnpm add @argus/oauth-custom     # Any OIDC provider

# Password policy (optional, pick any)
pnpm add @argus/policy-zxcvbn    # Strength estimation
pnpm add @argus/policy-hibp      # Breach database check

# Security engine (optional)
pnpm add @argus/security-engine
```

## Configuration

Full annotated configuration with all available options:

```typescript
import { Argus } from '@argus/core';
import { PostgresAdapter } from '@argus/db-postgres';
import { RedisCacheAdapter } from '@argus/cache-redis';
import { Argon2Hasher } from '@argus/hash-argon2';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { SendGridEmailProvider } from '@argus/email-sendgrid';
import { RedisRateLimiter } from '@argus/ratelimit-redis';
import { TOTPProvider } from '@argus/mfa-totp';
import { GoogleOAuth } from '@argus/oauth-google';
import { GitHubOAuth } from '@argus/oauth-github';
import { ZxcvbnPolicy } from '@argus/policy-zxcvbn';
import { HIBPPolicy } from '@argus/policy-hibp';
import { DefaultSecurityEngine } from '@argus/security-engine';

const argus = new Argus({
  // ── Required Adapters ─────────────────────────────────────────────────
  db: new PostgresAdapter({
    connectionString: process.env.DATABASE_URL!,
    max: 20,               // connection pool size
    idleTimeout: 30,        // seconds before idle connection is closed
    connectTimeout: 10,     // seconds to wait for a connection
  }),

  cache: new RedisCacheAdapter({
    url: process.env.REDIS_URL!,
  }),

  hasher: new Argon2Hasher({
    memoryCost: 65536,      // 64 MB (default, OWASP recommended)
    timeCost: 3,            // 3 iterations (default)
    parallelism: 4,         // 4 threads (default)
  }),

  token: new RS256TokenProvider({
    privateKey: process.env.JWT_PRIVATE_KEY, // PEM string, auto-generated if omitted
    keyId: 'prod-key-2026',                  // appears in JWKS
    issuer: 'auth.myplatform.com',           // JWT iss claim
    audience: ['api.myplatform.com'],        // JWT aud claim
    accessTokenTTL: 900,                     // 15 minutes (seconds)
    mfaTokenTTL: 300,                        // 5 minutes for MFA challenge
  }),

  // ── Optional Adapters ─────────────────────────────────────────────────
  email: new SendGridEmailProvider({
    apiKey: process.env.SENDGRID_API_KEY!,
    from: 'noreply@myplatform.com',
  }),

  rateLimiter: new RedisRateLimiter({
    url: process.env.REDIS_URL!,
  }),

  mfa: {
    totp: new TOTPProvider({ appName: 'MyPlatform', digits: 6, period: 30 }),
  },

  oauth: {
    google: new GoogleOAuth({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    }),
    github: new GitHubOAuth({
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    }),
  },

  passwordPolicy: [
    new ZxcvbnPolicy({ minScore: 3 }),   // 0-4 scale
    new HIBPPolicy(),                     // breach database
  ],

  security: new DefaultSecurityEngine({
    cache: new RedisCacheAdapter({ url: process.env.REDIS_URL! }),
    db: new PostgresAdapter({ connectionString: process.env.DATABASE_URL! }),
    config: {
      bruteForce: { maxAttempts: 10, lockoutDuration: 1800 },
      sharing: { maxConcurrentIPs: 3, maxConcurrentDevices: 5, action: 'challenge' },
      risk: { challengeThreshold: 50, blockThreshold: 75 },
    },
  }),

  // ── Configuration ─────────────────────────────────────────────────────
  password: {
    minLength: 10,          // minimum password length
    maxLength: 128,         // maximum password length
    historyCount: 5,        // prevent reuse of last N passwords
  },

  session: {
    maxPerUser: 5,              // max concurrent sessions per user
    absoluteTimeout: 2592000,   // 30 days in seconds
    inactivityTimeout: 86400,   // 24 hours in seconds
    rotateRefreshTokens: true,  // rotate refresh token on every refresh (default: true)
    cacheRefreshTokens: false,  // cache refresh token lookups in Redis (default: false)
    refreshTokenCacheTTL: 30,   // cache TTL in seconds when caching is enabled (default: 30)
  },

  lockout: {
    maxAttempts: 10,        // lock after N failed attempts
    duration: 1800,         // lock duration in seconds (30 min)
    captchaThreshold: 3,    // show CAPTCHA after N failed attempts
  },

  emailVerification: {
    required: true,         // require email verification before login
    tokenTTL: 86400,        // verification token TTL in seconds (24h)
  },

  audit: {
    enabled: true,          // enable audit logging
    retentionDays: 730,     // keep audit logs for 2 years
  },

  mfaEncryptionKey: process.env.MFA_ENCRYPTION_KEY!, // 64-char hex (32 bytes)

  // ── Lifecycle Hooks ───────────────────────────────────────────────────
  hooks: {
    beforeRegister: async ({ email }) => { /* validate, block disposable domains */ },
    afterRegister: async (user) => { /* provision in billing, CRM */ },
    beforeLogin: async ({ email }) => { /* custom checks */ },
    afterLogin: async (user, session) => { /* analytics, last seen */ },
    onPasswordChange: async (user) => { /* notify user */ },
    onAccountLock: async (user) => { /* alert security team */ },
    onSuspiciousActivity: async (user, event) => { /* escalate */ },
  },
});
```

## Performance Benchmarks

Benchmarks from k6 load tests against a single ArgusJS instance (Node.js 20, PostgreSQL 16, Redis 7):

| Endpoint | Requests/sec | p50 Latency | p95 Latency | p99 Latency | Notes |
|----------|-------------|-------------|-------------|-------------|-------|
| Health / JWKS | 9,317 | 7 ms | 12 ms | 18 ms | Cached, no DB hit |
| Token Refresh | 176 | 28 ms | 65 ms | 120 ms | DB read + write + JWT sign |
| Login | 179 | 159 ms | 280 ms | 450 ms | Argon2 verify + session + JWT |
| Registration (dev) | 230 | 125 ms | 200 ms | 350 ms | Lightweight Argon2 (4 MB) |
| Registration (prod) | 33 | 1,328 ms | 1,850 ms | 2,100 ms | Full Argon2 (64 MB, 3 iter) |

ArgusJS includes three pre-tuned **performance profiles** (Max Security, Balanced, Max Speed) that let you trade security for throughput. See [Performance Profiles](#performance-profiles) below and the [Trade-offs Guide](docs/TRADEOFFS.md) for details.

**Scaling notes:**
- These numbers are per single Node.js instance. Use `node cluster.js` for multi-core scaling (linear throughput gain).
- Set `UV_THREADPOOL_SIZE` to at least `16` or `cpu_count * 2` to prevent Argon2 thread starvation (the server does this automatically).
- Production Argon2 is intentionally slow -- 1.3 seconds per hash is the security target, not a bottleneck to optimize away.
- Horizontal scaling is straightforward: all state is in PostgreSQL + Redis, so you can run N instances behind a load balancer.

## Performance Profiles

ArgusJS ships with three recommended performance profiles. Each profile adjusts token rotation, refresh token caching, and Argon2 hashing parameters.

| Profile | Token Rotation | Refresh Cache | Argon2 | Best For |
|---------|---------------|---------------|--------|----------|
| **Max Security** (default) | ON | OFF | 64 MB, 3 iter | Banking, healthcare, fintech |
| **Balanced** | ON | 10s TTL | 19 MB, 2 iter | SaaS, e-commerce, social |
| **Max Speed** | OFF | 60s TTL | 4 MB, 2 iter | Internal tools, MVPs, prototypes |

See [docs/TRADEOFFS.md](docs/TRADEOFFS.md) for full benchmark numbers, security implications, and configuration examples for each profile.

## Comparison

| Feature | ArgusJS | Auth0 | Clerk | Supabase Auth | Keycloak |
|---------|---------|-------|-------|---------------|----------|
| Self-hosted | Yes | No | No | Yes | Yes |
| Open source | Apache 2.0 | No | No | Apache 2.0 | Apache 2.0 |
| Language | TypeScript | N/A (SaaS) | N/A (SaaS) | Go/TS | Java |
| Pluggable adapters | Yes (all) | No | No | Limited | Limited |
| MFA (TOTP + WebAuthn + SMS) | Yes | Yes | Yes | TOTP only | Yes |
| OAuth providers | 6 + custom OIDC | 30+ | 20+ | 4 | 10+ |
| RBAC + ABAC | Yes | Yes | Yes | RLS only | Yes |
| Organizations | Yes | Yes (paid) | Yes (paid) | No | Yes |
| Rate limiting | Built-in | Built-in | Built-in | External | External |
| Anomaly detection | Built-in | Yes (paid) | No | No | No |
| Password breach check | HIBP built-in | Yes | Yes | No | No |
| Webhook events | Yes | Yes | Yes | Yes | Yes |
| Admin dashboard | Yes (Next.js) | Yes | Yes | Yes | Yes |
| Client SDK (React) | Yes | Yes | Yes | Yes | Community |
| Audit logging | Yes | Yes (paid) | Yes (paid) | No | Yes |
| GDPR data export | Yes | Manual | Manual | Manual | Manual |
| Vendor lock-in | None | High | High | Medium | Low |
| Pricing | Free (Apache-2.0) | $23+/mo | $25+/mo | Free tier | Free |

## Docker

Start ArgusJS with PostgreSQL and Redis in one command:

```bash
# Start all services
docker compose up -d

# Verify it's running
curl http://localhost:3100/v1/health

# View logs
docker compose logs -f argus-server

# Stop everything
docker compose down

# Stop and wipe data
docker compose down -v
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    ports:
      - '5432:5432'
    environment:
      POSTGRES_USER: argus
      POSTGRES_PASSWORD: argus
      POSTGRES_DB: argus
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U argus']
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - '6379:6379'
    volumes:
      - redis_data:/data
    healthcheck:
      test: ['CMD', 'redis-cli', 'ping']
      interval: 5s
      timeout: 5s
      retries: 5

  argus-server:
    build: .
    ports:
      - '3100:3100'
    environment:
      DATABASE_URL: postgres://argus:argus@postgres:5432/argus
      REDIS_URL: redis://redis:6379
      PORT: 3100
      HOST: 0.0.0.0
      LOG_LEVEL: info
      JWT_ISSUER: auth.localhost
      JWT_AUDIENCE: api.localhost
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ['CMD', 'wget', '-qO-', 'http://localhost:3100/v1/health']
      interval: 10s
      timeout: 5s
      retries: 3

volumes:
  postgres_data:
  redis_data:
```

## API Endpoints

All endpoints are prefixed with `/v1` unless otherwise noted. See [docs/API.md](docs/API.md) for the full reference with request/response examples.

### Health

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/health` | No | Basic health check |
| `GET` | `/v1/health/live` | No | Liveness probe (Kubernetes) |
| `GET` | `/v1/health/ready` | No | Readiness probe (checks DB + cache) |

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/auth/register` | No | Register a new user |
| `POST` | `/v1/auth/login` | No | Log in with email + password |
| `POST` | `/v1/auth/refresh` | No | Refresh access token |
| `POST` | `/v1/auth/logout` | Yes | Log out (single or all devices) |

### Email & Password

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/auth/verify-email` | No | Verify email with token |
| `POST` | `/v1/auth/resend-verification` | Yes | Resend verification email |
| `POST` | `/v1/auth/forgot-password` | No | Request password reset email |
| `POST` | `/v1/auth/reset-password` | No | Reset password with token |
| `POST` | `/v1/auth/change-password` | Yes | Change password |

### MFA

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/auth/mfa/setup` | Yes | Begin MFA setup |
| `POST` | `/v1/auth/mfa/verify-setup` | Yes | Confirm MFA with code |
| `POST` | `/v1/auth/mfa/verify` | No | Complete MFA challenge |
| `POST` | `/v1/auth/mfa/disable` | Yes | Disable MFA |
| `GET` | `/v1/auth/mfa/backup-codes` | Yes | Regenerate backup codes |

### User Profile

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/auth/me` | Yes | Get current user |
| `PATCH` | `/v1/auth/me` | Yes | Update display name / avatar |
| `DELETE` | `/v1/auth/me` | Yes | Delete own account |
| `GET` | `/v1/auth/me/export` | Yes | Export user data (GDPR) |

### Sessions & Devices

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/auth/sessions` | Yes | List active sessions |
| `DELETE` | `/v1/auth/sessions/:id` | Yes | Revoke a session |
| `GET` | `/v1/auth/devices` | Yes | List trusted devices |
| `POST` | `/v1/auth/devices/:id/trust` | Yes | Trust a device |
| `DELETE` | `/v1/auth/devices/:id` | Yes | Remove trusted device |

### JWKS

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/.well-known/jwks.json` | No | JSON Web Key Set |

### Admin (requires `admin` role)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/admin/users` | List/search users |
| `GET` | `/v1/admin/users/:id` | Get user by ID |
| `PATCH` | `/v1/admin/users/:id` | Update user |
| `DELETE` | `/v1/admin/users/:id` | Delete user |
| `POST` | `/v1/admin/users/:id/unlock` | Unlock account |
| `POST` | `/v1/admin/users/:id/reset-mfa` | Reset user MFA |
| `POST` | `/v1/admin/users/:id/reset-password` | Trigger password reset |
| `POST` | `/v1/admin/impersonate` | Impersonate user |
| `GET` | `/v1/admin/audit-log` | Query audit logs |
| `GET` | `/v1/admin/stats` | System statistics |
| `GET` | `/v1/admin/sessions` | All active sessions |
| `GET` | `/v1/admin/roles` | List roles |
| `POST` | `/v1/admin/roles` | Create role |
| `PATCH` | `/v1/admin/roles/:name` | Update role |
| `DELETE` | `/v1/admin/roles/:name` | Delete role |

## Examples

The [`examples/`](examples/) directory contains runnable examples:

| Example | Description |
|---------|-------------|
| [01-basic-setup](examples/01-basic-setup) | Minimal setup with memory adapters |
| [02-production-postgres-redis](examples/02-production-postgres-redis) | PostgreSQL + Redis + full Argon2 |
| [03-swap-adapters](examples/03-swap-adapters) | Mix and match any adapter combination |
| [04-mfa-totp](examples/04-mfa-totp) | TOTP multi-factor authentication |
| [05-oauth-google](examples/05-oauth-google) | Google OAuth social login |
| [06-security-engine](examples/06-security-engine) | Brute force protection demo |
| [07-fastify-server](examples/07-fastify-server) | Full REST API server |
| [08-react-client](examples/08-react-client) | React app with auth hooks |
| [09-password-policies](examples/09-password-policies) | zxcvbn + HIBP password validation |
| [10-webhooks-events](examples/10-webhooks-events) | Event system and lifecycle hooks |

## Plugin Development

Every adapter implements a TypeScript interface from `@argus/core`. To create your own:

```typescript
import type { PasswordHasher } from '@argus/core';

export class MyHasher implements PasswordHasher {
  async hash(password: string): Promise<string> {
    // Your hashing logic
  }

  async verify(password: string, hash: string): Promise<boolean> {
    // Your verification logic
  }
}

// Use it
const argus = new Argus({
  hasher: new MyHasher(),
  // ...
});
```

### Adapter Interfaces

| Interface | Purpose |
|-----------|---------|
| `DbAdapter` | Database operations (users, sessions, tokens, orgs, audit) |
| `CacheAdapter` | Key-value cache for rate limits, MFA state, etc. |
| `PasswordHasher` | Password hashing and verification |
| `TokenProvider` | JWT signing, verification, and JWKS endpoint |
| `EmailProvider` | Transactional email delivery |
| `RateLimiter` | Request rate limiting |
| `MFAProvider` | Multi-factor authentication methods |
| `OAuthProviderAdapter` | OAuth/OIDC social login |
| `PasswordPolicy` | Password strength validation rules |
| `SecurityEngine` | Brute force, anomaly detection, device trust |

## Tech Stack

- **Runtime:** Node.js 20+
- **Language:** TypeScript 5.7
- **Server:** Fastify 5
- **Database:** PostgreSQL 16 via Drizzle ORM
- **Cache:** Redis 7 via ioredis
- **Monorepo:** Turborepo with pnpm workspaces
- **Testing:** Vitest (282 tests: unit, integration, battle, k6)
- **Linting:** ESLint 9 with TypeScript rules
- **Formatting:** Prettier
- **Containerization:** Docker with multi-stage builds

## Development

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run all tests
pnpm test

# Run unit tests only
pnpm test:unit

# Run integration tests (requires Postgres + Redis)
pnpm test:integration

# Type-check all packages
pnpm typecheck

# Lint
pnpm lint

# Start dev mode (watch)
pnpm dev

# Start production server
pnpm start

# Start cluster mode (multi-core)
pnpm start:cluster
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) -- System design, pipelines, token rotation
- [API Reference](docs/API.md) -- Complete REST API with examples
- [Security](docs/SECURITY.md) -- Hashing, token reuse detection, OWASP compliance
- [Performance](docs/PERFORMANCE.md) -- Benchmarks, scaling, capacity planning
- [Trade-offs](docs/TRADEOFFS.md) -- Security vs performance profiles, configurable options
- [Deployment](docs/DEPLOYMENT.md) -- Docker, Kubernetes, environment variables
- [Testing](docs/TESTING.md) -- Test strategy, running tests, writing custom tests

## License

Apache-2.0
