# Testing

ArgusJS has a comprehensive test suite covering unit tests, integration tests, battle tests (edge cases), and k6 performance tests.

## Test Strategy Overview

| Layer | Framework | What it tests | Infrastructure |
|-------|-----------|---------------|----------------|
| Unit tests | Vitest | Core engine logic, adapters, server routes | None (memory adapters) |
| Integration tests | Vitest | Full pipelines against real databases | PostgreSQL + Redis (Docker) |
| Battle tests | Vitest | Race conditions, edge cases, concurrency | PostgreSQL + Redis (Docker) |
| Performance tests | k6 | Throughput, latency, stress behavior | PostgreSQL + Redis (Docker) |

## Test Counts

| Package | Unit Tests | Notes |
|---------|-----------|-------|
| `@argus/core` | 143 | Registration, login, logout, refresh, MFA, organizations, RBAC, API keys, webhooks, events |
| `@argus/server` | 55 | Route handlers, middleware, error handling, request validation |
| `@argus/client` | 8 | Client SDK, React hooks |
| `@argus/security-engine` | 14 | Brute force, anomaly detection, sharing detection, device trust |
| Integration | 54 | Full auth flows, token rotation, concurrent access, data integrity |
| Battle tests | 22 | TOCTOU races, token replay, session limit edge cases |
| **Total** | **296** | |

## Running Tests

### Prerequisites

```bash
# Install dependencies
pnpm install

# Build all packages (tests import built artifacts)
pnpm build
```

### Unit Tests

Unit tests use in-memory adapters and require no external infrastructure:

```bash
# Run all unit tests
pnpm test:unit

# Run tests for a specific package
cd packages/core && pnpm test
cd packages/server && pnpm test
cd packages/client && pnpm test
cd packages/security && pnpm test

# Run a specific test file
pnpm vitest run packages/core/src/engine/__tests__/login.test.ts

# Watch mode
pnpm vitest --watch packages/core
```

### Integration Tests

Integration tests run against real PostgreSQL and Redis instances:

```bash
# 1. Start infrastructure
docker compose up -d postgres redis

# 2. Wait for health checks to pass
docker compose exec postgres pg_isready -U argus
docker compose exec redis redis-cli ping

# 3. Run integration tests
pnpm test:integration

# Or run specific integration test files:
pnpm vitest run tests/integration/auth-flows.test.ts
pnpm vitest run tests/integration/token-rotation.test.ts
pnpm vitest run tests/integration/concurrent-access.test.ts
pnpm vitest run tests/integration/data-integrity.test.ts
pnpm vitest run tests/integration/edge-cases.test.ts
pnpm vitest run tests/integration/battle-test.test.ts
```

### Integration Test Files

| File | Tests | Description |
|------|-------|-------------|
| `auth-flows.test.ts` | Full registration, login, refresh, logout pipelines | Happy path and error cases |
| `token-rotation.test.ts` | Refresh token rotation, reuse detection, family management | Security-critical token handling |
| `concurrent-access.test.ts` | Parallel logins, concurrent refreshes, race conditions | Multi-threaded safety |
| `data-integrity.test.ts` | Foreign keys, cascading deletes, constraint violations | Database correctness |
| `edge-cases.test.ts` | Boundary values, Unicode emails, max lengths | Input handling |
| `battle-test.test.ts` | 22 hardened edge cases: TOCTOU, replay attacks, session limits under concurrency | Security and correctness under stress |

### k6 Performance Tests

Performance tests use [k6](https://k6.io/) and require the server to be running:

```bash
# 1. Start infrastructure + server
docker compose up -d
# OR
pnpm build && pnpm start

# 2. Run all k6 scenarios
cd tests/k6
bash run-all.sh

# 3. Run individual scenarios
k6 run scenarios/login.js
k6 run scenarios/registration.js
k6 run scenarios/token-refresh.js
k6 run scenarios/mixed-realistic.js
k6 run scenarios/brute-force-protection.js
k6 run scenarios/rate-limiter-accuracy.js
k6 run scenarios/session-management.js
k6 run scenarios/concurrent-sessions.js
k6 run scenarios/password-reset.js
k6 run scenarios/pure-refresh.js
k6 run scenarios/token-refresh-isolated.js
```

### k6 Scenarios

| Scenario | Description |
|----------|-------------|
| `login.js` | Login throughput and latency |
| `registration.js` | Registration with Argon2 hashing |
| `token-refresh.js` | Token rotation throughput |
| `pure-refresh.js` | Isolated refresh (no login warm-up) |
| `token-refresh-isolated.js` | Single-user refresh chain |
| `mixed-realistic.js` | Realistic traffic mix (register, login, refresh, profile, sessions) |
| `brute-force-protection.js` | Verify lockout after N failed attempts |
| `rate-limiter-accuracy.js` | Verify rate limiter enforces limits correctly |
| `session-management.js` | Session creation, listing, revocation |
| `concurrent-sessions.js` | Session limits under concurrent logins |
| `password-reset.js` | Password reset flow |

## Unit Test Architecture

### Core Engine Tests

Core engine tests use a helper function that creates an `Argus` instance with all memory adapters:

```typescript
// packages/core/src/engine/__tests__/helpers.ts
import { Argus } from '../argus.js';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';
import { Argon2Hasher } from '@argus/hash-argon2';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { MemoryEmailProvider } from '@argus/email-memory';

export async function createTestArgus(overrides = {}) {
  const argus = new Argus({
    db: new MemoryDbAdapter(),
    cache: new MemoryCacheAdapter(),
    hasher: new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 }),
    token: new RS256TokenProvider({ issuer: 'test', audience: ['test'] }),
    email: new MemoryEmailProvider(),
    ...overrides,
  });
  await argus.init();
  return argus;
}
```

Each test file covers a specific domain:

- **registration.test.ts** -- happy path, duplicate email, weak password, policy violations
- **login.test.ts** -- correct credentials, wrong password, lockout, MFA challenge
- **logout.test.ts** -- single session, all devices
- **token-refresh.test.ts** -- normal rotation, expired token, reuse detection
- **mfa.test.ts** -- setup, verify, disable, backup codes
- **email-verification.test.ts** -- verify, expired token, already verified
- **password-reset.test.ts** -- request, reset, expired token, password history
- **organizations.test.ts** -- create, invite, join, leave, roles
- **authorization.test.ts** -- RBAC, permissions, access policies
- **api-keys.test.ts** -- create, revoke, scope validation
- **webhooks.test.ts** -- subscribe, dispatch, HMAC verification
- **event-emitter.test.ts** -- exact match, wildcard, namespace wildcard

### Server Tests

Server tests use Fastify's `inject()` method to send HTTP requests without starting a real server:

```typescript
import { createApp } from '../app.js';

const app = await createApp({ argus: testArgus, logger: false });

const res = await app.inject({
  method: 'POST',
  url: '/v1/auth/register',
  payload: { email: 'test@example.com', password: 'Test123!', displayName: 'Test' },
});

expect(res.statusCode).toBe(201);
expect(JSON.parse(res.body).user.email).toBe('test@example.com');
```

## Writing Custom Tests

### Testing a Custom Adapter

If you implement a custom adapter, test it against the same interface:

```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MyCustomDbAdapter } from './my-adapter.js';

describe('MyCustomDbAdapter', () => {
  let db: MyCustomDbAdapter;

  beforeEach(async () => {
    db = new MyCustomDbAdapter({ /* config */ });
    await db.init();
  });

  afterEach(async () => {
    await db.shutdown();
  });

  it('should create and find a user by email', async () => {
    const user = await db.createUser({
      email: 'test@example.com',
      passwordHash: 'hash',
      displayName: 'Test',
      roles: ['user'],
      emailVerified: false,
    });

    const found = await db.findUserByEmail('test@example.com');
    expect(found).not.toBeNull();
    expect(found!.id).toBe(user.id);
  });

  it('should atomically revoke refresh token', async () => {
    // Create user, session, and token...
    const token = await db.createRefreshToken({ /* ... */ });

    // First call should succeed
    const result1 = await db.revokeRefreshTokenIfActive(token.id, 'rotated');
    expect(result1).toBe(true);

    // Second call should fail (already revoked)
    const result2 = await db.revokeRefreshTokenIfActive(token.id, 'rotated');
    expect(result2).toBe(false);
  });
});
```

### Testing with the Full Engine

```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createTestArgus } from './helpers.js';

describe('My Feature', () => {
  let argus: Argus;

  beforeEach(async () => {
    argus = await createTestArgus();
  });

  afterEach(async () => {
    await argus.shutdown();
  });

  it('should register and login', async () => {
    const reg = await argus.register({
      email: 'test@example.com',
      password: 'SecurePass123!',
      displayName: 'Test',
      ipAddress: '127.0.0.1',
      userAgent: 'test',
    });

    expect(reg.user.email).toBe('test@example.com');
    expect(reg.accessToken).toBeDefined();

    const login = await argus.login('test@example.com', 'SecurePass123!', {
      ipAddress: '127.0.0.1',
      userAgent: 'test',
    });

    expect(login.user.id).toBe(reg.user.id);
  });
});
```

## CI Pipeline

Recommended GitHub Actions workflow:

```yaml
name: Test
on: [push, pull_request]

jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm
      - run: pnpm install
      - run: pnpm build
      - run: pnpm test:unit

  integration:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: argus
          POSTGRES_PASSWORD: argus
          POSTGRES_DB: argus
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    env:
      DATABASE_URL: postgres://argus:argus@localhost:5432/argus
      REDIS_URL: redis://localhost:6379
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm
      - run: pnpm install
      - run: pnpm build
      - run: pnpm test:integration
```
