# ArgusJS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build ArgusJS — a fully pluggable, enterprise-grade authentication platform with 42 packages, 60+ API endpoints, and every component swappable.

**Architecture:** Turborepo monorepo with `@argus/core` as the engine (plugin registry, auth pipeline, event system), adapter packages for every pluggable component (DB, cache, hashing, tokens, MFA, OAuth, email, rate limiting, security), `@argus/server` as a Fastify REST API, `@argus/dashboard` as a Next.js admin UI, and `@argus/client` as a TypeScript SDK.

**Tech Stack:** TypeScript (strict), Turborepo, Fastify, Next.js, Drizzle ORM, PostgreSQL 16, Redis 7, Argon2id, jose (JWT RS256), otplib (TOTP), openid-client, zxcvbn, Vitest, Docker Compose, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-03-20-argusjs-design.md`

---

## Phase Overview

This plan is split into 7 phases. Each phase produces working, testable software and builds on the previous one.

| Phase | What | Tasks |
|-------|------|-------|
| 1 | Monorepo scaffolding + core interfaces | 1-3 |
| 2 | Core engine + memory adapters (fully testable without infra) | 4-10 |
| 3 | Real adapters (Postgres, Redis, Argon2, JWT RS256) | 11-16 |
| 4 | Server — Fastify REST API | 17-23 |
| 5 | OAuth, MFA, Security Engine | 24-29 |
| 6 | Enterprise features (orgs, RBAC, API keys, webhooks, impersonation) | 30-35 |
| 7 | Dashboard, Client SDK, Docker, CI/CD | 36-40 |

---

## Phase 1: Monorepo Scaffolding + Core Interfaces

### Task 1: Initialize Monorepo

**Files:**
- Create: `package.json`
- Create: `turbo.json`
- Create: `tsconfig.base.json`
- Create: `.gitignore`
- Create: `.env.example`
- Create: `.npmrc`
- Create: `.prettierrc`
- Create: `eslint.config.mjs`
- Create: `vitest.workspace.ts`

- [ ] **Step 1: Create root package.json**

```json
{
  "name": "argus",
  "private": true,
  "workspaces": ["packages/*", "packages/db-adapters/*", "packages/cache-adapters/*", "packages/hash-adapters/*", "packages/token-adapters/*", "packages/mfa-adapters/*", "packages/oauth-providers/*", "packages/email-adapters/*", "packages/rate-limit-adapters/*", "packages/password-policy/*", "packages/security"],
  "scripts": {
    "build": "turbo run build",
    "test": "turbo run test",
    "test:unit": "turbo run test:unit",
    "test:integration": "turbo run test:integration",
    "dev": "turbo run dev",
    "lint": "turbo run lint",
    "typecheck": "turbo run typecheck",
    "clean": "turbo run clean && rm -rf node_modules"
  },
  "devDependencies": {
    "turbo": "^2.8.0",
    "typescript": "^5.7.0",
    "vitest": "^3.2.0",
    "eslint": "^9.0.0",
    "prettier": "^3.8.0",
    "@types/node": "^22.0.0"
  },
  "packageManager": "pnpm@9.15.0",
  "engines": {
    "node": ">=20.0.0"
  }
}
```

- [ ] **Step 2: Create turbo.json**

```json
{
  "$schema": "https://turbo.build/schema.json",
  "tasks": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": ["dist/**"]
    },
    "test": {
      "dependsOn": ["build"]
    },
    "test:unit": {},
    "test:integration": {
      "dependsOn": ["build"]
    },
    "dev": {
      "cache": false,
      "persistent": true
    },
    "lint": {},
    "typecheck": {
      "dependsOn": ["^build"]
    },
    "clean": {
      "cache": false
    }
  }
}
```

- [ ] **Step 3: Create tsconfig.base.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "dist",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "isolatedModules": true
  }
}
```

- [ ] **Step 4: Create .gitignore, .env.example, .npmrc, .prettierrc**

`.gitignore`:
```
node_modules/
dist/
.turbo/
.env
*.log
coverage/
.next/
```

`.env.example`:
```bash
# Database
DATABASE_URL=postgres://argus:argus@localhost:5432/argus

# Redis
REDIS_URL=redis://localhost:6379

# JWT
JWT_PRIVATE_KEY=<paste RSA private key PEM here>
JWT_KEY_ID=dev-key-001
JWT_ISSUER=auth.localhost
JWT_AUDIENCE=api.localhost

# MFA
MFA_ENCRYPTION_KEY=<32-byte hex key>
MFA_APP_NAME=ArgusJS

# Email (SendGrid)
SENDGRID_API_KEY=
EMAIL_FROM=noreply@localhost

# Server
PORT=3100
HOST=0.0.0.0
LOG_LEVEL=debug

# OAuth
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# Dashboard
NEXT_PUBLIC_API_URL=http://localhost:3100
```

`.npmrc`:
```
shamefully-hoist=true
```

`.prettierrc`:
```json
{
  "semi": true,
  "singleQuote": true,
  "trailingComma": "all",
  "printWidth": 100,
  "tabWidth": 2
}
```

- [ ] **Step 5: Create vitest.workspace.ts**

```typescript
import { defineWorkspace } from 'vitest/config';

export default defineWorkspace(['packages/*/vitest.config.ts', 'packages/*/*/vitest.config.ts']);
```

- [ ] **Step 6: Create eslint.config.mjs**

```javascript
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },
  {
    ignores: ['**/dist/**', '**/node_modules/**', '**/.next/**'],
  },
);
```

- [ ] **Step 7: Install dependencies**

Run: `pnpm install`
Expected: lockfile created, node_modules populated

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "chore: initialize argusjs monorepo with turborepo"
```

---

### Task 2: Core Package — Types & Interfaces

**Files:**
- Create: `packages/core/package.json`
- Create: `packages/core/tsconfig.json`
- Create: `packages/core/vitest.config.ts`
- Create: `packages/core/src/index.ts`
- Create: `packages/core/src/types/entities.ts`
- Create: `packages/core/src/types/inputs.ts`
- Create: `packages/core/src/types/responses.ts`
- Create: `packages/core/src/types/errors.ts`
- Create: `packages/core/src/types/events.ts`
- Create: `packages/core/src/types/config.ts`
- Create: `packages/core/src/types/index.ts`

- [ ] **Step 1: Create packages/core/package.json**

```json
{
  "name": "@argus/core",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    }
  },
  "scripts": {
    "build": "tsc",
    "test": "vitest run",
    "test:unit": "vitest run",
    "dev": "tsc --watch",
    "lint": "eslint src/",
    "typecheck": "tsc --noEmit",
    "clean": "rm -rf dist"
  },
  "devDependencies": {
    "typescript": "^5.7.0",
    "vitest": "^3.2.0"
  }
}
```

- [ ] **Step 2: Create packages/core/tsconfig.json**

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "outDir": "dist",
    "rootDir": "src"
  },
  "include": ["src"]
}
```

- [ ] **Step 3: Create packages/core/vitest.config.ts**

```typescript
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
  },
});
```

- [ ] **Step 4: Create entities types — packages/core/src/types/entities.ts**

All entity interfaces from the design spec: `User`, `Session`, `RefreshToken`, `PasswordResetToken`, `EmailVerificationToken`, `OAuthLink`, `MFASecret`, `AuditLogEntry`, `AuditAction`, `Organization`, `OrgSettings`, `OrgMember`, `OrgInvite`, `ApiKey`, `Role`, `AccessPolicy`, `PolicyCondition`, `Webhook`, `TrustedDevice`.

- [ ] **Step 5: Create input types — packages/core/src/types/inputs.ts**

All input interfaces: `CreateUserInput`, `CreateSessionInput`, `CreateRefreshTokenInput`, `CreateResetTokenInput`, `CreateVerificationInput`, `LinkOAuthInput`, `SaveMFAInput`, `CreateOrgInput`, `AddOrgMemberInput`, `CreateOrgInviteInput`, `CreateApiKeyInput`, `CreateWebhookInput`.

Also filter types: `AuditLogFilter`, `UserFilter`, `SystemStats`, `UserDataExport`.

- [ ] **Step 6: Create response types — packages/core/src/types/responses.ts**

All response interfaces: `AuthResponse`, `UserResponse`, `MFAChallengeResponse`, `SessionResponse`, `MFASetupData`, `OAuthTokens`, `OAuthUserProfile`, `RateLimitResult`, `PasswordPolicyResult`, `AccessTokenClaims`.

- [ ] **Step 7: Create error types — packages/core/src/types/errors.ts**

`ErrorResponse`, `ValidationError`, `ErrorCode` type union, and an `ArgusError` class:

```typescript
export class ArgusError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message: string,
    public readonly statusCode: number,
    public readonly details?: ValidationError[],
  ) {
    super(message);
    this.name = 'ArgusError';
  }
}
```

Also create factory functions for every error type:

```typescript
export const Errors = {
  validation: (details: ValidationError[]) =>
    new ArgusError('VALIDATION_ERROR', 'Request validation failed', 400, details),
  invalidCredentials: () =>
    new ArgusError('INVALID_CREDENTIALS', 'Invalid email or password', 401),
  invalidToken: () =>
    new ArgusError('INVALID_TOKEN', 'Access token is invalid or expired', 401),
  invalidRefreshToken: () =>
    new ArgusError('INVALID_REFRESH_TOKEN', 'Refresh token is invalid, expired, or revoked', 401),
  refreshTokenReuse: () =>
    new ArgusError('REFRESH_TOKEN_REUSE_DETECTED', 'Refresh token reuse detected. All sessions revoked.', 401),
  sessionExpired: () =>
    new ArgusError('SESSION_EXPIRED', 'Session has been revoked', 401),
  mfaRequired: () =>
    new ArgusError('MFA_REQUIRED', 'Multi-factor authentication is required', 403),
  invalidMfaCode: () =>
    new ArgusError('INVALID_MFA_CODE', 'Verification code is incorrect', 400),
  invalidMfaToken: () =>
    new ArgusError('INVALID_MFA_TOKEN', 'MFA challenge token is invalid or expired', 401),
  mfaAlreadyEnabled: () =>
    new ArgusError('MFA_ALREADY_ENABLED', 'MFA is already active', 409),
  mfaNotEnabled: () =>
    new ArgusError('MFA_NOT_ENABLED', 'MFA is not enabled on this account', 400),
  emailNotVerified: () =>
    new ArgusError('EMAIL_NOT_VERIFIED', 'Email verification required', 403),
  forbidden: () =>
    new ArgusError('FORBIDDEN', 'Insufficient permissions', 403),
  notFound: (resource: string) =>
    new ArgusError('NOT_FOUND', `${resource} not found`, 404),
  emailExists: () =>
    new ArgusError('EMAIL_ALREADY_EXISTS', 'Email is already registered', 409),
  weakPassword: (reasons: string[], suggestions?: string[]) =>
    new ArgusError('WEAK_PASSWORD', 'Password does not meet strength requirements', 422),
  breachedPassword: () =>
    new ArgusError('BREACHED_PASSWORD', 'Password found in data breach database', 422),
  passwordRecentlyUsed: () =>
    new ArgusError('PASSWORD_RECENTLY_USED', 'Cannot reuse a recent password', 422),
  accountLocked: (until: Date) =>
    new ArgusError('ACCOUNT_LOCKED', `Account locked until ${until.toISOString()}`, 423),
  rateLimitExceeded: (retryAfter: number) =>
    new ArgusError('RATE_LIMIT_EXCEEDED', `Too many requests. Retry after ${retryAfter}s`, 429),
  oauthFailed: (message: string) =>
    new ArgusError('OAUTH_FAILED', message, 401),
  providerNotConfigured: (provider: string) =>
    new ArgusError('PROVIDER_NOT_CONFIGURED', `OAuth provider '${provider}' is not configured`, 400),
  providerAlreadyLinked: () =>
    new ArgusError('PROVIDER_ALREADY_LINKED', 'This provider is already linked', 409),
  cannotUnlinkOnlyAuth: () =>
    new ArgusError('CANNOT_UNLINK_ONLY_AUTH', 'Cannot unlink only authentication method', 400),
  internal: (message?: string) =>
    new ArgusError('INTERNAL_SERVER_ERROR', message ?? 'An unexpected error occurred', 500),
};
```

- [ ] **Step 8: Create event types — packages/core/src/types/events.ts**

`ArgusEvent`, `ArgusEventType` union from the spec.

- [ ] **Step 9: Create config types — packages/core/src/types/config.ts**

`ArgusConfig` — the full configuration object accepted by the `Argus` constructor. Includes all adapter slots, session config, lockout config, password config, email verification config, audit config, and hooks.

- [ ] **Step 10: Create types barrel — packages/core/src/types/index.ts**

Re-export everything from all type files.

- [ ] **Step 11: Create main barrel — packages/core/src/index.ts**

```typescript
export * from './types/index.js';
```

- [ ] **Step 12: Build and verify**

Run: `cd packages/core && pnpm build`
Expected: dist/ directory created with all .js and .d.ts files, no errors.

- [ ] **Step 13: Commit**

```bash
git add packages/core/
git commit -m "feat(core): add all type definitions and error system"
```

---

### Task 3: Core Package — Plugin Interfaces

**Files:**
- Create: `packages/core/src/interfaces/db-adapter.ts`
- Create: `packages/core/src/interfaces/cache-adapter.ts`
- Create: `packages/core/src/interfaces/password-hasher.ts`
- Create: `packages/core/src/interfaces/token-provider.ts`
- Create: `packages/core/src/interfaces/mfa-provider.ts`
- Create: `packages/core/src/interfaces/oauth-provider.ts`
- Create: `packages/core/src/interfaces/email-provider.ts`
- Create: `packages/core/src/interfaces/rate-limiter.ts`
- Create: `packages/core/src/interfaces/password-policy.ts`
- Create: `packages/core/src/interfaces/security-engine.ts`
- Create: `packages/core/src/interfaces/index.ts`
- Modify: `packages/core/src/index.ts`

- [ ] **Step 1: Create all plugin interfaces**

Each file contains exactly one interface as defined in the spec (Section 4). Every method has full JSDoc documentation with param/return types.

`db-adapter.ts` — `DbAdapter` interface (full CRUD for all 18 tables)
`cache-adapter.ts` — `CacheAdapter` interface (get/set/del/exists/incr/sadd/sismember/smembers)
`password-hasher.ts` — `PasswordHasher` interface (hash/verify/needsRehash)
`token-provider.ts` — `TokenProvider` interface (sign/verify access+MFA tokens, JWKS, key rotation)
`mfa-provider.ts` — `MFAProvider` interface (generateSecret/verifyCode/generateBackupCodes)
`oauth-provider.ts` — `OAuthProviderAdapter` interface (getAuthorizationUrl/exchangeCode/getUserProfile)
`email-provider.ts` — `EmailProvider` interface (send verification/reset/alert/welcome/invite/device emails)
`rate-limiter.ts` — `RateLimiter` interface (check/reset)
`password-policy.ts` — `PasswordPolicy` interface (validate)
`security-engine.ts` — `SecurityEngine` interface + `RiskAssessment`, `RiskFactor`, `SharingDetection`, `BruteForceResult`, `LockStatus`, `LoginRiskContext`, `DeviceInfo`, `GeoLocation` types

- [ ] **Step 2: Create interfaces barrel — packages/core/src/interfaces/index.ts**

Re-export all interfaces.

- [ ] **Step 3: Update main barrel**

```typescript
export * from './types/index.js';
export * from './interfaces/index.js';
```

- [ ] **Step 4: Build and verify**

Run: `cd packages/core && pnpm build`
Expected: clean build, no errors

- [ ] **Step 5: Commit**

```bash
git add packages/core/
git commit -m "feat(core): add all plugin interfaces"
```

---

## Phase 2: Core Engine + Memory Adapters

### Task 4: Event Emitter

**Files:**
- Create: `packages/core/src/engine/event-emitter.ts`
- Create: `packages/core/src/engine/__tests__/event-emitter.test.ts`

- [ ] **Step 1: Write failing tests**

Test cases:
- Registers a listener and receives events
- Supports wildcard listeners (`user.*` matches `user.login`)
- Removes listeners with `off()`
- Multiple listeners on same event
- `once()` listener fires once then auto-removes
- Async listeners are awaited by `emitAsync()`

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/core && pnpm vitest run src/engine/__tests__/event-emitter.test.ts`
Expected: all tests FAIL

- [ ] **Step 3: Implement EventEmitter**

```typescript
export class ArgusEventEmitter {
  private listeners: Map<string, Set<Function>> = new Map();

  on(event: string, handler: Function): void { ... }
  once(event: string, handler: Function): void { ... }
  off(event: string, handler: Function): void { ... }
  async emit(event: string, data: unknown): Promise<void> { ... }
}
```

Wildcard matching: `user.*` matches any event starting with `user.`. `*` matches everything.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/core && pnpm vitest run src/engine/__tests__/event-emitter.test.ts`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/engine/
git commit -m "feat(core): add event emitter with wildcard support"
```

---

### Task 5: Crypto Utilities

**Files:**
- Create: `packages/core/src/utils/crypto.ts`
- Create: `packages/core/src/utils/__tests__/crypto.test.ts`

- [ ] **Step 1: Write failing tests**

Test cases:
- `generateToken(bytes)` returns a URL-safe base64 string of correct length
- `hashToken(token)` returns a SHA-256 hex string
- `hashToken` is deterministic (same input = same output)
- `generateUUID()` returns valid UUID v4
- `encryptAES256GCM(plaintext, key)` encrypts and `decryptAES256GCM(ciphertext, key)` decrypts correctly
- AES decryption with wrong key throws
- `timingSafeEqual(a, b)` returns true for equal strings, false for different

- [ ] **Step 2: Run tests — expect FAIL**

- [ ] **Step 3: Implement using Node.js `crypto` module**

All functions use `node:crypto`. No external dependencies.

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/utils/
git commit -m "feat(core): add crypto utilities (token gen, hashing, AES-256-GCM)"
```

---

### Task 6: Memory DB Adapter

**Files:**
- Create: `packages/db-adapters/memory/package.json`
- Create: `packages/db-adapters/memory/tsconfig.json`
- Create: `packages/db-adapters/memory/vitest.config.ts`
- Create: `packages/db-adapters/memory/src/index.ts`
- Create: `packages/db-adapters/memory/src/memory-db-adapter.ts`
- Create: `packages/db-adapters/memory/src/__tests__/memory-db-adapter.test.ts`

- [ ] **Step 1: Create package scaffolding**

`package.json` with `@argus/db-memory` name, dependency on `@argus/core`.

- [ ] **Step 2: Write failing tests**

Test every method on `DbAdapter` interface:
- User CRUD (create, findByEmail, findById, update, softDelete)
- Session CRUD (create, get, getActive, revoke, revokeAll, count)
- Refresh token CRUD (create, findByHash, revoke, revokeFamily, revokeAll)
- Password reset tokens (create, findByHash, markUsed, invalidateAll)
- Email verification tokens (create, findByHash, markUsed)
- OAuth links (link, find, getUserProviders, unlink)
- MFA secrets (save, get, delete, markBackupCodeUsed)
- Password history (get, add)
- Audit log (write, query with filters)
- Organizations (create, get, update, delete, members, invites)
- API keys (create, findByHash, list, revoke)
- Roles (create, get, list, update, delete)
- Webhooks (create, list, update, delete)
- Trusted devices (save, get, remove, isTrusted)
- Admin (listUsers with pagination/filters, getSystemStats, exportUserData)

- [ ] **Step 3: Run tests — expect FAIL**

- [ ] **Step 4: Implement MemoryDbAdapter**

In-memory Maps for each entity type. All methods are async to match the interface. Full filtering and pagination support in `listUsers` and `queryAuditLog`.

- [ ] **Step 5: Run tests — expect PASS**

- [ ] **Step 6: Commit**

```bash
git add packages/db-adapters/memory/
git commit -m "feat(db-memory): add in-memory database adapter"
```

---

### Task 7: Memory Cache Adapter

**Files:**
- Create: `packages/cache-adapters/memory/package.json`
- Create: `packages/cache-adapters/memory/tsconfig.json`
- Create: `packages/cache-adapters/memory/vitest.config.ts`
- Create: `packages/cache-adapters/memory/src/index.ts`
- Create: `packages/cache-adapters/memory/src/memory-cache-adapter.ts`
- Create: `packages/cache-adapters/memory/src/__tests__/memory-cache-adapter.test.ts`

- [ ] **Step 1: Write failing tests**

Test every method on `CacheAdapter`:
- get/set/del/exists with TTL expiry
- incr with TTL (atomic counter)
- sadd/sismember/smembers (set operations)
- TTL auto-expiry (use `vi.useFakeTimers()`)
- healthCheck returns true

- [ ] **Step 2: Run tests — expect FAIL**

- [ ] **Step 3: Implement MemoryCacheAdapter**

In-memory Map with TTL tracking using `setTimeout` or timestamp comparison.

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add packages/cache-adapters/memory/
git commit -m "feat(cache-memory): add in-memory cache adapter"
```

---

### Task 8: Memory Rate Limiter + Memory Email Adapter

**Files:**
- Create: `packages/rate-limit-adapters/memory/package.json` + src + tests
- Create: `packages/email-adapters/memory/package.json` + src + tests

- [ ] **Step 1: Write failing tests for MemoryRateLimiter**

- `check()` allows requests under limit
- `check()` blocks requests over limit
- Sliding window resets after window expires
- `reset()` clears the counter

- [ ] **Step 2: Implement MemoryRateLimiter**

Sliding window using an array of timestamps per key.

- [ ] **Step 3: Run tests — expect PASS**

- [ ] **Step 4: Write failing tests for MemoryEmailProvider**

- All send methods store emails in an internal array
- `getSentEmails()` returns all sent emails for testing assertions
- `clear()` resets the array

- [ ] **Step 5: Implement MemoryEmailProvider**

Simply pushes email records to an array. Used for testing only.

- [ ] **Step 6: Run tests — expect PASS**

- [ ] **Step 7: Commit**

```bash
git add packages/rate-limit-adapters/memory/ packages/email-adapters/memory/
git commit -m "feat: add memory rate limiter and email adapters"
```

---

### Task 9: Core Engine — Argus Class (Registration + Login + Logout)

**Files:**
- Create: `packages/core/src/engine/argus.ts`
- Create: `packages/core/src/engine/auth-pipeline.ts`
- Create: `packages/core/src/engine/__tests__/registration.test.ts`
- Create: `packages/core/src/engine/__tests__/login.test.ts`
- Create: `packages/core/src/engine/__tests__/logout.test.ts`

This is the heart of the system — the `Argus` class that wires all adapters together and implements the authentication pipeline.

- [ ] **Step 1: Write failing registration tests**

Test cases:
- Successful registration returns AuthResponse with user + tokens
- Registration with existing email throws EMAIL_ALREADY_EXISTS
- Registration with weak password throws WEAK_PASSWORD (if policy configured)
- Registration emits `user.registered` event
- Registration creates audit log entry
- Registration sends verification email
- hooks.afterRegister is called with the created user

All tests use memory adapters (no infra needed). Create a `createTestArgus()` helper that wires up all memory adapters with a simple mock token provider (returns predictable strings) and a mock hasher (returns `hashed_<password>`).

- [ ] **Step 2: Run tests — expect FAIL**

- [ ] **Step 3: Implement Argus class constructor and init/shutdown**

```typescript
export class Argus {
  constructor(config: ArgusConfig) { ... }
  async init(): Promise<void> { /* calls init() on all adapters */ }
  async shutdown(): Promise<void> { /* calls shutdown() on all adapters */ }
}
```

- [ ] **Step 4: Implement register() method**

Follow the registration pipeline from spec section 5.1 exactly.

- [ ] **Step 5: Run registration tests — expect PASS**

- [ ] **Step 6: Write failing login tests**

Test cases:
- Successful login returns AuthResponse
- Login with wrong email throws INVALID_CREDENTIALS
- Login with wrong password throws INVALID_CREDENTIALS
- Login increments failedLoginAttempts on failure
- Login resets failedLoginAttempts on success
- Locked account throws ACCOUNT_LOCKED
- Login with MFA enabled returns MFAChallengeResponse
- Login enforces session limit (revokes oldest)
- Login emits `user.login` event
- Login creates audit log entry
- hooks.beforeLogin and hooks.afterLogin are called

- [ ] **Step 7: Implement login() method**

Follow the login pipeline from spec section 5.2.

- [ ] **Step 8: Run login tests — expect PASS**

- [ ] **Step 9: Write failing logout tests**

- Logout revokes current session
- Logout with allDevices revokes all sessions
- Logout emits `user.logout` event

- [ ] **Step 10: Implement logout() method**

- [ ] **Step 11: Run logout tests — expect PASS**

- [ ] **Step 12: Commit**

```bash
git add packages/core/src/engine/
git commit -m "feat(core): add Argus engine with register, login, logout pipelines"
```

---

### Task 10: Core Engine — Token Refresh + Password Reset + Email Verification

**Files:**
- Create: `packages/core/src/engine/__tests__/token-refresh.test.ts`
- Create: `packages/core/src/engine/__tests__/password-reset.test.ts`
- Create: `packages/core/src/engine/__tests__/email-verification.test.ts`
- Modify: `packages/core/src/engine/argus.ts`

- [ ] **Step 1: Write failing token refresh tests**

- Successful refresh returns new tokens
- Refresh with invalid token throws INVALID_REFRESH_TOKEN
- Refresh with expired token throws INVALID_REFRESH_TOKEN
- Refresh token rotation: old token revoked with reason 'rotated'
- Refresh token reuse detection: revoked token presented → revoke entire family + all sessions
- Token reuse emits `token.reuse_detected` and `security.suspicious_activity`

- [ ] **Step 2: Implement refresh() method**

Follow spec section 5.4.

- [ ] **Step 3: Run tests — expect PASS**

- [ ] **Step 4: Write failing password reset tests**

- forgotPassword always succeeds (no user enumeration)
- forgotPassword sends reset email when user exists
- forgotPassword does nothing when user doesn't exist (but still returns success)
- resetPassword with valid token changes password
- resetPassword revokes all sessions and tokens
- resetPassword with invalid/expired/used token throws
- resetPassword checks password history
- resetPassword runs password policies

- [ ] **Step 5: Implement forgotPassword() and resetPassword() methods**

Follow spec section 5.6.

- [ ] **Step 6: Run tests — expect PASS**

- [ ] **Step 7: Write failing email verification tests**

- verifyEmail with valid token marks email as verified
- verifyEmail with invalid/expired/used token throws
- resendVerification sends new verification email

- [ ] **Step 8: Implement verifyEmail() and resendVerification() methods**

- [ ] **Step 9: Run tests — expect PASS**

- [ ] **Step 10: Commit**

```bash
git add packages/core/
git commit -m "feat(core): add token refresh, password reset, email verification"
```

---

## Phase 3: Real Adapters

### Task 11: Argon2 Hash Adapter

**Files:**
- Create: `packages/hash-adapters/argon2/package.json`
- Create: `packages/hash-adapters/argon2/tsconfig.json`
- Create: `packages/hash-adapters/argon2/vitest.config.ts`
- Create: `packages/hash-adapters/argon2/src/index.ts`
- Create: `packages/hash-adapters/argon2/src/argon2-hasher.ts`
- Create: `packages/hash-adapters/argon2/src/__tests__/argon2-hasher.test.ts`

- [ ] **Step 1: Write failing tests**

- hash() returns a string starting with `$argon2id$`
- verify() returns true for correct password
- verify() returns false for wrong password
- needsRehash() returns true when params differ from current config
- Hash is different each time (salt is random)

- [ ] **Step 2: Implement Argon2Hasher**

Dependency: `argon2` npm package. Configurable `memoryCost`, `timeCost`, `parallelism`.

```typescript
export class Argon2Hasher implements PasswordHasher {
  name = 'argon2id';
  constructor(private config: { memoryCost?: number; timeCost?: number; parallelism?: number }) {}
  async hash(password: string): Promise<string> { ... }
  async verify(password: string, hash: string): Promise<boolean> { ... }
  needsRehash(hash: string): boolean { ... }
}
```

- [ ] **Step 3: Run tests — expect PASS**

- [ ] **Step 4: Commit**

```bash
git add packages/hash-adapters/argon2/
git commit -m "feat(hash-argon2): add Argon2id password hasher"
```

---

### Task 12: bcrypt + scrypt Hash Adapters

**Files:**
- Create: `packages/hash-adapters/bcrypt/` (full package)
- Create: `packages/hash-adapters/scrypt/` (full package)

- [ ] **Step 1: Implement BcryptHasher**

Dependency: `bcrypt`. Same interface as Argon2.

- [ ] **Step 2: Implement ScryptHasher**

Uses Node.js built-in `crypto.scrypt`. No external dependency.

- [ ] **Step 3: Write tests for both, run, verify PASS**

- [ ] **Step 4: Commit**

```bash
git add packages/hash-adapters/bcrypt/ packages/hash-adapters/scrypt/
git commit -m "feat: add bcrypt and scrypt hash adapters"
```

---

### Task 13: JWT RS256 Token Provider

**Files:**
- Create: `packages/token-adapters/jwt-rs256/package.json`
- Create: `packages/token-adapters/jwt-rs256/src/index.ts`
- Create: `packages/token-adapters/jwt-rs256/src/rs256-token-provider.ts`
- Create: `packages/token-adapters/jwt-rs256/src/__tests__/rs256-token-provider.test.ts`

- [ ] **Step 1: Write failing tests**

- signAccessToken returns a JWT string with 3 parts
- verifyAccessToken decodes and returns correct claims
- verifyAccessToken throws for expired token
- verifyAccessToken throws for tampered token
- signMFAToken returns opaque token, verifyMFAToken returns userId
- getJWKS returns valid JWKS with the public key
- Token contains correct kid, iss, aud, sub claims

- [ ] **Step 2: Implement RS256TokenProvider**

Dependency: `jose`. Generate RSA key pair on init (or use provided PEM). Sign with RS256. JWKS endpoint returns the public key.

- [ ] **Step 3: Run tests — expect PASS**

- [ ] **Step 4: Commit**

```bash
git add packages/token-adapters/jwt-rs256/
git commit -m "feat(token-rs256): add JWT RS256 token provider with JWKS"
```

---

### Task 14: JWT ES256 + HS256 Token Providers

**Files:**
- Create: `packages/token-adapters/jwt-es256/` (full package)
- Create: `packages/token-adapters/jwt-hs256/` (full package)

- [ ] **Step 1: Implement ES256 (ECDSA) and HS256 (symmetric) providers**

Both follow TokenProvider interface. ES256 uses `jose` with EC keys. HS256 uses `jose` with a shared secret.

- [ ] **Step 2: Write tests, run, verify PASS**

- [ ] **Step 3: Commit**

```bash
git add packages/token-adapters/jwt-es256/ packages/token-adapters/jwt-hs256/
git commit -m "feat: add JWT ES256 and HS256 token providers"
```

---

### Task 15: PostgreSQL DB Adapter

**Files:**
- Create: `packages/db-adapters/postgres/package.json`
- Create: `packages/db-adapters/postgres/src/index.ts`
- Create: `packages/db-adapters/postgres/src/postgres-adapter.ts`
- Create: `packages/db-adapters/postgres/src/schema/` (Drizzle schema files for all 18 tables)
- Create: `packages/db-adapters/postgres/src/migrations/` (SQL migration files)
- Create: `packages/db-adapters/postgres/src/__tests__/postgres-adapter.integration.test.ts`
- Create: `packages/db-adapters/postgres/drizzle.config.ts`

- [ ] **Step 1: Define Drizzle schema for all 18 tables**

Split into files:
- `schema/users.ts`
- `schema/sessions.ts`
- `schema/refresh-tokens.ts`
- `schema/password-reset-tokens.ts`
- `schema/email-verification-tokens.ts`
- `schema/oauth-providers.ts`
- `schema/mfa-secrets.ts`
- `schema/password-history.ts`
- `schema/audit-log.ts`
- `schema/organizations.ts`
- `schema/org-members.ts`
- `schema/org-invites.ts`
- `schema/api-keys.ts`
- `schema/roles.ts`
- `schema/access-policies.ts`
- `schema/webhooks.ts`
- `schema/trusted-devices.ts`
- `schema/rate-limit-overrides.ts`
- `schema/index.ts`

All tables in `auth` schema. Use citext for email. UUID primary keys. Full indexes, constraints, and comments matching the knowledge vault blueprint.

- [ ] **Step 2: Generate migration from schema**

Run: `pnpm drizzle-kit generate`

- [ ] **Step 3: Implement PostgresAdapter**

Implements full `DbAdapter` interface using Drizzle queries. Dependency: `drizzle-orm`, `postgres` (postgres.js driver).

- [ ] **Step 4: Write integration tests**

Same test cases as memory adapter but using a real PostgreSQL instance. Tests use `beforeAll` to run migrations and `afterAll` to drop the schema. Use Docker Compose for test DB.

- [ ] **Step 5: Run integration tests — expect PASS**

Run: `docker compose up -d postgres && cd packages/db-adapters/postgres && pnpm test:integration`

- [ ] **Step 6: Commit**

```bash
git add packages/db-adapters/postgres/
git commit -m "feat(db-postgres): add PostgreSQL adapter with Drizzle ORM and 18-table schema"
```

---

### Task 16: Redis Cache Adapter + Redis Rate Limiter

**Files:**
- Create: `packages/cache-adapters/redis/` (full package)
- Create: `packages/rate-limit-adapters/redis/` (full package)

- [ ] **Step 1: Implement RedisCacheAdapter**

Dependency: `ioredis`. Implements `CacheAdapter` interface using Redis commands.

- [ ] **Step 2: Implement RedisRateLimiter**

Uses Lua scripts for atomic sliding window rate limiting (as described in the knowledge vault scaling plan).

- [ ] **Step 3: Write integration tests for both (require Docker Redis)**

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add packages/cache-adapters/redis/ packages/rate-limit-adapters/redis/
git commit -m "feat: add Redis cache adapter and sliding window rate limiter"
```

---

## Phase 4: Server — Fastify REST API

### Task 17: Server Scaffolding

**Files:**
- Create: `packages/server/package.json`
- Create: `packages/server/tsconfig.json`
- Create: `packages/server/vitest.config.ts`
- Create: `packages/server/src/index.ts`
- Create: `packages/server/src/app.ts`
- Create: `packages/server/src/server.ts`
- Create: `packages/server/src/plugins/argus.ts` (Fastify plugin that decorates with Argus instance)
- Create: `packages/server/src/plugins/error-handler.ts`
- Create: `packages/server/src/plugins/request-id.ts`
- Create: `packages/server/src/middleware/auth.ts` (Bearer token validation middleware)
- Create: `packages/server/src/middleware/rate-limit.ts`

- [ ] **Step 1: Create app.ts — Fastify factory**

`createApp(argus: Argus)` function that creates a Fastify instance with all plugins and routes registered. Uses `@fastify/sensible`, `@fastify/cors`, `@fastify/helmet`.

- [ ] **Step 2: Create server.ts — standalone entrypoint**

Reads env vars, constructs Argus with real adapters, calls `createApp()`, starts listening. Handles SIGTERM/SIGINT graceful shutdown.

- [ ] **Step 3: Create auth middleware**

Extracts `Bearer` token from `Authorization` header, verifies with `argus.token.verifyAccessToken()`, decorates request with user claims.

- [ ] **Step 4: Create error handler plugin**

Catches `ArgusError` instances and formats them into the `ErrorResponse` envelope. Catches Fastify validation errors and formats them as `VALIDATION_ERROR`.

- [ ] **Step 5: Commit**

```bash
git add packages/server/
git commit -m "feat(server): scaffold Fastify server with plugins and middleware"
```

---

### Task 18: Auth Routes — Register, Login, Refresh, Logout

**Files:**
- Create: `packages/server/src/routes/auth.ts`
- Create: `packages/server/src/__tests__/auth.test.ts`

- [ ] **Step 1: Write failing tests using Fastify inject**

Test each endpoint with `app.inject()` — no real server needed:
- `POST /v1/auth/register` — success 201, validation error 400, email exists 409
- `POST /v1/auth/login` — success 200, MFA challenge 200, invalid creds 401, locked 423
- `POST /v1/auth/refresh` — success 200, invalid token 401, reuse detected 401
- `POST /v1/auth/logout` — success 204, all devices 204

- [ ] **Step 2: Implement route handlers**

Each route: validate input with Fastify JSON Schema, call corresponding `argus.*` method, return formatted response.

- [ ] **Step 3: Run tests — expect PASS**

- [ ] **Step 4: Commit**

```bash
git add packages/server/src/routes/auth.ts packages/server/src/__tests__/auth.test.ts
git commit -m "feat(server): add auth routes (register, login, refresh, logout)"
```

---

### Task 19: Password Routes — Forgot, Reset, Change

**Files:**
- Create: `packages/server/src/routes/password.ts`
- Create: `packages/server/src/__tests__/password.test.ts`

- [ ] **Step 1: Write failing tests**

- `POST /v1/auth/forgot-password` — always 202
- `POST /v1/auth/reset-password` — success 200, invalid token 400, weak password 422
- `POST /v1/auth/change-password` — success 200, wrong current password 401 (requires auth)

- [ ] **Step 2: Implement route handlers**

- [ ] **Step 3: Run tests — expect PASS**

- [ ] **Step 4: Commit**

```bash
git add packages/server/src/routes/password.ts packages/server/src/__tests__/password.test.ts
git commit -m "feat(server): add password routes (forgot, reset, change)"
```

---

### Task 20: Email Verification + User Profile Routes

**Files:**
- Create: `packages/server/src/routes/verification.ts`
- Create: `packages/server/src/routes/profile.ts`
- Create: `packages/server/src/__tests__/verification.test.ts`
- Create: `packages/server/src/__tests__/profile.test.ts`

- [ ] **Step 1: Implement and test**

- `POST /v1/auth/verify-email` — 200, invalid 400
- `POST /v1/auth/resend-verification` — 202 (requires auth)
- `GET /v1/auth/me` — 200 with user + sessions + OAuth providers (requires auth)
- `PATCH /v1/auth/me` — 200 (requires auth)
- `DELETE /v1/auth/me` — 204 soft delete (requires auth)
- `GET /v1/auth/me/export` — 200 GDPR data export (requires auth)

- [ ] **Step 2: Run tests — expect PASS**

- [ ] **Step 3: Commit**

```bash
git add packages/server/src/routes/verification.ts packages/server/src/routes/profile.ts packages/server/src/__tests__/
git commit -m "feat(server): add email verification and user profile routes"
```

---

### Task 21: Session & Device Routes

**Files:**
- Create: `packages/server/src/routes/sessions.ts`
- Create: `packages/server/src/__tests__/sessions.test.ts`

- [ ] **Step 1: Implement and test**

- `GET /v1/auth/sessions` — list active sessions (requires auth)
- `DELETE /v1/auth/sessions/:id` — revoke session (requires auth, must own session)
- `GET /v1/auth/devices` — list trusted devices (requires auth)
- `POST /v1/auth/devices/:id/trust` — trust a device (requires auth)
- `DELETE /v1/auth/devices/:id` — revoke device trust (requires auth)

- [ ] **Step 2: Run tests — expect PASS**

- [ ] **Step 3: Commit**

```bash
git add packages/server/src/routes/sessions.ts packages/server/src/__tests__/sessions.test.ts
git commit -m "feat(server): add session and device management routes"
```

---

### Task 22: Health + JWKS + Metrics Routes

**Files:**
- Create: `packages/server/src/routes/health.ts`
- Create: `packages/server/src/routes/jwks.ts`
- Create: `packages/server/src/__tests__/health.test.ts`

- [ ] **Step 1: Implement and test**

- `GET /v1/health` — 200 `{ status: 'ok' }`
- `GET /v1/health/live` — 200 (liveness)
- `GET /v1/health/ready` — 200/503 (checks DB + cache)
- `GET /.well-known/jwks.json` — 200 with JWKS keys (Cache-Control: public, max-age=3600)
- `GET /v1/metrics` — 200 Prometheus format (if metrics enabled)

- [ ] **Step 2: Run tests — expect PASS**

- [ ] **Step 3: Commit**

```bash
git add packages/server/src/routes/health.ts packages/server/src/routes/jwks.ts packages/server/src/__tests__/health.test.ts
git commit -m "feat(server): add health, JWKS, and metrics routes"
```

---

### Task 23: Admin Routes

**Files:**
- Create: `packages/server/src/routes/admin.ts`
- Create: `packages/server/src/middleware/admin.ts` (role check middleware)
- Create: `packages/server/src/__tests__/admin.test.ts`

- [ ] **Step 1: Create admin middleware**

Checks that the authenticated user has `admin` or `super_admin` role.

- [ ] **Step 2: Implement and test admin routes**

- `GET /v1/admin/users` — paginated, filterable user list
- `GET /v1/admin/users/:id` — user detail
- `PATCH /v1/admin/users/:id` — update user (roles, lock, etc.)
- `DELETE /v1/admin/users/:id` — soft delete
- `POST /v1/admin/users/:id/unlock` — unlock account
- `POST /v1/admin/users/:id/reset-mfa` — disable MFA
- `POST /v1/admin/users/:id/reset-password` — trigger reset
- `POST /v1/admin/impersonate` — impersonation (returns short-lived token with impersonator claims)
- `GET /v1/admin/audit-log` — query audit log
- `GET /v1/admin/stats` — system statistics
- `GET /v1/admin/sessions` — all active sessions

- [ ] **Step 3: Run tests — expect PASS**

- [ ] **Step 4: Commit**

```bash
git add packages/server/src/routes/admin.ts packages/server/src/middleware/admin.ts packages/server/src/__tests__/admin.test.ts
git commit -m "feat(server): add admin routes with impersonation and audit log"
```

---

## Phase 5: OAuth, MFA, Security Engine

### Task 24: TOTP MFA Adapter

**Files:**
- Create: `packages/mfa-adapters/totp/` (full package)

- [ ] **Step 1: Implement TOTPProvider**

Dependency: `otplib`. Implements `MFAProvider` interface.
- `generateSecret()` — returns base32 secret, otpauth:// URI, 10 backup codes
- `verifyCode()` — checks TOTP code with 1-step window tolerance
- `generateBackupCodes()` — 10 codes in `XXXX-XXXX` format

- [ ] **Step 2: Write tests, run, verify PASS**

- [ ] **Step 3: Commit**

```bash
git add packages/mfa-adapters/totp/
git commit -m "feat(mfa-totp): add TOTP MFA adapter"
```

---

### Task 25: WebAuthn MFA Adapter

**Files:**
- Create: `packages/mfa-adapters/webauthn/` (full package)

- [ ] **Step 1: Implement WebAuthnProvider**

Dependency: `@simplewebauthn/server`. Implements `MFAProvider` interface for FIDO2/passkeys.

- [ ] **Step 2: Write tests, run, verify PASS**

- [ ] **Step 3: Commit**

```bash
git add packages/mfa-adapters/webauthn/
git commit -m "feat(mfa-webauthn): add WebAuthn/FIDO2 MFA adapter"
```

---

### Task 26: SMS MFA Adapter

**Files:**
- Create: `packages/mfa-adapters/sms/` (full package)

- [ ] **Step 1: Implement SMSProvider**

Dependency: `twilio`. Sends OTP codes via SMS. Stores code hash in cache with TTL.

- [ ] **Step 2: Write tests (mock Twilio client), run, verify PASS**

- [ ] **Step 3: Commit**

```bash
git add packages/mfa-adapters/sms/
git commit -m "feat(mfa-sms): add SMS MFA adapter"
```

---

### Task 27: Core MFA Pipeline + MFA Server Routes

**Files:**
- Create: `packages/core/src/engine/__tests__/mfa.test.ts`
- Modify: `packages/core/src/engine/argus.ts` (add MFA methods)
- Create: `packages/server/src/routes/mfa.ts`
- Create: `packages/server/src/__tests__/mfa.test.ts`

- [ ] **Step 1: Write failing core tests**

- setupMFA returns secret + QR URL + backup codes
- verifyMFASetup activates MFA on account
- verifyMFALogin completes login flow and returns tokens
- disableMFA removes MFA from account
- Backup code usage marks code as consumed
- regenerateBackupCodes replaces all codes

- [ ] **Step 2: Implement MFA methods on Argus class**

`argus.mfa.setup()`, `argus.mfa.verifySetup()`, `argus.mfa.verifyLogin()`, `argus.mfa.disable()`, `argus.mfa.regenerateBackupCodes()`

- [ ] **Step 3: Run core tests — expect PASS**

- [ ] **Step 4: Implement and test MFA server routes**

- `POST /v1/auth/mfa/setup` — 200
- `POST /v1/auth/mfa/verify` — 200 (setup or login context)
- `POST /v1/auth/mfa/disable` — 204
- `GET /v1/auth/mfa/backup-codes` — 200

- [ ] **Step 5: Run server tests — expect PASS**

- [ ] **Step 6: Commit**

```bash
git add packages/core/ packages/server/
git commit -m "feat: add MFA pipeline (setup, verify, disable, backup codes) + routes"
```

---

### Task 28: OAuth Providers + OAuth Pipeline

**Files:**
- Create: `packages/oauth-providers/google/` (full package)
- Create: `packages/oauth-providers/github/` (full package)
- Create: `packages/oauth-providers/apple/` (full package)
- Create: `packages/oauth-providers/microsoft/` (full package)
- Create: `packages/oauth-providers/discord/` (full package)
- Create: `packages/oauth-providers/custom/` (full package)
- Create: `packages/core/src/engine/__tests__/oauth.test.ts`
- Modify: `packages/core/src/engine/argus.ts` (add OAuth methods)
- Create: `packages/server/src/routes/oauth.ts`
- Create: `packages/server/src/__tests__/oauth.test.ts`

- [ ] **Step 1: Implement OAuth provider adapters**

Each provider implements `OAuthProviderAdapter` interface using `openid-client` library. PKCE support on all providers that support it.

Google: `accounts.google.com`, scopes: `openid email profile`
GitHub: `github.com/login/oauth`, scopes: `user:email`
Apple: `appleid.apple.com`, scopes: `name email`
Microsoft: `login.microsoftonline.com`, scopes: `openid email profile`
Discord: `discord.com/oauth2`, scopes: `identify email`
Custom: configurable OIDC discovery URL

- [ ] **Step 2: Implement OAuth pipeline on Argus class**

`argus.oauth.getAuthorizationUrl()`, `argus.oauth.handleCallback()`, `argus.oauth.link()`, `argus.oauth.unlink()`

Core flow: exchange code → get profile → find or create user → link provider → create session → return tokens.

- [ ] **Step 3: Write core + server tests with mocked providers**

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add packages/oauth-providers/ packages/core/ packages/server/
git commit -m "feat: add OAuth providers (Google, GitHub, Apple, Microsoft, Discord, Custom) + pipeline"
```

---

### Task 29: Security Engine

**Files:**
- Create: `packages/security/package.json`
- Create: `packages/security/src/index.ts`
- Create: `packages/security/src/security-engine.ts`
- Create: `packages/security/src/anomaly-detector.ts`
- Create: `packages/security/src/device-trust.ts`
- Create: `packages/security/src/sharing-detector.ts`
- Create: `packages/security/src/brute-force.ts`
- Create: `packages/security/src/__tests__/security-engine.test.ts`
- Create: `packages/security/src/__tests__/anomaly-detector.test.ts`
- Create: `packages/security/src/__tests__/brute-force.test.ts`

- [ ] **Step 1: Implement BruteForceProtection**

Per-IP and per-account rate limiting with progressive delays. Uses CacheAdapter for counters.

- [ ] **Step 2: Implement AnomalyDetector**

New device detection, impossible travel, unusual time, Tor exit node detection. Uses CacheAdapter for known devices/geos/login history. Risk scoring 0-100.

- [ ] **Step 3: Implement DeviceTrust**

Device fingerprint management. Uses DbAdapter for persistent storage, CacheAdapter for fast lookup.

- [ ] **Step 4: Implement SharingDetector**

Concurrent session analysis. Checks active sessions for same user across different IPs/devices.

- [ ] **Step 5: Implement SecurityEngine facade**

Composes all four components. Implements the `SecurityEngine` interface.

- [ ] **Step 6: Write comprehensive tests for each component**

- [ ] **Step 7: Run tests — expect PASS**

- [ ] **Step 8: Wire security engine into Argus login pipeline**

- [ ] **Step 9: Commit**

```bash
git add packages/security/
git commit -m "feat(security): add security engine (anomaly detection, device trust, sharing prevention, brute force)"
```

---

## Phase 6: Enterprise Features

### Task 30: Password Policies (zxcvbn + HIBP)

**Files:**
- Create: `packages/password-policy/zxcvbn/` (full package)
- Create: `packages/password-policy/hibp/` (full package)

- [ ] **Step 1: Implement ZxcvbnPolicy**

Dependency: `zxcvbn`. Returns score 0-4, reasons, and suggestions.

- [ ] **Step 2: Implement HIBPPolicy**

Uses k-anonymity model to check passwords against Have I Been Pwned API. SHA-1 hash, send first 5 chars, check response for match.

- [ ] **Step 3: Write tests, run, verify PASS**

- [ ] **Step 4: Commit**

```bash
git add packages/password-policy/
git commit -m "feat: add password policies (zxcvbn strength scoring, HIBP breach check)"
```

---

### Task 31: Email Adapters (SendGrid, SES, SMTP)

**Files:**
- Create: `packages/email-adapters/sendgrid/` (full package)
- Create: `packages/email-adapters/ses/` (full package)
- Create: `packages/email-adapters/smtp/` (full package)

- [ ] **Step 1: Implement SendGridEmailProvider**

Dependency: `@sendgrid/mail`. Configurable templates for each email type.

- [ ] **Step 2: Implement SESEmailProvider**

Dependency: `@aws-sdk/client-ses`.

- [ ] **Step 3: Implement SMTPEmailProvider**

Dependency: `nodemailer`. Configurable SMTP host/port/auth. Built-in HTML templates with Handlebars.

- [ ] **Step 4: Write tests with mocked clients, run, verify PASS**

- [ ] **Step 5: Commit**

```bash
git add packages/email-adapters/sendgrid/ packages/email-adapters/ses/ packages/email-adapters/smtp/
git commit -m "feat: add email adapters (SendGrid, SES, SMTP)"
```

---

### Task 32: Organizations + Multi-Tenancy

**Files:**
- Create: `packages/core/src/engine/__tests__/organizations.test.ts`
- Modify: `packages/core/src/engine/argus.ts` (add org methods)
- Create: `packages/server/src/routes/orgs.ts`
- Create: `packages/server/src/__tests__/orgs.test.ts`

- [ ] **Step 1: Implement org methods on Argus class**

`argus.orgs.create()`, `.get()`, `.update()`, `.delete()`, `.addMember()`, `.removeMember()`, `.updateMember()`, `.listMembers()`, `.createInvite()`, `.acceptInvite()`, `.updateSettings()`

Org settings enforce auth policies: SSO-only, mandatory MFA, IP allowlist, session timeout, password policy overrides.

- [ ] **Step 2: Write core tests**

- [ ] **Step 3: Implement server routes (all /v1/orgs/* endpoints)**

- [ ] **Step 4: Write server tests**

- [ ] **Step 5: Run all tests — expect PASS**

- [ ] **Step 6: Commit**

```bash
git add packages/core/ packages/server/
git commit -m "feat: add organization management with multi-tenancy and auth policy enforcement"
```

---

### Task 33: RBAC + ABAC (Roles, Permissions, Access Policies)

**Files:**
- Create: `packages/core/src/engine/authorization.ts`
- Create: `packages/core/src/engine/__tests__/authorization.test.ts`
- Create: `packages/server/src/routes/roles.ts`
- Create: `packages/server/src/__tests__/roles.test.ts`

- [ ] **Step 1: Implement authorization engine**

`argus.authorize(userId, action, context)` — checks roles, permissions, and access policies. Role inheritance resolution. ABAC condition evaluation.

- [ ] **Step 2: Implement default roles**

```typescript
const DEFAULT_ROLES: Role[] = [
  { name: 'super_admin', permissions: ['*'], inherits: [], isSystem: true },
  { name: 'admin', permissions: ['admin:*'], inherits: ['user'], isSystem: true },
  { name: 'moderator', permissions: ['moderate:*'], inherits: ['user'], isSystem: true },
  { name: 'user', permissions: ['read:own', 'write:own'], inherits: ['viewer'], isSystem: true },
  { name: 'viewer', permissions: ['read:own'], inherits: [], isSystem: true },
];
```

- [ ] **Step 3: Write comprehensive tests**

- [ ] **Step 4: Implement server routes (/v1/admin/roles/*, /v1/admin/policies/*)**

- [ ] **Step 5: Run tests — expect PASS**

- [ ] **Step 6: Commit**

```bash
git add packages/core/ packages/server/
git commit -m "feat: add RBAC + ABAC authorization engine with role inheritance"
```

---

### Task 34: API Keys

**Files:**
- Create: `packages/core/src/engine/__tests__/api-keys.test.ts`
- Modify: `packages/core/src/engine/argus.ts`
- Create: `packages/server/src/routes/api-keys.ts`
- Create: `packages/server/src/__tests__/api-keys.test.ts`
- Modify: `packages/server/src/middleware/auth.ts` (support API key auth)

- [ ] **Step 1: Implement API key methods**

`argus.apiKeys.create()`, `.list()`, `.revoke()`, `.validate()`

Key format: `argus_pk_<random 48 chars>`. Store SHA-256 hash only. Show full key once on creation.

- [ ] **Step 2: Update auth middleware to support API key**

Check `Authorization: Bearer argus_pk_*` — if key prefix matches, validate as API key instead of JWT.

- [ ] **Step 3: Write tests, run, verify PASS**

- [ ] **Step 4: Commit**

```bash
git add packages/core/ packages/server/
git commit -m "feat: add API key authentication for service-to-service auth"
```

---

### Task 35: Webhooks

**Files:**
- Create: `packages/core/src/engine/webhook-dispatcher.ts`
- Create: `packages/core/src/engine/__tests__/webhooks.test.ts`
- Create: `packages/server/src/routes/webhooks.ts`
- Create: `packages/server/src/__tests__/webhooks.test.ts`

- [ ] **Step 1: Implement WebhookDispatcher**

Listens to Argus events. For each matching webhook subscription, sends an HTTP POST with:
- `X-Argus-Signature: sha256=<HMAC of body>`
- `X-Argus-Event: <event type>`
- `X-Argus-Delivery: <unique ID>`

Retry with exponential backoff (3 attempts). Increment failure count on persistent failure. Disable webhook after 10 consecutive failures.

- [ ] **Step 2: Wire into Argus event system**

- [ ] **Step 3: Implement server routes (/v1/webhooks/*)**

Including `POST /v1/webhooks/:id/test` — sends a test payload.

- [ ] **Step 4: Write tests, run, verify PASS**

- [ ] **Step 5: Commit**

```bash
git add packages/core/ packages/server/
git commit -m "feat: add webhook system with HMAC signing and retry"
```

---

## Phase 7: Dashboard, Client SDK, Docker, CI/CD

### Task 36: Client SDK

**Files:**
- Create: `packages/client/package.json`
- Create: `packages/client/src/index.ts`
- Create: `packages/client/src/argus-client.ts`
- Create: `packages/client/src/react/index.ts`
- Create: `packages/client/src/react/auth-provider.tsx`
- Create: `packages/client/src/react/hooks.ts`
- Create: `packages/client/src/__tests__/argus-client.test.ts`

- [ ] **Step 1: Implement ArgusClient class**

Framework-agnostic HTTP client. Handles:
- register, login, verifyMFA, logout
- token refresh with deduplication (concurrent requests share one refresh)
- proactive refresh at 80% of token lifetime
- password reset, email verification
- session management, device management
- OAuth redirect helpers
- API key management
- Organization management

- [ ] **Step 2: Implement React bindings**

- `AuthProvider` — context provider, auto-refreshes session on mount
- `useAuth()` — login, logout, register, user state
- `useUser()` — current user data
- `useSession()` — session list, revoke
- `useMFA()` — setup, verify, disable

- [ ] **Step 3: Write tests, run, verify PASS**

- [ ] **Step 4: Commit**

```bash
git add packages/client/
git commit -m "feat(client): add TypeScript SDK with React hooks"
```

---

### Task 37: Dashboard — Next.js Admin UI

**Files:**
- Create: `packages/dashboard/package.json`
- Create: `packages/dashboard/next.config.js`
- Create: `packages/dashboard/tsconfig.json`
- Create: `packages/dashboard/src/app/layout.tsx`
- Create: `packages/dashboard/src/app/page.tsx` (overview)
- Create: `packages/dashboard/src/app/users/page.tsx`
- Create: `packages/dashboard/src/app/users/[id]/page.tsx`
- Create: `packages/dashboard/src/app/sessions/page.tsx`
- Create: `packages/dashboard/src/app/audit/page.tsx`
- Create: `packages/dashboard/src/app/orgs/page.tsx`
- Create: `packages/dashboard/src/app/roles/page.tsx`
- Create: `packages/dashboard/src/app/security/page.tsx`
- Create: `packages/dashboard/src/app/webhooks/page.tsx`
- Create: `packages/dashboard/src/app/settings/page.tsx`
- Create: `packages/dashboard/src/components/` (shared UI components)
- Create: `packages/dashboard/src/lib/api.ts` (uses @argus/client)

- [ ] **Step 1: Scaffold Next.js app with App Router**

Dependencies: `next`, `react`, `recharts`, `@argus/client`, `tailwindcss`.

- [ ] **Step 2: Implement layout with sidebar navigation**

10 pages: Overview, Users, User Detail, Sessions, Audit Log, Organizations, Roles & Permissions, Security, Webhooks, Settings.

- [ ] **Step 3: Implement Overview page**

Real-time stats: total users, active sessions, login rate, failure rate, MFA adoption rate. Charts with Recharts.

- [ ] **Step 4: Implement Users page**

Searchable, filterable, paginated table. Inline actions: lock/unlock, reset MFA, impersonate, delete.

- [ ] **Step 5: Implement User Detail page**

Profile info, active sessions, OAuth providers, MFA status, audit trail, API keys, org memberships.

- [ ] **Step 6: Implement remaining pages**

Sessions, Audit Log, Organizations, Roles, Security (anomaly dashboard), Webhooks, Settings.

- [ ] **Step 7: Commit**

```bash
git add packages/dashboard/
git commit -m "feat(dashboard): add Next.js admin UI with all 10 pages"
```

---

### Task 38: Docker Compose

**Files:**
- Create: `docker-compose.yml`
- Create: `Dockerfile`
- Create: `.dockerignore`

- [ ] **Step 1: Create multi-stage Dockerfile**

Stage 1: deps (install with pnpm)
Stage 2: build (compile TypeScript)
Stage 3: production (node:20-alpine, non-root user, dumb-init, health check)

- [ ] **Step 2: Create docker-compose.yml**

Services:
- `argus-server` — the Fastify API (port 3100)
- `argus-dashboard` — Next.js admin UI (port 3200)
- `postgres` — PostgreSQL 16 (port 5432, with init script for auth schema)
- `redis` — Redis 7 (port 6379)
- `migrate` — one-shot migration runner

Health checks on all services. Volume mounts for data persistence. Network isolation.

- [ ] **Step 3: Create .dockerignore**

- [ ] **Step 4: Test full stack**

Run: `docker compose up --build`
Expected: all services start, health checks pass, API responds on port 3100.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml Dockerfile .dockerignore
git commit -m "feat: add Docker Compose for local development"
```

---

### Task 39: CI/CD — GitHub Actions

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Create CI workflow**

Triggers on push to main and PRs. Jobs:
1. **Lint & Typecheck** — `pnpm lint && pnpm typecheck`
2. **Unit Tests** — `pnpm test:unit` with coverage
3. **Integration Tests** — with PostgreSQL + Redis services, run migrations, `pnpm test:integration`
4. **Security Scan** — `pnpm audit --audit-level=high`
5. **Build** — `pnpm build` (verify all packages compile)

- [ ] **Step 2: Create Release workflow**

Triggers on tag push. Builds Docker image, pushes to GHCR.

- [ ] **Step 3: Commit**

```bash
git add .github/
git commit -m "ci: add GitHub Actions workflows for CI and release"
```

---

### Task 40: README + Documentation

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write comprehensive README**

Sections:
- What is ArgusJS (one paragraph)
- Features list (bulleted, categorized)
- Quick Start (5-line code example)
- Installation (which packages to install)
- Configuration (full example from spec)
- API Reference (link to each endpoint group)
- Architecture diagram (Mermaid)
- Plugin Development (how to create a custom adapter)
- Docker Compose quickstart
- Environment Variables reference table
- Contributing guide
- License (MIT)

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add comprehensive README with quickstart and architecture"
```

---

## Phase 8: Performance & Load Testing

### Task 41: k6 Performance Test Suite

**Files:**
- Create: `tests/k6/config.js` (shared config: base URL, thresholds, stages)
- Create: `tests/k6/helpers/auth.js` (helper: register + login to get tokens)
- Create: `tests/k6/scenarios/registration.js`
- Create: `tests/k6/scenarios/login.js`
- Create: `tests/k6/scenarios/login-mfa.js`
- Create: `tests/k6/scenarios/token-refresh.js`
- Create: `tests/k6/scenarios/session-management.js`
- Create: `tests/k6/scenarios/password-reset.js`
- Create: `tests/k6/scenarios/concurrent-sessions.js`
- Create: `tests/k6/scenarios/mixed-realistic.js`
- Create: `tests/k6/scenarios/brute-force-protection.js`
- Create: `tests/k6/scenarios/rate-limiter-accuracy.js`
- Create: `tests/k6/run-all.sh`
- Create: `docker-compose.k6.yml` (k6 + server + postgres + redis for CI)

- [ ] **Step 1: Create shared config and helpers**

```javascript
// tests/k6/config.js
export const BASE_URL = __ENV.BASE_URL || 'http://localhost:3100';

export const THRESHOLDS = {
  http_req_duration: ['p(50)<100', 'p(95)<300', 'p(99)<500'],
  http_req_failed: ['rate<0.01'],  // <1% error rate
};

export const STAGES_SMOKE = [
  { duration: '10s', target: 5 },
  { duration: '30s', target: 5 },
  { duration: '10s', target: 0 },
];

export const STAGES_LOAD = [
  { duration: '30s', target: 50 },
  { duration: '2m', target: 50 },
  { duration: '30s', target: 100 },
  { duration: '2m', target: 100 },
  { duration: '30s', target: 0 },
];

export const STAGES_STRESS = [
  { duration: '1m', target: 100 },
  { duration: '2m', target: 200 },
  { duration: '2m', target: 500 },
  { duration: '1m', target: 0 },
];

export const STAGES_SPIKE = [
  { duration: '10s', target: 10 },
  { duration: '5s', target: 500 },
  { duration: '30s', target: 500 },
  { duration: '10s', target: 10 },
  { duration: '30s', target: 0 },
];
```

- [ ] **Step 2: Registration performance test**

```javascript
// tests/k6/scenarios/registration.js
// Metrics:
//   - Registration p50/p95/p99 latency
//   - Argon2id hashing time contribution
//   - Throughput (registrations/sec)
//   - Error rate under load
// Thresholds:
//   - p95 < 500ms (Argon2 is intentionally slow)
//   - p99 < 1000ms
//   - error rate < 1%
```

Each VU registers a unique user (unique email per iteration using `__VU` and `__ITER`). Validates response status 201, checks response body has accessToken.

- [ ] **Step 3: Login performance test**

```javascript
// tests/k6/scenarios/login.js
// Setup: pre-register 1000 users
// Metrics:
//   - Login p50/p95/p99 latency
//   - Password verification time
//   - Throughput (logins/sec)
// Thresholds:
//   - p95 < 300ms
//   - p99 < 500ms
//   - error rate < 1%
```

Setup phase creates test users. Each VU picks a random user and logs in. Validates 200 + token in response.

- [ ] **Step 4: Login with MFA performance test**

```javascript
// tests/k6/scenarios/login-mfa.js
// Two-step flow: login → MFA verify
// Metrics: full round-trip time for MFA login
// Thresholds:
//   - p95 < 500ms (combined)
```

- [ ] **Step 5: Token refresh performance test**

```javascript
// tests/k6/scenarios/token-refresh.js
// Setup: register users, get refresh tokens
// This is the highest-frequency operation in production
// Metrics:
//   - Refresh p50/p95/p99
//   - Throughput (refreshes/sec)
// Thresholds:
//   - p95 < 50ms (this should be FAST — Redis + JWT sign)
//   - p99 < 100ms
//   - error rate < 0.1%
```

- [ ] **Step 6: Session management performance test**

```javascript
// tests/k6/scenarios/session-management.js
// GET /v1/auth/sessions — list active sessions
// GET /v1/auth/me — profile fetch
// DELETE /v1/auth/sessions/:id — revoke
// Metrics: latency for each operation
```

- [ ] **Step 7: Password reset flow performance test**

```javascript
// tests/k6/scenarios/password-reset.js
// POST /v1/auth/forgot-password → POST /v1/auth/reset-password
// Measures full reset cycle latency
```

- [ ] **Step 8: Concurrent sessions stress test**

```javascript
// tests/k6/scenarios/concurrent-sessions.js
// 100 VUs all logging in as the SAME user simultaneously
// Tests:
//   - Session limit enforcement under race conditions
//   - No duplicate sessions created beyond maxPerUser
//   - Oldest session correctly evicted
// Thresholds:
//   - Active sessions never exceed maxPerUser + 1 (race tolerance)
```

- [ ] **Step 9: Mixed realistic workload test**

```javascript
// tests/k6/scenarios/mixed-realistic.js
// Simulates real production traffic distribution:
//   - 85% token refresh
//   - 10% login
//   - 3% registration
//   - 1% password reset
//   - 1% profile/session management
// Uses weighted scenarios in k6 options
// Thresholds per operation type using custom metrics (Trend, Rate)
```

- [ ] **Step 10: Brute force protection test**

```javascript
// tests/k6/scenarios/brute-force-protection.js
// Validates security under load:
//   - Send 20 wrong-password logins for same account
//   - Verify account gets locked after threshold
//   - Verify locked account returns 423
//   - Verify rate limit headers are present
//   - Measure rate limiter latency overhead
```

- [ ] **Step 11: Rate limiter accuracy test**

```javascript
// tests/k6/scenarios/rate-limiter-accuracy.js
// Send exactly N+1 requests in a window
// Verify exactly 1 gets 429
// Verify Retry-After header is correct
// Verify X-RateLimit-Remaining counts down correctly
// Test with multiple IPs (using X-Forwarded-For)
```

- [ ] **Step 12: Create docker-compose.k6.yml**

```yaml
# Dedicated compose for k6 testing
# Services: argus-server, postgres, redis, k6
# k6 runs as a one-shot container, exits with test result code
```

- [ ] **Step 13: Create run-all.sh**

```bash
#!/bin/bash
# Runs all k6 scenarios sequentially
# Outputs summary table with pass/fail per scenario
# Exit code 1 if any scenario fails thresholds
```

- [ ] **Step 14: Commit**

```bash
git add tests/k6/ docker-compose.k6.yml
git commit -m "test: add k6 performance test suite (11 scenarios)"
```

---

### Task 42: Integration Test Hardening

**Files:**
- Create: `tests/integration/setup.ts` (shared test harness: Docker containers, migrations, cleanup)
- Create: `tests/integration/auth-flows.test.ts`
- Create: `tests/integration/token-rotation.test.ts`
- Create: `tests/integration/mfa-flows.test.ts`
- Create: `tests/integration/oauth-flows.test.ts`
- Create: `tests/integration/security-engine.test.ts`
- Create: `tests/integration/organization-flows.test.ts`
- Create: `tests/integration/rbac.test.ts`
- Create: `tests/integration/api-keys.test.ts`
- Create: `tests/integration/webhooks.test.ts`
- Create: `tests/integration/concurrent-access.test.ts`
- Create: `tests/integration/data-integrity.test.ts`

- [ ] **Step 1: Create shared test harness**

Uses `testcontainers` to spin up PostgreSQL + Redis Docker containers per test suite. Auto-runs migrations. Provides `createTestArgus()` factory with real Postgres + Redis adapters.

- [ ] **Step 2: Full auth flow integration tests**

End-to-end: register → verify email → login → refresh → change password → logout. All against real Postgres + Redis. Verify DB state after each operation.

- [ ] **Step 3: Token rotation integration tests**

- Refresh token rotation creates new generation
- Reuse detection across concurrent requests (race condition)
- Family revocation cascades correctly
- Expired token cleanup

- [ ] **Step 4: MFA flow integration tests**

- TOTP setup → verify → login with MFA → backup code usage
- MFA disable flow
- MFA with wrong codes (lockout)

- [ ] **Step 5: Security engine integration tests**

- Brute force lockout with real Redis counters
- Concurrent session detection accuracy
- Device trust persistence across sessions
- Risk scoring with real data

- [ ] **Step 6: Organization flow integration tests**

- Create org → invite → accept → enforce org settings → remove member
- Org auth policy enforcement (mandatory MFA, IP allowlist, session timeout)

- [ ] **Step 7: RBAC integration tests**

- Role inheritance resolution
- Permission checks with nested roles
- ABAC policy evaluation with conditions

- [ ] **Step 8: Concurrent access tests**

- Two sessions refreshing the same token simultaneously (only one should win)
- Registration with same email from two requests (only one should succeed)
- Session limit enforcement under concurrent logins

- [ ] **Step 9: Data integrity tests**

- Soft delete cascading (deleted user's sessions, tokens, etc.)
- Password history preservation
- Audit log completeness (every action logged)
- GDPR export contains all user data

- [ ] **Step 10: Commit**

```bash
git add tests/integration/
git commit -m "test: add comprehensive integration test suite (12 test files)"
```

---

## Summary

| Phase | Tasks | What's testable after |
|-------|-------|----------------------|
| 1 | 1-3 | Monorepo builds, all types/interfaces compile |
| 2 | 4-10 | Full auth pipeline works with memory adapters (no infra needed) |
| 3 | 11-16 | Real adapters (Postgres, Redis, Argon2, JWT) with integration tests |
| 4 | 17-23 | Complete REST API with 30+ endpoints |
| 5 | 24-29 | MFA (TOTP, WebAuthn, SMS), OAuth (6 providers), Security Engine |
| 6 | 30-35 | Enterprise features: orgs, RBAC, API keys, webhooks, password policies |
| 7 | 36-40 | Dashboard, Client SDK, Docker, CI/CD, README |
| 8 | 41-42 | k6 perf tests (11 scenarios) + hardened integration tests (12 suites) |

**Total: 42 tasks, ~60+ endpoints, 42 packages, 18 DB tables, 11 k6 scenarios, 12 integration suites.**
