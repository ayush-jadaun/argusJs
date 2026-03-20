# ArgusJS — Enterprise Authentication Platform Design Spec

**Date:** 2026-03-20
**Project:** #6 from 25-Day Production Sprint
**Status:** Approved

---

## 1. Overview

ArgusJS is a fully pluggable, enterprise-grade authentication and identity platform. Every component — database, cache, password hashing, token signing, MFA methods, OAuth providers, email delivery, rate limiting, password policies, and security engine — is a plugin that can be registered, enabled, disabled, or swapped at boot time. ArgusJS ships as:

- **`@argus/core`** — engine, plugin system, interfaces, authentication pipeline
- **`@argus/server`** — Fastify REST API microservice
- **`@argus/dashboard`** — Next.js admin UI for user/session/audit management
- **`@argus/client`** — TypeScript SDK for consuming the API

Plus 35+ adapter packages for every pluggable component.

## 2. Package Structure

```
argus/
  packages/
    core/                    @argus/core — engine, plugin system, interfaces, pipeline
    server/                  @argus/server — Fastify REST API microservice
    dashboard/               @argus/dashboard — Next.js admin UI
    client/                  @argus/client — TypeScript SDK

    db-adapters/
      postgres/              @argus/db-postgres (Drizzle ORM, PostgreSQL 16)
      mongodb/               @argus/db-mongodb
      memory/                @argus/db-memory (testing/dev)

    cache-adapters/
      redis/                 @argus/cache-redis (sessions, tokens, rate limits)
      memory/                @argus/cache-memory (testing/dev)

    hash-adapters/
      argon2/                @argus/hash-argon2 (default — Argon2id)
      bcrypt/                @argus/hash-bcrypt
      scrypt/                @argus/hash-scrypt

    token-adapters/
      jwt-rs256/             @argus/token-jwt-rs256 (default — RSA asymmetric)
      jwt-es256/             @argus/token-jwt-es256 (ECDSA)
      jwt-hs256/             @argus/token-jwt-hs256 (symmetric)

    mfa-adapters/
      totp/                  @argus/mfa-totp (Google Authenticator, Authy)
      webauthn/              @argus/mfa-webauthn (FIDO2/passkeys)
      sms/                   @argus/mfa-sms (Twilio, etc.)

    oauth-providers/
      google/                @argus/oauth-google
      github/                @argus/oauth-github
      apple/                 @argus/oauth-apple
      microsoft/             @argus/oauth-microsoft
      discord/               @argus/oauth-discord
      custom/                @argus/oauth-custom (build your own OIDC provider)

    email-adapters/
      sendgrid/              @argus/email-sendgrid
      ses/                   @argus/email-ses
      smtp/                  @argus/email-smtp
      memory/                @argus/email-memory (testing/dev)

    rate-limit-adapters/
      redis/                 @argus/ratelimit-redis (sliding window)
      memory/                @argus/ratelimit-memory (testing/dev)

    password-policy/
      zxcvbn/                @argus/policy-zxcvbn (strength scoring)
      hibp/                  @argus/policy-hibp (Have I Been Pwned breach check)

    security/                @argus/security-engine (anomaly detection, device trust,
                               sharing prevention, impossible travel, brute force)

  docker-compose.yml
  turbo.json
  package.json
  tsconfig.base.json
```

## 3. Enterprise Features

### 3.1 Security Engine (`@argus/security-engine`)

A dedicated package for advanced threat detection and account sharing prevention.

**Anomaly Detection:**
- New device detection — flag logins from unrecognized user-agents
- New geolocation detection — flag logins from new countries/regions
- Impossible travel — detect logins from geographically impossible locations (e.g., India then US in 10 minutes)
- Unusual time-of-day — flag logins outside user's typical pattern
- Tor/VPN exit node detection — flag logins from anonymizing networks
- Risk scoring — composite 0-100 score based on all signals

**Account Sharing Prevention:**
- Simultaneous session detection — detect same account active on multiple devices/IPs concurrently
- Device trust registry — users must approve new devices via email/MFA before login proceeds
- Configurable enforcement modes:
  - `warn` — allow login, emit event for monitoring
  - `challenge` — force MFA re-verification on suspicious login
  - `block` — deny the second concurrent session entirely
- Trusted device management — users can view, name, and revoke trusted devices
- Device limit enforcement — configurable max trusted devices per user

**Brute Force Protection:**
- Per-IP rate limiting with sliding window
- Per-account progressive delays after failed attempts
- Account lockout with configurable threshold and duration
- CAPTCHA challenge threshold (pluggable — hCaptcha, reCAPTCHA, Turnstile)
- Credential stuffing detection — aggregate failure rate anomaly monitoring

```typescript
interface SecurityEngine {
  init(): Promise<void>;
  shutdown(): Promise<void>;

  // Risk assessment
  assessLoginRisk(context: LoginRiskContext): Promise<RiskAssessment>;
  assessSessionRisk(session: Session): Promise<RiskAssessment>;

  // Device trust
  isDeviceTrusted(userId: string, fingerprint: string): Promise<boolean>;
  trustDevice(userId: string, device: DeviceInfo): Promise<TrustedDevice>;
  revokeDevice(userId: string, deviceId: string): Promise<void>;
  listTrustedDevices(userId: string): Promise<TrustedDevice[]>;

  // Account sharing
  detectConcurrentSessions(userId: string, currentSession: Session): Promise<SharingDetection>;

  // Brute force
  recordFailedAttempt(identifier: string, ip: string): Promise<BruteForceResult>;
  isLocked(identifier: string): Promise<LockStatus>;
  resetAttempts(identifier: string): Promise<void>;
}

interface LoginRiskContext {
  userId: string;
  ipAddress: string;
  userAgent: string;
  deviceFingerprint?: string;
  geoLocation?: GeoLocation;
}

interface RiskAssessment {
  score: number;                  // 0-100
  level: 'low' | 'medium' | 'high' | 'critical';
  factors: RiskFactor[];
  action: 'allow' | 'challenge' | 'block';
}

interface RiskFactor {
  type: string;                   // 'new_device' | 'impossible_travel' | 'tor_exit' | etc.
  score: number;
  description: string;
}

interface TrustedDevice {
  id: string;
  userId: string;
  fingerprint: string;
  name: string;                   // user-assigned name: "My MacBook"
  browser: string;
  os: string;
  lastUsedAt: Date;
  lastIp: string;
  trustedAt: Date;
}

interface SharingDetection {
  detected: boolean;
  activeSessions: number;
  uniqueIps: number;
  uniqueDevices: number;
  action: 'allow' | 'challenge' | 'block';
}

interface BruteForceResult {
  allowed: boolean;
  failedAttempts: number;
  maxAttempts: number;
  lockoutUntil?: Date;
  requireCaptcha: boolean;
}
```

### 3.2 RBAC + ABAC (Authorization)

Fine-grained role-based and attribute-based access control built into core.

**Roles:** Hierarchical role system with inheritance.
```typescript
// Built-in roles (customizable)
// super_admin > admin > moderator > user > viewer

interface Role {
  name: string;
  description: string;
  permissions: string[];
  inherits?: string[];            // inherit permissions from parent roles
  isSystem: boolean;              // system roles can't be deleted
}

// Permission format: "action:resource" or "action:resource:scope"
// Examples: "read:users", "write:projects", "delete:users:own", "admin:billing:org"
```

**Attribute-Based Access Control:**
```typescript
interface AccessPolicy {
  id: string;
  name: string;
  effect: 'allow' | 'deny';
  actions: string[];              // ['read:reports', 'write:reports']
  conditions: PolicyCondition[];  // ALL must match
}

interface PolicyCondition {
  attribute: string;              // 'user.orgId' | 'user.roles' | 'request.ip' | 'time.hour'
  operator: 'eq' | 'neq' | 'in' | 'not_in' | 'gt' | 'lt' | 'contains' | 'matches';
  value: unknown;
}

// Usage:
// argus.authorize(userId, 'write:reports', { orgId: 'org-123' })
```

### 3.3 Multi-Tenancy (Organizations)

Full organization support with team hierarchies.

```typescript
interface Organization {
  id: string;
  name: string;
  slug: string;                   // URL-safe identifier
  ownerId: string;
  plan: string;                   // 'free' | 'pro' | 'enterprise'
  settings: OrgSettings;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

interface OrgSettings {
  enforceSSO: boolean;            // require OAuth login for all members
  allowedAuthMethods: string[];   // ['password', 'google', 'saml']
  enforceMFA: boolean;            // require MFA for all members
  allowedMFAMethods: string[];    // ['totp', 'webauthn']
  sessionTimeout: number;         // org-level session timeout override
  maxSessionsPerUser: number;
  ipAllowlist: string[];          // restrict login to specific IPs/CIDRs
  passwordPolicy: {
    minLength: number;
    requireMFA: boolean;
    maxAge: number;               // force password rotation (days, 0 = disabled)
  };
}

interface OrgMember {
  userId: string;
  orgId: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
  permissions: string[];          // org-specific permission overrides
  joinedAt: Date;
}

interface OrgInvite {
  id: string;
  orgId: string;
  email: string;
  role: string;
  invitedBy: string;
  token: string;
  expiresAt: Date;
  acceptedAt: Date | null;
  createdAt: Date;
}
```

### 3.4 API Keys (Service-to-Service Auth)

For machine-to-machine authentication without user sessions.

```typescript
interface ApiKey {
  id: string;
  name: string;                   // "Production Backend", "CI Pipeline"
  keyPrefix: string;              // first 8 chars shown for identification: "argus_pk_a1b2c3d4..."
  keyHash: string;                // SHA-256 of full key
  userId: string;                 // key owner
  orgId: string | null;
  permissions: string[];          // scoped permissions
  rateLimit: { max: number; windowSeconds: number } | null;
  ipAllowlist: string[];          // restrict to specific IPs
  expiresAt: Date | null;         // null = never expires
  lastUsedAt: Date | null;
  createdAt: Date;
  revokedAt: Date | null;
}

// Usage: Authorization: Bearer argus_pk_a1b2c3d4...full_key_here
// Core validates by hashing the provided key and looking up keyHash
```

### 3.5 Admin Impersonation

Allows admins to act as another user for debugging/support, with full audit trail.

```typescript
// POST /admin/impersonate
// Returns a special access token with:
interface ImpersonationClaims extends AccessTokenClaims {
  impersonator: {
    id: string;
    email: string;
    roles: string[];
  };
  isImpersonation: true;
}

// All actions during impersonation are audit-logged with both the admin's
// and the target user's IDs. The impersonation token has a short TTL (15 min)
// and cannot perform destructive actions (delete account, change password, disable MFA).
```

### 3.6 Account Recovery

Multiple recovery paths when users lose access:

- **Email-based recovery** — standard password reset flow
- **Backup codes** — one-time codes generated during MFA setup
- **Recovery email** — secondary email for account recovery
- **Admin-initiated recovery** — admin can trigger password reset or disable MFA
- **Recovery questions** (optional, pluggable) — configurable security questions

### 3.7 Compliance & Data Governance

- **GDPR:** Full data export (`GET /auth/me/export`), right to deletion (`DELETE /auth/me`), consent tracking
- **SOC 2:** Complete audit trail, access controls, encryption at rest
- **HIPAA:** Session timeouts, automatic logoff, audit logging
- **Data residency:** Configurable per-org data region (supports multi-region deployment)
- **User data encryption:** Sensitive fields (MFA secrets, OAuth tokens) encrypted with AES-256-GCM at application layer
- **PII masking:** Audit logs mask sensitive fields by default

### 3.8 Webhooks

External systems can subscribe to auth events.

```typescript
interface Webhook {
  id: string;
  url: string;
  events: ArgusEventType[];       // which events trigger this webhook
  secret: string;                 // HMAC signing secret for payload verification
  orgId: string | null;
  active: boolean;
  failureCount: number;
  lastTriggeredAt: Date | null;
  createdAt: Date;
}

// Webhook payload:
// POST https://your-app.com/webhooks/auth
// Headers:
//   X-Argus-Signature: sha256=<HMAC of body using webhook secret>
//   X-Argus-Event: user.registered
//   X-Argus-Delivery: <unique delivery ID>
// Body: { event: ArgusEvent }
```

## 4. Core Plugin Interfaces

### 4.1 DB Adapter

```typescript
interface DbAdapter {
  init(): Promise<void>;
  shutdown(): Promise<void>;

  // Users
  createUser(user: CreateUserInput): Promise<User>;
  findUserByEmail(email: string): Promise<User | null>;
  findUserById(id: string): Promise<User | null>;
  updateUser(id: string, updates: Partial<User>): Promise<User>;
  softDeleteUser(id: string): Promise<void>;

  // Sessions
  createSession(session: CreateSessionInput): Promise<Session>;
  getSession(id: string): Promise<Session | null>;
  getActiveSessions(userId: string): Promise<Session[]>;
  revokeSession(id: string, reason: string): Promise<void>;
  revokeAllSessions(userId: string, reason: string, excludeSessionId?: string): Promise<void>;
  countActiveSessions(userId: string): Promise<number>;

  // Refresh Tokens
  createRefreshToken(token: CreateRefreshTokenInput): Promise<RefreshToken>;
  findRefreshTokenByHash(hash: string): Promise<RefreshToken | null>;
  revokeRefreshToken(id: string, reason: string): Promise<void>;
  revokeTokenFamily(family: string, reason: string): Promise<void>;
  revokeAllUserTokens(userId: string, reason: string): Promise<void>;

  // Password Reset
  createPasswordResetToken(input: CreateResetTokenInput): Promise<PasswordResetToken>;
  findPasswordResetByHash(hash: string): Promise<PasswordResetToken | null>;
  markResetTokenUsed(id: string): Promise<void>;
  invalidateUserResetTokens(userId: string): Promise<void>;

  // Email Verification
  createEmailVerificationToken(input: CreateVerificationInput): Promise<EmailVerificationToken>;
  findVerificationByHash(hash: string): Promise<EmailVerificationToken | null>;
  markVerificationUsed(id: string): Promise<void>;

  // OAuth
  linkOAuthProvider(input: LinkOAuthInput): Promise<OAuthLink>;
  findOAuthProvider(provider: string, providerUserId: string): Promise<OAuthLink | null>;
  getUserOAuthProviders(userId: string): Promise<OAuthLink[]>;
  unlinkOAuthProvider(userId: string, provider: string): Promise<void>;

  // MFA
  saveMFASecret(input: SaveMFAInput): Promise<MFASecret>;
  getMFASecret(userId: string): Promise<MFASecret | null>;
  deleteMFASecret(userId: string): Promise<void>;
  markBackupCodeUsed(userId: string, codeIndex: number): Promise<void>;

  // Password History
  getPasswordHistory(userId: string, limit: number): Promise<string[]>;
  addPasswordHistory(userId: string, hash: string): Promise<void>;

  // Audit Log
  writeAuditLog(entry: AuditLogEntry): Promise<void>;
  queryAuditLog(filter: AuditLogFilter): Promise<{ entries: AuditLogEntry[]; total: number }>;

  // Organizations
  createOrganization(org: CreateOrgInput): Promise<Organization>;
  getOrganization(id: string): Promise<Organization | null>;
  updateOrganization(id: string, updates: Partial<Organization>): Promise<Organization>;
  deleteOrganization(id: string): Promise<void>;
  listOrgMembers(orgId: string): Promise<OrgMember[]>;
  addOrgMember(input: AddOrgMemberInput): Promise<OrgMember>;
  updateOrgMember(orgId: string, userId: string, updates: Partial<OrgMember>): Promise<OrgMember>;
  removeOrgMember(orgId: string, userId: string): Promise<void>;

  // Org Invites
  createOrgInvite(input: CreateOrgInviteInput): Promise<OrgInvite>;
  findOrgInviteByToken(token: string): Promise<OrgInvite | null>;
  acceptOrgInvite(id: string): Promise<void>;
  listPendingInvites(orgId: string): Promise<OrgInvite[]>;

  // API Keys
  createApiKey(input: CreateApiKeyInput): Promise<ApiKey>;
  findApiKeyByHash(hash: string): Promise<ApiKey | null>;
  listApiKeys(userId: string): Promise<ApiKey[]>;
  revokeApiKey(id: string): Promise<void>;
  updateApiKeyLastUsed(id: string): Promise<void>;

  // Roles & Permissions
  createRole(role: Role): Promise<Role>;
  getRole(name: string): Promise<Role | null>;
  listRoles(): Promise<Role[]>;
  updateRole(name: string, updates: Partial<Role>): Promise<Role>;
  deleteRole(name: string): Promise<void>;

  // Access Policies
  createPolicy(policy: AccessPolicy): Promise<AccessPolicy>;
  listPolicies(): Promise<AccessPolicy[]>;
  deletePolicy(id: string): Promise<void>;

  // Webhooks
  createWebhook(input: CreateWebhookInput): Promise<Webhook>;
  listWebhooks(orgId?: string): Promise<Webhook[]>;
  updateWebhook(id: string, updates: Partial<Webhook>): Promise<Webhook>;
  deleteWebhook(id: string): Promise<void>;
  incrementWebhookFailure(id: string): Promise<void>;
  resetWebhookFailure(id: string): Promise<void>;

  // Trusted Devices
  saveTrustedDevice(device: TrustedDevice): Promise<TrustedDevice>;
  getTrustedDevices(userId: string): Promise<TrustedDevice[]>;
  removeTrustedDevice(userId: string, deviceId: string): Promise<void>;
  isTrustedDevice(userId: string, fingerprint: string): Promise<boolean>;

  // Admin
  listUsers(filter: UserFilter): Promise<{ users: User[]; total: number }>;
  getSystemStats(): Promise<SystemStats>;
  exportUserData(userId: string): Promise<UserDataExport>;  // GDPR
}
```

### 4.2 Cache Adapter

```typescript
interface CacheAdapter {
  init(): Promise<void>;
  shutdown(): Promise<void>;

  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  del(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
  incr(key: string, ttlSeconds: number): Promise<number>;
  sadd(key: string, member: string): Promise<void>;
  sismember(key: string, member: string): Promise<boolean>;
  smembers(key: string): Promise<string[]>;
  healthCheck(): Promise<boolean>;
}
```

### 4.3 Password Hasher

```typescript
interface PasswordHasher {
  name: string;
  hash(password: string): Promise<string>;
  verify(password: string, hash: string): Promise<boolean>;
  needsRehash?(hash: string): boolean;
}
```

### 4.4 Token Provider

```typescript
interface TokenProvider {
  init(): Promise<void>;
  shutdown?(): Promise<void>;
  signAccessToken(payload: AccessTokenClaims): Promise<string>;
  verifyAccessToken(token: string): Promise<AccessTokenClaims>;
  signMFAToken(userId: string): Promise<string>;
  verifyMFAToken(token: string): Promise<{ userId: string }>;
  getJWKS(): JsonWebKeySet;
  rotateKeys?(): Promise<void>;
}
```

### 4.5 MFA Provider

```typescript
interface MFAProvider {
  name: string;
  init?(): Promise<void>;
  shutdown?(): Promise<void>;
  generateSecret(user: User): Promise<MFASetupData>;
  verifyCode(secret: string, code: string): Promise<boolean>;
  generateBackupCodes?(): string[];
}
```

### 4.6 OAuth Provider

```typescript
interface OAuthProviderAdapter {
  name: string;
  init?(): Promise<void>;
  getAuthorizationUrl(state: string, redirectUri: string, codeChallenge?: string): string;
  exchangeCode(code: string, redirectUri: string, codeVerifier?: string): Promise<OAuthTokens>;
  getUserProfile(tokens: OAuthTokens): Promise<OAuthUserProfile>;
}
```

### 4.7 Email Provider

```typescript
interface EmailProvider {
  name: string;
  init?(): Promise<void>;
  shutdown?(): Promise<void>;
  sendVerificationEmail(to: string, token: string, user: User): Promise<void>;
  sendPasswordResetEmail(to: string, token: string, user: User): Promise<void>;
  sendSecurityAlertEmail(to: string, event: SecurityEvent, user: User): Promise<void>;
  sendWelcomeEmail(to: string, user: User): Promise<void>;
  sendOrgInviteEmail(to: string, invite: OrgInvite, org: Organization): Promise<void>;
  sendDeviceVerificationEmail(to: string, device: DeviceInfo, user: User): Promise<void>;
}
```

### 4.8 Rate Limiter

```typescript
interface RateLimiter {
  init?(): Promise<void>;
  shutdown?(): Promise<void>;
  check(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult>;
  reset(key: string): Promise<void>;
}
```

### 4.9 Password Policy (composable)

```typescript
interface PasswordPolicy {
  name: string;
  init?(): Promise<void>;
  validate(password: string, context?: { email?: string; displayName?: string }): Promise<PasswordPolicyResult>;
}
```

## 5. Authentication Pipeline

### 5.1 Registration Flow

```
argus.register(input)
  -> Validate input (email format, displayName length)
  -> Run password policies (zxcvbn score, HIBP breach check, min length)
  -> Check if email exists -> EMAIL_ALREADY_EXISTS
  -> Hash password (Argon2id)
  -> Create user record in DB
  -> Generate email verification token
  -> Store verification token (hashed) in DB
  -> Send verification email
  -> Generate access + refresh tokens
  -> Create session in DB + cache
  -> Write audit log: USER_REGISTERED
  -> Emit 'user.registered' event
  -> Trigger webhooks
  -> Execute hooks.afterRegister()
  -> Return AuthResponse
```

### 5.2 Login Flow

```
argus.login(email, password, options)
  -> Execute hooks.beforeLogin()
  -> Rate limit check (per-IP)
  -> Brute force check (per-account) -> ACCOUNT_LOCKED
  -> Find user by email -> INVALID_CREDENTIALS
  -> Check account not soft-deleted
  -> Check account not locked
  -> Verify password (Argon2id) -> INVALID_CREDENTIALS (+ record failure)
  -> Check if password needs rehash (needsRehash) -> rehash in background
  -> Reset failed login attempts
  -> Security engine: assess login risk
    -> If risk.action === 'block' -> SUSPICIOUS_ACTIVITY
    -> If risk.action === 'challenge' -> force MFA even if not enabled
  -> Check if MFA enabled
    -> If yes: return MFAChallengeResponse (mfaToken, available methods)
    -> If no: continue
  -> Account sharing check (concurrent sessions)
    -> If sharing.action === 'block' -> CONCURRENT_SESSION_LIMIT
    -> If sharing.action === 'challenge' -> force device verification
  -> Device trust check
    -> If untrusted device + device trust enabled -> send device verification email, return challenge
  -> Enforce session limit (revoke oldest if over max)
  -> Generate access + refresh tokens
  -> Create session in DB + cache
  -> Update user: lastLoginAt, lastLoginIp, reset failedLoginAttempts
  -> Write audit log: LOGIN_SUCCESS
  -> Emit 'user.login' event
  -> Trigger webhooks
  -> Execute hooks.afterLogin()
  -> Return AuthResponse
```

### 5.3 MFA Verification Flow

```
argus.verifyMFA(mfaToken, code, method)
  -> Verify MFA token (short-lived, from login response)
  -> Get user's MFA secret for the specified method
  -> Verify code against secret (TOTP / WebAuthn / backup code)
    -> If backup code: mark as used, emit 'mfa.backup_code_used'
  -> If invalid -> record failure, INVALID_MFA_CODE
  -> Generate access + refresh tokens
  -> Create session
  -> Write audit log: MFA_CHALLENGE_PASSED
  -> Emit 'mfa.challenge_passed' event
  -> Return AuthResponse
```

### 5.4 Token Refresh Flow

```
argus.refresh(refreshToken)
  -> Hash the provided token
  -> Look up refresh token by hash
  -> If not found -> INVALID_REFRESH_TOKEN
  -> If revoked -> TOKEN REUSE DETECTED
    -> Revoke entire token family
    -> Revoke all sessions for user
    -> Write audit log: TOKEN_REUSE_DETECTED
    -> Emit 'token.reuse_detected' + 'security.suspicious_activity'
    -> Return REFRESH_TOKEN_REUSE_DETECTED
  -> If expired -> INVALID_REFRESH_TOKEN
  -> Verify session is still active
  -> Revoke old refresh token (reason: 'rotated')
  -> Generate new access + refresh tokens (same family, generation + 1)
  -> Update session lastActivityAt
  -> Write audit log: TOKEN_REFRESHED
  -> Emit 'token.refreshed'
  -> Return new tokens
```

### 5.5 OAuth Flow

```
argus.oauth.authorize(provider, redirectUri, state)
  -> Validate provider is configured
  -> Generate PKCE code verifier + challenge
  -> Store state + code verifier in cache (5 min TTL)
  -> Return authorization URL

argus.oauth.callback(provider, code, state)
  -> Validate state matches cache
  -> Exchange code for tokens (with PKCE verifier)
  -> Get user profile from provider
  -> Check if OAuth link exists
    -> If yes: log in existing user
    -> If no: check if email matches existing user
      -> If yes: link OAuth to existing account
      -> If no: create new user + link OAuth
  -> Generate access + refresh tokens
  -> Create session
  -> Write audit log: OAUTH_LINKED or LOGIN_SUCCESS
  -> Return AuthResponse (or redirect)
```

### 5.6 Password Reset Flow

```
argus.forgotPassword(email)
  -> Always return 202 (prevent user enumeration)
  -> Rate limit check
  -> Find user by email (silently no-op if not found)
  -> Invalidate any existing reset tokens for user
  -> Generate cryptographically random reset token
  -> Store hashed token in DB (1 hour TTL)
  -> Send password reset email
  -> Write audit log: PASSWORD_RESET_REQUESTED

argus.resetPassword(token, newPassword)
  -> Hash token, look up in DB
  -> Validate: not expired, not used
  -> Run password policies on new password
  -> Check password history (not recently used)
  -> Hash new password
  -> Update user password
  -> Mark reset token as used
  -> Revoke ALL sessions for user
  -> Revoke ALL refresh tokens for user
  -> Add old password to history
  -> Send security alert email
  -> Write audit log: PASSWORD_RESET_COMPLETED
  -> Emit 'user.password_changed'
  -> Trigger webhooks
```

### 5.7 Logout Flow

```
argus.logout(sessionId, options)
  -> If options.allDevices:
    -> Revoke all sessions for user
    -> Revoke all refresh tokens for user
    -> Write audit log: LOGOUT_ALL_SESSIONS
  -> Else:
    -> Revoke current session
    -> Revoke refresh tokens for current session
    -> Write audit log: LOGOUT
  -> Remove session from cache
  -> Emit 'user.logout'
```

## 6. REST API Endpoints (`@argus/server`)

### Authentication
```
POST   /v1/auth/register                  Register new user
POST   /v1/auth/login                     Login with email/password
POST   /v1/auth/refresh                   Refresh access token
POST   /v1/auth/logout                    Logout (current or all devices)
POST   /v1/auth/forgot-password           Request password reset
POST   /v1/auth/reset-password            Reset password with token
POST   /v1/auth/change-password           Change password (authenticated)
POST   /v1/auth/verify-email              Verify email with token
POST   /v1/auth/resend-verification       Resend verification email
```

### MFA
```
POST   /v1/auth/mfa/setup                 Start MFA setup
POST   /v1/auth/mfa/verify                Verify MFA code (setup or login)
POST   /v1/auth/mfa/disable               Disable MFA
GET    /v1/auth/mfa/backup-codes          Regenerate backup codes
```

### OAuth
```
GET    /v1/auth/oauth/:provider/authorize  Start OAuth flow
GET    /v1/auth/oauth/:provider/callback   OAuth callback
POST   /v1/auth/oauth/:provider/link       Link OAuth to existing account
DELETE /v1/auth/oauth/:provider/unlink     Unlink OAuth provider
```

### User Profile
```
GET    /v1/auth/me                         Get current user profile
PATCH  /v1/auth/me                         Update profile
DELETE /v1/auth/me                         Delete account (GDPR)
GET    /v1/auth/me/export                  Export all user data (GDPR)
```

### Sessions & Devices
```
GET    /v1/auth/sessions                   List active sessions
DELETE /v1/auth/sessions/:id               Revoke a session
GET    /v1/auth/devices                    List trusted devices
POST   /v1/auth/devices/:id/trust          Trust a device
DELETE /v1/auth/devices/:id                Revoke device trust
```

### API Keys
```
POST   /v1/auth/api-keys                  Create API key
GET    /v1/auth/api-keys                  List API keys
DELETE /v1/auth/api-keys/:id              Revoke API key
```

### Organizations
```
POST   /v1/orgs                            Create organization
GET    /v1/orgs/:id                        Get organization
PATCH  /v1/orgs/:id                        Update organization
DELETE /v1/orgs/:id                        Delete organization
GET    /v1/orgs/:id/members                List members
POST   /v1/orgs/:id/members                Add member
PATCH  /v1/orgs/:id/members/:userId        Update member role
DELETE /v1/orgs/:id/members/:userId        Remove member
POST   /v1/orgs/:id/invites                Create invite
GET    /v1/orgs/:id/invites                List pending invites
POST   /v1/orgs/invites/:token/accept      Accept invite
PATCH  /v1/orgs/:id/settings               Update org auth settings
```

### Admin
```
GET    /v1/admin/users                     List users (paginated, filterable)
GET    /v1/admin/users/:id                 Get user details
PATCH  /v1/admin/users/:id                 Update user (roles, lock, etc.)
DELETE /v1/admin/users/:id                 Soft delete user
POST   /v1/admin/users/:id/unlock          Unlock user
POST   /v1/admin/users/:id/reset-mfa       Disable MFA for user
POST   /v1/admin/users/:id/reset-password  Trigger password reset
POST   /v1/admin/impersonate               Impersonate user
GET    /v1/admin/audit-log                 Query audit log
GET    /v1/admin/stats                     System statistics
GET    /v1/admin/sessions                  All active sessions
```

### Roles & Permissions
```
GET    /v1/admin/roles                     List roles
POST   /v1/admin/roles                     Create role
PATCH  /v1/admin/roles/:name               Update role
DELETE /v1/admin/roles/:name               Delete role
GET    /v1/admin/policies                  List access policies
POST   /v1/admin/policies                  Create policy
DELETE /v1/admin/policies/:id              Delete policy
```

### Webhooks
```
POST   /v1/webhooks                        Create webhook
GET    /v1/webhooks                        List webhooks
PATCH  /v1/webhooks/:id                    Update webhook
DELETE /v1/webhooks/:id                    Delete webhook
POST   /v1/webhooks/:id/test               Test webhook
```

### System
```
GET    /v1/health                          Health check (basic)
GET    /v1/health/live                     Liveness probe
GET    /v1/health/ready                    Readiness probe
GET    /.well-known/jwks.json              JWKS public keys
GET    /v1/metrics                         Prometheus metrics
```

**Total: 60+ endpoints.**

## 7. Dashboard (`@argus/dashboard`)

Next.js admin UI connecting to `@argus/server` REST API.

### Pages

1. **Overview** — real-time stats: total users, active sessions, login rate, failure rate, MFA adoption, recent security events
2. **Users** — searchable, filterable user table with inline actions (lock/unlock, reset MFA, impersonate, delete)
3. **User Detail** — profile, sessions, OAuth links, MFA status, audit trail, API keys, org memberships
4. **Sessions** — all active sessions system-wide with revoke actions
5. **Audit Log** — full searchable, filterable audit trail with expandable detail view
6. **Organizations** — list orgs, manage members, settings, invites
7. **Roles & Permissions** — manage roles, permissions, access policies
8. **Security** — anomaly detection dashboard, brute force metrics, locked accounts, trusted devices overview
9. **Webhooks** — manage webhook subscriptions, view delivery logs
10. **Settings** — system configuration, rate limits, session policies, email templates

## 8. Client SDK (`@argus/client`)

TypeScript SDK with:
- Full type safety
- Automatic token refresh with deduplication
- MFA flow handling
- OAuth redirect helpers
- React hooks (`useAuth`, `useUser`, `useSession`, `useMFA`)
- Framework-agnostic core + React bindings

## 9. Event System

```typescript
// Wildcard support
argus.on('user.*', handler);
argus.on('security.*', handler);
argus.on('mfa.challenge_failed', handler);

// Webhook delivery on all events
// Retry with exponential backoff (3 attempts)
// Dead letter after max retries
// HMAC-SHA256 signature verification
```

## 10. Tech Stack

- **Language:** TypeScript (strict mode)
- **Monorepo:** Turborepo
- **Core:** Node.js
- **Server:** Fastify (schema-based validation, plugin architecture)
- **Dashboard:** Next.js + Recharts
- **Default DB:** PostgreSQL 16 via Drizzle ORM
- **Default Cache:** Redis 7 (sessions, rate limits, brute force counters)
- **Default Hasher:** Argon2id (memory: 64 MB, iterations: 3, parallelism: 4)
- **Default Token:** RS256 via jose library
- **Default MFA:** otplib (TOTP, RFC 6238)
- **OAuth:** openid-client (PKCE support)
- **Password Strength:** zxcvbn
- **Breach Check:** Have I Been Pwned API (k-anonymity)
- **Security:** @simplewebauthn/server (WebAuthn/FIDO2)
- **Testing:** Vitest (unit + integration)
- **Containerization:** Docker Compose
- **CI/CD:** GitHub Actions
- **Linting:** ESLint + Prettier

## 11. Database Schema

Full PostgreSQL schema in dedicated `auth` schema with:
- `users` — core accounts (CITEXT email, Argon2id hash, roles, permissions, org support, soft delete)
- `sessions` — active sessions (IP, user-agent, device fingerprint, expiry, revocation)
- `refresh_tokens` — token rotation with family tracking and reuse detection
- `password_reset_tokens` — hashed tokens with 1-hour TTL
- `email_verification_tokens` — hashed tokens with 24-hour TTL
- `oauth_providers` — linked OAuth accounts with encrypted tokens
- `mfa_secrets` — AES-256-GCM encrypted TOTP/WebAuthn secrets + backup codes
- `password_history` — last 5 password hashes for reuse prevention
- `audit_log` — partitioned by month, append-only, 2-year retention
- `organizations` — multi-tenant org support
- `org_members` — user-org membership with roles
- `org_invites` — pending org invitations
- `api_keys` — service-to-service authentication
- `roles` — custom role definitions with permission inheritance
- `access_policies` — ABAC policy rules
- `webhooks` — webhook subscriptions
- `trusted_devices` — device trust registry
- `rate_limit_overrides` — custom rate limits per IP/user/API key

**18 tables** with full indexes, constraints, triggers (auto-update timestamps, password history, session limit enforcement, audit logging), RLS policies, and maintenance procedures.

## 12. Standards (per Master Plan)

- Standalone git repo
- Complete TypeScript source
- README with architecture docs
- Docker Compose for local dev
- Test suite (unit + integration)
- `.env.example` config templates
- Deployment guide
- CI/CD config (GitHub Actions)
- Production-grade error handling, logging, security
