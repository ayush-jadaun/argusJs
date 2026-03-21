# Security

This document covers the security architecture of ArgusJS, including password hashing, token management, brute force protection, and OWASP compliance.

## Password Hashing

### Why Argon2id

ArgusJS defaults to Argon2id, the winner of the 2015 Password Hashing Competition and the algorithm recommended by OWASP, NIST, and the IETF.

| Property | Argon2id | bcrypt | scrypt | SHA-256 |
|----------|----------|--------|--------|---------|
| Memory-hard | Yes (64 MB+) | No (4 KB) | Yes (configurable) | No |
| GPU-resistant | Strong | Moderate | Moderate | None |
| ASIC-resistant | Strong | Moderate | Moderate | None |
| Side-channel resistant | Yes (hybrid) | N/A | No (Argon2i variant) | N/A |
| OWASP recommended | First choice | Acceptable | Acceptable | Never |

### Production Parameters

```typescript
// Default production parameters (OWASP recommended):
new Argon2Hasher({
  memoryCost: 65536,  // 64 MB per hash
  timeCost: 3,        // 3 iterations
  parallelism: 4,     // 4 threads
})
```

These parameters ensure that:
- Each hash attempt requires 64 MB of RAM, limiting GPU parallelism
- A single hash takes approximately 1.3 seconds on modern hardware
- An attacker with 12 GPUs would be limited to hundreds of attempts per second (vs. billions for SHA-256)

### Development Parameters

```typescript
// Used when NODE_ENV !== 'production':
new Argon2Hasher({
  memoryCost: 4096,   // 4 MB
  timeCost: 2,
  parallelism: 1,
})
```

The server automatically selects dev or production parameters based on `NODE_ENV`.

### Pluggable Alternatives

If Argon2 native compilation is not possible in your environment:
- `@argus/hash-bcrypt` -- bcrypt with configurable rounds (default: 12)
- `@argus/hash-scrypt` -- Node.js built-in scrypt (no native dependencies)

## Token Rotation with Reuse Detection

ArgusJS implements refresh token rotation as recommended by the OAuth 2.0 Security Best Current Practice (RFC 6819).

### How Rotation Works

```
Registration/Login:
  -> Generate refresh token T0 (family=F1, generation=0)
  -> Store hash(T0) in database

First refresh:
  -> Client sends T0
  -> Server verifies T0, revokes T0
  -> Generate T1 (family=F1, generation=1)
  -> Return T1 to client

Second refresh:
  -> Client sends T1
  -> Server verifies T1, revokes T1
  -> Generate T2 (family=F1, generation=2)
  -> Return T2 to client
```

### Reuse Detection

If an attacker steals T0 and tries to use it after the legitimate user has already refreshed to T1:

```
Attacker sends T0:
  -> Server finds T0 in database
  -> T0 is REVOKED (already used)
  -> REUSE DETECTED:
     1. Revoke ALL tokens in family F1 (T0, T1, T2, ...)
     2. Revoke ALL user sessions
     3. Write audit log: TOKEN_REUSE_DETECTED
     4. Emit security.suspicious_activity event
     5. Return 401: "Refresh token reuse detected. All sessions revoked."
```

This ensures that token theft is detected and mitigated within one refresh cycle.

### The TOCTOU Race Condition Fix

A naive "check then revoke" implementation has a Time-of-Check-to-Time-of-Use (TOCTOU) race condition:

```
Thread A: SELECT token WHERE id=X    -> not revoked
Thread B: SELECT token WHERE id=X    -> not revoked (RACE!)
Thread A: UPDATE token SET revoked=true -> success
Thread A: INSERT new token            -> T1
Thread B: UPDATE token SET revoked=true -> success (already revoked!)
Thread B: INSERT new token            -> T2 (DUPLICATE!)
```

Now both T1 and T2 are valid, which defeats the purpose of rotation.

ArgusJS solves this with an **atomic revocation** operation:

```typescript
// DbAdapter interface:
revokeRefreshTokenIfActive(id: string, reason: string): Promise<boolean>;
```

The PostgreSQL implementation:

```sql
UPDATE refresh_tokens
SET revoked = true, revoked_at = NOW(), revoked_reason = $2
WHERE id = $1 AND revoked = false
RETURNING id;
```

This uses PostgreSQL's row-level locking to ensure only one transaction can flip `revoked` from `false` to `true`. The second concurrent caller gets an empty result set and treats it as token reuse, triggering the security response (revoke all sessions).

The in-memory adapter uses a similar atomic check-and-set pattern.

## Configurable Token Rotation

Token rotation is enabled by default (`rotateRefreshTokens: true`) because it provides the strongest protection against refresh token theft. However, it can be disabled for use cases where reuse detection is not needed.

### Rotation ON (default)

- Every refresh revokes the old token and issues a new one
- Stolen tokens are detected immediately when the legitimate user refreshes
- Reuse triggers revocation of all sessions (security alert)
- Two DB writes per refresh (revoke + insert)

This is the recommended setting for any application handling user data. The default is ON because the security benefit (instant theft detection) far outweighs the cost (~15ms additional latency per refresh).

### Rotation OFF

- The same refresh token is reused until it expires
- No reuse detection -- a stolen token remains valid for its full lifetime (up to 30 days)
- Zero DB writes per refresh (only a read to validate)
- Matches Keycloak's default behavior

Use this only for internal tools, server-to-server flows, or prototypes where token theft risk is minimal.

```typescript
session: {
  rotateRefreshTokens: false, // disable rotation (Keycloak-style)
}
```

## Refresh Token Cache Security Window

When `cacheRefreshTokens` is enabled, refresh token lookups are served from Redis instead of PostgreSQL. This introduces a security window equal to `refreshTokenCacheTTL` (default: 30 seconds) during which a revoked token could still be considered valid by the cache.

**The attack scenario:** A token is revoked in the database (e.g., via logout or session termination), but the cached copy in Redis has not yet expired. During this window, the revoked token can still be used to obtain a new access token.

**Mitigation:**
- Keep `refreshTokenCacheTTL` short (5-10 seconds for sensitive apps)
- Session revocation also invalidates the session cache, limiting the blast radius
- For maximum security, leave caching OFF (`cacheRefreshTokens: false`, the default)

## Brute Force Protection

### Account Lockout

After a configurable number of failed login attempts (default: 5), the account is locked for a configurable duration (default: 30 minutes).

```typescript
lockout: {
  maxAttempts: 5,       // Lock after 5 failures
  duration: 1800,       // Lock for 30 minutes
  captchaThreshold: 3,  // Show CAPTCHA after 3 failures
}
```

The lockout state is stored on the user record (`failedLoginAttempts`, `lockedUntil`), not in an external cache, so it persists across server restarts.

### IP-Based Rate Limiting

When the `rateLimiter` adapter is configured, all endpoints are rate-limited using a sliding window algorithm:

- **Login:** 10 attempts per minute per IP
- **Registration:** 5 per minute per IP
- **Password reset:** 3 per minute per IP
- **General API:** 100 per minute per IP

Rate limit headers are included in every response:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1711022400
```

When exceeded:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 42

{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Retry after 42s"
  }
}
```

## Account Sharing Prevention

The `@argus/security-engine` monitors concurrent active sessions per user:

```typescript
sharing: {
  maxConcurrentIPs: 3,      // Max 3 different IPs at once
  maxConcurrentDevices: 5,   // Max 5 different devices at once
  action: 'challenge',       // 'allow' | 'challenge' | 'block'
}
```

When the threshold is exceeded:
- **allow:** Log but take no action
- **challenge:** Require additional verification (MFA or email)
- **block:** Reject the login attempt

## Anomaly Detection

The anomaly detector scores each login attempt based on risk factors:

| Factor | Default Score | Description |
|--------|--------------|-------------|
| New device | +20 | Device fingerprint not seen before |
| New geolocation | +30 | IP resolves to a new geographic region |
| Unusual time | +10 | Login at unusual hour for this user |
| Tor exit node | +25 | IP is a known Tor exit relay |

The total score determines the action:

| Score | Action |
|-------|--------|
| 0-49 | Allow |
| 50-74 | Challenge (require MFA or email verification) |
| 75+ | Block |

Scores are configurable:

```typescript
risk: {
  newDeviceScore: 20,
  newGeoScore: 30,
  unusualTimeScore: 10,
  torExitScore: 25,
  challengeThreshold: 50,
  blockThreshold: 75,
}
```

## Device Trust

Users can mark devices as "trusted" via `POST /v1/auth/devices/:id/trust`. Trusted devices reduce the risk score from the anomaly detector, effectively whitelisting known devices.

Trusted devices are stored in the database with fingerprint, user agent, and last-seen timestamp. They can be viewed and removed by the user.

## Audit Logging

Every security-relevant action is recorded in the audit log when `audit.enabled` is true:

| Action | Logged When |
|--------|------------|
| `USER_REGISTERED` | New user created |
| `LOGIN_SUCCESS` | Successful login |
| `LOGIN_FAILED` | Failed login attempt |
| `LOGOUT` | User logged out |
| `LOGOUT_ALL_SESSIONS` | All sessions revoked |
| `ACCOUNT_LOCKED` | Account locked after max failures |
| `ACCOUNT_UNLOCKED` | Admin unlocked account |
| `PASSWORD_CHANGED` | Password changed |
| `PASSWORD_RESET_REQUESTED` | Reset email sent |
| `PASSWORD_RESET_COMPLETED` | Password reset via token |
| `EMAIL_VERIFIED` | Email verified |
| `MFA_ENABLED` | MFA turned on |
| `MFA_DISABLED` | MFA turned off |
| `MFA_CHALLENGE_PASSED` | MFA code verified |
| `MFA_CHALLENGE_FAILED` | MFA code rejected |
| `TOKEN_REFRESHED` | Token rotation |
| `TOKEN_REUSE_DETECTED` | Refresh token reuse attack |
| `IMPERSONATION_STARTED` | Admin began impersonation |
| `ROLE_CHANGED` | User roles updated |

Each entry includes:
- User ID
- IP address
- User agent
- Timestamp
- Action-specific metadata

Retention is configurable (default: unlimited, recommendation: 2 years for compliance).

## Email Enumeration Prevention

The password reset endpoint always returns the same response regardless of whether the email exists:

```json
{ "success": true, "message": "If the email exists, a reset link has been sent" }
```

This prevents attackers from discovering which email addresses are registered.

## Token Storage

- **Access tokens:** JWTs signed with RS256/ES256/HS256. Stateless verification. Not stored in the database.
- **Refresh tokens:** Random 48-byte values. Only the SHA-256 hash is stored in the database. The plaintext is returned to the client once and never stored server-side.
- **MFA secrets:** Encrypted with AES-256-GCM using a server-side key before storage.
- **Password reset tokens:** Random 32-byte values. Only the SHA-256 hash is stored. Time-limited (default: 1 hour).
- **Email verification tokens:** Same pattern as password reset tokens. Time-limited (default: 24 hours).

## OWASP Compliance Checklist

| OWASP Recommendation | ArgusJS Implementation | Status |
|----------------------|----------------------|--------|
| Use Argon2id for password hashing | Default hasher with 64 MB / 3 iter | Done |
| Minimum password length 8+ chars | Configurable, default 8 | Done |
| Maximum password length 128 chars | Configurable, default 128 | Done |
| Check passwords against breach databases | `@argus/policy-hibp` (HIBP API) | Done |
| Password strength estimation | `@argus/policy-zxcvbn` | Done |
| Account lockout after failed attempts | Configurable threshold + duration | Done |
| Rate limit authentication endpoints | Sliding window rate limiter | Done |
| Secure password reset (time-limited tokens) | 1-hour expiry, single-use, hashed | Done |
| Email verification | Required by default | Done |
| Multi-factor authentication | TOTP, WebAuthn, SMS | Done |
| JWT short expiry (access tokens) | 15 minutes default | Done |
| Refresh token rotation | Rotation with reuse detection | Done |
| Session management (limits, revocation) | Max per user, absolute + inactivity timeout | Done |
| Secure headers (Helmet) | Fastify Helmet plugin | Done |
| HTTPS enforcement | Trust proxy enabled, configure at load balancer | Done |
| No sensitive data in JWTs | Tokens contain email + roles, no passwords | Done |
| Audit logging | All security events logged | Done |
| GDPR data export | GET /v1/auth/me/export | Done |
| GDPR account deletion | DELETE /v1/auth/me (soft delete) | Done |
| Prevent email enumeration | Constant-time responses on reset | Done |
