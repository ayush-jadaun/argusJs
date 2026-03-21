# API Reference

All endpoints return JSON. The server runs on Fastify 5 with gzip compression (for responses > 1 KB), Helmet security headers, CORS support, and a 10-second request timeout.

Base URL: `http://localhost:3100` (configurable via `PORT` and `HOST` env vars).

## Common Headers

### Request

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes (POST/PATCH) | `application/json` |
| `Authorization` | Protected routes | `Bearer <accessToken>` |

### Response

| Header | Description |
|--------|-------------|
| `X-Request-Id` | Unique request ID (UUID) for tracing |
| `X-RateLimit-Limit` | Max requests in window |
| `X-RateLimit-Remaining` | Remaining requests |
| `X-RateLimit-Reset` | Window reset timestamp (Unix epoch) |
| `Retry-After` | Seconds until rate limit resets (only on 429) |

## Error Format

All errors follow a consistent structure:

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "statusCode": 401,
    "requestId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "timestamp": "2026-03-21T12:00:00.000Z",
    "details": []
  }
}
```

### Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `VALIDATION_ERROR` | 400 | Request body validation failed |
| `INVALID_CREDENTIALS` | 401 | Wrong email or password |
| `INVALID_TOKEN` | 401 | Access token invalid or expired |
| `INVALID_REFRESH_TOKEN` | 401 | Refresh token invalid, expired, or revoked |
| `REFRESH_TOKEN_REUSE_DETECTED` | 401 | Token reuse attack -- all sessions revoked |
| `SESSION_EXPIRED` | 401 | Session has been revoked |
| `UNAUTHORIZED` | 401 | Missing or invalid authorization |
| `MFA_REQUIRED` | 403 | Login succeeded but MFA challenge needed |
| `EMAIL_NOT_VERIFIED` | 403 | Email verification required |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `EMAIL_ALREADY_EXISTS` | 409 | Email is already registered |
| `MFA_ALREADY_ENABLED` | 409 | MFA is already active |
| `PROVIDER_ALREADY_LINKED` | 409 | OAuth provider already linked |
| `WEAK_PASSWORD` | 422 | Password does not meet strength requirements |
| `BREACHED_PASSWORD` | 422 | Password found in breach database |
| `PASSWORD_RECENTLY_USED` | 422 | Password was used recently |
| `ACCOUNT_LOCKED` | 423 | Account locked due to failed attempts |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_SERVER_ERROR` | 500 | Unexpected server error |

---

## Health

### GET /v1/health

Basic health check. Always returns 200 if the server is running.

**Auth:** None

**Response:** `200 OK`
```json
{
  "status": "ok",
  "timestamp": "2026-03-21T12:00:00.000Z"
}
```

### GET /v1/health/live

Kubernetes liveness probe. Returns 200 if the process is alive.

**Auth:** None

**Response:** `200 OK`
```json
{ "status": "ok" }
```

### GET /v1/health/ready

Kubernetes readiness probe. Checks database and cache connectivity.

**Auth:** None

**Response:** `200 OK` (healthy) or `503 Service Unavailable` (degraded)
```json
{
  "status": "ok",
  "checks": {
    "db": "ok",
    "cache": "ok"
  }
}
```

---

## Authentication

### POST /v1/auth/register

Create a new user account.

**Auth:** None

**Request:**
```json
{
  "email": "alice@example.com",
  "password": "SecurePass123!",
  "displayName": "Alice"
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `email` | string | Yes | Valid email format |
| `password` | string | Yes | Min 8 chars (configurable), max 128 |
| `displayName` | string | Yes | 1-100 characters |

**Response:** `201 Created`
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "alice@example.com",
    "displayName": "Alice",
    "avatarUrl": null,
    "emailVerified": false,
    "mfaEnabled": false,
    "mfaMethods": [],
    "roles": ["user"],
    "orgId": null,
    "orgRole": null,
    "metadata": {},
    "createdAt": "2026-03-21T12:00:00.000Z",
    "updatedAt": "2026-03-21T12:00:00.000Z"
  },
  "accessToken": "eyJhbGciOiJSUzI1NiIs...",
  "refreshToken": "dGhpcyBpcyBhIHJlZnJl...",
  "expiresIn": 900,
  "tokenType": "Bearer"
}
```

**Errors:** `VALIDATION_ERROR`, `EMAIL_ALREADY_EXISTS`, `WEAK_PASSWORD`, `BREACHED_PASSWORD`, `RATE_LIMIT_EXCEEDED`

---

### POST /v1/auth/login

Authenticate with email and password.

**Auth:** None

**Request:**
```json
{
  "email": "alice@example.com",
  "password": "SecurePass123!"
}
```

**Response (no MFA):** `200 OK`
```json
{
  "user": { ... },
  "accessToken": "eyJ...",
  "refreshToken": "dGh...",
  "expiresIn": 900,
  "tokenType": "Bearer"
}
```

**Response (MFA enabled):** `200 OK`
```json
{
  "mfaRequired": true,
  "mfaToken": "eyJ...",
  "mfaMethods": ["totp"],
  "expiresIn": 300
}
```

**Errors:** `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, `EMAIL_NOT_VERIFIED`, `RATE_LIMIT_EXCEEDED`

---

### POST /v1/auth/refresh

Exchange a refresh token for a new access token + refresh token pair (rotation).

**Auth:** None

**Request:**
```json
{
  "refreshToken": "dGhpcyBpcyBhIHJlZnJl..."
}
```

**Response:** `200 OK`
```json
{
  "user": { ... },
  "accessToken": "eyJ... (new)",
  "refreshToken": "abc... (new, old is revoked)",
  "expiresIn": 900,
  "tokenType": "Bearer"
}
```

> **Note:** When `rotateRefreshTokens` is set to `false`, the `refreshToken` field in the response will be the same value as the input token (the token is reused, not rotated). When rotation is enabled (the default), a new refresh token is issued and the old one is revoked.

**Errors:** `INVALID_REFRESH_TOKEN`, `REFRESH_TOKEN_REUSE_DETECTED`, `SESSION_EXPIRED`

---

### POST /v1/auth/logout

Log out the current session, or all sessions.

**Auth:** Required (Bearer token)

**Request:**
```json
{
  "allDevices": false
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `allDevices` | boolean | No | `false` | If true, revokes all sessions |

**Response:** `200 OK`
```json
{ "success": true }
```

---

## Email Verification

### POST /v1/auth/verify-email

Verify a user's email with the token sent via email.

**Auth:** None

**Request:**
```json
{
  "token": "abc123def456..."
}
```

**Response:** `200 OK`
```json
{ "success": true, "message": "Email verified" }
```

**Errors:** `INVALID_TOKEN`, `NOT_FOUND`

---

### POST /v1/auth/resend-verification

Resend the verification email.

**Auth:** Required

**Response:** `200 OK`
```json
{ "success": true, "message": "Verification email sent" }
```

---

## Password Management

### POST /v1/auth/forgot-password

Request a password reset email.

**Auth:** None

**Request:**
```json
{
  "email": "alice@example.com"
}
```

**Response:** `200 OK` (always, even if email not found -- prevents enumeration)
```json
{ "success": true, "message": "If the email exists, a reset link has been sent" }
```

---

### POST /v1/auth/reset-password

Reset password using the token from the email.

**Auth:** None

**Request:**
```json
{
  "token": "reset-token-from-email",
  "password": "NewSecurePass456!"
}
```

**Response:** `200 OK`
```json
{ "success": true, "message": "Password reset successfully" }
```

**Errors:** `INVALID_TOKEN`, `WEAK_PASSWORD`, `BREACHED_PASSWORD`, `PASSWORD_RECENTLY_USED`

---

### POST /v1/auth/change-password

Change password while logged in. Requires current password.

**Auth:** Required

**Request:**
```json
{
  "currentPassword": "SecurePass123!",
  "newPassword": "EvenMoreSecure789!"
}
```

**Response:** `200 OK`
```json
{ "success": true, "message": "Password changed" }
```

**Errors:** `INVALID_CREDENTIALS`, `WEAK_PASSWORD`, `BREACHED_PASSWORD`, `PASSWORD_RECENTLY_USED`

---

## Multi-Factor Authentication

### POST /v1/auth/mfa/setup

Begin MFA setup for the authenticated user.

**Auth:** Required

**Request:**
```json
{
  "method": "totp"
}
```

**Response:** `200 OK`
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qrCodeUrl": "otpauth://totp/MyApp:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp&digits=6&period=30",
  "backupCodes": [
    "a1b2c3d4", "e5f6g7h8", "i9j0k1l2",
    "m3n4o5p6", "q7r8s9t0", "u1v2w3x4",
    "y5z6a7b8", "c9d0e1f2"
  ],
  "expiresIn": 600
}
```

---

### POST /v1/auth/mfa/verify-setup

Confirm MFA setup by entering a valid code from the authenticator app.

**Auth:** Required

**Request:**
```json
{
  "code": "123456",
  "method": "totp"
}
```

**Response:** `200 OK`
```json
{ "success": true, "message": "MFA enabled" }
```

**Errors:** `INVALID_MFA_CODE`

---

### POST /v1/auth/mfa/verify

Complete an MFA challenge during login.

**Auth:** None (uses mfaToken from login response)

**Request:**
```json
{
  "mfaToken": "eyJ...",
  "code": "123456",
  "method": "totp"
}
```

**Response:** `200 OK`
```json
{
  "user": { ... },
  "accessToken": "eyJ...",
  "refreshToken": "abc...",
  "expiresIn": 900,
  "tokenType": "Bearer"
}
```

**Errors:** `INVALID_MFA_TOKEN`, `INVALID_MFA_CODE`

---

### POST /v1/auth/mfa/disable

Disable MFA for the authenticated user.

**Auth:** Required

**Request:**
```json
{
  "code": "123456"
}
```

**Response:** `200 OK`
```json
{ "success": true, "message": "MFA disabled" }
```

---

### GET /v1/auth/mfa/backup-codes

Regenerate backup codes (invalidates old ones).

**Auth:** Required

**Response:** `200 OK`
```json
{
  "backupCodes": ["a1b2c3d4", "e5f6g7h8", "..."]
}
```

---

## User Profile

### GET /v1/auth/me

Get the current authenticated user's profile.

**Auth:** Required

**Response:** `200 OK`
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "alice@example.com",
    "displayName": "Alice",
    "avatarUrl": null,
    "emailVerified": true,
    "mfaEnabled": false,
    "mfaMethods": [],
    "roles": ["user"],
    "orgId": null,
    "orgRole": null,
    "metadata": {},
    "createdAt": "2026-03-21T12:00:00.000Z",
    "updatedAt": "2026-03-21T12:00:00.000Z"
  }
}
```

---

### PATCH /v1/auth/me

Update display name or avatar.

**Auth:** Required

**Request:**
```json
{
  "displayName": "Alice W.",
  "avatarUrl": "https://example.com/avatar.jpg"
}
```

**Response:** `200 OK`
```json
{ "user": { ... } }
```

---

### DELETE /v1/auth/me

Soft-delete the current user's account. Revokes all sessions.

**Auth:** Required

**Response:** `200 OK`
```json
{ "success": true, "message": "Account deleted" }
```

---

### GET /v1/auth/me/export

Export all user data (GDPR right of access).

**Auth:** Required

**Response:** `200 OK`
```json
{
  "user": { ... },
  "sessions": [ ... ],
  "auditLog": [ ... ],
  "oauthProviders": [ ... ],
  "organizations": [ ... ]
}
```

---

## Sessions & Devices

### GET /v1/auth/sessions

List all active sessions for the current user.

**Auth:** Required

**Response:** `200 OK`
```json
{
  "sessions": [
    {
      "id": "sess-uuid-1",
      "ipAddress": "1.2.3.4",
      "userAgent": "Mozilla/5.0 (Macintosh; ...)",
      "createdAt": "2026-03-21T12:00:00.000Z",
      "lastActivityAt": "2026-03-21T14:30:00.000Z",
      "isCurrent": true
    },
    {
      "id": "sess-uuid-2",
      "ipAddress": "5.6.7.8",
      "userAgent": "Mozilla/5.0 (iPhone; ...)",
      "createdAt": "2026-03-20T09:00:00.000Z",
      "lastActivityAt": "2026-03-20T18:00:00.000Z",
      "isCurrent": false
    }
  ]
}
```

---

### DELETE /v1/auth/sessions/:id

Revoke a specific session.

**Auth:** Required

**Response:** `200 OK`
```json
{ "success": true }
```

---

### GET /v1/auth/devices

List trusted devices.

**Auth:** Required

**Response:** `200 OK`
```json
{
  "devices": [
    {
      "id": "dev-uuid-1",
      "fingerprint": "abc123",
      "name": "Chrome on macOS",
      "trusted": true,
      "lastSeenAt": "2026-03-21T12:00:00.000Z"
    }
  ]
}
```

---

### POST /v1/auth/devices/:id/trust

Mark a device as trusted (reduces risk score for future logins).

**Auth:** Required

**Response:** `200 OK`
```json
{ "success": true }
```

---

### DELETE /v1/auth/devices/:id

Remove a trusted device.

**Auth:** Required

**Response:** `200 OK`
```json
{ "success": true }
```

---

## JWKS

### GET /.well-known/jwks.json

JSON Web Key Set for verifying JWT access tokens. Used by API gateways, microservices, and any service that needs to verify ArgusJS tokens without calling the auth server.

**Auth:** None

**Response:** `200 OK`
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "prod-key-2026",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGc...",
      "e": "AQAB"
    }
  ]
}
```

---

## Admin Endpoints

All admin endpoints require the `admin` role. Unauthorized requests receive `403 FORBIDDEN`.

### GET /v1/admin/users

List users with search, filter, and pagination.

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `search` | string | Search by email or display name |
| `role` | string | Filter by role |
| `emailVerified` | boolean | Filter by verification status |
| `mfaEnabled` | boolean | Filter by MFA status |
| `locked` | boolean | Filter locked accounts |
| `orgId` | string | Filter by organization |
| `limit` | number | Results per page (default 50) |
| `offset` | number | Pagination offset |

**Response:** `200 OK`
```json
{
  "users": [ ... ],
  "total": 1234,
  "limit": 50,
  "offset": 0
}
```

---

### GET /v1/admin/users/:id

Get a single user by ID.

**Response:** `200 OK`
```json
{ "user": { ... } }
```

---

### PATCH /v1/admin/users/:id

Update user fields (roles, permissions, displayName, etc.).

**Request:**
```json
{
  "roles": ["user", "editor"],
  "displayName": "Alice Admin"
}
```

**Response:** `200 OK`
```json
{ "user": { ... } }
```

---

### DELETE /v1/admin/users/:id

Soft-delete a user.

**Response:** `200 OK`
```json
{ "success": true }
```

---

### POST /v1/admin/users/:id/unlock

Unlock a locked user account.

**Response:** `200 OK`
```json
{ "success": true }
```

---

### POST /v1/admin/users/:id/reset-mfa

Reset MFA for a user (disables it, they must re-enroll).

**Response:** `200 OK`
```json
{ "success": true }
```

---

### POST /v1/admin/users/:id/reset-password

Trigger a password reset email for the user.

**Response:** `200 OK`
```json
{ "success": true }
```

---

### POST /v1/admin/impersonate

Generate an impersonation token for a user (for support). The audit log records who impersonated whom.

**Request:**
```json
{
  "userId": "target-user-id"
}
```

**Response:** `200 OK`
```json
{
  "accessToken": "eyJ...",
  "expiresIn": 3600
}
```

---

### GET /v1/admin/audit-log

Query audit log entries.

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `userId` | string | Filter by user ID |
| `action` | string | Filter by action (e.g., `LOGIN_SUCCESS`) |
| `from` | string | Start date (ISO 8601) |
| `to` | string | End date (ISO 8601) |
| `limit` | number | Results per page |
| `offset` | number | Pagination offset |

**Response:** `200 OK`
```json
{
  "entries": [
    {
      "id": "audit-uuid",
      "userId": "user-uuid",
      "action": "LOGIN_SUCCESS",
      "ipAddress": "1.2.3.4",
      "userAgent": "Mozilla/5.0",
      "metadata": {},
      "createdAt": "2026-03-21T12:00:00.000Z"
    }
  ],
  "total": 5678
}
```

---

### GET /v1/admin/stats

System-wide statistics.

**Response:** `200 OK`
```json
{
  "totalUsers": 12345,
  "activeUsers24h": 1234,
  "activeSessions": 5678,
  "mfaAdoption": 0.42,
  "lockedAccounts": 12
}
```

---

### GET /v1/admin/sessions

List all active sessions across all users.

**Response:** `200 OK`
```json
{
  "sessions": [ ... ],
  "total": 5678
}
```

---

### GET /v1/admin/roles

List all defined roles.

**Response:** `200 OK`
```json
{
  "roles": [
    { "name": "user", "permissions": ["read:own"] },
    { "name": "admin", "permissions": ["read:all", "write:all", "admin:*"] }
  ]
}
```

---

### POST /v1/admin/roles

Create a new role.

**Request:**
```json
{
  "name": "editor",
  "permissions": ["read:own", "write:content"]
}
```

**Response:** `201 Created`
```json
{ "role": { "name": "editor", "permissions": ["read:own", "write:content"] } }
```

---

### PATCH /v1/admin/roles/:name

Update a role's permissions.

**Request:**
```json
{
  "permissions": ["read:own", "write:content", "publish:content"]
}
```

**Response:** `200 OK`
```json
{ "role": { ... } }
```

---

### DELETE /v1/admin/roles/:name

Delete a role.

**Response:** `200 OK`
```json
{ "success": true }
```
