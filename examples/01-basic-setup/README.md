# 01 - Basic Setup

The simplest possible ArgusJS setup. Uses in-memory adapters for everything, so you need zero infrastructure -- no database, no Redis, no email provider.

## What it demonstrates

- Creating an `Argus` instance with memory adapters
- Registering a new user (email + password)
- Logging in and receiving access + refresh tokens
- Refreshing an access token using a refresh token
- Logging out (revoking a session)

## Adapters used

| Component | Adapter | Notes |
|-----------|---------|-------|
| Database | `@argusjs/db-memory` | In-memory, data lost on restart |
| Cache | `@argusjs/cache-memory` | In-memory |
| Hashing | `@argusjs/hash-argon2` | Lightweight dev params (4 MB, 2 iterations) |
| Tokens | `@argusjs/token-jwt-rs256` | Auto-generates RSA key pair |
| Email | `@argusjs/email-memory` | Stores emails in memory (inspect with `.getSentEmails()`) |

## Run

```bash
npx tsx examples/01-basic-setup/index.ts
```

## Expected output

```
Registered: alice@example.com
Access Token: eyJhbGciOiJSUzI1NiIsInR5c...
Logged in: alice@example.com
Refreshed, new token: eyJhbGciOiJSUzI1NiIsInR5c...
Logged out
```

## Next steps

- Swap memory adapters for PostgreSQL + Redis: see `02-production-postgres-redis`
- Add MFA: see `04-mfa-totp`
- Run as a REST API: see `07-fastify-server`
