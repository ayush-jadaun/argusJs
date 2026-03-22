# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-22

### Added
- Core engine with full authentication pipeline (register, login, logout, token refresh, password reset, email verification)
- Token rotation with atomic reuse detection (TOCTOU-safe)
- Configurable refresh token rotation (`rotateRefreshTokens` option)
- Configurable refresh token caching (`cacheRefreshTokens` option)
- Redis session and user caching with automatic invalidation
- Async audit log batching (buffer + periodic flush)
- MFA support: TOTP, WebAuthn/FIDO2, SMS with backup codes
- OAuth providers: Google, GitHub, Apple, Microsoft, Discord, Custom OIDC
- Security engine: anomaly detection, brute force protection, device trust, account sharing prevention
- Organizations with multi-tenancy and auth policy enforcement
- RBAC + ABAC authorization with role inheritance and policy conditions
- API keys for service-to-service authentication
- Webhook system with HMAC-SHA256 signing and retry
- Admin impersonation with audit trail
- GDPR compliance: data export and right to deletion

#### Adapters
- Database: PostgreSQL (Drizzle ORM), MongoDB, Memory
- Cache: Redis, Memory
- Password hashing: Argon2id, bcrypt, scrypt
- Token signing: JWT RS256, ES256, HS256
- Email: SendGrid, SES, SMTP, Memory
- Rate limiting: Redis (sliding window), Memory
- Password policies: zxcvbn (strength), HIBP (breach check)

#### Server & Dashboard
- Fastify REST API with 60+ endpoints
- Next.js admin dashboard with 10 pages
- TypeScript client SDK with React hooks (useAuth, useUser, useSession, useMFA)
- Docker Compose for local development
- GitHub Actions CI/CD workflows
- Cluster mode with graceful shutdown

#### Performance
- UV_THREADPOOL_SIZE optimization for Argon2
- Three configurable performance profiles (Max Security, Balanced, Max Speed)
- Head-to-head benchmarks vs Keycloak 26

#### Testing
- 250+ unit and integration tests
- 22 battle tests that found 2 real bugs (whitespace password, TOCTOU race condition)
- 17 k6 performance test scenarios
- Integration tests against real PostgreSQL + Redis

#### Documentation
- Comprehensive README with architecture diagram and feature comparison
- 7 documentation guides (API, Architecture, Deployment, Performance, Security, Testing, Trade-offs)
- 13 runnable examples covering every feature
- Performance trade-off guide with real benchmarked numbers
