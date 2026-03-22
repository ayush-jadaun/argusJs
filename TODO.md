# ArgusJS — TODO

## Benchmarks & Testing

- [ ] Benchmark vs **FusionAuth** — Docker image pulled, benchmark scripts exist at `benchmarks/k6/bench-fusionauth.js`, needs FusionAuth setup
- [ ] **Stress test** (500+ VUs) — find the breaking point
- [ ] **Soak test** (1hr+ sustained load) — find memory leaks, connection pool exhaustion
- [x] ~~**MongoDB adapter**~~ — Done
- [ ] **End-to-end browser tests** — Playwright/Cypress for dashboard + client SDK
- [ ] **MongoDB integration tests** — need a MongoDB Docker container

## Publish Readiness

- [x] ~~**LICENSE file**~~ — Done. Apache 2.0
- [x] ~~**CHANGELOG.md**~~ — Done. v0.1.0 entry
- [x] ~~**Package READMEs**~~ — Done. All 33 packages have README.md
- [x] ~~**npm files field**~~ — Done. All packages publish only dist/ + README.md
- [x] ~~**npmignore**~~ — Done. Root .npmignore excludes src/tests/configs
- [x] ~~**license field**~~ — Done. All 33 package.json files have Apache-2.0
- [x] ~~**npm scope**~~ — Done. Renamed to @argusjs/*
- [ ] **CONTRIBUTING.md** — how to contribute, PR process, code standards
- [ ] **bumpcraft integration** — set up once Turborepo monorepo support is ready

## Performance Optimization (Future)

- [ ] **Dedicated Argon2 worker thread pool** — separate pool from libuv
- [ ] **Prepared statements** — Postgres prepared statements in Drizzle
- [ ] **Fastify response serialization** — fast-json-stringify
- [ ] **JWKS in-memory cache** — cache JSON response with TTL
- [ ] **Benchmark with HS256** — JWT_ALGORITHM env var support

## Features (Future)

- [ ] **SAML SSO** — SAML 2.0 for Okta, Azure AD
- [ ] **SCIM provisioning** — automated user provisioning/deprovisioning
- [ ] **Passkey-only authentication** — passwordless WebAuthn as primary
- [ ] **Magic link login** — email-based passwordless
- [ ] **Session binding** — TLS certificate fingerprint binding
- [ ] **Rate limit dashboard** — visualize rate limit hits in admin UI
- [ ] **Webhook delivery log** — track attempts/failures in dashboard
- [ ] **User import/export CLI** — bulk CSV/JSON import/export
