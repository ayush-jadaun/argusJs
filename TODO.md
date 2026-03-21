# ArgusJS — TODO

## Benchmarks & Testing

- [ ] Benchmark vs **FusionAuth** — Docker image pulled, benchmark scripts exist at `benchmarks/k6/bench-fusionauth.js`, needs FusionAuth setup (OpenSearch + API key + app ID)
- [ ] **Stress test** (500+ VUs) — current tests max at 100 VUs. Need to find the breaking point: where does latency spike, what fails first (connection pool, memory, event loop)
- [ ] **Soak test** (1hr+ sustained load) — find memory leaks, connection pool exhaustion, Redis connection drift, audit buffer growth over time
- [ ] **MongoDB adapter** — `DbAdapter` interface exists, `@argus/db-mongodb` package was never built. Need Mongoose/native driver implementation + integration tests
- [ ] **End-to-end browser tests** — Dashboard + client SDK work but have no Playwright/Cypress tests. Cover: login flow, MFA setup, session management, admin user table

## Publish Readiness

- [ ] **LICENSE file** — MIT license mentioned in README but `LICENSE` file doesn't exist at repo root
- [ ] **CHANGELOG.md** — version history, follows Keep a Changelog format
- [ ] **CONTRIBUTING.md** — how to contribute, PR process, code standards, commit conventions, how to add a new adapter
- [ ] **npm publish dry run** — verify all 32 packages publish correctly with `npm pack --dry-run`, check exports, types, missing files
- [ ] **Package READMEs** — each of the 32 packages should have its own README.md with install + usage example (currently only `examples/01-basic-setup/` has one)

## Performance Optimization (Future)

- [ ] **Dedicated Argon2 worker thread pool** — separate pool from libuv to prevent hash operations from blocking refresh/health endpoints under mixed load
- [ ] **Prepared statements** — use Postgres prepared statements in Drizzle for repeated queries (user lookup, session lookup, token lookup)
- [ ] **Fastify response serialization** — use `fast-json-stringify` with JSON schema for response bodies instead of `JSON.stringify`
- [ ] **JWKS in-memory cache** — cache the JWKS JSON response in memory with TTL instead of rebuilding on every request
- [ ] **Benchmark with HS256** — need server.ts to support `JWT_ALGORITHM` env var to switch token provider at runtime, then benchmark refresh at ~0.1ms sign time

## Features (Future)

- [ ] **SAML SSO** — enterprise customers need SAML 2.0 support for IdP integration (Okta, Azure AD)
- [ ] **SCIM provisioning** — automated user provisioning/deprovisioning from IdPs
- [ ] **Passkey-only authentication** — passwordless login using WebAuthn as primary (not just MFA)
- [ ] **Magic link login** — email-based passwordless authentication
- [ ] **Session binding** — bind sessions to TLS certificate fingerprint for mutual TLS environments
- [ ] **Rate limit dashboard** — visualize rate limit hits, blocked IPs, top offenders in the admin dashboard
- [ ] **Webhook delivery log** — track webhook delivery attempts, failures, retries in the dashboard
- [ ] **User import/export CLI** — bulk import users from CSV/JSON, export for migration
