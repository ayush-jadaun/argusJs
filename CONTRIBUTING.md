# Contributing to ArgusJS

Thanks for your interest in contributing! This guide covers everything you need to know.

## Development Setup

```bash
# Clone
git clone https://github.com/ayush-jadaun/argusJs.git
cd argusJs

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test:unit
```

## Project Structure

```
packages/
  core/                  Engine, types, interfaces
  server/                Fastify REST API
  dashboard/             Next.js admin UI
  client/                TypeScript SDK + React hooks
  db-adapters/           Database adapters (postgres, mongodb, memory)
  cache-adapters/        Cache adapters (redis, memory)
  hash-adapters/         Password hashers (argon2, bcrypt, scrypt)
  token-adapters/        JWT providers (rs256, es256, hs256)
  mfa-adapters/          MFA providers (totp, webauthn, sms)
  oauth-providers/       OAuth providers (google, github, apple, microsoft, discord, custom)
  email-adapters/        Email providers (sendgrid, ses, smtp, memory)
  rate-limit-adapters/   Rate limiters (redis, memory)
  password-policy/       Password policies (zxcvbn, hibp)
  security/              Security engine
```

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/) with [bumpcraft](https://github.com/ayush-jadaun/bumpcraft) for releases.

```
feat(core): add session fingerprinting     # minor bump on core
fix(server): handle malformed JWT          # patch bump on server
feat!: redesign token API                  # major bump (all packages)
docs: update API reference                 # no version bump
test: add edge case for refresh            # no version bump
```

### Scopes

Use the package name as scope: `core`, `server`, `client`, `dashboard`, `db-postgres`, `db-mongodb`, `cache-redis`, `hash-argon2`, `token-rs256`, `mfa-totp`, `oauth-google`, `email-sendgrid`, `ratelimit-redis`, `policy-zxcvbn`, `security`, etc.

## Creating a New Adapter

ArgusJS is fully pluggable. To create a new adapter:

1. **Pick the interface** from `@argusjs/core` (e.g., `DbAdapter`, `PasswordHasher`, `TokenProvider`)
2. **Create the package** under the appropriate directory (e.g., `packages/db-adapters/my-adapter/`)
3. **Implement the interface** -- every method must be implemented
4. **Add tests** -- use Vitest, follow TDD
5. **Add package.json** with `@argusjs/` scope, `"files": ["dist", "README.md"]`, `"license": "Apache-2.0"`
6. **Add README.md** with install + usage example
7. **Build and test**: `pnpm build && pnpm test`

### Example: Custom Database Adapter

```typescript
import type { DbAdapter } from '@argusjs/core';

export class MyDbAdapter implements DbAdapter {
  async init() { /* connect */ }
  async shutdown() { /* disconnect */ }
  async createUser(input) { /* ... */ }
  // ... implement all ~80 methods
}
```

## Testing

```bash
# Unit tests (no infrastructure needed)
pnpm test:unit

# Integration tests (needs Docker Postgres + Redis)
DATABASE_URL=postgres://... REDIS_URL=redis://... pnpm test:integration

# Nuclear edge case tests
npx vitest run tests/nuclear/ --config tests/nuclear/vitest.config.ts

# Single package
cd packages/core && pnpm vitest run
```

### Test Rules

- **Never change tests to make them pass** -- always fix source code
- Write tests FIRST (TDD)
- Use memory adapters for unit tests
- Integration tests skip gracefully when infrastructure is unavailable

## Pull Request Process

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make changes with conventional commits
4. Run `pnpm build && pnpm test:unit`
5. Push and open a PR against `main`
6. Ensure CI passes

## Releasing

Releases are managed by [bumpcraft](https://github.com/ayush-jadaun/bumpcraft):

```bash
npx bumpcraft status      # preview pending changes
npx bumpcraft validate    # dry run
npx bumpcraft release     # release locally
npx bumpcraft publish     # publish to npm
```

Or trigger from GitHub Actions: **Actions > Release & Publish > Run workflow**.

## License

By contributing, you agree that your contributions will be licensed under the [Apache-2.0 License](./LICENSE).
