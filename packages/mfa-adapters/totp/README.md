# @argusjs/mfa-totp

TOTP multi-factor authentication provider (Google Authenticator compatible).

Part of [ArgusJS](https://github.com/ayush-jadaun/argusJs) -- Enterprise-grade, fully pluggable authentication platform.

## Install

```bash
pnpm add @argusjs/mfa-totp
```

## Usage

```typescript
import { TOTPProvider } from '@argusjs/mfa-totp';

const totp = new TOTPProvider({ appName: 'MyApp' });
```

## Docs

See the [main documentation](https://github.com/ayush-jadaun/argusJs) for full API reference and examples.

## License

[Apache-2.0](../../../LICENSE)
