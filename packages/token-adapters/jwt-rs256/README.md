# @argusjs/token-jwt-rs256

JWT RS256 token provider with JWKS support.

Part of [ArgusJS](https://github.com/ayush-jadaun/argusJs) -- Enterprise-grade, fully pluggable authentication platform.

## Install

```bash
pnpm add @argusjs/token-jwt-rs256
```

## Usage

```typescript
import { RS256TokenProvider } from '@argusjs/token-jwt-rs256';

const token = new RS256TokenProvider({ issuer: 'auth.myapp.com' });
```

## Docs

See the [main documentation](https://github.com/ayush-jadaun/argusJs) for full API reference and examples.

## License

[Apache-2.0](../../../LICENSE)
