# @argusjs/oauth-custom

Custom OAuth provider for any OpenID Connect-compatible identity provider.

Part of [ArgusJS](https://github.com/ayush-jadaun/argusJs) -- Enterprise-grade, fully pluggable authentication platform.

## Install

```bash
pnpm add @argusjs/oauth-custom
```

## Usage

```typescript
import { CustomOAuth } from '@argusjs/oauth-custom';

const provider = new CustomOAuth({ clientId: '...', clientSecret: '...' });
```

## Docs

See the [main documentation](https://github.com/ayush-jadaun/argusJs) for full API reference and examples.

## License

[Apache-2.0](../../../LICENSE)
