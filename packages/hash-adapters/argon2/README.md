# @argusjs/hash-argon2

Argon2id password hasher (recommended for production).

Part of [ArgusJS](https://github.com/ayush-jadaun/argusJs) -- Enterprise-grade, fully pluggable authentication platform.

## Install

```bash
pnpm add @argusjs/hash-argon2
```

## Usage

```typescript
import { Argon2Hasher } from '@argusjs/hash-argon2';

const hasher = new Argon2Hasher({ memoryCost: 65536, timeCost: 3 });
```

## Docs

See the [main documentation](https://github.com/ayush-jadaun/argusJs) for full API reference and examples.

## License

[Apache-2.0](../../../LICENSE)
