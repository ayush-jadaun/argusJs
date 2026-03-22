# @argusjs/core

Core engine providing types, interfaces, and the authentication pipeline.

Part of [ArgusJS](https://github.com/ayush-jadaun/argusJs) -- Enterprise-grade, fully pluggable authentication platform.

## Install

```bash
pnpm add @argusjs/core
```

## Usage

```typescript
import { Argus } from '@argusjs/core';

const argus = new Argus({ db, cache, hasher, token });
await argus.init();
```

## Docs

See the [main documentation](https://github.com/ayush-jadaun/argusJs) for full API reference and examples.

## License

[Apache-2.0](../../LICENSE)
