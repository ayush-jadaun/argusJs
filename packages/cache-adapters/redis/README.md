# @argusjs/cache-redis

Redis cache adapter for production caching.

Part of [ArgusJS](https://github.com/ayush-jadaun/argusJs) -- Enterprise-grade, fully pluggable authentication platform.

## Install

```bash
pnpm add @argusjs/cache-redis
```

## Usage

```typescript
import { RedisCacheAdapter } from '@argusjs/cache-redis';

const cache = new RedisCacheAdapter({ url: 'redis://localhost:6379' });
```

## Docs

See the [main documentation](https://github.com/ayush-jadaun/argusJs) for full API reference and examples.

## License

[Apache-2.0](../../../LICENSE)
