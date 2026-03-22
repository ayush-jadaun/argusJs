# @argusjs/server

Fastify REST API server with 60+ authentication endpoints.

Part of [ArgusJS](https://github.com/ayush-jadaun/argusJs) -- Enterprise-grade, fully pluggable authentication platform.

## Install

```bash
pnpm add @argusjs/server
```

## Usage

```typescript
import { createApp } from '@argusjs/server';

const app = await createApp({ argus });
await app.listen({ port: 3100 });
```

## Docs

See the [main documentation](https://github.com/ayush-jadaun/argusJs) for full API reference and examples.

## License

[Apache-2.0](../../LICENSE)
