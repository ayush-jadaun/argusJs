# @argusjs/db-postgres

PostgreSQL database adapter using Drizzle ORM with 18 tables.

Part of [ArgusJS](https://github.com/ayush-jadaun/argusJs) -- Enterprise-grade, fully pluggable authentication platform.

## Install

```bash
pnpm add @argusjs/db-postgres
```

## Usage

```typescript
import { PostgresAdapter } from '@argusjs/db-postgres';

const db = new PostgresAdapter({ connectionString: process.env.DATABASE_URL });
```

## Docs

See the [main documentation](https://github.com/ayush-jadaun/argusJs) for full API reference and examples.

## License

[Apache-2.0](../../../LICENSE)
