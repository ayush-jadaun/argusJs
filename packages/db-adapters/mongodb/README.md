# @argusjs/db-mongodb

MongoDB database adapter using the native driver.

Part of [ArgusJS](https://github.com/ayush-jadaun/argusJs) -- Enterprise-grade, fully pluggable authentication platform.

## Install

```bash
pnpm add @argusjs/db-mongodb
```

## Usage

```typescript
import { MongoDbAdapter } from '@argusjs/db-mongodb';

const db = new MongoDbAdapter({ url: 'mongodb://localhost:27017', dbName: 'auth' });
```

## Docs

See the [main documentation](https://github.com/ayush-jadaun/argusJs) for full API reference and examples.

## License

[Apache-2.0](../../../LICENSE)
