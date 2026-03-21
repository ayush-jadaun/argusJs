// Running ArgusJS as a Fastify REST API
import { Argus } from '@argus/core';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';
import { Argon2Hasher } from '@argus/hash-argon2';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { MemoryEmailProvider } from '@argus/email-memory';
import { createApp } from '@argus/server';

async function main() {
  const argus = new Argus({
    db: new MemoryDbAdapter(),
    cache: new MemoryCacheAdapter(),
    hasher: new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 }),
    token: new RS256TokenProvider({ issuer: 'my-app', audience: ['my-app'] }),
    email: new MemoryEmailProvider(),
  });

  await argus.init();

  const app = await createApp({ argus });
  await app.listen({ port: 3100, host: '0.0.0.0' });

  console.log('ArgusJS API server running on http://localhost:3100');
  console.log('\nEndpoints:');
  console.log('  POST /v1/auth/register');
  console.log('  POST /v1/auth/login');
  console.log('  POST /v1/auth/refresh');
  console.log('  POST /v1/auth/logout');
  console.log('  POST /v1/auth/forgot-password');
  console.log('  POST /v1/auth/reset-password');
  console.log('  POST /v1/auth/change-password');
  console.log('  POST /v1/auth/verify-email');
  console.log('  GET  /v1/auth/me');
  console.log('  GET  /v1/auth/sessions');
  console.log('  GET  /v1/health');
  console.log('  GET  /.well-known/jwks.json');
  console.log('  ... and 50+ more');
}

main().catch(console.error);
