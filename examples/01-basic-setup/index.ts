// Most basic ArgusJS setup — memory adapters, no infrastructure needed
import { Argus } from '@argusjs/core';
import { MemoryDbAdapter } from '@argusjs/db-memory';
import { MemoryCacheAdapter } from '@argusjs/cache-memory';
import { Argon2Hasher } from '@argusjs/hash-argon2';
import { RS256TokenProvider } from '@argusjs/token-jwt-rs256';
import { MemoryEmailProvider } from '@argusjs/email-memory';

async function main() {
  const argus = new Argus({
    db: new MemoryDbAdapter(),
    cache: new MemoryCacheAdapter(),
    hasher: new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 }),
    token: new RS256TokenProvider({ issuer: 'my-app', audience: ['my-app'] }),
    email: new MemoryEmailProvider(),
  });

  await argus.init();

  // Register a user
  const result = await argus.register({
    email: 'alice@example.com',
    password: 'SecurePass123!',
    displayName: 'Alice',
    ipAddress: '127.0.0.1',
    userAgent: 'example',
  });

  console.log('Registered:', result.user.email);
  console.log('Access Token:', result.accessToken.substring(0, 30) + '...');

  // Login
  const login = await argus.login('alice@example.com', 'SecurePass123!', {
    ipAddress: '127.0.0.1',
    userAgent: 'example',
  });
  console.log('Logged in:', login.user.email);

  // Refresh token
  const refreshed = await argus.refresh(login.refreshToken);
  console.log('Refreshed, new token:', refreshed.accessToken.substring(0, 30) + '...');

  // Logout
  const sessions = await argus.db.getActiveSessions(login.user.id);
  await argus.logout(login.user.id, sessions[0].id);
  console.log('Logged out');

  await argus.shutdown();
}

main().catch(console.error);
