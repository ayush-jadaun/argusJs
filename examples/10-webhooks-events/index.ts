// Event system + webhook subscriptions
import { Argus } from '@argus/core';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';
import { Argon2Hasher } from '@argus/hash-argon2';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { MemoryEmailProvider } from '@argus/email-memory';

async function main() {
  const argus = new Argus({
    db: new MemoryDbAdapter(),
    cache: new MemoryCacheAdapter(),
    hasher: new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 }),
    token: new RS256TokenProvider({ issuer: 'my-app', audience: ['my-app'] }),
    email: new MemoryEmailProvider(),
    hooks: {
      afterRegister: async (user) => {
        console.log('[Hook] afterRegister:', user.email);
        // Provision user in billing system, CRM, etc.
      },
      afterLogin: async (user, session) => {
        console.log('[Hook] afterLogin:', user.email, 'from', session.ipAddress);
        // Track analytics, update last seen, etc.
      },
      onAccountLock: async (user) => {
        console.log('[Hook] onAccountLock:', user.email);
        // Alert security team
      },
    },
  });

  await argus.init();

  // Subscribe to events
  argus.on('user.registered', (data) => {
    console.log('[Event] user.registered:', data);
  });

  argus.on('user.login', (data) => {
    console.log('[Event] user.login:', data);
  });

  argus.on('user.login_failed', (data) => {
    console.log('[Event] user.login_failed:', data);
  });

  argus.on('security.*', (data) => {
    console.log('[Event] security.*:', data);
  });

  // Wildcard — catch everything
  argus.on('*', (data) => {
    // Send to analytics, logging, etc.
  });

  // Trigger events
  await argus.register({
    email: 'events@example.com', password: 'EventDemo123!',
    displayName: 'Events Demo', ipAddress: '1.2.3.4', userAgent: 'example',
  });

  await argus.login('events@example.com', 'EventDemo123!', {
    ipAddress: '1.2.3.4', userAgent: 'example',
  });

  // Trigger a failed login
  try {
    await argus.login('events@example.com', 'wrong', {
      ipAddress: '5.6.7.8', userAgent: 'attacker',
    });
  } catch {}

  await argus.shutdown();
}

main().catch(console.error);
