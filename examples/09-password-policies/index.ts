// Password strength validation with zxcvbn + HIBP breach check
import { Argus } from '@argus/core';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';
import { Argon2Hasher } from '@argus/hash-argon2';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { MemoryEmailProvider } from '@argus/email-memory';
import { ZxcvbnPolicy } from '@argus/policy-zxcvbn';
import { HIBPPolicy } from '@argus/policy-hibp';

async function main() {
  const argus = new Argus({
    db: new MemoryDbAdapter(),
    cache: new MemoryCacheAdapter(),
    hasher: new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 }),
    token: new RS256TokenProvider({ issuer: 'my-app', audience: ['my-app'] }),
    email: new MemoryEmailProvider(),
    passwordPolicy: [
      new ZxcvbnPolicy({ minScore: 3 }),  // 0-4 scale, 3 = "safely unguessable"
      new HIBPPolicy(),                     // checks Have I Been Pwned database
    ],
    password: { minLength: 10, maxLength: 128, historyCount: 5 },
  });

  await argus.init();

  // Try weak password
  console.log('Trying weak password "password123"...');
  try {
    await argus.register({
      email: 'test@example.com', password: 'password123',
      displayName: 'Test', ipAddress: '127.0.0.1', userAgent: 'example',
    });
  } catch (e: any) {
    console.log('Rejected:', e.message);
  }

  // Try breached password
  console.log('\nTrying breached password "P@ssw0rd!"...');
  try {
    await argus.register({
      email: 'test@example.com', password: 'P@ssw0rd!',
      displayName: 'Test', ipAddress: '127.0.0.1', userAgent: 'example',
    });
  } catch (e: any) {
    console.log('Rejected:', e.message);
  }

  // Try strong password
  console.log('\nTrying strong password...');
  const result = await argus.register({
    email: 'test@example.com', password: 'correct-horse-battery-staple-42!',
    displayName: 'Test', ipAddress: '127.0.0.1', userAgent: 'example',
  });
  console.log('Accepted! User:', result.user.email);

  await argus.shutdown();
}

main().catch(console.error);
