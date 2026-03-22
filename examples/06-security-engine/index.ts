// Security engine: brute force, anomaly detection, device trust
import { Argus } from '@argusjs/core';
import { MemoryDbAdapter } from '@argusjs/db-memory';
import { MemoryCacheAdapter } from '@argusjs/cache-memory';
import { Argon2Hasher } from '@argusjs/hash-argon2';
import { RS256TokenProvider } from '@argusjs/token-jwt-rs256';
import { MemoryEmailProvider } from '@argusjs/email-memory';
import { DefaultSecurityEngine } from '@argusjs/security-engine';

async function main() {
  const db = new MemoryDbAdapter();
  const cache = new MemoryCacheAdapter();

  const argus = new Argus({
    db,
    cache,
    hasher: new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 }),
    token: new RS256TokenProvider({ issuer: 'my-app', audience: ['my-app'] }),
    email: new MemoryEmailProvider(),
    security: new DefaultSecurityEngine({
      cache,
      db,
      config: {
        bruteForce: {
          maxAttempts: 5,
          lockoutDuration: 300, // 5 min
          captchaThreshold: 3,
        },
        sharing: {
          maxConcurrentIPs: 3,
          maxConcurrentDevices: 5,
          action: 'challenge', // 'allow' | 'challenge' | 'block'
        },
        risk: {
          newDeviceScore: 20,
          newGeoScore: 30,
          challengeThreshold: 50,
          blockThreshold: 75,
        },
      },
    }),
    lockout: { maxAttempts: 5, duration: 300, captchaThreshold: 3 },
  });

  await argus.init();

  // Register a user
  await argus.register({
    email: 'secure@example.com',
    password: 'SecurePass123!',
    displayName: 'Secure User',
    ipAddress: '1.2.3.4',
    userAgent: 'Chrome/120',
  });

  // Simulate failed login attempts
  console.log('Simulating brute force attack...');
  for (let i = 0; i < 6; i++) {
    try {
      await argus.login('secure@example.com', 'wrong-password', {
        ipAddress: '5.6.7.8',
        userAgent: 'AttackerBot/1.0',
      });
    } catch (e: any) {
      console.log(`  Attempt ${i + 1}: ${e.message}`);
    }
  }

  // Try correct password — account is locked
  try {
    await argus.login('secure@example.com', 'SecurePass123!', {
      ipAddress: '1.2.3.4',
      userAgent: 'Chrome/120',
    });
  } catch (e: any) {
    console.log(`\nCorrect password but locked: ${e.message}`);
  }

  await argus.shutdown();
}

main().catch(console.error);
