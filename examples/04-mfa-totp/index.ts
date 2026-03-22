// MFA with TOTP (Google Authenticator / Authy)
import { Argus } from '@argusjs/core';
import { MemoryDbAdapter } from '@argusjs/db-memory';
import { MemoryCacheAdapter } from '@argusjs/cache-memory';
import { Argon2Hasher } from '@argusjs/hash-argon2';
import { RS256TokenProvider } from '@argusjs/token-jwt-rs256';
import { MemoryEmailProvider } from '@argusjs/email-memory';
import { TOTPProvider } from '@argusjs/mfa-totp';

async function main() {
  const argus = new Argus({
    db: new MemoryDbAdapter(),
    cache: new MemoryCacheAdapter(),
    hasher: new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 }),
    token: new RS256TokenProvider({ issuer: 'my-app', audience: ['my-app'] }),
    email: new MemoryEmailProvider(),
    mfa: {
      totp: new TOTPProvider({ appName: 'MyApp', digits: 6, period: 30 }),
    },
    mfaEncryptionKey: 'a'.repeat(64), // 32-byte hex key — use a real one in production!
  });

  await argus.init();

  // 1. Register user
  const reg = await argus.register({
    email: 'mfa-user@example.com',
    password: 'SecurePass123!',
    displayName: 'MFA User',
    ipAddress: '127.0.0.1',
    userAgent: 'example',
  });
  console.log('User registered:', reg.user.email);

  // 2. Setup MFA
  const setup = await argus.mfa.setup(reg.user.id, 'totp');
  console.log('MFA Setup:');
  console.log('  Secret:', setup.secret);
  console.log('  QR Code URL:', setup.qrCodeUrl);
  console.log('  Backup Codes:', setup.backupCodes);

  // 3. In real app, user scans QR with authenticator, enters code
  // For demo, we'd need to generate a valid TOTP code from the secret
  console.log('\nUser would scan QR code, enter 6-digit code to verify setup');
  console.log('Then on login, MFA challenge is returned instead of tokens');

  // 4. Login with MFA
  const loginResult = await argus.login('mfa-user@example.com', 'SecurePass123!', {
    ipAddress: '127.0.0.1',
    userAgent: 'example',
  });

  // Before MFA is verified/enabled, login returns tokens directly
  // After MFA is enabled, login returns MFAChallengeResponse:
  // { mfaRequired: true, mfaToken: '...', mfaMethods: ['totp'], expiresIn: 300 }
  console.log('Login result:', 'mfaRequired' in loginResult ? 'MFA Challenge' : 'Tokens');

  await argus.shutdown();
}

main().catch(console.error);
