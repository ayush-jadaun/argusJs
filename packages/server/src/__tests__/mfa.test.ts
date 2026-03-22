import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createApp } from '../app.js';
import { Argus } from '@argusjs/core';
import { MemoryDbAdapter } from '@argusjs/db-memory';
import { MemoryCacheAdapter } from '@argusjs/cache-memory';
import { MemoryRateLimiter } from '@argusjs/ratelimit-memory';
import { MemoryEmailProvider } from '@argusjs/email-memory';
import type { FastifyInstance } from 'fastify';
import type { MFAProvider } from '@argusjs/core';

class MockHasher {
  name = 'mock';
  async hash(p: string) { return `hashed_${p}`; }
  async verify(p: string, h: string) { return h === `hashed_${p}`; }
}

class MockTokenProvider {
  private c = 0;
  private tokens = new Map<string, any>();
  async init() {}
  async signAccessToken(payload: any) {
    this.c++;
    const token = `at_${this.c}_${payload.sub}`;
    this.tokens.set(token, payload);
    return token;
  }
  async verifyAccessToken(token: string) {
    const stored = this.tokens.get(token);
    if (stored) return stored;
    const parts = token.split('_');
    const sub = parts[parts.length - 1];
    return {
      iss: 't', sub, aud: ['t'], exp: Math.floor(Date.now() / 1000) + 900,
      iat: Math.floor(Date.now() / 1000), jti: 'j', email: 'test@test.com',
      emailVerified: false, roles: ['user'], permissions: [], sessionId: 's',
    };
  }
  async signMFAToken(userId: string) { return `mfa_${userId}`; }
  async verifyMFAToken(token: string) { return { userId: token.replace('mfa_', '') }; }
  getJWKS() { return { keys: [] }; }
}

const mockMFAProvider: MFAProvider = {
  name: 'totp',
  async generateSecret(user) {
    return {
      secret: 'JBSWY3DPEHPK3PXP',
      qrCodeUrl: 'otpauth://totp/Argus:test@test.com?secret=JBSWY3DPEHPK3PXP',
      backupCodes: ['1111-1111', '2222-2222'],
      expiresIn: 600,
    };
  },
  async verifyCode(secret, code) {
    return code === '123456';
  },
  generateBackupCodes() {
    return ['AAAA-BBBB', 'CCCC-DDDD', 'EEEE-FFFF'];
  },
};

async function createTestApp() {
  const db = new MemoryDbAdapter();
  const argus = new Argus({
    db,
    cache: new MemoryCacheAdapter(),
    hasher: new MockHasher() as any,
    token: new MockTokenProvider() as any,
    email: new MemoryEmailProvider(),
    rateLimiter: new MemoryRateLimiter(),
    session: { maxPerUser: 5, absoluteTimeout: 86400 },
    lockout: { maxAttempts: 5, duration: 1800, captchaThreshold: 3 },
    audit: { enabled: true },
    mfa: { totp: mockMFAProvider },
    mfaEncryptionKey: 'a'.repeat(64),
  });
  await argus.init();
  const app = await createApp({ argus, logger: false });
  return { app, argus, db };
}

describe('MFA Routes', () => {
  let app: FastifyInstance;
  let accessToken: string;
  let userId: string;

  beforeAll(async () => {
    const ctx = await createTestApp();
    app = ctx.app;

    // Register a user
    const regRes = await app.inject({
      method: 'POST',
      url: '/v1/auth/register',
      payload: {
        email: 'mfa-test@example.com',
        password: 'securepass123',
        displayName: 'MFA Tester',
      },
    });
    const regBody = regRes.json();
    accessToken = regBody.accessToken;
    userId = regBody.user.id;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /v1/auth/mfa/setup', () => {
    it('should return setup data', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/mfa/setup',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { method: 'totp' },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.secret).toBe('JBSWY3DPEHPK3PXP');
      expect(body.qrCodeUrl).toBeDefined();
      expect(body.backupCodes).toHaveLength(2);
      expect(body.expiresIn).toBe(600);
    });

    it('should return 401 without auth', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/mfa/setup',
        payload: { method: 'totp' },
      });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('POST /v1/auth/mfa/verify-setup', () => {
    it('should enable MFA with correct code', async () => {
      // Setup first
      await app.inject({
        method: 'POST',
        url: '/v1/auth/mfa/setup',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { method: 'totp' },
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/mfa/verify-setup',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { method: 'totp', code: '123456' },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
    });
  });

  describe('POST /v1/auth/mfa/verify', () => {
    it('should complete login with MFA', async () => {
      // Login should return MFA challenge now
      const loginRes = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: {
          email: 'mfa-test@example.com',
          password: 'securepass123',
        },
      });
      const loginBody = loginRes.json();
      expect(loginBody.mfaRequired).toBe(true);

      // Verify MFA
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/mfa/verify',
        payload: {
          mfaToken: loginBody.mfaToken,
          code: '123456',
          method: 'totp',
        },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.accessToken).toBeDefined();
      expect(body.refreshToken).toBeDefined();
      expect(body.user.email).toBe('mfa-test@example.com');
    });
  });

  describe('POST /v1/auth/mfa/disable', () => {
    it('should disable MFA with valid code', async () => {
      // We need a fresh access token since MFA was enabled
      const loginRes = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: {
          email: 'mfa-test@example.com',
          password: 'securepass123',
        },
      });
      const loginBody = loginRes.json();

      const verifyRes = await app.inject({
        method: 'POST',
        url: '/v1/auth/mfa/verify',
        payload: {
          mfaToken: loginBody.mfaToken,
          code: '123456',
          method: 'totp',
        },
      });
      const newToken = verifyRes.json().accessToken;

      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/mfa/disable',
        headers: { authorization: `Bearer ${newToken}` },
        payload: { code: '123456' },
      });
      expect(res.statusCode).toBe(204);
    });
  });
});
