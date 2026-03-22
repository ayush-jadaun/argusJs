import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createApp } from '../app.js';
import { Argus } from '@argusjs/core';
import { MemoryDbAdapter } from '@argusjs/db-memory';
import { MemoryCacheAdapter } from '@argusjs/cache-memory';
import { MemoryRateLimiter } from '@argusjs/ratelimit-memory';
import { MemoryEmailProvider } from '@argusjs/email-memory';
import type { FastifyInstance } from 'fastify';

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

async function createTestApp() {
  const db = new MemoryDbAdapter();
  const email = new MemoryEmailProvider();
  const argus = new Argus({
    db,
    cache: new MemoryCacheAdapter(),
    hasher: new MockHasher() as any,
    token: new MockTokenProvider() as any,
    email,
    rateLimiter: new MemoryRateLimiter(),
    password: { minLength: 8, maxLength: 128, historyCount: 5 },
    session: { maxPerUser: 5, absoluteTimeout: 86400 },
    lockout: { maxAttempts: 5, duration: 1800, captchaThreshold: 3 },
    audit: { enabled: true },
  });
  await argus.init();
  const app = await createApp({ argus, logger: false });
  return { app, argus, db, email };
}

describe('Password Routes', () => {
  let app: FastifyInstance;
  let db: MemoryDbAdapter;
  let email: MemoryEmailProvider;

  beforeAll(async () => {
    const ctx = await createTestApp();
    app = ctx.app;
    db = ctx.db;
    email = ctx.email;

    // Register a user for testing
    await app.inject({
      method: 'POST',
      url: '/v1/auth/register',
      payload: {
        email: 'user@example.com',
        password: 'securepass123',
        displayName: 'Test User',
      },
    });
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /v1/auth/forgot-password', () => {
    it('should return 202 for any email', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/forgot-password',
        payload: { email: 'user@example.com' },
      });
      expect(res.statusCode).toBe(202);

      // Also test with non-existent email — should still be 202
      const res2 = await app.inject({
        method: 'POST',
        url: '/v1/auth/forgot-password',
        payload: { email: 'nobody@example.com' },
      });
      expect(res2.statusCode).toBe(202);
    });
  });

  describe('POST /v1/auth/reset-password', () => {
    it('should reset password with valid token', async () => {
      // Trigger forgot-password to generate a reset token
      await app.inject({
        method: 'POST',
        url: '/v1/auth/forgot-password',
        payload: { email: 'user@example.com' },
      });

      // Get the most recent reset token from the email provider's sent emails
      const sentEmails = email.getSentEmails();
      const resetEmails = sentEmails.filter((e) => e.type === 'password_reset');
      const resetEmail = resetEmails[resetEmails.length - 1];
      expect(resetEmail).toBeDefined();
      const token = resetEmail.token;

      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/reset-password',
        payload: { token, newPassword: 'newSecurePass456' },
      });
      expect(res.statusCode).toBe(200);

      // Verify we can log in with the new password
      const loginRes = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: { email: 'user@example.com', password: 'newSecurePass456' },
      });
      expect(loginRes.statusCode).toBe(200);
    });

    it('should return 400 for invalid token', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/reset-password',
        payload: { token: 'invalid-token', newPassword: 'newpass12345' },
      });
      // ArgusError for INVALID_TOKEN has statusCode 401
      expect(res.statusCode).toBe(401);
      const body = res.json();
      expect(body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('POST /v1/auth/change-password', () => {
    it('should change password when authenticated', async () => {
      // Login with the password set from the reset test
      const loginRes = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: { email: 'user@example.com', password: 'newSecurePass456' },
      });
      const { accessToken } = loginRes.json();

      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/change-password',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: {
          currentPassword: 'newSecurePass456',
          newPassword: 'changedPass789',
        },
      });
      expect(res.statusCode).toBe(200);

      // Verify we can log in with the changed password
      const loginRes2 = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: { email: 'user@example.com', password: 'changedPass789' },
      });
      expect(loginRes2.statusCode).toBe(200);
    });

    it('should return 401 for wrong current password', async () => {
      // Login first
      const loginRes = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: { email: 'user@example.com', password: 'changedPass789' },
      });
      const { accessToken } = loginRes.json();

      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/change-password',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: {
          currentPassword: 'wrongPassword',
          newPassword: 'anotherPass123',
        },
      });
      expect(res.statusCode).toBe(401);
      const body = res.json();
      expect(body.error.code).toBe('INVALID_CREDENTIALS');
    });

    it('should return 401 without auth', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/change-password',
        payload: {
          currentPassword: 'somePassword',
          newPassword: 'anotherPass123',
        },
      });
      expect(res.statusCode).toBe(401);
    });
  });
});
