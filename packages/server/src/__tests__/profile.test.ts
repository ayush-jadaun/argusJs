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
  });
  await argus.init();
  const app = await createApp({ argus, logger: false });
  return { app, argus, db };
}

describe('Profile Routes', () => {
  let app: FastifyInstance;
  let accessToken: string;

  beforeAll(async () => {
    const ctx = await createTestApp();
    app = ctx.app;

    // Register a user to get an access token
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/register',
      payload: {
        email: 'profile@example.com',
        password: 'securepass123',
        displayName: 'Profile User',
      },
    });
    accessToken = res.json().accessToken;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /v1/auth/me', () => {
    it('should return 200 with user data when authenticated', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/auth/me',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.user).toBeDefined();
      expect(body.user.email).toBe('profile@example.com');
      expect(body.user.displayName).toBe('Profile User');
    });

    it('should return 401 without auth', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/auth/me',
      });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('PATCH /v1/auth/me', () => {
    it('should return 200 with updated user data', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: '/v1/auth/me',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: { displayName: 'Updated Name' },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.user.displayName).toBe('Updated Name');
    });

    it('should return 401 without auth', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: '/v1/auth/me',
        payload: { displayName: 'No Auth' },
      });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('DELETE /v1/auth/me', () => {
    it('should return 204 on soft delete', async () => {
      // Register a separate user for deletion test
      const regRes = await app.inject({
        method: 'POST',
        url: '/v1/auth/register',
        payload: {
          email: 'delete-me@example.com',
          password: 'securepass123',
          displayName: 'Delete Me',
        },
      });
      const deleteToken = regRes.json().accessToken;

      const res = await app.inject({
        method: 'DELETE',
        url: '/v1/auth/me',
        headers: { authorization: `Bearer ${deleteToken}` },
      });
      expect(res.statusCode).toBe(204);
    });

    it('should return 401 without auth', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/v1/auth/me',
      });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('GET /v1/auth/me/export', () => {
    it('should return 200 with user data export', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/auth/me/export',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.user).toBeDefined();
    });

    it('should return 401 without auth', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/auth/me/export',
      });
      expect(res.statusCode).toBe(401);
    });
  });
});
