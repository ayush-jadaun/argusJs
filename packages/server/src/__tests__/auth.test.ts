import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createApp } from '../app.js';
import { Argus } from '@argus/core';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';
import { MemoryRateLimiter } from '@argus/ratelimit-memory';
import { MemoryEmailProvider } from '@argus/email-memory';
import type { FastifyInstance } from 'fastify';

class MockHasher {
  name = 'mock';
  async hash(p: string) { return `hashed_${p}`; }
  async verify(p: string, h: string) { return h === `hashed_${p}`; }
}

// Token provider that tracks sessions so verifyAccessToken returns correct claims
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

describe('Auth Routes', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const ctx = await createTestApp();
    app = ctx.app;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /v1/auth/register', () => {
    it('should register a user and return 201', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/register',
        payload: {
          email: 'alice@example.com',
          password: 'securepass123',
          displayName: 'Alice',
        },
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.user).toBeDefined();
      expect(body.user.email).toBe('alice@example.com');
      expect(body.user.displayName).toBe('Alice');
      expect(body.accessToken).toBeDefined();
      expect(body.refreshToken).toBeDefined();
      expect(body.tokenType).toBe('Bearer');
    });

    it('should return 400 for missing fields', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/register',
        payload: { email: 'bob@example.com' },
      });
      expect(res.statusCode).toBe(400);
    });

    it('should return 409 for duplicate email', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/register',
        payload: {
          email: 'alice@example.com',
          password: 'anotherpass123',
          displayName: 'Alice2',
        },
      });
      expect(res.statusCode).toBe(409);
      const body = res.json();
      expect(body.error.code).toBe('EMAIL_ALREADY_EXISTS');
    });
  });

  describe('POST /v1/auth/login', () => {
    it('should login and return 200 with tokens', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: {
          email: 'alice@example.com',
          password: 'securepass123',
        },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.user).toBeDefined();
      expect(body.accessToken).toBeDefined();
      expect(body.refreshToken).toBeDefined();
    });

    it('should return 401 for wrong credentials', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: {
          email: 'alice@example.com',
          password: 'wrongpassword',
        },
      });
      expect(res.statusCode).toBe(401);
      const body = res.json();
      expect(body.error.code).toBe('INVALID_CREDENTIALS');
    });

    it('should return MFA challenge when MFA enabled', async () => {
      // Register a user, then enable MFA on them directly
      await app.inject({
        method: 'POST',
        url: '/v1/auth/register',
        payload: {
          email: 'mfa-user@example.com',
          password: 'securepass123',
          displayName: 'MFA User',
        },
      });

      // Enable MFA directly on the user via DB
      const db = (app as any).argus.db as MemoryDbAdapter;
      const user = await db.findUserByEmail('mfa-user@example.com');
      await db.updateUser(user!.id, { mfaEnabled: true, mfaMethods: ['totp'] });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: {
          email: 'mfa-user@example.com',
          password: 'securepass123',
        },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.mfaRequired).toBe(true);
      expect(body.mfaToken).toBeDefined();
      expect(body.mfaMethods).toContain('totp');
    });
  });

  describe('POST /v1/auth/refresh', () => {
    it('should return new tokens on valid refresh', async () => {
      // Login to get a refresh token
      const loginRes = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: {
          email: 'alice@example.com',
          password: 'securepass123',
        },
      });
      const { refreshToken } = loginRes.json();

      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/refresh',
        payload: { refreshToken },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.accessToken).toBeDefined();
      expect(body.refreshToken).toBeDefined();
      expect(body.refreshToken).not.toBe(refreshToken);
    });

    it('should return 401 for invalid token', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/refresh',
        payload: { refreshToken: 'invalid-token-value' },
      });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('POST /v1/auth/logout', () => {
    it('should return 204 on logout', async () => {
      // Login to get an access token
      const loginRes = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: {
          email: 'alice@example.com',
          password: 'securepass123',
        },
      });
      const { accessToken } = loginRes.json();

      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/logout',
        headers: { authorization: `Bearer ${accessToken}` },
        payload: {},
      });
      expect(res.statusCode).toBe(204);
    });

    it('should return 401 without auth token', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/logout',
        payload: {},
      });
      expect(res.statusCode).toBe(401);
    });
  });
});
