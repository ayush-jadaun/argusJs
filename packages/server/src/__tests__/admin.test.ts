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

describe('Admin Routes', () => {
  let app: FastifyInstance;
  let db: MemoryDbAdapter;
  let adminToken: string;
  let normalToken: string;
  let normalUserId: string;

  beforeAll(async () => {
    const ctx = await createTestApp();
    app = ctx.app;
    db = ctx.db;

    // Register an admin user
    const adminRes = await app.inject({
      method: 'POST',
      url: '/v1/auth/register',
      payload: {
        email: 'admin@example.com',
        password: 'securepass123',
        displayName: 'Admin User',
      },
    });
    const adminBody = adminRes.json();
    const adminUserId = adminBody.user.id;

    // Update admin user's roles to ['admin']
    await db.updateUser(adminUserId, { roles: ['admin'] });

    // Login as admin to get a token with the updated roles
    const adminLoginRes = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: {
        email: 'admin@example.com',
        password: 'securepass123',
      },
    });
    adminToken = adminLoginRes.json().accessToken;

    // Register a normal user
    const normalRes = await app.inject({
      method: 'POST',
      url: '/v1/auth/register',
      payload: {
        email: 'normal@example.com',
        password: 'securepass123',
        displayName: 'Normal User',
      },
    });
    const normalBody = normalRes.json();
    normalToken = normalBody.accessToken;
    normalUserId = normalBody.user.id;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /v1/admin/users', () => {
    it('should return paginated list of users', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/admin/users',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.users).toBeDefined();
      expect(Array.isArray(body.users)).toBe(true);
      expect(body.total).toBeGreaterThanOrEqual(2);
      expect(body.users.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('GET /v1/admin/users/:id', () => {
    it('should return user detail', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/v1/admin/users/${normalUserId}`,
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.user).toBeDefined();
      expect(body.user.id).toBe(normalUserId);
      expect(body.user.email).toBe('normal@example.com');
    });

    it('should return 404 for non-existent user', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/admin/users/non-existent-id',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(res.statusCode).toBe(404);
    });
  });

  describe('PATCH /v1/admin/users/:id', () => {
    it('should update user fields', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/v1/admin/users/${normalUserId}`,
        headers: { authorization: `Bearer ${adminToken}` },
        payload: { displayName: 'Updated Normal User', roles: ['user', 'editor'] },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.user.displayName).toBe('Updated Normal User');
      expect(body.user.roles).toContain('editor');
    });
  });

  describe('DELETE /v1/admin/users/:id', () => {
    it('should soft delete user', async () => {
      // Register a user specifically for deletion
      const regRes = await app.inject({
        method: 'POST',
        url: '/v1/auth/register',
        payload: {
          email: 'to-delete@example.com',
          password: 'securepass123',
          displayName: 'To Delete',
        },
      });
      const deleteUserId = regRes.json().user.id;

      const res = await app.inject({
        method: 'DELETE',
        url: `/v1/admin/users/${deleteUserId}`,
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(res.statusCode).toBe(204);
    });
  });

  describe('POST /v1/admin/users/:id/unlock', () => {
    it('should unlock a locked user account', async () => {
      // Lock the normal user first
      await db.updateUser(normalUserId, {
        lockedUntil: new Date(Date.now() + 3600000),
        failedLoginAttempts: 5,
      });

      const res = await app.inject({
        method: 'POST',
        url: `/v1/admin/users/${normalUserId}/unlock`,
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.user.lockedUntil).toBeNull();
      expect(body.user.failedLoginAttempts).toBe(0);
    });
  });

  describe('POST /v1/admin/impersonate', () => {
    it('should return short-lived token with impersonator claims', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/admin/impersonate',
        headers: { authorization: `Bearer ${adminToken}` },
        payload: { userId: normalUserId },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.accessToken).toBeDefined();
      expect(body.expiresIn).toBe(900);
      expect(body.tokenType).toBe('Bearer');
      expect(body.impersonating).toBeDefined();
      expect(body.impersonating.id).toBe(normalUserId);
    });

    it('should return 404 for non-existent user', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/admin/impersonate',
        headers: { authorization: `Bearer ${adminToken}` },
        payload: { userId: 'non-existent-id' },
      });
      expect(res.statusCode).toBe(404);
    });
  });

  describe('GET /v1/admin/audit-log', () => {
    it('should return audit log entries', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/admin/audit-log',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.entries).toBeDefined();
      expect(Array.isArray(body.entries)).toBe(true);
      expect(body.total).toBeGreaterThanOrEqual(0);
    });
  });

  describe('GET /v1/admin/stats', () => {
    it('should return system stats', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/admin/stats',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.stats).toBeDefined();
      expect(body.stats.totalUsers).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Authorization', () => {
    it('should return 403 for normal user on admin routes', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/admin/users',
        headers: { authorization: `Bearer ${normalToken}` },
      });
      expect(res.statusCode).toBe(403);
    });

    it('should return 401 for unauthenticated requests', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/admin/users',
      });
      expect(res.statusCode).toBe(401);
    });
  });
});
