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

describe('Session Routes', () => {
  let app: FastifyInstance;
  let db: MemoryDbAdapter;
  let accessToken: string;

  beforeAll(async () => {
    const ctx = await createTestApp();
    app = ctx.app;
    db = ctx.db;

    // Register a user
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/register',
      payload: {
        email: 'session@example.com',
        password: 'securepass123',
        displayName: 'Session User',
      },
    });
    accessToken = res.json().accessToken;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /v1/auth/sessions', () => {
    it('should return 200 with session list', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/auth/sessions',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.sessions).toBeDefined();
      expect(Array.isArray(body.sessions)).toBe(true);
      expect(body.sessions.length).toBeGreaterThanOrEqual(1);
    });

    it('should return 401 without auth', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/auth/sessions',
      });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('DELETE /v1/auth/sessions/:id', () => {
    it('should return 204 when revoking own session', async () => {
      // Login to create a new session we can revoke
      const loginRes = await app.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: {
          email: 'session@example.com',
          password: 'securepass123',
        },
      });
      const newAccessToken = loginRes.json().accessToken;

      // List sessions to get a session ID
      const sessionsRes = await app.inject({
        method: 'GET',
        url: '/v1/auth/sessions',
        headers: { authorization: `Bearer ${newAccessToken}` },
      });
      const sessions = sessionsRes.json().sessions;
      // Find a non-current session to revoke
      const sessionToRevoke = sessions.find((s: any) => !s.isCurrent) ?? sessions[0];

      const res = await app.inject({
        method: 'DELETE',
        url: `/v1/auth/sessions/${sessionToRevoke.id}`,
        headers: { authorization: `Bearer ${newAccessToken}` },
      });
      expect(res.statusCode).toBe(204);
    });

    it('should return 401 without auth', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/v1/auth/sessions/some-id',
      });
      expect(res.statusCode).toBe(401);
    });
  });
});
