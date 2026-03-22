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
  async init() {}
  async signAccessToken(payload: any) { return `at_${++this.c}_${payload.sub}`; }
  async verifyAccessToken(token: string) {
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
  getJWKS() { return { keys: [{ kty: 'RSA', kid: 'test-key' }] }; }
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

describe('Health Routes', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const ctx = await createTestApp();
    app = ctx.app;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /v1/health', () => {
    it('should return 200 with status ok and timestamp', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/health',
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.status).toBe('ok');
      expect(body.timestamp).toBeDefined();
    });
  });

  describe('GET /v1/health/live', () => {
    it('should return 200 with status ok', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/health/live',
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.status).toBe('ok');
    });
  });

  describe('GET /v1/health/ready', () => {
    it('should return 200 when db and cache are healthy', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/v1/health/ready',
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.status).toBe('ok');
      expect(body.checks.db).toBe('ok');
      expect(body.checks.cache).toBe('ok');
    });
  });
});

describe('JWKS Route', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const ctx = await createTestApp();
    app = ctx.app;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /.well-known/jwks.json', () => {
    it('should return 200 with keys array', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/.well-known/jwks.json',
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.keys).toBeDefined();
      expect(Array.isArray(body.keys)).toBe(true);
      expect(res.headers['cache-control']).toBe('public, max-age=3600');
    });
  });
});
