import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createApp } from '../app.js';
import { Argus } from '@argus/core';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';
import { MemoryRateLimiter } from '@argus/ratelimit-memory';
import { MemoryEmailProvider } from '@argus/email-memory';

// Reuse mock helpers from core tests
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
    const sub = token.split('_').pop()!;
    return { iss: 't', sub, aud: ['t'], exp: Math.floor(Date.now()/1000)+900, iat: Math.floor(Date.now()/1000), jti: 'j', email: 'test@test.com', emailVerified: false, roles: ['user'], permissions: [], sessionId: 's' };
  }
  async signMFAToken(userId: string) { return `mfa_${userId}`; }
  async verifyMFAToken(token: string) { return { userId: token.replace('mfa_', '') }; }
  getJWKS() { return { keys: [] }; }
}

export async function createTestApp() {
  const argus = new Argus({
    db: new MemoryDbAdapter(),
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
  return { app, argus };
}

describe('App scaffolding', () => {
  it('should create app without errors', async () => {
    const { app } = await createTestApp();
    expect(app).toBeDefined();
    await app.close();
  });

  it('should return 404 for unknown routes', async () => {
    const { app } = await createTestApp();
    const res = await app.inject({ method: 'GET', url: '/nonexistent' });
    expect(res.statusCode).toBe(404);
    await app.close();
  });

  it('should set X-Request-Id header', async () => {
    const { app } = await createTestApp();
    const res = await app.inject({ method: 'GET', url: '/nonexistent' });
    expect(res.headers['x-request-id']).toBeDefined();
    await app.close();
  });

  it('should use client-provided X-Request-Id', async () => {
    const { app } = await createTestApp();
    const res = await app.inject({ method: 'GET', url: '/nonexistent', headers: { 'x-request-id': 'my-custom-id' } });
    expect(res.headers['x-request-id']).toBe('my-custom-id');
    await app.close();
  });
});
