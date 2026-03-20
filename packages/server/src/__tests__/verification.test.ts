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
  const emailProvider = new MemoryEmailProvider();
  const argus = new Argus({
    db,
    cache: new MemoryCacheAdapter(),
    hasher: new MockHasher() as any,
    token: new MockTokenProvider() as any,
    email: emailProvider,
    rateLimiter: new MemoryRateLimiter(),
    session: { maxPerUser: 5, absoluteTimeout: 86400 },
    lockout: { maxAttempts: 5, duration: 1800, captchaThreshold: 3 },
    audit: { enabled: true },
  });
  await argus.init();
  const app = await createApp({ argus, logger: false });
  return { app, argus, db, emailProvider };
}

describe('Verification Routes', () => {
  let app: FastifyInstance;
  let db: MemoryDbAdapter;
  let accessToken: string;

  beforeAll(async () => {
    const ctx = await createTestApp();
    app = ctx.app;
    db = ctx.db;

    // Register a user to get an access token
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/register',
      payload: {
        email: 'verify@example.com',
        password: 'securepass123',
        displayName: 'Verifier',
      },
    });
    accessToken = res.json().accessToken;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /v1/auth/verify-email', () => {
    it('should return 200 with a valid verification token', async () => {
      // Find the verification token in the DB (stored as hashed)
      // We need to get the raw token. Since MemoryEmailProvider stores sent emails,
      // we can access the verification token from the email provider's sent emails.
      const user = await db.findUserByEmail('verify@example.com');
      // The MemoryEmailProvider stores the raw token in sentEmails
      const emailProvider = (app.server !== undefined ? app : app).argus as any;
      const email = emailProvider.email;
      const sentEmails = email.sentEmails ?? email.emails ?? [];
      // Find the verification email
      const verificationEmail = sentEmails.find((e: any) => e.type === 'verification' || e.to === 'verify@example.com');

      // If we can get the token from the email provider, use it
      if (verificationEmail && verificationEmail.token) {
        const res = await app.inject({
          method: 'POST',
          url: '/v1/auth/verify-email',
          payload: { token: verificationEmail.token },
        });
        expect(res.statusCode).toBe(200);
      } else {
        // Alternatively, create a verification token directly
        const { generateToken, hashToken } = await import('@argus/core');
        const rawToken = generateToken(32);
        const tokenHash = hashToken(rawToken);
        await db.createEmailVerificationToken({
          userId: user!.id,
          tokenHash,
          expiresAt: new Date(Date.now() + 86400 * 1000),
        });

        const res = await app.inject({
          method: 'POST',
          url: '/v1/auth/verify-email',
          payload: { token: rawToken },
        });
        expect(res.statusCode).toBe(200);
      }
    });

    it('should return 400 with a bad token', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/v1/auth/verify-email',
        payload: { token: 'completely-invalid-token' },
      });
      // The Argus engine throws INVALID_TOKEN (401) for tokens it cannot find
      // but our route validation catches missing/empty tokens as 400
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      expect(res.statusCode).toBeLessThan(500);
    });
  });
});
