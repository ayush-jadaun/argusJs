import type { TokenProvider, JsonWebKeySet } from '../../interfaces/token-provider.js';
import type { PasswordHasher } from '../../interfaces/password-hasher.js';
import type { AccessTokenClaims } from '../../types/responses.js';
import type { ArgusConfig } from '../../types/config.js';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';
import { MemoryRateLimiter } from '@argus/ratelimit-memory';
import { MemoryEmailProvider } from '@argus/email-memory';
import { Argus } from '../argus.js';

export class MockHasher implements PasswordHasher {
  name = 'mock';
  async hash(password: string): Promise<string> {
    return `hashed_${password}`;
  }
  async verify(password: string, hash: string): Promise<boolean> {
    return hash === `hashed_${password}`;
  }
}

export class MockTokenProvider implements TokenProvider {
  private counter = 0;
  async init(): Promise<void> {}
  async signAccessToken(payload: AccessTokenClaims): Promise<string> {
    this.counter++;
    return `access_token_${this.counter}_${payload.sub}`;
  }
  async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    const parts = token.split('_');
    const sub = parts[parts.length - 1];
    return {
      iss: 'test', sub, aud: ['test'], exp: Math.floor(Date.now() / 1000) + 900,
      iat: Math.floor(Date.now() / 1000), jti: `jti_${this.counter}`,
      email: 'test@test.com', emailVerified: false, roles: ['user'],
      permissions: [], sessionId: 'test-session',
    };
  }
  async signMFAToken(userId: string): Promise<string> {
    return `mfa_token_${userId}`;
  }
  async verifyMFAToken(token: string): Promise<{ userId: string }> {
    const userId = token.replace('mfa_token_', '');
    return { userId };
  }
  getJWKS(): JsonWebKeySet {
    return { keys: [] };
  }
}

export function createTestArgus(overrides?: Partial<ArgusConfig>): { argus: Argus; db: MemoryDbAdapter; cache: MemoryCacheAdapter; email: MemoryEmailProvider } {
  const db = new MemoryDbAdapter();
  const cache = new MemoryCacheAdapter();
  const email = new MemoryEmailProvider();
  const argus = new Argus({
    db,
    cache,
    hasher: new MockHasher(),
    token: new MockTokenProvider(),
    email,
    rateLimiter: new MemoryRateLimiter(),
    password: { minLength: 8, maxLength: 128, historyCount: 5 },
    session: { maxPerUser: 5, absoluteTimeout: 2592000 },
    lockout: { maxAttempts: 5, duration: 1800, captchaThreshold: 3 },
    emailVerification: { required: true, tokenTTL: 86400 },
    audit: { enabled: true },
    ...overrides,
  });
  return { argus, db, cache, email };
}
