import { describe, it, expect, beforeAll } from 'vitest';
import { HS256TokenProvider } from '../hs256-token-provider.js';

describe('HS256TokenProvider', () => {
  let provider: HS256TokenProvider;

  beforeAll(async () => {
    provider = new HS256TokenProvider({
      secret: 'a-very-long-secret-that-is-at-least-32-characters-for-hs256',
      issuer: 'test', audience: ['test'],
    });
    await provider.init();
  });

  it('should sign access token', async () => {
    const token = await provider.signAccessToken({
      iss: 'test', sub: 'u1', aud: ['test'],
      exp: Math.floor(Date.now() / 1000) + 900, iat: Math.floor(Date.now() / 1000),
      jti: 'j1', email: 'a@b.com', emailVerified: true,
      roles: ['user'], permissions: [], sessionId: 's1',
    });
    expect(token.split('.')).toHaveLength(3);
  });

  it('should verify and return claims', async () => {
    const token = await provider.signAccessToken({
      iss: 'test', sub: 'u2', aud: ['test'],
      exp: Math.floor(Date.now() / 1000) + 900, iat: Math.floor(Date.now() / 1000),
      jti: 'j2', email: 'b@c.com', emailVerified: false,
      roles: ['user'], permissions: [], sessionId: 's2',
    });
    const claims = await provider.verifyAccessToken(token);
    expect(claims.sub).toBe('u2');
  });

  it('should reject token signed with different secret', async () => {
    const other = new HS256TokenProvider({
      secret: 'completely-different-secret-that-is-also-long-enough',
      issuer: 'test', audience: ['test'],
    });
    await other.init();
    const token = await other.signAccessToken({
      iss: 'test', sub: 'u1', aud: ['test'],
      exp: Math.floor(Date.now() / 1000) + 900, iat: Math.floor(Date.now() / 1000),
      jti: 'j1', email: 'a@b.com', emailVerified: true,
      roles: ['user'], permissions: [], sessionId: 's1',
    });
    await expect(provider.verifyAccessToken(token)).rejects.toThrow();
  });

  it('should sign and verify MFA token', async () => {
    const token = await provider.signMFAToken('user-mfa');
    const result = await provider.verifyMFAToken(token);
    expect(result.userId).toBe('user-mfa');
  });

  it('should return empty JWKS (symmetric key)', () => {
    const jwks = provider.getJWKS();
    expect(jwks.keys).toHaveLength(0);
  });
});
