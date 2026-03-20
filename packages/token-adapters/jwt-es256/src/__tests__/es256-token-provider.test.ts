import { describe, it, expect, beforeAll } from 'vitest';
import { ES256TokenProvider } from '../es256-token-provider.js';

describe('ES256TokenProvider', () => {
  let provider: ES256TokenProvider;

  beforeAll(async () => {
    provider = new ES256TokenProvider({ issuer: 'test', audience: ['test'] });
    await provider.init();
  });

  it('should sign access token as JWT', async () => {
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
      roles: ['admin'], permissions: ['x'], sessionId: 's2',
    });
    const claims = await provider.verifyAccessToken(token);
    expect(claims.sub).toBe('u2');
    expect(claims.roles).toEqual(['admin']);
  });

  it('should reject tampered token', async () => {
    const token = await provider.signAccessToken({
      iss: 'test', sub: 'u1', aud: ['test'],
      exp: Math.floor(Date.now() / 1000) + 900, iat: Math.floor(Date.now() / 1000),
      jti: 'j3', email: 'a@b.com', emailVerified: true,
      roles: ['user'], permissions: [], sessionId: 's1',
    });
    await expect(provider.verifyAccessToken(token.slice(0, -5) + 'XXXXX')).rejects.toThrow();
  });

  it('should sign and verify MFA token', async () => {
    const token = await provider.signMFAToken('user-x');
    const result = await provider.verifyMFAToken(token);
    expect(result.userId).toBe('user-x');
  });

  it('should return JWKS with EC key', () => {
    const jwks = provider.getJWKS();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kty).toBe('EC');
    expect(jwks.keys[0].alg).toBe('ES256');
    expect(jwks.keys[0].crv).toBe('P-256');
  });

  it('should auto-generate keys', async () => {
    const p = new ES256TokenProvider();
    await p.init();
    const token = await p.signAccessToken({
      iss: 'argus', sub: 'u1', aud: ['argus'],
      exp: Math.floor(Date.now() / 1000) + 60, iat: Math.floor(Date.now() / 1000),
      jti: 'j1', email: 'x@y.com', emailVerified: false,
      roles: ['user'], permissions: [], sessionId: 's1',
    });
    const c = await p.verifyAccessToken(token);
    expect(c.sub).toBe('u1');
  });
});
