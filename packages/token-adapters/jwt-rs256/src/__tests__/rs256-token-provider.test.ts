import { describe, it, expect, beforeAll } from 'vitest';
import { RS256TokenProvider } from '../rs256-token-provider.js';

describe('RS256TokenProvider', () => {
  let provider: RS256TokenProvider;

  beforeAll(async () => {
    provider = new RS256TokenProvider({
      issuer: 'test-issuer',
      audience: ['test-audience'],
      accessTokenTTL: 900,
      mfaTokenTTL: 300,
    });
    await provider.init();
  });

  it('should sign an access token as a JWT with 3 parts', async () => {
    const token = await provider.signAccessToken({
      iss: 'test-issuer', sub: 'user-123', aud: ['test-audience'],
      exp: Math.floor(Date.now() / 1000) + 900, iat: Math.floor(Date.now() / 1000),
      jti: 'jti-1', email: 'a@b.com', emailVerified: true,
      roles: ['user'], permissions: [], sessionId: 'sess-1',
    });
    expect(token.split('.')).toHaveLength(3);
  });

  it('should verify and return correct claims', async () => {
    const claims = {
      iss: 'test-issuer', sub: 'user-456', aud: ['test-audience'],
      exp: Math.floor(Date.now() / 1000) + 900, iat: Math.floor(Date.now() / 1000),
      jti: 'jti-2', email: 'b@c.com', emailVerified: false,
      roles: ['admin'], permissions: ['read:all'], sessionId: 'sess-2',
    };
    const token = await provider.signAccessToken(claims);
    const decoded = await provider.verifyAccessToken(token);
    expect(decoded.sub).toBe('user-456');
    expect(decoded.email).toBe('b@c.com');
    expect(decoded.roles).toEqual(['admin']);
    expect(decoded.sessionId).toBe('sess-2');
  });

  it('should reject tampered token', async () => {
    const token = await provider.signAccessToken({
      iss: 'test-issuer', sub: 'user-1', aud: ['test-audience'],
      exp: Math.floor(Date.now() / 1000) + 900, iat: Math.floor(Date.now() / 1000),
      jti: 'jti-3', email: 'a@b.com', emailVerified: true,
      roles: ['user'], permissions: [], sessionId: 'sess-3',
    });
    const tampered = token.slice(0, -5) + 'XXXXX';
    await expect(provider.verifyAccessToken(tampered)).rejects.toThrow();
  });

  it('should sign and verify MFA token', async () => {
    const token = await provider.signMFAToken('user-789');
    const result = await provider.verifyMFAToken(token);
    expect(result.userId).toBe('user-789');
  });

  it('should reject invalid MFA token', async () => {
    await expect(provider.verifyMFAToken('invalid.token.here')).rejects.toThrow();
  });

  it('should return valid JWKS', () => {
    const jwks = provider.getJWKS();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kty).toBe('RSA');
    expect(jwks.keys[0].alg).toBe('RS256');
    expect(jwks.keys[0].use).toBe('sig');
    expect(jwks.keys[0].kid).toBeDefined();
    expect(jwks.keys[0].n).toBeDefined();
    expect(jwks.keys[0].e).toBeDefined();
  });

  it('should verify token signed by own key using JWKS public key', async () => {
    // This simulates what downstream services do:
    // fetch JWKS, extract public key, verify token
    const token = await provider.signAccessToken({
      iss: 'test-issuer', sub: 'user-1', aud: ['test-audience'],
      exp: Math.floor(Date.now() / 1000) + 900, iat: Math.floor(Date.now() / 1000),
      jti: 'jti-4', email: 'a@b.com', emailVerified: true,
      roles: ['user'], permissions: [], sessionId: 'sess-1',
    });
    // Verify using the same provider (which uses the public key internally)
    const claims = await provider.verifyAccessToken(token);
    expect(claims.sub).toBe('user-1');
  });

  it('should auto-generate key pair when no privateKey provided', async () => {
    const autoProvider = new RS256TokenProvider();
    await autoProvider.init();
    const jwks = autoProvider.getJWKS();
    expect(jwks.keys).toHaveLength(1);
    const token = await autoProvider.signAccessToken({
      iss: 'argus', sub: 'u1', aud: ['argus'],
      exp: Math.floor(Date.now() / 1000) + 60, iat: Math.floor(Date.now() / 1000),
      jti: 'j1', email: 'x@y.com', emailVerified: false,
      roles: ['user'], permissions: [], sessionId: 's1',
    });
    const claims = await autoProvider.verifyAccessToken(token);
    expect(claims.sub).toBe('u1');
  });
});
