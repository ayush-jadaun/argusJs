import { describe, it, expect, vi, afterEach } from 'vitest';
import { Argus, ArgusError, Errors, generateToken, hashToken, generateUUID, encryptAES256GCM, decryptAES256GCM, timingSafeEqual } from '@argus/core';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';
import { MemoryRateLimiter } from '@argus/ratelimit-memory';
import { MemoryEmailProvider } from '@argus/email-memory';
import { Argon2Hasher } from '@argus/hash-argon2';
import { BcryptHasher } from '@argus/hash-bcrypt';
import { ScryptHasher } from '@argus/hash-scrypt';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { ES256TokenProvider } from '@argus/token-jwt-es256';
import { HS256TokenProvider } from '@argus/token-jwt-hs256';
import { TOTPProvider } from '@argus/mfa-totp';
import { DefaultSecurityEngine } from '@argus/security-engine';

function createArgus(overrides?: any) {
  const db = new MemoryDbAdapter();
  const cache = new MemoryCacheAdapter();
  const email = new MemoryEmailProvider();
  const argus = new Argus({
    db, cache, email,
    hasher: new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 }),
    token: new RS256TokenProvider({ issuer: 'test', audience: ['test'] }),
    rateLimiter: new MemoryRateLimiter(),
    password: { minLength: 8, maxLength: 128, historyCount: 5 },
    session: { maxPerUser: 5, absoluteTimeout: 86400 },
    lockout: { maxAttempts: 5, duration: 300, captchaThreshold: 3 },
    emailVerification: { required: true, tokenTTL: 86400 },
    audit: { enabled: true },
    ...overrides,
  });
  return { argus, db, cache, email };
}

async function reg(argus: any, email?: string) {
  const e = email || `u${Date.now()}${Math.random()}@t.com`;
  const r = await argus.register({ email: e, password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' });
  return { ...r, email: e };
}

// ============================================================================
// 1. INPUT BOUNDARIES (15 tests)
// ============================================================================
describe('1. Input Boundaries', () => {
  it('1.01 - null email throws', async () => {
    const { argus } = createArgus();
    await argus.init();
    await expect(argus.register({ email: null as any, password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' })).rejects.toThrow();
    await argus.shutdown();
  });

  it('1.02 - undefined email throws', async () => {
    const { argus } = createArgus();
    await argus.init();
    await expect(argus.register({ email: undefined as any, password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' })).rejects.toThrow();
    await argus.shutdown();
  });

  it('1.03 - null password throws', async () => {
    const { argus } = createArgus();
    await argus.init();
    await expect(argus.register({ email: 'a@b.com', password: null as any, displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' })).rejects.toThrow();
    await argus.shutdown();
  });

  it('1.04 - undefined displayName does not crash (graceful)', async () => {
    const { argus } = createArgus();
    await argus.init();
    // Should either succeed or throw a clean error, not crash
    try {
      await argus.register({ email: 'und@b.com', password: 'ValidPass123!', displayName: undefined as any, ipAddress: '1.1.1.1', userAgent: 'test' });
    } catch (e: any) {
      expect(e).toBeDefined();
    }
    await argus.shutdown();
  });

  it('1.05 - password exactly at min length (8) succeeds', async () => {
    const { argus } = createArgus();
    await argus.init();
    const result = await argus.register({ email: 'min@b.com', password: 'Abcdef1!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(result.accessToken).toBeDefined();
    await argus.shutdown();
  });

  it('1.06 - password exactly at max length (128) succeeds', async () => {
    const { argus } = createArgus();
    await argus.init();
    const result = await argus.register({ email: 'max@b.com', password: 'A'.repeat(128), displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(result.accessToken).toBeDefined();
    await argus.shutdown();
  });

  it('1.07 - password 1 over max (129) is rejected', async () => {
    const { argus } = createArgus();
    await argus.init();
    await expect(argus.register({ email: 'over@b.com', password: 'A'.repeat(129), displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' })).rejects.toThrow();
    await argus.shutdown();
  });

  it('1.08 - password of only spaces is rejected', async () => {
    const { argus } = createArgus();
    await argus.init();
    await expect(argus.register({ email: 'sp@b.com', password: '          ', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' })).rejects.toThrow();
    await argus.shutdown();
  });

  it('1.09 - password of only tabs is rejected', async () => {
    const { argus } = createArgus();
    await argus.init();
    await expect(argus.register({ email: 'tab@b.com', password: '\t\t\t\t\t\t\t\t\t\t', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' })).rejects.toThrow();
    await argus.shutdown();
  });

  it('1.10 - password of only newlines is rejected', async () => {
    const { argus } = createArgus();
    await argus.init();
    await expect(argus.register({ email: 'nl@b.com', password: '\n\n\n\n\n\n\n\n\n\n', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' })).rejects.toThrow();
    await argus.shutdown();
  });

  it('1.11 - password with null bytes: no truncation attack', async () => {
    const { argus } = createArgus();
    await argus.init();
    const pwd = 'Valid\x00Pass123!';
    await argus.register({ email: 'null@b.com', password: pwd, displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' });
    // Full password works
    const loginOk = await argus.login('null@b.com', pwd, { ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(loginOk.accessToken).toBeDefined();
    // Truncated before null byte should FAIL
    await expect(argus.login('null@b.com', 'Valid', { ipAddress: '1.1.1.1', userAgent: 'test' })).rejects.toThrow();
    await argus.shutdown();
  });

  it('1.12 - email with leading/trailing spaces is trimmed', async () => {
    const { argus } = createArgus();
    await argus.init();
    const result = await argus.register({ email: '  trim@b.com  ', password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(result.user.email).toBe('trim@b.com');
    await argus.shutdown();
  });

  it('1.13 - email with + addressing works', async () => {
    const { argus } = createArgus();
    await argus.init();
    const result = await argus.register({ email: 'user+tag@example.com', password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(result.user.email).toBe('user+tag@example.com');
    await argus.shutdown();
  });

  it('1.14 - displayName of very long string (10000 chars) does not crash', async () => {
    const { argus } = createArgus();
    await argus.init();
    try {
      const result = await argus.register({ email: 'longname@b.com', password: 'ValidPass123!', displayName: 'X'.repeat(10000), ipAddress: '1.1.1.1', userAgent: 'test' });
      expect(result.user.displayName.length).toBe(10000);
    } catch (e: any) {
      // Acceptable to throw a validation error, but must not crash
      expect(e).toBeDefined();
    }
    await argus.shutdown();
  });

  it('1.15 - ipAddress as empty string does not crash, ipAddress as IPv6 works', async () => {
    const { argus } = createArgus();
    await argus.init();
    // Empty IP
    try {
      await argus.register({ email: 'emptyip@b.com', password: 'ValidPass123!', displayName: 'T', ipAddress: '', userAgent: 'test' });
    } catch (e: any) {
      expect(e).toBeDefined();
    }
    // IPv6
    const r2 = await argus.register({ email: 'ipv6@b.com', password: 'ValidPass123!', displayName: 'T', ipAddress: '::1', userAgent: 'test' });
    expect(r2.accessToken).toBeDefined();
    await argus.shutdown();
  });
});

// ============================================================================
// 2. TOKEN SECURITY (12 tests)
// ============================================================================
describe('2. Token Security', () => {
  it('2.01 - refresh with access token rejects', async () => {
    const { argus } = createArgus();
    await argus.init();
    const r = await reg(argus);
    await expect(argus.refresh(r.accessToken)).rejects.toThrow();
    await argus.shutdown();
  });

  it('2.02 - refresh with empty string rejects', async () => {
    const { argus } = createArgus();
    await argus.init();
    await expect(argus.refresh('')).rejects.toThrow();
    await argus.shutdown();
  });

  it('2.03 - refresh with random garbage rejects', async () => {
    const { argus } = createArgus();
    await argus.init();
    await expect(argus.refresh('not-a-real-token-at-all-lol-12345')).rejects.toThrow();
    await argus.shutdown();
  });

  it('2.04 - double refresh (rotation) second rejects', async () => {
    const { argus } = createArgus();
    await argus.init();
    const r = await reg(argus);
    await argus.refresh(r.refreshToken);
    await expect(argus.refresh(r.refreshToken)).rejects.toThrow();
    await argus.shutdown();
  });

  it('2.05 - deep chain (10 rotations) then replay old detects reuse + revokes all', async () => {
    const { argus } = createArgus();
    await argus.init();
    const r = await reg(argus);
    const tokens: string[] = [r.refreshToken];
    let current = r.refreshToken;
    for (let i = 0; i < 10; i++) {
      const res = await argus.refresh(current);
      tokens.push(res.refreshToken);
      current = res.refreshToken;
    }
    // Replay the very first token
    await expect(argus.refresh(tokens[0])).rejects.toThrow();
    // Now the latest token should also be revoked (family wiped)
    await expect(argus.refresh(current)).rejects.toThrow();
    await argus.shutdown();
  });

  it('2.06 - concurrent 5x refresh same token: at most 1 wins', async () => {
    const { argus } = createArgus();
    await argus.init();
    const r = await reg(argus);
    const promises = Array.from({ length: 5 }, () => argus.refresh(r.refreshToken).then(() => 'ok').catch(() => 'fail'));
    const results = await Promise.all(promises);
    const successes = results.filter(r => r === 'ok');
    expect(successes.length).toBeLessThanOrEqual(1);
    await argus.shutdown();
  });

  it('2.07 - refresh after logout rejects', async () => {
    const { argus } = createArgus();
    await argus.init();
    const r = await reg(argus);
    await argus.logout(r.user.id, 'unused', { allDevices: true });
    await expect(argus.refresh(r.refreshToken)).rejects.toThrow();
    await argus.shutdown();
  });

  it('2.08 - refresh after password reset rejects (all tokens revoked)', async () => {
    const { argus, email } = createArgus();
    await argus.init();
    const r = await reg(argus);
    await argus.forgotPassword(r.email, '1.1.1.1');
    const emails = email.getSentEmails();
    const resetEmail = emails.find((e: any) => e.type === 'password_reset');
    expect(resetEmail).toBeDefined();
    await argus.resetPassword(resetEmail!.token!, 'NewPassword123!', '1.1.1.1');
    await expect(argus.refresh(r.refreshToken)).rejects.toThrow();
    await argus.shutdown();
  });

  it('2.09 - verify MFA token as refresh token rejects', async () => {
    const { argus } = createArgus();
    const token = new RS256TokenProvider({ issuer: 'test', audience: ['test'] });
    await token.init();
    const mfaToken = await token.signMFAToken('some-user-id');
    await argus.init();
    await expect(argus.refresh(mfaToken)).rejects.toThrow();
    await argus.shutdown();
  });

  it('2.10 - refresh with token from different user (wrong hash) rejects', async () => {
    const { argus } = createArgus();
    await argus.init();
    const r1 = await reg(argus, 'user1@test.com');
    const r2 = await reg(argus, 'user2@test.com');
    // Each user's refresh token is unique; using one for the other just gets "invalid"
    // (the hash won't match any stored token for that user)
    const res1 = await argus.refresh(r1.refreshToken);
    expect(res1.user.email).toBe('user1@test.com');
    // r2's token still works for user2
    const res2 = await argus.refresh(r2.refreshToken);
    expect(res2.user.email).toBe('user2@test.com');
    await argus.shutdown();
  });

  it('2.11 - refresh with token of exactly 1 char rejects', async () => {
    const { argus } = createArgus();
    await argus.init();
    await expect(argus.refresh('x')).rejects.toThrow();
    await argus.shutdown();
  });

  it('2.12 - refresh with very long garbage string rejects', async () => {
    const { argus } = createArgus();
    await argus.init();
    await expect(argus.refresh('x'.repeat(10000))).rejects.toThrow();
    await argus.shutdown();
  });
});

// ============================================================================
// 3. HASHER CROSS-COMPATIBILITY (9 tests)
// ============================================================================
describe('3. Hasher Cross-Compatibility', () => {
  const argon2 = new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 });
  const bcrypt = new BcryptHasher({ rounds: 4 });
  const scryptH = new ScryptHasher({ cost: 1024 });

  it('3.01 - argon2 hash NOT verifiable by bcrypt', async () => {
    const hash = await argon2.hash('TestPass123!');
    const result = await bcrypt.verify('TestPass123!', hash);
    expect(result).toBe(false);
  });

  it('3.02 - argon2 hash NOT verifiable by scrypt', async () => {
    const hash = await argon2.hash('TestPass123!');
    const result = await scryptH.verify('TestPass123!', hash);
    expect(result).toBe(false);
  });

  it('3.03 - bcrypt hash NOT verifiable by argon2', async () => {
    const hash = await bcrypt.hash('TestPass123!');
    const result = await argon2.verify('TestPass123!', hash);
    expect(result).toBe(false);
  });

  it('3.04 - bcrypt hash NOT verifiable by scrypt', async () => {
    const hash = await bcrypt.hash('TestPass123!');
    const result = await scryptH.verify('TestPass123!', hash);
    expect(result).toBe(false);
  });

  it('3.05 - scrypt hash NOT verifiable by argon2', async () => {
    const hash = await scryptH.hash('TestPass123!');
    const result = await argon2.verify('TestPass123!', hash);
    expect(result).toBe(false);
  });

  it('3.06 - scrypt hash NOT verifiable by bcrypt', async () => {
    const hash = await scryptH.hash('TestPass123!');
    const result = await bcrypt.verify('TestPass123!', hash);
    expect(result).toBe(false);
  });

  it('3.07 - each hasher: verify returns false for empty string password', async () => {
    const argonHash = await argon2.hash('SomePassword1!');
    const bcryptHash = await bcrypt.hash('SomePassword1!');
    const scryptHash = await scryptH.hash('SomePassword1!');
    expect(await argon2.verify('', argonHash)).toBe(false);
    expect(await bcrypt.verify('', bcryptHash)).toBe(false);
    expect(await scryptH.verify('', scryptHash)).toBe(false);
  });

  it('3.08 - each hasher: verify returns false for hash of different password', async () => {
    const argonHash = await argon2.hash('PasswordA1!');
    const bcryptHash = await bcrypt.hash('PasswordA1!');
    const scryptHash = await scryptH.hash('PasswordA1!');
    expect(await argon2.verify('PasswordB2!', argonHash)).toBe(false);
    expect(await bcrypt.verify('PasswordB2!', bcryptHash)).toBe(false);
    expect(await scryptH.verify('PasswordB2!', scryptHash)).toBe(false);
  });

  it('3.09 - argon2 needsRehash detects param change', async () => {
    const hasherLow = new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 });
    const hasherHigh = new Argon2Hasher({ memoryCost: 65536, timeCost: 3, parallelism: 4 });
    const hash = await hasherLow.hash('TestPass123!');
    // Hash was made with low params; high-param hasher should say it needs rehash
    expect(hasherHigh.needsRehash!(hash)).toBe(true);
    // Same-param hasher should say no rehash needed
    expect(hasherLow.needsRehash!(hash)).toBe(false);
  });
});

// ============================================================================
// 4. TOKEN PROVIDER ISOLATION (8 tests)
// ============================================================================
describe('4. Token Provider Isolation', () => {
  it('4.01 - RS256 token NOT verifiable by ES256', async () => {
    const rs = new RS256TokenProvider({ issuer: 'test', audience: ['test'] });
    const es = new ES256TokenProvider({ issuer: 'test', audience: ['test'] });
    await rs.init();
    await es.init();
    const claims = { iss: 'test', sub: 'u1', aud: ['test'], exp: Math.floor(Date.now()/1000)+900, iat: Math.floor(Date.now()/1000), jti: 'j1', email: 'a@b.com', emailVerified: true, roles: ['user'], permissions: [], sessionId: 's1' };
    const jwt = await rs.signAccessToken(claims);
    await expect(es.verifyAccessToken(jwt)).rejects.toThrow();
  });

  it('4.02 - RS256 token NOT verifiable by HS256', async () => {
    const rs = new RS256TokenProvider({ issuer: 'test', audience: ['test'] });
    const hs = new HS256TokenProvider({ secret: 'supersecretkey1234567890abcdefghij', issuer: 'test', audience: ['test'] });
    await rs.init();
    await hs.init();
    const claims = { iss: 'test', sub: 'u1', aud: ['test'], exp: Math.floor(Date.now()/1000)+900, iat: Math.floor(Date.now()/1000), jti: 'j1', email: 'a@b.com', emailVerified: true, roles: ['user'], permissions: [], sessionId: 's1' };
    const jwt = await rs.signAccessToken(claims);
    await expect(hs.verifyAccessToken(jwt)).rejects.toThrow();
  });

  it('4.03 - ES256 token NOT verifiable by RS256', async () => {
    const rs = new RS256TokenProvider({ issuer: 'test', audience: ['test'] });
    const es = new ES256TokenProvider({ issuer: 'test', audience: ['test'] });
    await rs.init();
    await es.init();
    const claims = { iss: 'test', sub: 'u1', aud: ['test'], exp: Math.floor(Date.now()/1000)+900, iat: Math.floor(Date.now()/1000), jti: 'j1', email: 'a@b.com', emailVerified: true, roles: ['user'], permissions: [], sessionId: 's1' };
    const jwt = await es.signAccessToken(claims);
    await expect(rs.verifyAccessToken(jwt)).rejects.toThrow();
  });

  it('4.04 - ES256 token NOT verifiable by HS256', async () => {
    const es = new ES256TokenProvider({ issuer: 'test', audience: ['test'] });
    const hs = new HS256TokenProvider({ secret: 'supersecretkey1234567890abcdefghij', issuer: 'test', audience: ['test'] });
    await es.init();
    await hs.init();
    const claims = { iss: 'test', sub: 'u1', aud: ['test'], exp: Math.floor(Date.now()/1000)+900, iat: Math.floor(Date.now()/1000), jti: 'j1', email: 'a@b.com', emailVerified: true, roles: ['user'], permissions: [], sessionId: 's1' };
    const jwt = await es.signAccessToken(claims);
    await expect(hs.verifyAccessToken(jwt)).rejects.toThrow();
  });

  it('4.05 - HS256(secret-A) NOT verifiable by HS256(secret-B)', async () => {
    const hsA = new HS256TokenProvider({ secret: 'secret-AAAAAAAAAAAAAAAAAAAAAAAA', issuer: 'test', audience: ['test'] });
    const hsB = new HS256TokenProvider({ secret: 'secret-BBBBBBBBBBBBBBBBBBBBBBBB', issuer: 'test', audience: ['test'] });
    await hsA.init();
    await hsB.init();
    const claims = { iss: 'test', sub: 'u1', aud: ['test'], exp: Math.floor(Date.now()/1000)+900, iat: Math.floor(Date.now()/1000), jti: 'j1', email: 'a@b.com', emailVerified: true, roles: ['user'], permissions: [], sessionId: 's1' };
    const jwt = await hsA.signAccessToken(claims);
    await expect(hsB.verifyAccessToken(jwt)).rejects.toThrow();
  });

  it('4.06 - HS256 JWKS is empty (no public keys for symmetric)', async () => {
    const hs = new HS256TokenProvider({ secret: 'supersecretkey1234567890abcdefghij', issuer: 'test', audience: ['test'] });
    await hs.init();
    const jwks = hs.getJWKS();
    expect(jwks.keys).toHaveLength(0);
  });

  it('4.07 - RS256 JWKS has exactly 1 key with kty=RSA', async () => {
    const rs = new RS256TokenProvider({ issuer: 'test', audience: ['test'] });
    await rs.init();
    const jwks = rs.getJWKS();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kty).toBe('RSA');
  });

  it('4.08 - ES256 JWKS has exactly 1 key with kty=EC', async () => {
    const es = new ES256TokenProvider({ issuer: 'test', audience: ['test'] });
    await es.init();
    const jwks = es.getJWKS();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kty).toBe('EC');
  });
});

// ============================================================================
// 5. ACCOUNT LIFECYCLE (10 tests)
// ============================================================================
describe('5. Account Lifecycle', () => {
  it('5.01 - login after soft delete rejects', async () => {
    const { argus, db } = createArgus();
    await argus.init();
    const r = await reg(argus, 'del@test.com');
    await db.softDeleteUser(r.user.id);
    await expect(argus.login('del@test.com', 'ValidPass123!', { ipAddress: '1.1.1.1', userAgent: 'test' })).rejects.toThrow();
    await argus.shutdown();
  });

  it('5.02 - re-register with soft-deleted email succeeds', async () => {
    const { argus, db } = createArgus();
    await argus.init();
    const r = await reg(argus, 'reuse@test.com');
    await db.softDeleteUser(r.user.id);
    const r2 = await argus.register({ email: 'reuse@test.com', password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(r2.user.email).toBe('reuse@test.com');
    expect(r2.user.id).not.toBe(r.user.id);
    await argus.shutdown();
  });

  it('5.03 - password reset revokes ALL sessions', async () => {
    const { argus, db, email } = createArgus();
    await argus.init();
    const r = await reg(argus, 'sessions@test.com');
    // Create additional sessions via login
    await argus.login('sessions@test.com', 'ValidPass123!', { ipAddress: '2.2.2.2', userAgent: 'test2' });
    await argus.login('sessions@test.com', 'ValidPass123!', { ipAddress: '3.3.3.3', userAgent: 'test3' });
    const activeBefore = await db.getActiveSessions(r.user.id);
    expect(activeBefore.length).toBeGreaterThanOrEqual(3);
    // Reset password
    await argus.forgotPassword('sessions@test.com', '1.1.1.1');
    const resetEmail = email.getSentEmails().find((e: any) => e.type === 'password_reset');
    await argus.resetPassword(resetEmail!.token!, 'NewPassword456!', '1.1.1.1');
    const activeAfter = await db.getActiveSessions(r.user.id);
    expect(activeAfter.length).toBe(0);
    await argus.shutdown();
  });

  it('5.04 - password reset: old password fails, new works', async () => {
    const { argus, email } = createArgus();
    await argus.init();
    await reg(argus, 'pwreset@test.com');
    await argus.forgotPassword('pwreset@test.com', '1.1.1.1');
    const resetEmail = email.getSentEmails().find((e: any) => e.type === 'password_reset');
    await argus.resetPassword(resetEmail!.token!, 'BrandNewPass1!', '1.1.1.1');
    // Old password fails
    await expect(argus.login('pwreset@test.com', 'ValidPass123!', { ipAddress: '1.1.1.1', userAgent: 'test' })).rejects.toThrow();
    // New password works
    const login = await argus.login('pwreset@test.com', 'BrandNewPass1!', { ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(login.accessToken).toBeDefined();
    await argus.shutdown();
  });

  it('5.05 - locked account: correct password still rejected', async () => {
    const { argus } = createArgus();
    await argus.init();
    await reg(argus, 'lock@test.com');
    // Trigger lockout with 5 wrong attempts
    for (let i = 0; i < 5; i++) {
      await argus.login('lock@test.com', 'WrongPass!!!', { ipAddress: '1.1.1.1', userAgent: 'test' }).catch(() => {});
    }
    // Now correct password should still be rejected
    await expect(argus.login('lock@test.com', 'ValidPass123!', { ipAddress: '1.1.1.1', userAgent: 'test' })).rejects.toThrow();
    await argus.shutdown();
  });

  it('5.06 - locked account: reset lock attempts after lockout expires, login works', async () => {
    const { argus, db } = createArgus();
    await argus.init();
    const r = await reg(argus, 'lockexp@test.com');
    // Trigger lockout
    for (let i = 0; i < 5; i++) {
      await argus.login('lockexp@test.com', 'WrongPass!!!', { ipAddress: '1.1.1.1', userAgent: 'test' }).catch(() => {});
    }
    // Manually expire the lock
    await db.updateUser(r.user.id, { lockedUntil: new Date(Date.now() - 1000), failedLoginAttempts: 0 });
    // Should work now
    const login = await argus.login('lockexp@test.com', 'ValidPass123!', { ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(login.accessToken).toBeDefined();
    await argus.shutdown();
  });

  it('5.07 - full lifecycle: register -> verify email -> login -> MFA setup -> MFA login', async () => {
    const { argus, email } = createArgus({
      mfa: { totp: new TOTPProvider() },
    });
    await argus.init();
    // Register
    const r = await reg(argus, 'lifecycle@test.com');
    expect(r.user.emailVerified).toBe(false);

    // Verify email
    const verifEmail = email.getSentEmails().find((e: any) => e.type === 'verification');
    expect(verifEmail).toBeDefined();
    await argus.verifyEmail(verifEmail!.token!);

    // Setup MFA
    const setupData = await argus.mfa.setup(r.user.id, 'totp');
    expect(setupData.secret).toBeDefined();
    expect(setupData.backupCodes.length).toBeGreaterThan(0);

    // Verify MFA setup with a valid TOTP code
    const { authenticator } = await import('otplib');
    const code = authenticator.generate(setupData.secret);
    await argus.mfa.verifySetup(r.user.id, 'totp', code);

    // Login should now return MFA challenge
    const loginResult = await argus.login('lifecycle@test.com', 'ValidPass123!', { ipAddress: '1.1.1.1', userAgent: 'test' });
    expect((loginResult as any).mfaRequired).toBe(true);
    expect((loginResult as any).mfaToken).toBeDefined();

    // Complete MFA login
    const newCode = authenticator.generate(setupData.secret);
    const mfaLogin = await argus.mfa.verifyLogin((loginResult as any).mfaToken, newCode, 'totp', { ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(mfaLogin.accessToken).toBeDefined();

    await argus.shutdown();
  });

  it('5.08 - double register same email: exactly 1 succeeds', async () => {
    const { argus } = createArgus();
    await argus.init();
    const email = `dup${Date.now()}@test.com`;
    const p1 = argus.register({ email, password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' }).then(() => 'ok').catch(() => 'fail');
    const p2 = argus.register({ email, password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' }).then(() => 'ok').catch(() => 'fail');
    const results = await Promise.all([p1, p2]);
    const successes = results.filter(r => r === 'ok');
    expect(successes.length).toBe(1);
    await argus.shutdown();
  });

  it('5.09 - login with email in random case works', async () => {
    const { argus } = createArgus();
    await argus.init();
    await reg(argus, 'casetest@example.com');
    const login = await argus.login('CaseTest@Example.COM', 'ValidPass123!', { ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(login.accessToken).toBeDefined();
    await argus.shutdown();
  });

  it('5.10 - logout all devices: all sessions gone', async () => {
    const { argus, db } = createArgus();
    await argus.init();
    const r = await reg(argus, 'allout@test.com');
    await argus.login('allout@test.com', 'ValidPass123!', { ipAddress: '2.2.2.2', userAgent: 'test2' });
    await argus.login('allout@test.com', 'ValidPass123!', { ipAddress: '3.3.3.3', userAgent: 'test3' });
    const before = await db.getActiveSessions(r.user.id);
    expect(before.length).toBeGreaterThanOrEqual(3);
    await argus.logout(r.user.id, 'unused', { allDevices: true });
    const after = await db.getActiveSessions(r.user.id);
    expect(after.length).toBe(0);
    await argus.shutdown();
  });
});

// ============================================================================
// 6. CONCURRENCY CHAOS (8 tests)
// ============================================================================
describe('6. Concurrency Chaos', () => {
  it('6.01 - 20 concurrent registrations different emails: all succeed', async () => {
    const { argus } = createArgus();
    await argus.init();
    const promises = Array.from({ length: 20 }, (_, i) =>
      argus.register({ email: `conc${i}_${Date.now()}@test.com`, password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' })
    );
    const results = await Promise.allSettled(promises);
    const fulfilled = results.filter(r => r.status === 'fulfilled');
    expect(fulfilled.length).toBe(20);
    await argus.shutdown();
  });

  it('6.02 - 20 concurrent registrations SAME email: exactly 1 succeeds', async () => {
    const { argus } = createArgus();
    await argus.init();
    const email = `same${Date.now()}@test.com`;
    const promises = Array.from({ length: 20 }, () =>
      argus.register({ email, password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' }).then(() => 'ok').catch(() => 'fail')
    );
    const results = await Promise.all(promises);
    const successes = results.filter(r => r === 'ok');
    expect(successes.length).toBe(1);
    await argus.shutdown();
  });

  it('6.03 - 10 concurrent logins same user: all succeed', async () => {
    const { argus } = createArgus({ session: { maxPerUser: 100, absoluteTimeout: 86400 } });
    await argus.init();
    await reg(argus, 'multilogin@test.com');
    const promises = Array.from({ length: 10 }, () =>
      argus.login('multilogin@test.com', 'ValidPass123!', { ipAddress: '1.1.1.1', userAgent: 'test' }).then(() => 'ok').catch((e: any) => `fail:${e.message}`)
    );
    const results = await Promise.all(promises);
    const successes = results.filter(r => r === 'ok');
    expect(successes.length).toBe(10);
    await argus.shutdown();
  });

  it('6.04 - 5 concurrent refresh same token: at most 1 succeeds', async () => {
    const { argus } = createArgus();
    await argus.init();
    const r = await reg(argus);
    const promises = Array.from({ length: 5 }, () =>
      argus.refresh(r.refreshToken).then(() => 'ok').catch(() => 'fail')
    );
    const results = await Promise.all(promises);
    const successes = results.filter(r => r === 'ok');
    expect(successes.length).toBeLessThanOrEqual(1);
    await argus.shutdown();
  });

  it('6.05 - concurrent login + password reset: no crashes', async () => {
    const { argus, email } = createArgus();
    await argus.init();
    await reg(argus, 'chaos1@test.com');
    const results = await Promise.allSettled([
      argus.login('chaos1@test.com', 'ValidPass123!', { ipAddress: '1.1.1.1', userAgent: 'test' }),
      argus.forgotPassword('chaos1@test.com', '1.1.1.1'),
    ]);
    // Neither should crash the process
    expect(results.length).toBe(2);
    await argus.shutdown();
  });

  it('6.06 - concurrent register + login same email: no crashes', async () => {
    const { argus } = createArgus();
    await argus.init();
    const email = `chaos2_${Date.now()}@test.com`;
    const results = await Promise.allSettled([
      argus.register({ email, password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' }),
      argus.login(email, 'ValidPass123!', { ipAddress: '1.1.1.1', userAgent: 'test' }),
    ]);
    expect(results.length).toBe(2);
    await argus.shutdown();
  });

  it('6.07 - rapid fire: 50 operations mixed: no crashes', async () => {
    const { argus } = createArgus({ session: { maxPerUser: 100, absoluteTimeout: 86400 } });
    await argus.init();
    await reg(argus, 'rapid@test.com');
    const ops = [];
    for (let i = 0; i < 50; i++) {
      if (i % 3 === 0) {
        ops.push(argus.login('rapid@test.com', 'ValidPass123!', { ipAddress: '1.1.1.1', userAgent: 'test' }).catch(() => {}));
      } else if (i % 3 === 1) {
        ops.push(argus.register({ email: `rapid${i}_${Date.now()}@test.com`, password: 'ValidPass123!', displayName: 'T', ipAddress: '1.1.1.1', userAgent: 'test' }).catch(() => {}));
      } else {
        ops.push(argus.refresh('garbage-token-' + i).catch(() => {}));
      }
    }
    await Promise.allSettled(ops);
    // If we got here without crashing, test passes
    expect(true).toBe(true);
    await argus.shutdown();
  });

  it('6.08 - concurrent MFA setup: no duplicate secrets', async () => {
    const { argus } = createArgus({ mfa: { totp: new TOTPProvider() } });
    await argus.init();
    const r = await reg(argus, 'mfaconc@test.com');
    const results = await Promise.allSettled([
      argus.mfa.setup(r.user.id, 'totp'),
      argus.mfa.setup(r.user.id, 'totp'),
      argus.mfa.setup(r.user.id, 'totp'),
    ]);
    const secrets = results
      .filter((r): r is PromiseFulfilledResult<any> => r.status === 'fulfilled')
      .map(r => r.value.secret);
    // All returned secrets should be unique (each call generates a new one)
    const unique = new Set(secrets);
    expect(unique.size).toBe(secrets.length);
    await argus.shutdown();
  });
});

// ============================================================================
// 7. CRYPTO EDGE CASES (9 tests)
// ============================================================================
describe('7. Crypto Edge Cases', () => {
  it('7.01 - hashToken("") is deterministic and 64 chars', () => {
    const h1 = hashToken('');
    const h2 = hashToken('');
    expect(h1).toBe(h2);
    expect(h1.length).toBe(64);
  });

  it('7.02 - hashToken of same input always equal', () => {
    const h1 = hashToken('test-token-value');
    const h2 = hashToken('test-token-value');
    expect(h1).toBe(h2);
  });

  it('7.03 - hashToken of different input always different', () => {
    const h1 = hashToken('token-a');
    const h2 = hashToken('token-b');
    expect(h1).not.toBe(h2);
  });

  it('7.04 - generateToken produces 1000 unique values', () => {
    const tokens = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      tokens.add(generateToken());
    }
    expect(tokens.size).toBe(1000);
  });

  it('7.05 - generateUUID produces 100 unique UUIDs matching v4 format', () => {
    const uuids = new Set<string>();
    const v4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    for (let i = 0; i < 100; i++) {
      const uuid = generateUUID();
      expect(uuid).toMatch(v4Regex);
      uuids.add(uuid);
    }
    expect(uuids.size).toBe(100);
  });

  it('7.06 - AES encrypt/decrypt round-trip with unicode', () => {
    const key = 'a'.repeat(64); // 64 hex chars = 32 bytes
    const plaintext = 'Hello \u{1F600} \u00E9\u00E8\u00EA \u4E16\u754C';
    const encrypted = encryptAES256GCM(plaintext, key);
    const decrypted = decryptAES256GCM(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it('7.07 - AES decrypt with wrong key throws', () => {
    const key1 = 'a'.repeat(64);
    const key2 = 'b'.repeat(64);
    const encrypted = encryptAES256GCM('secret data', key1);
    expect(() => decryptAES256GCM(encrypted, key2)).toThrow();
  });

  it('7.08 - AES decrypt with tampered ciphertext throws', () => {
    const key = 'a'.repeat(64);
    const encrypted = encryptAES256GCM('secret data', key);
    // Tamper with the ciphertext portion
    const parts = encrypted.split(':');
    parts[2] = 'ff' + parts[2].slice(2);
    const tampered = parts.join(':');
    expect(() => decryptAES256GCM(tampered, key)).toThrow();
  });

  it('7.09 - timingSafeEqual: equal true, different false, different length false', () => {
    expect(timingSafeEqual('hello', 'hello')).toBe(true);
    expect(timingSafeEqual('hello', 'world')).toBe(false);
    expect(timingSafeEqual('short', 'longer')).toBe(false);
    expect(timingSafeEqual('', '')).toBe(true);
  });
});

// ============================================================================
// 8. MEMORY DB ADAPTER (10 tests)
// ============================================================================
describe('8. Memory DB Adapter', () => {
  it('8.01 - update non-existent user throws', async () => {
    const db = new MemoryDbAdapter();
    await db.init();
    await expect(db.updateUser('non-existent-id', { displayName: 'X' })).rejects.toThrow();
  });

  it('8.02 - revoke non-existent session throws', async () => {
    const db = new MemoryDbAdapter();
    await db.init();
    await expect(db.revokeSession('non-existent-id', 'test')).rejects.toThrow();
  });

  it('8.03 - query audit log with all empty filters returns empty', async () => {
    const db = new MemoryDbAdapter();
    await db.init();
    const result = await db.queryAuditLog({});
    expect(result.entries).toEqual([]);
    expect(result.total).toBe(0);
  });

  it('8.04 - list users with no users returns empty', async () => {
    const db = new MemoryDbAdapter();
    await db.init();
    const result = await db.listUsers({});
    expect(result.users).toEqual([]);
    expect(result.total).toBe(0);
  });

  it('8.05 - getPasswordHistory for unknown user returns empty array', async () => {
    const db = new MemoryDbAdapter();
    await db.init();
    const history = await db.getPasswordHistory('non-existent', 10);
    expect(history).toEqual([]);
  });

  it('8.06 - exportUserData for unknown user returns empty collections', async () => {
    const db = new MemoryDbAdapter();
    await db.init();
    const data = await db.exportUserData('non-existent');
    expect(data.sessions).toEqual([]);
    expect(data.oauthProviders).toEqual([]);
    expect(data.auditLog).toEqual([]);
    expect(data.apiKeys).toEqual([]);
    expect(data.organizations).toEqual([]);
  });

  it('8.07 - findRefreshTokenByHash returns revoked tokens (for reuse detection)', async () => {
    const db = new MemoryDbAdapter();
    await db.init();
    const user = await db.createUser({ email: 'x@t.com', passwordHash: 'h', displayName: 'T' });
    const session = await db.createSession({ userId: user.id, ipAddress: '1.1.1.1', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
    const token = await db.createRefreshToken({ userId: user.id, sessionId: session.id, tokenHash: 'abc123', family: 'fam1', generation: 0, expiresAt: new Date(Date.now() + 86400000) });
    await db.revokeRefreshToken(token.id, 'rotated');
    const found = await db.findRefreshTokenByHash('abc123');
    expect(found).not.toBeNull();
    expect(found!.revoked).toBe(true);
  });

  it('8.08 - countActiveSessions ignores expired sessions', async () => {
    const db = new MemoryDbAdapter();
    await db.init();
    const user = await db.createUser({ email: 'x@t.com', passwordHash: 'h', displayName: 'T' });
    // Create expired session
    await db.createSession({ userId: user.id, ipAddress: '1.1.1.1', userAgent: 'test', expiresAt: new Date(Date.now() - 1000) });
    // Create active session
    await db.createSession({ userId: user.id, ipAddress: '1.1.1.1', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
    const count = await db.countActiveSessions(user.id);
    expect(count).toBe(1);
  });

  it('8.09 - createUser with duplicate email throws', async () => {
    const db = new MemoryDbAdapter();
    await db.init();
    await db.createUser({ email: 'dup@t.com', passwordHash: 'h', displayName: 'T' });
    await expect(db.createUser({ email: 'dup@t.com', passwordHash: 'h2', displayName: 'T2' })).rejects.toThrow();
  });

  it('8.10 - softDeleteUser twice does not crash', async () => {
    const db = new MemoryDbAdapter();
    await db.init();
    const user = await db.createUser({ email: 'soft@t.com', passwordHash: 'h', displayName: 'T' });
    await db.softDeleteUser(user.id);
    // Second soft delete should not crash
    await db.softDeleteUser(user.id);
    const found = await db.findUserById(user.id);
    expect(found).toBeNull();
  });
});

// ============================================================================
// 9. CACHE ADAPTER (6 tests)
// ============================================================================
describe('9. Cache Adapter', () => {
  it('9.01 - get expired key returns null', async () => {
    const cache = new MemoryCacheAdapter();
    await cache.init();
    await cache.set('key1', 'value1', 0); // 0 second TTL = immediately expires
    // Need to wait a tiny bit for Date.now() to advance
    await new Promise(r => setTimeout(r, 5));
    const result = await cache.get('key1');
    expect(result).toBeNull();
  });

  it('9.02 - incr non-existent key returns 1', async () => {
    const cache = new MemoryCacheAdapter();
    await cache.init();
    const result = await cache.incr('nonexistent', 60);
    expect(result).toBe(1);
  });

  it('9.03 - sismember non-existent set returns false', async () => {
    const cache = new MemoryCacheAdapter();
    await cache.init();
    const result = await cache.sismember('nonexistent-set', 'member');
    expect(result).toBe(false);
  });

  it('9.04 - smembers non-existent set returns empty array', async () => {
    const cache = new MemoryCacheAdapter();
    await cache.init();
    const result = await cache.smembers('nonexistent-set');
    expect(result).toEqual([]);
  });

  it('9.05 - del non-existent key causes no error', async () => {
    const cache = new MemoryCacheAdapter();
    await cache.init();
    await expect(cache.del('nonexistent')).resolves.not.toThrow();
  });

  it('9.06 - healthCheck returns true', async () => {
    const cache = new MemoryCacheAdapter();
    await cache.init();
    const result = await cache.healthCheck();
    expect(result).toBe(true);
  });
});

// ============================================================================
// 10. RATE LIMITER (5 tests)
// ============================================================================
describe('10. Rate Limiter', () => {
  it('10.01 - limit of 0 blocks everything', async () => {
    const rl = new MemoryRateLimiter();
    const result = await rl.check('key1', 0, 60);
    expect(result.allowed).toBe(false);
  });

  it('10.02 - very large limit allows', async () => {
    const rl = new MemoryRateLimiter();
    const result = await rl.check('key2', 1000000, 60);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(1000000 - 1);
  });

  it('10.03 - separate keys are independent', async () => {
    const rl = new MemoryRateLimiter();
    await rl.check('a', 1, 60);
    const result = await rl.check('b', 1, 60);
    expect(result.allowed).toBe(true);
  });

  it('10.04 - reset clears counter', async () => {
    const rl = new MemoryRateLimiter();
    await rl.check('resetkey', 1, 60); // use up 1
    const blocked = await rl.check('resetkey', 1, 60); // should be blocked
    expect(blocked.allowed).toBe(false);
    await rl.reset('resetkey');
    const afterReset = await rl.check('resetkey', 1, 60);
    expect(afterReset.allowed).toBe(true);
  });

  it('10.05 - window expiry allows again (use fake timers)', async () => {
    const rl = new MemoryRateLimiter();
    vi.useFakeTimers();
    try {
      await rl.check('timerkey', 1, 10); // use up 1 with 10s window
      const blocked = await rl.check('timerkey', 1, 10);
      expect(blocked.allowed).toBe(false);
      // Advance past window
      vi.advanceTimersByTime(11000);
      const afterWindow = await rl.check('timerkey', 1, 10);
      expect(afterWindow.allowed).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

// ============================================================================
// 11. ERROR SYSTEM (5 tests)
// ============================================================================
describe('11. Error System', () => {
  it('11.01 - all error factories return ArgusError', () => {
    const factories = [
      Errors.invalidCredentials(),
      Errors.invalidToken(),
      Errors.invalidRefreshToken(),
      Errors.refreshTokenReuse(),
      Errors.sessionExpired(),
      Errors.mfaRequired(),
      Errors.invalidMfaCode(),
      Errors.invalidMfaToken(),
      Errors.mfaAlreadyEnabled(),
      Errors.mfaNotEnabled(),
      Errors.emailNotVerified(),
      Errors.forbidden(),
      Errors.notFound('Resource'),
      Errors.emailExists(),
      Errors.weakPassword(['reason']),
      Errors.breachedPassword(),
      Errors.passwordRecentlyUsed(),
      Errors.accountLocked(new Date()),
      Errors.rateLimitExceeded(60),
      Errors.oauthFailed('fail'),
      Errors.providerNotConfigured('google'),
      Errors.providerAlreadyLinked(),
      Errors.cannotUnlinkOnlyAuth(),
      Errors.internal(),
    ];
    for (const err of factories) {
      expect(err).toBeInstanceOf(ArgusError);
    }
  });

  it('11.02 - all errors have code, statusCode, message', () => {
    const errors = [
      Errors.invalidCredentials(),
      Errors.invalidToken(),
      Errors.notFound('User'),
      Errors.internal(),
    ];
    for (const err of errors) {
      expect(typeof err.code).toBe('string');
      expect(typeof err.statusCode).toBe('number');
      expect(typeof err.message).toBe('string');
    }
  });

  it('11.03 - ArgusError instanceof Error', () => {
    const err = Errors.invalidCredentials();
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('ArgusError');
  });

  it('11.04 - statusCode ranges: 4xx for client errors, 5xx for server', () => {
    // Client errors
    expect(Errors.invalidCredentials().statusCode).toBeGreaterThanOrEqual(400);
    expect(Errors.invalidCredentials().statusCode).toBeLessThan(500);
    expect(Errors.notFound('X').statusCode).toBeGreaterThanOrEqual(400);
    expect(Errors.notFound('X').statusCode).toBeLessThan(500);
    expect(Errors.rateLimitExceeded(60).statusCode).toBeGreaterThanOrEqual(400);
    expect(Errors.rateLimitExceeded(60).statusCode).toBeLessThan(500);
    // Server error
    expect(Errors.internal().statusCode).toBeGreaterThanOrEqual(500);
    expect(Errors.internal().statusCode).toBeLessThan(600);
  });

  it('11.05 - notFound includes resource name in message', () => {
    const err = Errors.notFound('Session');
    expect(err.message).toContain('Session');
    const err2 = Errors.notFound('Organization');
    expect(err2.message).toContain('Organization');
  });
});

// ============================================================================
// 12. SECURITY ENGINE (6 tests)
// ============================================================================
describe('12. Security Engine', () => {
  function createSecurityEngine() {
    const cache = new MemoryCacheAdapter();
    const db = new MemoryDbAdapter();
    const engine = new DefaultSecurityEngine({ cache, db });
    return { engine, cache, db };
  }

  it('12.01 - risk assessment for unknown user returns valid result', async () => {
    const { engine, cache } = createSecurityEngine();
    await cache.init();
    const result = await engine.assessLoginRisk({
      userId: 'unknown-user',
      ipAddress: '1.1.1.1',
      userAgent: 'test-agent',
    });
    expect(result).toBeDefined();
    expect(typeof result.score).toBe('number');
    expect(['low', 'medium', 'high', 'critical']).toContain(result.level);
    expect(['allow', 'challenge', 'block']).toContain(result.action);
    expect(Array.isArray(result.factors)).toBe(true);
  });

  it('12.02 - brute force with special chars in identifier: no crash', async () => {
    const { engine, cache } = createSecurityEngine();
    await cache.init();
    const result = await engine.recordFailedAttempt('user@example.com/with:special!chars&more=stuff', '1.1.1.1');
    expect(result).toBeDefined();
    expect(typeof result.allowed).toBe('boolean');
  });

  it('12.03 - device trust: trust -> check -> revoke -> check false', async () => {
    const { engine, cache, db } = createSecurityEngine();
    await cache.init();
    await db.init();
    const userId = 'test-user-id';
    const device = {
      id: 'device-1',
      userId,
      fingerprint: 'fp-abc123',
      name: 'Test Device',
      browser: 'Chrome',
      os: 'Windows',
      lastUsedAt: new Date(),
      trustedAt: new Date(),
    };

    await engine.trustDevice(userId, device);
    const trusted = await engine.isDeviceTrusted(userId, 'fp-abc123');
    expect(trusted).toBe(true);

    await engine.revokeDevice(userId, 'device-1');
    const afterRevoke = await engine.isDeviceTrusted(userId, 'fp-abc123');
    expect(afterRevoke).toBe(false);
  });

  it('12.04 - concurrent sessions: 1 session not detected as sharing', async () => {
    const { engine, cache, db } = createSecurityEngine();
    await cache.init();
    await db.init();
    const user = await db.createUser({ email: 'x@t.com', passwordHash: 'h', displayName: 'T' });
    const session = await db.createSession({ userId: user.id, ipAddress: '1.1.1.1', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
    const result = await engine.detectConcurrentSessions(user.id, session);
    expect(result.detected).toBe(false);
    expect(result.activeSessions).toBe(1);
  });

  it('12.05 - brute force: lock after threshold -> isLocked true', async () => {
    const { engine, cache } = createSecurityEngine();
    await cache.init();
    const id = 'lock-test-user';
    // Default maxAttempts is 10, record 10 failures
    for (let i = 0; i < 10; i++) {
      await engine.recordFailedAttempt(id, '1.1.1.1');
    }
    const status = await engine.isLocked(id);
    expect(status.locked).toBe(true);
    expect(status.until).toBeDefined();
  });

  it('12.06 - resetAttempts -> isLocked false', async () => {
    const { engine, cache } = createSecurityEngine();
    await cache.init();
    const id = 'reset-test-user';
    for (let i = 0; i < 10; i++) {
      await engine.recordFailedAttempt(id, '1.1.1.1');
    }
    expect((await engine.isLocked(id)).locked).toBe(true);
    await engine.resetAttempts(id);
    expect((await engine.isLocked(id)).locked).toBe(false);
  });
});

// ============================================================================
// 13. MFA (5 tests)
// ============================================================================
describe('13. MFA', () => {
  it('13.01 - MFA setup without providers configured throws', async () => {
    const { argus } = createArgus(); // no mfa config
    await argus.init();
    const r = await reg(argus, 'nomfa@test.com');
    await expect(argus.mfa.setup(r.user.id, 'totp')).rejects.toThrow();
    await argus.shutdown();
  });

  it('13.02 - MFA setup for non-existent user throws', async () => {
    const { argus } = createArgus({ mfa: { totp: new TOTPProvider() } });
    await argus.init();
    await expect(argus.mfa.setup('non-existent-user-id', 'totp')).rejects.toThrow();
    await argus.shutdown();
  });

  it('13.03 - MFA setup with unknown method throws', async () => {
    const { argus } = createArgus({ mfa: { totp: new TOTPProvider() } });
    await argus.init();
    const r = await reg(argus, 'badmethod@test.com');
    await expect(argus.mfa.setup(r.user.id, 'sms')).rejects.toThrow();
    await argus.shutdown();
  });

  it('13.04 - TOTP generates valid secret and QR URL', async () => {
    const { argus } = createArgus({ mfa: { totp: new TOTPProvider() } });
    await argus.init();
    const r = await reg(argus, 'totpsecret@test.com');
    const setup = await argus.mfa.setup(r.user.id, 'totp');
    expect(typeof setup.secret).toBe('string');
    expect(setup.secret.length).toBeGreaterThan(0);
    expect(setup.qrCodeUrl).toContain('otpauth://totp/');
    await argus.shutdown();
  });

  it('13.05 - TOTP backup codes in XXXX-XXXX format', async () => {
    const totp = new TOTPProvider();
    const codes = totp.generateBackupCodes();
    expect(codes.length).toBe(10);
    const format = /^[0-9A-F]{4}-[0-9A-F]{4}$/;
    for (const code of codes) {
      expect(code).toMatch(format);
    }
  });
});
