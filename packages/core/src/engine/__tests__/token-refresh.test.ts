import { describe, it, expect, vi } from 'vitest';
import { createTestArgus } from './helpers.js';

describe('Argus.refresh', () => {
  async function setupUser(argus: any) {
    return argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
  }

  it('should return new tokens on valid refresh', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    const reg = await setupUser(argus);
    const result = await argus.refresh(reg.refreshToken);
    expect(result.accessToken).toBeDefined();
    expect(result.refreshToken).toBeDefined();
    expect(result.refreshToken).not.toBe(reg.refreshToken);
  });

  it('should throw for invalid refresh token', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    await expect(argus.refresh('invalid-token')).rejects.toThrow('Refresh token is invalid');
  });

  it('should throw for expired refresh token', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();
    const reg = await setupUser(argus);
    // Expire the token via the test helper (mutates internal state)
    const { hashToken } = await import('../../../utils/crypto.js');
    const hash = hashToken(reg.refreshToken);
    (db as any)._expireRefreshTokenByHash(hash);
    await expect(argus.refresh(reg.refreshToken)).rejects.toThrow();
  });

  it('should detect token reuse and revoke family', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    const reg = await setupUser(argus);
    const oldToken = reg.refreshToken;
    // Use the token once (rotates it)
    await argus.refresh(oldToken);
    // Try to use the old token again (reuse detection)
    await expect(argus.refresh(oldToken)).rejects.toThrow('reuse detected');
  });

  it('should emit token.reuse_detected on reuse', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    const reg = await setupUser(argus);
    const handler = vi.fn();
    argus.on('token.reuse_detected', handler);
    await argus.refresh(reg.refreshToken);
    try { await argus.refresh(reg.refreshToken); } catch { /* expected */ }
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('should write audit log on refresh', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();
    const reg = await setupUser(argus);
    await argus.refresh(reg.refreshToken);
    const logs = await db.queryAuditLog({ action: 'TOKEN_REFRESHED' });
    expect(logs.entries.length).toBe(1);
  });

  describe('with rotateRefreshTokens: false', () => {
    it('should return the SAME refresh token (no rotation)', async () => {
      const { argus } = createTestArgus({ session: { rotateRefreshTokens: false, maxPerUser: 5, absoluteTimeout: 86400 } });
      await argus.init();
      const reg = await argus.register({ email: 'norotate@test.com', password: 'strongpass123', displayName: 'NoRot', ipAddress: '1.2.3.4', userAgent: 'test' });
      const r1 = await argus.refresh(reg.refreshToken);
      expect(r1.refreshToken).toBe(reg.refreshToken); // same token returned
      expect(r1.accessToken).toBeDefined();
    });

    it('should allow reusing the same refresh token multiple times', async () => {
      const { argus } = createTestArgus({ session: { rotateRefreshTokens: false, maxPerUser: 5, absoluteTimeout: 86400 } });
      await argus.init();
      const reg = await argus.register({ email: 'reuse-ok@test.com', password: 'strongpass123', displayName: 'ReuseOK', ipAddress: '1.2.3.4', userAgent: 'test' });
      // Use the same token 5 times — all should succeed
      for (let i = 0; i < 5; i++) {
        const result = await argus.refresh(reg.refreshToken);
        expect(result.accessToken).toBeDefined();
        expect(result.refreshToken).toBe(reg.refreshToken);
      }
    });

    it('should still reject expired tokens', async () => {
      const { argus, db } = createTestArgus({ session: { rotateRefreshTokens: false, maxPerUser: 5, absoluteTimeout: 86400 } });
      await argus.init();
      const reg = await argus.register({ email: 'expire-norot@test.com', password: 'strongpass123', displayName: 'Exp', ipAddress: '1.2.3.4', userAgent: 'test' });
      const { hashToken } = await import('../../../utils/crypto.js');
      const hash = hashToken(reg.refreshToken);
      (db as any)._expireRefreshTokenByHash(hash);
      await expect(argus.refresh(reg.refreshToken)).rejects.toThrow();
    });
  });
});
