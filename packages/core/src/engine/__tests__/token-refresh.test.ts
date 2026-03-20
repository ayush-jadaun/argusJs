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
    // Manually expire the token by finding and updating it
    // We need to get the hash of the refresh token to find it
    const { hashToken } = await import('../../../utils/crypto.js');
    const hash = hashToken(reg.refreshToken);
    const token = await db.findRefreshTokenByHash(hash);
    // Directly mutate for test (set expiresAt to past)
    if (token) {
      (token as any).expiresAt = new Date(Date.now() - 1000);
    }
    await expect(argus.refresh(reg.refreshToken)).rejects.toThrow();
  });

  it('should detect token reuse and revoke family', async () => {
    const { argus, db } = createTestArgus();
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
    try { await argus.refresh(reg.refreshToken); } catch {}
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
});
