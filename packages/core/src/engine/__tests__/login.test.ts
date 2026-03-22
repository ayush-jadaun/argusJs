import { describe, it, expect, vi } from 'vitest';
import { createTestArgus } from './helpers.js';

describe('Argus.login', () => {
  async function registerUser(argus: any) {
    return argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
  }

  it('should login successfully and return AuthResponse', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    await registerUser(argus);
    const result = await argus.login('alice@example.com', 'strongpass123', { ipAddress: '1.2.3.4', userAgent: 'test' });
    expect(result).toHaveProperty('accessToken');
    expect(result).toHaveProperty('refreshToken');
    expect((result as any).user.email).toBe('alice@example.com');
  });

  it('should throw INVALID_CREDENTIALS for wrong email', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    await expect(argus.login('nobody@example.com', 'pass', { ipAddress: '1.2.3.4', userAgent: 'test' }))
      .rejects.toThrow('Invalid email or password');
  });

  it('should throw INVALID_CREDENTIALS for wrong password', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    await registerUser(argus);
    await expect(argus.login('alice@example.com', 'wrongpass', { ipAddress: '1.2.3.4', userAgent: 'test' }))
      .rejects.toThrow('Invalid email or password');
  });

  it('should increment failed attempts on wrong password', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();
    await registerUser(argus);
    try { await argus.login('alice@example.com', 'wrong', { ipAddress: '1.2.3.4', userAgent: 'test' }); } catch { /* expected */ }
    const user = await db.findUserByEmail('alice@example.com');
    expect(user!.failedLoginAttempts).toBe(1);
  });

  it('should lock account after max attempts', async () => {
    const { argus } = createTestArgus({ lockout: { maxAttempts: 3, duration: 1800, captchaThreshold: 2 } });
    await argus.init();
    await registerUser(argus);
    for (let i = 0; i < 3; i++) {
      try { await argus.login('alice@example.com', 'wrong', { ipAddress: '1.2.3.4', userAgent: 'test' }); } catch { /* expected */ }
    }
    await expect(argus.login('alice@example.com', 'strongpass123', { ipAddress: '1.2.3.4', userAgent: 'test' }))
      .rejects.toThrow('Account locked');
  });

  it('should reset failed attempts on successful login', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();
    await registerUser(argus);
    try { await argus.login('alice@example.com', 'wrong', { ipAddress: '1.2.3.4', userAgent: 'test' }); } catch { /* expected */ }
    await argus.login('alice@example.com', 'strongpass123', { ipAddress: '1.2.3.4', userAgent: 'test' });
    const user = await db.findUserByEmail('alice@example.com');
    expect(user!.failedLoginAttempts).toBe(0);
  });

  it('should return MFA challenge when MFA enabled', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();
    await registerUser(argus);
    const user = await db.findUserByEmail('alice@example.com');
    await db.updateUser(user!.id, { mfaEnabled: true, mfaMethods: ['totp'] });
    const result = await argus.login('alice@example.com', 'strongpass123', { ipAddress: '1.2.3.4', userAgent: 'test' });
    expect((result as any).mfaRequired).toBe(true);
    expect((result as any).mfaToken).toBeDefined();
    expect((result as any).mfaMethods).toEqual(['totp']);
  });

  it('should enforce session limit', async () => {
    const { argus, db } = createTestArgus({ session: { maxPerUser: 2, absoluteTimeout: 86400 } });
    await argus.init();
    await registerUser(argus);
    await argus.login('alice@example.com', 'strongpass123', { ipAddress: '1.1.1.1', userAgent: 'agent1' });
    await argus.login('alice@example.com', 'strongpass123', { ipAddress: '2.2.2.2', userAgent: 'agent2' });
    await argus.login('alice@example.com', 'strongpass123', { ipAddress: '3.3.3.3', userAgent: 'agent3' });
    const user = await db.findUserByEmail('alice@example.com');
    const sessions = await db.getActiveSessions(user!.id);
    expect(sessions.length).toBeLessThanOrEqual(2);
  });

  it('should create audit log on login', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();
    await registerUser(argus);
    await argus.login('alice@example.com', 'strongpass123', { ipAddress: '1.2.3.4', userAgent: 'test' });
    const logs = await db.queryAuditLog({ action: 'LOGIN_SUCCESS' });
    expect(logs.entries.length).toBe(1);
  });

  it('should emit user.login event', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    await registerUser(argus);
    const handler = vi.fn();
    argus.on('user.login', handler);
    await argus.login('alice@example.com', 'strongpass123', { ipAddress: '1.2.3.4', userAgent: 'test' });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('should call hooks', async () => {
    const beforeLogin = vi.fn();
    const afterLogin = vi.fn();
    const { argus } = createTestArgus({ hooks: { beforeLogin, afterLogin } });
    await argus.init();
    await registerUser(argus);
    await argus.login('alice@example.com', 'strongpass123', { ipAddress: '1.2.3.4', userAgent: 'test' });
    expect(beforeLogin).toHaveBeenCalledTimes(1);
    expect(afterLogin).toHaveBeenCalledTimes(1);
  });
});
