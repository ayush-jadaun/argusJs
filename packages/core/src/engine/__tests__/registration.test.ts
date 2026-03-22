import { describe, it, expect, vi } from 'vitest';
import { createTestArgus } from './helpers.js';

describe('Argus.register', () => {
  it('should register a new user and return AuthResponse', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    const result = await argus.register({
      email: 'alice@example.com', password: 'strongpass123',
      displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test',
    });
    expect(result.user.email).toBe('alice@example.com');
    expect(result.user.displayName).toBe('Alice');
    expect(result.user.emailVerified).toBe(false);
    expect(result.accessToken).toBeDefined();
    expect(result.refreshToken).toBeDefined();
    expect(result.tokenType).toBe('Bearer');
    expect(result.expiresIn).toBe(900);
  });

  it('should throw EMAIL_ALREADY_EXISTS for duplicate email', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    await expect(argus.register({ email: 'alice@example.com', password: 'otherpass123', displayName: 'Alice2', ipAddress: '1.2.3.4', userAgent: 'test' }))
      .rejects.toThrow('Email is already registered');
  });

  it('should throw for password below min length', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    await expect(argus.register({ email: 'a@b.com', password: 'short', displayName: 'A', ipAddress: '1.2.3.4', userAgent: 'test' }))
      .rejects.toThrow();
  });

  it('should send verification email', async () => {
    const { argus, email } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    const sent = email.getSentEmails();
    expect(sent.length).toBeGreaterThanOrEqual(1);
    expect(sent.find(e => e.type === 'verification')).toBeDefined();
  });

  it('should create audit log entry', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    const logs = await db.queryAuditLog({ action: 'USER_REGISTERED' });
    expect(logs.entries.length).toBe(1);
  });

  it('should emit user.registered event', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    const handler = vi.fn();
    argus.on('user.registered', handler);
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('should call afterRegister hook', async () => {
    const afterRegister = vi.fn();
    const { argus } = createTestArgus({ hooks: { afterRegister } });
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    expect(afterRegister).toHaveBeenCalledTimes(1);
  });

  it('should handle case-insensitive email duplicate', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'Alice@Example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    await expect(argus.register({ email: 'alice@example.com', password: 'otherpass123', displayName: 'Alice2', ipAddress: '1.2.3.4', userAgent: 'test' }))
      .rejects.toThrow('Email is already registered');
  });
});
