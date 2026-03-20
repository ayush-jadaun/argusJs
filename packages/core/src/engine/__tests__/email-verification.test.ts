import { describe, it, expect } from 'vitest';
import { createTestArgus } from './helpers.js';

describe('Argus.verifyEmail / resendVerification', () => {
  it('should verify email with valid token', async () => {
    const { argus, email, db } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    const verificationEmail = email.getSentEmails().find(e => e.type === 'verification');
    await argus.verifyEmail(verificationEmail!.token);
    const user = await db.findUserByEmail('alice@example.com');
    expect(user!.emailVerified).toBe(true);
    expect(user!.emailVerifiedAt).toBeInstanceOf(Date);
  });

  it('should throw for invalid verification token', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    await expect(argus.verifyEmail('bad-token')).rejects.toThrow();
  });

  it('should throw for already-used verification token', async () => {
    const { argus, email } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    const token = email.getSentEmails().find(e => e.type === 'verification')!.token;
    await argus.verifyEmail(token);
    await expect(argus.verifyEmail(token)).rejects.toThrow();
  });

  it('should resend verification email', async () => {
    const { argus, email, db } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    const user = await db.findUserByEmail('alice@example.com');
    email.clear();
    await argus.resendVerification(user!.id);
    const sent = email.getSentEmails();
    expect(sent.find(e => e.type === 'verification')).toBeDefined();
  });

  it('should write audit log on verification', async () => {
    const { argus, email, db } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    const token = email.getSentEmails().find(e => e.type === 'verification')!.token;
    await argus.verifyEmail(token);
    const logs = await db.queryAuditLog({ action: 'EMAIL_VERIFIED' });
    expect(logs.entries.length).toBe(1);
  });
});
