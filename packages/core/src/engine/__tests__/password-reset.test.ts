import { describe, it, expect } from 'vitest';
import { createTestArgus } from './helpers.js';

describe('Argus.forgotPassword / resetPassword', () => {
  async function setupUser(argus: any) {
    return argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
  }

  it('should not throw for non-existent email (prevent enumeration)', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    await expect(argus.forgotPassword('nobody@example.com', '1.2.3.4')).resolves.toBeUndefined();
  });

  it('should send reset email for existing user', async () => {
    const { argus, email } = createTestArgus();
    await argus.init();
    await setupUser(argus);
    email.clear(); // clear registration emails
    await argus.forgotPassword('alice@example.com', '1.2.3.4');
    const sent = email.getSentEmails();
    expect(sent.find(e => e.type === 'password_reset')).toBeDefined();
  });

  it('should reset password with valid token', async () => {
    const { argus, email } = createTestArgus();
    await argus.init();
    await setupUser(argus);
    email.clear();
    await argus.forgotPassword('alice@example.com', '1.2.3.4');
    const resetEmail = email.getSentEmails().find(e => e.type === 'password_reset');
    const token = resetEmail!.token;
    await argus.resetPassword(token, 'newstrongpass456', '1.2.3.4');
    // Should be able to login with new password
    const result = await argus.login('alice@example.com', 'newstrongpass456', { ipAddress: '1.2.3.4', userAgent: 'test' });
    expect(result).toHaveProperty('accessToken');
  });

  it('should revoke all sessions on password reset', async () => {
    const { argus, email, db } = createTestArgus();
    await argus.init();
    await setupUser(argus);
    const user = await db.findUserByEmail('alice@example.com');
    email.clear();
    await argus.forgotPassword('alice@example.com', '1.2.3.4');
    const resetEmail = email.getSentEmails().find(e => e.type === 'password_reset');
    await argus.resetPassword(resetEmail!.token, 'newstrongpass456', '1.2.3.4');
    const sessions = await db.getActiveSessions(user!.id);
    expect(sessions.length).toBe(0);
  });

  it('should throw for invalid reset token', async () => {
    const { argus } = createTestArgus();
    await argus.init();
    await expect(argus.resetPassword('bad-token', 'newpass12345', '1.2.3.4')).rejects.toThrow();
  });

  it('should throw for already-used reset token', async () => {
    const { argus, email } = createTestArgus();
    await argus.init();
    await setupUser(argus);
    email.clear();
    await argus.forgotPassword('alice@example.com', '1.2.3.4');
    const token = email.getSentEmails().find(e => e.type === 'password_reset')!.token;
    await argus.resetPassword(token, 'newstrongpass456', '1.2.3.4');
    await expect(argus.resetPassword(token, 'anotherpass789', '1.2.3.4')).rejects.toThrow();
  });

  it('should reject weak password on reset', async () => {
    const { argus, email } = createTestArgus();
    await argus.init();
    await setupUser(argus);
    email.clear();
    await argus.forgotPassword('alice@example.com', '1.2.3.4');
    const token = email.getSentEmails().find(e => e.type === 'password_reset')!.token;
    await expect(argus.resetPassword(token, 'short', '1.2.3.4')).rejects.toThrow();
  });

  it('should write audit log', async () => {
    const { argus, email, db } = createTestArgus();
    await argus.init();
    await setupUser(argus);
    email.clear();
    await argus.forgotPassword('alice@example.com', '1.2.3.4');
    const logs = await db.queryAuditLog({ action: 'PASSWORD_RESET_REQUESTED' });
    expect(logs.entries.length).toBe(1);
  });
});
