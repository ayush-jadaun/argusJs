import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIntegrationArgus } from './setup.js';

describe('Integration: Full Auth Flows', () => {
  let argus, db, email;

  beforeAll(async () => {
    ({ argus, db, email } = await createIntegrationArgus());
  });

  afterAll(async () => {
    await argus.shutdown();
  });

  it('should complete full registration → verify email → login → refresh → logout flow', async () => {
    // Register
    const reg = await argus.register({ email: 'integ@test.com', password: 'StrongPass123!', displayName: 'Integ', ipAddress: '1.2.3.4', userAgent: 'test' });
    expect(reg.accessToken).toBeDefined();

    // Verify email
    const verificationEmail = email.getSentEmails().find(e => e.type === 'verification');
    await argus.verifyEmail(verificationEmail.token);
    const user = await db.findUserByEmail('integ@test.com');
    expect(user.emailVerified).toBe(true);

    // Login
    const login = await argus.login('integ@test.com', 'StrongPass123!', { ipAddress: '1.2.3.4', userAgent: 'test' });
    expect(login.accessToken).toBeDefined();

    // Refresh
    const refreshed = await argus.refresh(login.refreshToken);
    expect(refreshed.accessToken).not.toBe(login.accessToken);

    // Logout
    const sessions = await db.getActiveSessions(user.id);
    await argus.logout(user.id, sessions[0].id);
    const remaining = await db.getActiveSessions(user.id);
    expect(remaining.length).toBeLessThan(sessions.length);
  });

  it('should complete password reset flow', async () => {
    await argus.register({ email: 'reset@test.com', password: 'OldPass123!', displayName: 'Reset', ipAddress: '1.2.3.4', userAgent: 'test' });
    email.clear();
    await argus.forgotPassword('reset@test.com', '1.2.3.4');
    const resetEmail = email.getSentEmails().find(e => e.type === 'password_reset');
    await argus.resetPassword(resetEmail.token, 'NewPass456!', '1.2.3.4');

    // Login with new password
    const login = await argus.login('reset@test.com', 'NewPass456!', { ipAddress: '1.2.3.4', userAgent: 'test' });
    expect(login.accessToken).toBeDefined();

    // Old password should fail
    await expect(argus.login('reset@test.com', 'OldPass123!', { ipAddress: '1.2.3.4', userAgent: 'test' })).rejects.toThrow();
  });
});
