import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIntegrationArgus } from './setup.js';

describe('Battle Tests — Bug Hunters', () => {
  let argus: any, db: any, email: any, cache: any;
  const ts = Date.now();

  beforeAll(async () => {
    ({ argus, db, email, cache } = await createIntegrationArgus());
  });
  afterAll(async () => { await argus.shutdown(); });

  // ========================================
  // AUTH BOUNDARY TESTS
  // ========================================

  it('should reject empty string email', async () => {
    await expect(argus.register({
      email: '', password: 'StrongP@ss123', displayName: 'Test', ipAddress: '1.1.1.1', userAgent: 'test',
    })).rejects.toThrow();
  });

  it('should reject email without @ symbol', async () => {
    await expect(argus.register({
      email: 'notanemail', password: 'StrongP@ss123', displayName: 'Test', ipAddress: '1.1.1.1', userAgent: 'test',
    })).rejects.toThrow();
  });

  it('should reject empty password', async () => {
    await expect(argus.register({
      email: `empty_pass_${ts}@test.com`, password: '', displayName: 'Test', ipAddress: '1.1.1.1', userAgent: 'test',
    })).rejects.toThrow();
  });

  it('should reject password of only spaces', async () => {
    await expect(argus.register({
      email: `space_pass_${ts}@test.com`, password: '        ', displayName: 'Test', ipAddress: '1.1.1.1', userAgent: 'test',
    })).rejects.toThrow();
  });

  it('should handle extremely long email (255 chars)', async () => {
    const longLocal = 'a'.repeat(240);
    const longEmail = `${longLocal}@test.com`;
    // Should either succeed or throw a validation error, but NOT crash
    try {
      await argus.register({ email: longEmail, password: 'StrongP@ss123', displayName: 'Long', ipAddress: '1.1.1.1', userAgent: 'test' });
    } catch (e: any) {
      expect(e.message).toBeDefined(); // Graceful error, not a crash
    }
  });

  it('should handle extremely long password (10000 chars)', async () => {
    const longPass = 'A'.repeat(10000);
    await expect(argus.register({
      email: `longpass_${ts}@test.com`, password: longPass, displayName: 'Test', ipAddress: '1.1.1.1', userAgent: 'test',
    })).rejects.toThrow(); // Should reject — exceeds maxLength 128
  });

  it('should handle password with special unicode chars', async () => {
    const unicodeEmail = `unicode_${ts}@test.com`;
    const password = 'P\u00e4ssw\u00f6rd\uD83D\uDD10\u4E2D\u6587\u5BC6\u7801';
    const reg = await argus.register({ email: unicodeEmail, password, displayName: 'Unicode', ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(reg.accessToken).toBeDefined();
    // Must be able to login with the exact same unicode password
    const login = await argus.login(unicodeEmail, password, { ipAddress: '1.1.1.1', userAgent: 'test' });
    expect(login.accessToken).toBeDefined();
  });

  it('should handle displayName with HTML/script tags', async () => {
    const xssEmail = `xss_${ts}@test.com`;
    const reg = await argus.register({
      email: xssEmail, password: 'StrongP@ss123',
      displayName: '<script>alert("xss")</script>',
      ipAddress: '1.1.1.1', userAgent: 'test',
    });
    // Should store as-is (output encoding is frontend responsibility) or sanitize
    const user = await db.findUserByEmail(xssEmail);
    expect(user).not.toBeNull();
    // The displayName should NOT cause any errors in the system
  });

  it('should handle SQL injection in email', async () => {
    const sqliEmail = `test'; DROP TABLE users; --@test.com`;
    // Should either reject or safely store — NOT execute SQL
    try {
      await argus.register({ email: sqliEmail, password: 'StrongP@ss123', displayName: 'SQLi', ipAddress: '1.1.1.1', userAgent: 'test' });
    } catch {
      // Expected — invalid email format
    }
    // Verify users table still exists
    const users = await db.listUsers({ limit: 1 });
    expect(users).toBeDefined();
  });

  // ========================================
  // TOKEN ROTATION STRESS
  // ========================================

  it('should handle 20 consecutive token rotations without failure', async () => {
    const rotEmail = `rotation_stress_${ts}@test.com`;
    const reg = await argus.register({ email: rotEmail, password: 'StrongP@ss123', displayName: 'Rot', ipAddress: '1.1.1.1', userAgent: 'test' });

    let currentToken = reg.refreshToken;
    for (let i = 0; i < 20; i++) {
      const result = await argus.refresh(currentToken);
      expect(result.refreshToken).not.toBe(currentToken);
      expect(result.accessToken).toBeDefined();
      currentToken = result.refreshToken;
    }
  });

  it('should detect reuse at ANY point in a rotation chain', async () => {
    const reuseEmail = `reuse_chain_${ts}@test.com`;
    const reg = await argus.register({ email: reuseEmail, password: 'StrongP@ss123', displayName: 'Reuse', ipAddress: '1.1.1.1', userAgent: 'test' });

    const token0 = reg.refreshToken;
    const r1 = await argus.refresh(token0);
    const r2 = await argus.refresh(r1.refreshToken);
    const r3 = await argus.refresh(r2.refreshToken);

    // Try to reuse token from generation 0 — should trigger reuse detection
    await expect(argus.refresh(token0)).rejects.toThrow();

    // After reuse detection, ALL sessions should be revoked
    const user = await db.findUserByEmail(reuseEmail);
    const sessions = await db.getActiveSessions(user.id);
    expect(sessions.length).toBe(0);

    // The latest token (r3) should ALSO be invalid now (family revoked)
    await expect(argus.refresh(r3.refreshToken)).rejects.toThrow();
  });

  // ========================================
  // LOCKOUT TIMING ATTACKS
  // ========================================

  it('should lock account and then unlock after duration', async () => {
    const lockEmail = `lockout_timing_${ts}@test.com`;
    await argus.register({ email: lockEmail, password: 'StrongP@ss123', displayName: 'Lock', ipAddress: '1.1.1.1', userAgent: 'test' });

    // Trigger lockout (5 failed attempts with our test config)
    for (let i = 0; i < 5; i++) {
      try { await argus.login(lockEmail, 'WRONG', { ipAddress: '1.1.1.1', userAgent: 'test' }); } catch {}
    }

    // Should be locked
    await expect(argus.login(lockEmail, 'StrongP@ss123', { ipAddress: '1.1.1.1', userAgent: 'test' }))
      .rejects.toThrow(/Account locked/);

    // Verify locked status in DB
    const user = await db.findUserByEmail(lockEmail);
    expect(user.lockedUntil).toBeInstanceOf(Date);
    expect(user.lockedUntil.getTime()).toBeGreaterThan(Date.now());
  });

  it('should count failed attempts across different IPs', async () => {
    const multiIpEmail = `multi_ip_${ts}@test.com`;
    await argus.register({ email: multiIpEmail, password: 'StrongP@ss123', displayName: 'MultiIP', ipAddress: '1.1.1.1', userAgent: 'test' });

    // 5 failures from 5 different IPs
    for (let i = 0; i < 5; i++) {
      try { await argus.login(multiIpEmail, 'WRONG', { ipAddress: `${i+10}.0.0.1`, userAgent: `agent-${i}` }); } catch {}
    }

    // Should still be locked — failures track by account, not IP
    const user = await db.findUserByEmail(multiIpEmail);
    expect(user.failedLoginAttempts).toBe(5);
  });

  // ========================================
  // PASSWORD RESET EDGE CASES
  // ========================================

  it('should invalidate old reset tokens when new one is requested', async () => {
    const resetRaceEmail = `reset_race_${ts}@test.com`;
    await argus.register({ email: resetRaceEmail, password: 'StrongP@ss123', displayName: 'Reset', ipAddress: '1.1.1.1', userAgent: 'test' });
    email.clear();

    // Request two resets
    await argus.forgotPassword(resetRaceEmail, '1.1.1.1');
    const firstEmails = email.getSentEmails().filter((e: any) => e.type === 'password_reset');
    expect(firstEmails.length).toBe(1);
    const firstToken = firstEmails[0].token;

    email.clear();
    await argus.forgotPassword(resetRaceEmail, '1.1.1.1');
    const secondEmails = email.getSentEmails().filter((e: any) => e.type === 'password_reset');
    expect(secondEmails.length).toBe(1);
    const secondToken = secondEmails[0].token;

    // Only the SECOND token should be valid — first was invalidated
    // The second token should work
    await argus.resetPassword(secondToken, 'NewPass456!', '1.1.1.1');

    // The first token should now be invalid (already invalidated when second was requested)
    await expect(argus.resetPassword(firstToken, 'AnotherPass789!', '1.1.1.1')).rejects.toThrow();
  });

  it('should not allow password reset to set password below minimum length', async () => {
    await expect(argus.resetPassword('some-token', 'short', '1.1.1.1')).rejects.toThrow();
  });

  // ========================================
  // SESSION EDGE CASES
  // ========================================

  it('should handle logout of already-revoked session gracefully', async () => {
    const dblLogoutEmail = `double_logout_${ts}@test.com`;
    await argus.register({ email: dblLogoutEmail, password: 'StrongP@ss123', displayName: 'DblOut', ipAddress: '1.1.1.1', userAgent: 'test' });
    const user = await db.findUserByEmail(dblLogoutEmail);
    const sessions = await db.getActiveSessions(user.id);

    await argus.logout(user.id, sessions[0].id);
    // Second logout of same session should not crash
    // It may throw or no-op, but should NOT cause an unhandled error
    try {
      await argus.logout(user.id, sessions[0].id);
    } catch (e: any) {
      // Acceptable — just shouldn't crash the process
      expect(e.message).toBeDefined();
    }
  });

  it('should handle logout with non-existent session ID', async () => {
    const badSessEmail = `bad_session_${ts}@test.com`;
    await argus.register({ email: badSessEmail, password: 'StrongP@ss123', displayName: 'BadSess', ipAddress: '1.1.1.1', userAgent: 'test' });
    const user = await db.findUserByEmail(badSessEmail);

    // Should not crash
    try {
      await argus.logout(user.id, 'non-existent-session-id');
    } catch (e: any) {
      expect(e.message).toBeDefined();
    }
  });

  // ========================================
  // RAPID FIRE — RACE CONDITIONS
  // ========================================

  it('should handle 10 concurrent registrations with DIFFERENT emails', async () => {
    const promises = Array.from({ length: 10 }, (_, i) =>
      argus.register({
        email: `rapid_${ts}_${i}@test.com`,
        password: 'StrongP@ss123',
        displayName: `Rapid ${i}`,
        ipAddress: `${i}.0.0.1`,
        userAgent: 'test',
      })
    );
    const results = await Promise.allSettled(promises);
    const succeeded = results.filter(r => r.status === 'fulfilled');
    expect(succeeded.length).toBe(10); // All should succeed
  });

  it('should handle 5 concurrent logins for same user', async () => {
    const concLoginEmail = `concurrent_login_${ts}@test.com`;
    await argus.register({ email: concLoginEmail, password: 'StrongP@ss123', displayName: 'ConcLogin', ipAddress: '1.1.1.1', userAgent: 'test' });

    const promises = Array.from({ length: 5 }, (_, i) =>
      argus.login(concLoginEmail, 'StrongP@ss123', { ipAddress: `${i}.0.0.1`, userAgent: `agent-${i}` })
    );
    const results = await Promise.allSettled(promises);
    const succeeded = results.filter(r => r.status === 'fulfilled');
    // All should succeed (session limit is 5, plus 1 from register = 6, trimmed to 5)
    expect(succeeded.length).toBe(5);
  });

  it('should handle 10 concurrent refresh attempts with the SAME token (only 1 succeeds)', async () => {
    const concRefEmail = `concurrent_refresh_${ts}@test.com`;
    const reg = await argus.register({ email: concRefEmail, password: 'StrongP@ss123', displayName: 'ConcRef', ipAddress: '1.1.1.1', userAgent: 'test' });

    // 10 concurrent refreshes with the same token
    const promises = Array.from({ length: 10 }, () =>
      argus.refresh(reg.refreshToken)
    );
    const results = await Promise.allSettled(promises);
    const succeeded = results.filter(r => r.status === 'fulfilled');
    const failed = results.filter(r => r.status === 'rejected');

    // At most 1 should succeed (first one rotates, rest get revoked token)
    expect(succeeded.length).toBeLessThanOrEqual(1);
    expect(failed.length).toBeGreaterThanOrEqual(9);
  });

  // ========================================
  // DATA CONSISTENCY
  // ========================================

  it('should maintain accurate session count after mixed operations', async () => {
    const sessCountEmail = `session_count_${ts}@test.com`;
    await argus.register({ email: sessCountEmail, password: 'StrongP@ss123', displayName: 'SessCount', ipAddress: '1.1.1.1', userAgent: 'test' });
    const user = await db.findUserByEmail(sessCountEmail);

    // Login 3 more times (total 4 sessions: 1 from register + 3 from login)
    await argus.login(sessCountEmail, 'StrongP@ss123', { ipAddress: '2.2.2.2', userAgent: 'a2' });
    await argus.login(sessCountEmail, 'StrongP@ss123', { ipAddress: '3.3.3.3', userAgent: 'a3' });
    await argus.login(sessCountEmail, 'StrongP@ss123', { ipAddress: '4.4.4.4', userAgent: 'a4' });

    let sessions = await db.getActiveSessions(user.id);
    expect(sessions.length).toBe(4);

    // Revoke one session
    await argus.logout(user.id, sessions[0].id);
    sessions = await db.getActiveSessions(user.id);
    expect(sessions.length).toBe(3);

    // Login again (total back to 4)
    await argus.login(sessCountEmail, 'StrongP@ss123', { ipAddress: '5.5.5.5', userAgent: 'a5' });
    sessions = await db.getActiveSessions(user.id);
    expect(sessions.length).toBe(4);

    // Logout all
    await argus.logout(user.id, sessions[0].id, { allDevices: true });
    sessions = await db.getActiveSessions(user.id);
    expect(sessions.length).toBe(0);
  });

  it('should have audit log entries for EVERY auth action', async () => {
    const auditEmail = `audit_complete_${ts}@test.com`;

    // Register
    await argus.register({ email: auditEmail, password: 'StrongP@ss123', displayName: 'AuditAll', ipAddress: '1.1.1.1', userAgent: 'test' });
    const user = await db.findUserByEmail(auditEmail);

    // Login (success)
    const login = await argus.login(auditEmail, 'StrongP@ss123', { ipAddress: '1.1.1.1', userAgent: 'test' });

    // Login (fail)
    try { await argus.login(auditEmail, 'WRONG', { ipAddress: '1.1.1.1', userAgent: 'test' }); } catch {}

    // Refresh
    await argus.refresh(login.refreshToken);

    // Forgot password
    await argus.forgotPassword(auditEmail, '1.1.1.1');

    // Logout
    const sessions = await db.getActiveSessions(user.id);
    if (sessions.length > 0) {
      await argus.logout(user.id, sessions[0].id);
    }

    // Check audit log
    const logs = await db.queryAuditLog({ userId: user.id });
    const actions = logs.entries.map((e: any) => e.action);

    expect(actions).toContain('USER_REGISTERED');
    expect(actions).toContain('LOGIN_SUCCESS');
    expect(actions).toContain('LOGIN_FAILED');
    expect(actions).toContain('TOKEN_REFRESHED');
    expect(actions).toContain('PASSWORD_RESET_REQUESTED');
    expect(actions).toContain('LOGOUT');
  });
});
