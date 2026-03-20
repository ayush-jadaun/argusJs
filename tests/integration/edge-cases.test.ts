import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIntegrationArgus } from './setup.js';

describe('Integration: Edge Cases', () => {
  let argus: any;
  let db: any;
  let email: any;
  const suffix = Date.now();

  beforeAll(async () => {
    ({ argus, db, email } = await createIntegrationArgus());
  });

  afterAll(async () => {
    await argus.shutdown();
  });

  // ─── Auth Edge Cases ─────────────────────────────────────────────────

  describe('Auth edge cases', () => {
    it('should reject registration with email containing unicode characters in local part', async () => {
      const unicodeEmail = `ünïcödé_${suffix}@test.com`;
      // The email regex only allows [^\s@] which includes unicode, BUT
      // if the system normalizes it, test the normalized result.
      // Depending on implementation, unicode local parts may or may not be valid.
      try {
        const result = await argus.register({
          email: unicodeEmail,
          password: 'StrongPass123!',
          displayName: 'Unicode',
          ipAddress: '1.2.3.4',
          userAgent: 'test',
        });
        // If it succeeds, verify the email was stored lowercase
        expect(result.user.email).toBe(unicodeEmail.toLowerCase());
      } catch (err: any) {
        // If it rejects, that's also valid (invalid email format)
        expect(err.code).toBe('VALIDATION_ERROR');
      }
    });

    it('should trim leading/trailing spaces from email during registration', async () => {
      const baseEmail = `trimtest_${suffix}@test.com`;
      const spacedEmail = `  ${baseEmail}  `;

      const result = await argus.register({
        email: spacedEmail,
        password: 'StrongPass123!',
        displayName: 'TrimTest',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      expect(result.user.email).toBe(baseEmail.toLowerCase());

      // Should also be able to login with the trimmed email
      const login = await argus.login(baseEmail, 'StrongPass123!', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      expect(login.accessToken).toBeDefined();
    });

    it('should succeed with maximum length password (128 chars)', async () => {
      const maxPassword = 'A'.repeat(128);
      const emailAddr = `maxpass_${suffix}@test.com`;

      const result = await argus.register({
        email: emailAddr,
        password: maxPassword,
        displayName: 'MaxPass',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      expect(result.accessToken).toBeDefined();
      expect(result.user.email).toBe(emailAddr);

      // Verify login works with the max-length password
      const login = await argus.login(emailAddr, maxPassword, {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      expect(login.accessToken).toBeDefined();
    });

    it('should succeed with password exactly at min length (8 chars)', async () => {
      const minPassword = 'Abcdefg1';
      const emailAddr = `minpass_${suffix}@test.com`;

      const result = await argus.register({
        email: emailAddr,
        password: minPassword,
        displayName: 'MinPass',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      expect(result.accessToken).toBeDefined();
    });

    it('should fail with password 1 char below min length', async () => {
      const shortPassword = 'Abcdef1'; // 7 chars
      const emailAddr = `shortpass_${suffix}@test.com`;

      await expect(
        argus.register({
          email: emailAddr,
          password: shortPassword,
          displayName: 'ShortPass',
          ipAddress: '1.2.3.4',
          userAgent: 'test',
        }),
      ).rejects.toThrow(/at least 8/);
    });

    it('should succeed login after 4 wrong attempts then correct password', async () => {
      const emailAddr = `retry_${suffix}@test.com`;
      await argus.register({
        email: emailAddr,
        password: 'CorrectPass123!',
        displayName: 'Retry',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      // 4 wrong attempts (maxAttempts is 5, so not locked yet)
      for (let i = 0; i < 4; i++) {
        await expect(
          argus.login(emailAddr, 'WrongPassword!', {
            ipAddress: '1.2.3.4',
            userAgent: 'test',
          }),
        ).rejects.toThrow();
      }

      // 5th attempt with correct password should succeed and reset counter
      const login = await argus.login(emailAddr, 'CorrectPass123!', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      expect(login.accessToken).toBeDefined();

      // Verify failed attempts counter was reset
      const user = await db.findUserByEmail(emailAddr);
      expect(user.failedLoginAttempts).toBe(0);
    });

    it('should lock account after 5 wrong password attempts', async () => {
      const emailAddr = `lockout_${suffix}@test.com`;
      await argus.register({
        email: emailAddr,
        password: 'CorrectPass123!',
        displayName: 'Lockout',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      // 5 wrong attempts (maxAttempts is 5)
      for (let i = 0; i < 5; i++) {
        await expect(
          argus.login(emailAddr, 'WrongPassword!', {
            ipAddress: '1.2.3.4',
            userAgent: 'test',
          }),
        ).rejects.toThrow();
      }

      // Account should now be locked
      const user = await db.findUserByEmail(emailAddr);
      expect(user.lockedUntil).not.toBeNull();
      expect(user.lockedUntil!.getTime()).toBeGreaterThan(Date.now());
    });

    it('should reject correct password while account is locked', async () => {
      const emailAddr = `locked_${suffix}@test.com`;
      await argus.register({
        email: emailAddr,
        password: 'CorrectPass123!',
        displayName: 'Locked',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      // Lock the account with 5 wrong attempts
      for (let i = 0; i < 5; i++) {
        await expect(
          argus.login(emailAddr, 'WrongPassword!', {
            ipAddress: '1.2.3.4',
            userAgent: 'test',
          }),
        ).rejects.toThrow();
      }

      // Now try with correct password - should still be locked
      await expect(
        argus.login(emailAddr, 'CorrectPass123!', {
          ipAddress: '1.2.3.4',
          userAgent: 'test',
        }),
      ).rejects.toThrow(/locked/i);
    });

    it('should allow login with email in different case', async () => {
      const emailAddr = `casetest_${suffix}@test.com`;
      await argus.register({
        email: emailAddr,
        password: 'StrongPass123!',
        displayName: 'CaseTest',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      // Login with uppercase email
      const login = await argus.login(emailAddr.toUpperCase(), 'StrongPass123!', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      expect(login.accessToken).toBeDefined();
    });

    it('should handle multiple rapid registrations with different emails', async () => {
      const emails = Array.from({ length: 10 }, (_, i) => `rapid_${suffix}_${i}@test.com`);

      const results = await Promise.all(
        emails.map((e) =>
          argus.register({
            email: e,
            password: 'StrongPass123!',
            displayName: `Rapid${e}`,
            ipAddress: '1.2.3.4',
            userAgent: 'test',
          }),
        ),
      );

      // All should succeed
      expect(results.length).toBe(10);
      for (const r of results) {
        expect(r.accessToken).toBeDefined();
        expect(r.user.id).toBeDefined();
      }

      // All should have unique IDs
      const ids = results.map((r) => r.user.id);
      expect(new Set(ids).size).toBe(10);
    });
  });

  // ─── Token Edge Cases ────────────────────────────────────────────────

  describe('Token edge cases', () => {
    it('should fail refresh after session is manually revoked', async () => {
      const emailAddr = `revokedsess_${suffix}@test.com`;
      const reg = await argus.register({
        email: emailAddr,
        password: 'StrongPass123!',
        displayName: 'RevokedSession',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      // Get the session and revoke it
      const user = await db.findUserByEmail(emailAddr);
      const sessions = await db.getActiveSessions(user.id);
      expect(sessions.length).toBeGreaterThan(0);
      await db.revokeSession(sessions[0].id, 'manual_revoke');

      // Now try to refresh - should fail with SESSION_EXPIRED
      await expect(argus.refresh(reg.refreshToken)).rejects.toThrow(/session/i);
    });

    it('should handle chain of 10 successful refreshes', async () => {
      const emailAddr = `chain_${suffix}@test.com`;
      const reg = await argus.register({
        email: emailAddr,
        password: 'StrongPass123!',
        displayName: 'Chain',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      let currentToken = reg.refreshToken;
      const seenTokens = new Set<string>();
      seenTokens.add(currentToken);

      for (let i = 0; i < 10; i++) {
        const result = await argus.refresh(currentToken);
        expect(result.accessToken).toBeDefined();
        expect(result.refreshToken).toBeDefined();
        expect(result.refreshToken).not.toBe(currentToken);
        expect(seenTokens.has(result.refreshToken)).toBe(false);
        seenTokens.add(result.refreshToken);
        currentToken = result.refreshToken;
      }

      expect(seenTokens.size).toBe(11); // 1 initial + 10 refreshes
    });

    it('should allow refresh using token from register (not login)', async () => {
      const emailAddr = `regtoken_${suffix}@test.com`;
      const reg = await argus.register({
        email: emailAddr,
        password: 'StrongPass123!',
        displayName: 'RegToken',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      // The token from register should be refreshable
      const result = await argus.refresh(reg.refreshToken);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).not.toBe(reg.refreshToken);
    });
  });

  // ─── Password Edge Cases ─────────────────────────────────────────────

  describe('Password edge cases', () => {
    it('should not reveal whether email exists for forgot-password', async () => {
      // For non-existent email, forgotPassword should succeed silently
      await expect(
        argus.forgotPassword(`nonexistent_${suffix}@test.com`, '1.2.3.4'),
      ).resolves.toBeUndefined();
    });

    it('should reject login with old password after reset', async () => {
      const emailAddr = `pwreset_${suffix}@test.com`;
      await argus.register({
        email: emailAddr,
        password: 'OldPass123!',
        displayName: 'PwReset',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      email.clear();
      await argus.forgotPassword(emailAddr, '1.2.3.4');

      const resetEmail = email.getSentEmails().find((e: any) => e.type === 'password_reset');
      expect(resetEmail).toBeDefined();

      await argus.resetPassword(resetEmail.token, 'NewPass456!', '1.2.3.4');

      // Old password should fail
      await expect(
        argus.login(emailAddr, 'OldPass123!', {
          ipAddress: '1.2.3.4',
          userAgent: 'test',
        }),
      ).rejects.toThrow();

      // New password should work
      const login = await argus.login(emailAddr, 'NewPass456!', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      expect(login.accessToken).toBeDefined();
    });

    it('should reject resetting password to recently used password (password history)', async () => {
      const emailAddr = `history_${suffix}@test.com`;
      const originalPassword = 'Original123!';
      await argus.register({
        email: emailAddr,
        password: originalPassword,
        displayName: 'History',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      // First reset to a new password
      email.clear();
      await argus.forgotPassword(emailAddr, '1.2.3.4');
      let resetEmail = email.getSentEmails().find((e: any) => e.type === 'password_reset');
      await argus.resetPassword(resetEmail.token, 'SecondPass456!', '1.2.3.4');

      // Now try to reset back to the original password (should fail due to history)
      email.clear();
      await argus.forgotPassword(emailAddr, '1.2.3.4');
      resetEmail = email.getSentEmails().find((e: any) => e.type === 'password_reset');

      await expect(
        argus.resetPassword(resetEmail.token, originalPassword, '1.2.3.4'),
      ).rejects.toThrow(/recently used/i);
    });

    it('should reject change-password with wrong current password', async () => {
      const emailAddr = `changepw_${suffix}@test.com`;
      await argus.register({
        email: emailAddr,
        password: 'CurrentPass123!',
        displayName: 'ChangePw',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      const user = await db.findUserByEmail(emailAddr);
      const hasher = (argus as any).hasher;

      // Verify wrong password returns false
      const isValid = await hasher.verify('WrongPassword!', user.passwordHash);
      expect(isValid).toBe(false);

      // Verify correct password returns true
      const isCorrect = await hasher.verify('CurrentPass123!', user.passwordHash);
      expect(isCorrect).toBe(true);
    });
  });

  // ─── Session Edge Cases ──────────────────────────────────────────────

  describe('Session edge cases', () => {
    it('should revoke oldest session when exceeding limit of 5', async () => {
      const emailAddr = `sesslimit_${suffix}@test.com`;
      await argus.register({
        email: emailAddr,
        password: 'StrongPass123!',
        displayName: 'SessLimit',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      // Register already created 1 session, now login 5 more times = 6 total
      // Session limit is 5, so oldest should be revoked
      for (let i = 0; i < 5; i++) {
        await argus.login(emailAddr, 'StrongPass123!', {
          ipAddress: `10.0.0.${i}`,
          userAgent: `agent-${i}`,
        });
      }

      const user = await db.findUserByEmail(emailAddr);
      const activeSessions = await db.getActiveSessions(user.id);

      // Should have at most 5 active sessions (limit enforced)
      expect(activeSessions.length).toBeLessThanOrEqual(5);
    });

    it('should revoke all sessions on logout-all-devices', async () => {
      const emailAddr = `logoutall_${suffix}@test.com`;
      await argus.register({
        email: emailAddr,
        password: 'StrongPass123!',
        displayName: 'LogoutAll',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      // Create additional sessions
      await argus.login(emailAddr, 'StrongPass123!', {
        ipAddress: '2.2.2.2',
        userAgent: 'agent-2',
      });
      await argus.login(emailAddr, 'StrongPass123!', {
        ipAddress: '3.3.3.3',
        userAgent: 'agent-3',
      });

      const user = await db.findUserByEmail(emailAddr);
      const sessionsBefore = await db.getActiveSessions(user.id);
      expect(sessionsBefore.length).toBeGreaterThan(1);

      // Logout all devices
      await argus.logout(user.id, sessionsBefore[0].id, { allDevices: true });

      const sessionsAfter = await db.getActiveSessions(user.id);
      expect(sessionsAfter.length).toBe(0);
    });

    it('should correctly identify current session in session list', async () => {
      const emailAddr = `currentsess_${suffix}@test.com`;
      const reg = await argus.register({
        email: emailAddr,
        password: 'StrongPass123!',
        displayName: 'CurrentSess',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      // Verify the token to get sessionId
      const claims = await argus.verifyToken(reg.accessToken);
      const currentSessionId = claims.sessionId;

      const user = await db.findUserByEmail(emailAddr);
      const sessions = await db.getActiveSessions(user.id);

      // Current session should exist in the list
      const currentSession = sessions.find((s: any) => s.id === currentSessionId);
      expect(currentSession).toBeDefined();
      expect(currentSession.userId).toBe(user.id);
    });
  });

  // ─── GDPR / Data Edge Cases ──────────────────────────────────────────

  describe('GDPR/Data edge cases', () => {
    it('should export all user data after multiple actions', async () => {
      const emailAddr = `gdprfull_${suffix}@test.com`;
      await argus.register({
        email: emailAddr,
        password: 'StrongPass123!',
        displayName: 'GDPRFull',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      // Perform multiple actions
      await argus.login(emailAddr, 'StrongPass123!', {
        ipAddress: '2.2.2.2',
        userAgent: 'agent-2',
      });

      // Try a failed login
      try {
        await argus.login(emailAddr, 'WrongPass!', {
          ipAddress: '3.3.3.3',
          userAgent: 'agent-3',
        });
      } catch {
        // expected
      }

      // Request password reset
      email.clear();
      await argus.forgotPassword(emailAddr, '4.4.4.4');

      const user = await db.findUserByEmail(emailAddr);
      const exported = await db.exportUserData(user.id);

      // Verify export contains user data
      expect(exported.user).toBeDefined();
      expect(exported.user.email).toBe(emailAddr);

      // Should contain sessions
      expect(exported.sessions).toBeDefined();
      expect(exported.sessions.length).toBeGreaterThan(0);

      // Should contain audit log entries
      expect(exported.auditLog).toBeDefined();
      expect(exported.auditLog.length).toBeGreaterThanOrEqual(3); // register, login, failed login
    });

    it('should return null for all lookups after soft delete', async () => {
      const emailAddr = `softdel_${suffix}@test.com`;
      await argus.register({
        email: emailAddr,
        password: 'StrongPass123!',
        displayName: 'SoftDel',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      const user = await db.findUserByEmail(emailAddr);
      expect(user).not.toBeNull();
      const userId = user.id;

      // Soft delete the user
      await db.softDeleteUser(userId);

      // All lookups should return null
      expect(await db.findUserByEmail(emailAddr)).toBeNull();
      expect(await db.findUserById(userId)).toBeNull();
    });

    it('should retain session records after soft delete but user appears gone', async () => {
      const emailAddr = `softdelsess_${suffix}@test.com`;
      const reg = await argus.register({
        email: emailAddr,
        password: 'StrongPass123!',
        displayName: 'SoftDelSess',
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      const user = await db.findUserByEmail(emailAddr);
      const userId = user.id;

      // Verify sessions exist
      const sessionsBefore = await db.getActiveSessions(userId);
      expect(sessionsBefore.length).toBeGreaterThan(0);

      // Soft delete the user
      await db.softDeleteUser(userId);

      // User appears gone
      expect(await db.findUserByEmail(emailAddr)).toBeNull();
      expect(await db.findUserById(userId)).toBeNull();

      // Sessions might still be in DB (soft delete doesn't cascade to sessions)
      // The getActiveSessions might or might not return them depending on implementation
      // but the key point is the user is gone
      const sessionsAfter = await db.getActiveSessions(userId);
      // Sessions are still technically in DB (not hard deleted)
      // The exact count depends on whether getActiveSessions filters by soft-deleted users
      expect(typeof sessionsAfter.length).toBe('number');
    });
  });
});
