import { describe, it, expect } from 'vitest';
import { createTestArgus } from './helpers.js';
import type { MFAProvider } from '../../interfaces/mfa-provider.js';

const mockMFAProvider: MFAProvider = {
  name: 'totp',
  async generateSecret(_user) {
    return {
      secret: 'JBSWY3DPEHPK3PXP',
      qrCodeUrl: 'otpauth://totp/Argus:test@test.com?secret=JBSWY3DPEHPK3PXP',
      backupCodes: ['1111-1111', '2222-2222'],
      expiresIn: 600,
    };
  },
  async verifyCode(secret, code) {
    return code === '123456';
  },
  generateBackupCodes() {
    return ['AAAA-BBBB', 'CCCC-DDDD', 'EEEE-FFFF'];
  },
};

describe('Argus.mfa', () => {
  async function registerUser(argus: any) {
    return argus.register({
      email: 'alice@example.com',
      password: 'strongpass123',
      displayName: 'Alice',
      ipAddress: '1.2.3.4',
      userAgent: 'test',
    });
  }

  function createMFATestArgus() {
    return createTestArgus({
      mfa: { totp: mockMFAProvider },
      mfaEncryptionKey: 'a'.repeat(64),
    });
  }

  describe('setup', () => {
    it('should return secret, QR code, and backup codes', async () => {
      const { argus } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      const setupData = await argus.mfa.setup(auth.user.id, 'totp');
      expect(setupData.secret).toBe('JBSWY3DPEHPK3PXP');
      expect(setupData.qrCodeUrl).toContain('otpauth://');
      expect(setupData.backupCodes).toHaveLength(2);
      expect(setupData.expiresIn).toBe(600);
    });

    it('should throw if MFA already enabled', async () => {
      const { argus, db } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);
      await db.updateUser(auth.user.id, { mfaEnabled: true, mfaMethods: ['totp'] });

      await expect(argus.mfa.setup(auth.user.id, 'totp')).rejects.toThrow('MFA is already active');
    });
  });

  describe('verifySetup', () => {
    it('should enable MFA with correct code', async () => {
      const { argus, db } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      await argus.mfa.setup(auth.user.id, 'totp');
      await argus.mfa.verifySetup(auth.user.id, 'totp', '123456');

      const user = await db.findUserById(auth.user.id);
      expect(user!.mfaEnabled).toBe(true);
      expect(user!.mfaMethods).toContain('totp');
    });

    it('should throw with wrong code', async () => {
      const { argus } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      await argus.mfa.setup(auth.user.id, 'totp');
      await expect(argus.mfa.verifySetup(auth.user.id, 'totp', '000000'))
        .rejects.toThrow('Verification code is incorrect');
    });
  });

  describe('verifyLogin', () => {
    it('should return tokens with correct code', async () => {
      const { argus } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      // Setup and verify MFA
      await argus.mfa.setup(auth.user.id, 'totp');
      await argus.mfa.verifySetup(auth.user.id, 'totp', '123456');

      // Login returns MFA challenge
      const loginResult = await argus.login('alice@example.com', 'strongpass123', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      expect((loginResult as any).mfaRequired).toBe(true);
      const mfaToken = (loginResult as any).mfaToken;

      // Verify MFA login
      const result = await argus.mfa.verifyLogin(mfaToken, '123456', 'totp', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(result.user.email).toBe('alice@example.com');
    });

    it('should throw with wrong code', async () => {
      const { argus } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      await argus.mfa.setup(auth.user.id, 'totp');
      await argus.mfa.verifySetup(auth.user.id, 'totp', '123456');

      const loginResult = await argus.login('alice@example.com', 'strongpass123', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      const mfaToken = (loginResult as any).mfaToken;

      await expect(
        argus.mfa.verifyLogin(mfaToken, '000000', 'totp', {
          ipAddress: '1.2.3.4',
          userAgent: 'test',
        }),
      ).rejects.toThrow('Verification code is incorrect');
    });

    it('should accept backup code for login', async () => {
      const { argus } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      // Setup MFA
      const setupData = await argus.mfa.setup(auth.user.id, 'totp');
      await argus.mfa.verifySetup(auth.user.id, 'totp', '123456');

      // Login
      const loginResult = await argus.login('alice@example.com', 'strongpass123', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      const mfaToken = (loginResult as any).mfaToken;

      // Use backup code
      const result = await argus.mfa.verifyLogin(mfaToken, setupData.backupCodes[0], 'totp', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });
  });

  describe('disable', () => {
    it('should disable MFA with valid code', async () => {
      const { argus, db } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      await argus.mfa.setup(auth.user.id, 'totp');
      await argus.mfa.verifySetup(auth.user.id, 'totp', '123456');

      await argus.mfa.disable(auth.user.id, '123456');

      const user = await db.findUserById(auth.user.id);
      expect(user!.mfaEnabled).toBe(false);
      expect(user!.mfaMethods).toEqual([]);
    });

    it('should throw with wrong code', async () => {
      const { argus } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      await argus.mfa.setup(auth.user.id, 'totp');
      await argus.mfa.verifySetup(auth.user.id, 'totp', '123456');

      await expect(argus.mfa.disable(auth.user.id, '000000'))
        .rejects.toThrow('Verification code is incorrect');
    });
  });

  describe('audit logs', () => {
    it('should write MFA_ENABLED audit on verifySetup', async () => {
      const { argus, db } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      await argus.mfa.setup(auth.user.id, 'totp');
      await argus.mfa.verifySetup(auth.user.id, 'totp', '123456');

      const { entries } = await db.queryAuditLog({ userId: auth.user.id, action: 'MFA_ENABLED' });
      expect(entries.length).toBeGreaterThanOrEqual(1);
      expect(entries[0].action).toBe('MFA_ENABLED');
    });

    it('should write MFA_DISABLED audit on disable', async () => {
      const { argus, db } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      await argus.mfa.setup(auth.user.id, 'totp');
      await argus.mfa.verifySetup(auth.user.id, 'totp', '123456');
      await argus.mfa.disable(auth.user.id, '123456');

      const { entries } = await db.queryAuditLog({ userId: auth.user.id, action: 'MFA_DISABLED' });
      expect(entries.length).toBeGreaterThanOrEqual(1);
      expect(entries[0].action).toBe('MFA_DISABLED');
    });

    it('should write MFA_CHALLENGE_FAILED audit on invalid login code', async () => {
      const { argus, db } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      await argus.mfa.setup(auth.user.id, 'totp');
      await argus.mfa.verifySetup(auth.user.id, 'totp', '123456');

      const loginResult = await argus.login('alice@example.com', 'strongpass123', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      const mfaToken = (loginResult as any).mfaToken;

      try {
        await argus.mfa.verifyLogin(mfaToken, '000000', 'totp', {
          ipAddress: '1.2.3.4',
          userAgent: 'test',
        });
      } catch { /* expected */ }

      const { entries } = await db.queryAuditLog({ userId: auth.user.id, action: 'MFA_CHALLENGE_FAILED' });
      expect(entries.length).toBeGreaterThanOrEqual(1);
    });

    it('should write MFA_CHALLENGE_PASSED audit on valid login', async () => {
      const { argus, db } = createMFATestArgus();
      await argus.init();
      const auth = await registerUser(argus);

      await argus.mfa.setup(auth.user.id, 'totp');
      await argus.mfa.verifySetup(auth.user.id, 'totp', '123456');

      const loginResult = await argus.login('alice@example.com', 'strongpass123', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });
      const mfaToken = (loginResult as any).mfaToken;

      await argus.mfa.verifyLogin(mfaToken, '123456', 'totp', {
        ipAddress: '1.2.3.4',
        userAgent: 'test',
      });

      const { entries } = await db.queryAuditLog({ userId: auth.user.id, action: 'MFA_CHALLENGE_PASSED' });
      expect(entries.length).toBeGreaterThanOrEqual(1);
    });
  });
});
