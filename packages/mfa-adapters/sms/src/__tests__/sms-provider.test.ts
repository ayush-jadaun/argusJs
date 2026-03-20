import { describe, it, expect, vi } from 'vitest';
import { SMSProvider } from '../sms-provider.js';

vi.mock('twilio', () => ({
  default: vi.fn().mockReturnValue({
    messages: { create: vi.fn().mockResolvedValue({ sid: 'SM123' }) },
  }),
}));

describe('SMSProvider', () => {
  const provider = new SMSProvider({ accountSid: 'AC_test', authToken: 'tok', fromNumber: '+15551234567' });

  it('should have name sms', () => { expect(provider.name).toBe('sms'); });
  it('should generate 6-digit code', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'A', metadata: { phone: '+15559876543' } } as any;
    const setup = await provider.generateSecret(user);
    expect(setup.secret).toMatch(/^\d{6}$/);
  });
  it('should verify correct code', async () => { expect(await provider.verifyCode('123456', '123456')).toBe(true); });
  it('should reject wrong code', async () => { expect(await provider.verifyCode('123456', '000000')).toBe(false); });
  it('should generate backup codes', () => { expect(provider.generateBackupCodes!()).toHaveLength(10); });
});
