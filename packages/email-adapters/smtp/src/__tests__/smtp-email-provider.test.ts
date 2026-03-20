import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SMTPEmailProvider } from '../smtp-email-provider.js';

// Mock nodemailer
vi.mock('nodemailer', () => ({
  default: {
    createTransport: vi.fn().mockReturnValue({
      sendMail: vi.fn().mockResolvedValue({ messageId: 'test-id' }),
      verify: vi.fn().mockResolvedValue(true),
    }),
  },
}));

describe('SMTPEmailProvider', () => {
  let provider: SMTPEmailProvider;

  beforeEach(() => {
    vi.clearAllMocks();
    provider = new SMTPEmailProvider({
      host: 'smtp.test.com',
      port: 587,
      secure: false,
      auth: { user: 'testuser', pass: 'testpass' },
      from: 'noreply@test.com',
      baseUrl: 'https://app.test.com',
    });
  });

  it('should have name smtp', () => {
    expect(provider.name).toBe('smtp');
  });

  it('should send verification email', async () => {
    const nodemailer = (await import('nodemailer')).default;
    const transport = nodemailer.createTransport();
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    await provider.sendVerificationEmail('a@b.com', 'token123', user);
    expect(transport.sendMail).toHaveBeenCalledTimes(1);
    const call = (transport.sendMail as any).mock.calls[0][0];
    expect(call.to).toBe('a@b.com');
    expect(call.from).toBe('noreply@test.com');
    expect(call.subject).toContain('erif');
  });

  it('should send password reset email', async () => {
    const nodemailer = (await import('nodemailer')).default;
    const transport = nodemailer.createTransport();
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    await provider.sendPasswordResetEmail('a@b.com', 'reset-tok', user);
    expect(transport.sendMail).toHaveBeenCalledTimes(1);
  });

  it('should send security alert email', async () => {
    const nodemailer = (await import('nodemailer')).default;
    const transport = nodemailer.createTransport();
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    const event = { type: 'new_login', description: 'New device', timestamp: new Date() };
    await provider.sendSecurityAlertEmail('a@b.com', event, user);
    expect(transport.sendMail).toHaveBeenCalledTimes(1);
  });

  it('should send welcome email', async () => {
    const nodemailer = (await import('nodemailer')).default;
    const transport = nodemailer.createTransport();
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    await provider.sendWelcomeEmail('a@b.com', user);
    expect(transport.sendMail).toHaveBeenCalledTimes(1);
  });

  it('should send org invite email', async () => {
    const nodemailer = (await import('nodemailer')).default;
    const transport = nodemailer.createTransport();
    const invite = { id: 'i1', orgId: 'o1', email: 'b@c.com', role: 'member', token: 'inv-tok' } as any;
    const org = { id: 'o1', name: 'Acme' } as any;
    await provider.sendOrgInviteEmail('b@c.com', invite, org);
    expect(transport.sendMail).toHaveBeenCalledTimes(1);
  });

  it('should send device verification email', async () => {
    const nodemailer = (await import('nodemailer')).default;
    const transport = nodemailer.createTransport();
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    const device = { fingerprint: 'fp', browser: 'Chrome', os: 'Win', ipAddress: '1.2.3.4' };
    await provider.sendDeviceVerificationEmail('a@b.com', device, user);
    expect(transport.sendMail).toHaveBeenCalledTimes(1);
  });
});
