import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SendGridEmailProvider } from '../sendgrid-email-provider.js';

// Mock the sendgrid module
vi.mock('@sendgrid/mail', () => ({
  default: {
    setApiKey: vi.fn(),
    send: vi.fn().mockResolvedValue([{ statusCode: 202 }]),
  },
}));

describe('SendGridEmailProvider', () => {
  let provider: SendGridEmailProvider;

  beforeEach(() => {
    vi.clearAllMocks();
    provider = new SendGridEmailProvider({
      apiKey: 'SG.test-key',
      from: 'noreply@test.com',
      baseUrl: 'https://app.test.com',
    });
  });

  it('should have name sendgrid', () => {
    expect(provider.name).toBe('sendgrid');
  });

  it('should send verification email', async () => {
    const sgMail = (await import('@sendgrid/mail')).default;
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    await provider.sendVerificationEmail('a@b.com', 'token123', user);
    expect(sgMail.send).toHaveBeenCalledTimes(1);
    const call = (sgMail.send as any).mock.calls[0][0];
    expect(call.to).toBe('a@b.com');
    expect(call.from).toBe('noreply@test.com');
    expect(call.subject).toContain('erif');
  });

  it('should send password reset email', async () => {
    const sgMail = (await import('@sendgrid/mail')).default;
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    await provider.sendPasswordResetEmail('a@b.com', 'reset-tok', user);
    expect(sgMail.send).toHaveBeenCalledTimes(1);
  });

  it('should send security alert email', async () => {
    const sgMail = (await import('@sendgrid/mail')).default;
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    const event = { type: 'new_login', description: 'New device', timestamp: new Date() };
    await provider.sendSecurityAlertEmail('a@b.com', event, user);
    expect(sgMail.send).toHaveBeenCalledTimes(1);
  });

  it('should send welcome email', async () => {
    const sgMail = (await import('@sendgrid/mail')).default;
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    await provider.sendWelcomeEmail('a@b.com', user);
    expect(sgMail.send).toHaveBeenCalledTimes(1);
  });

  it('should send org invite email', async () => {
    const sgMail = (await import('@sendgrid/mail')).default;
    const invite = { id: 'i1', orgId: 'o1', email: 'b@c.com', role: 'member', token: 'inv-tok' } as any;
    const org = { id: 'o1', name: 'Acme' } as any;
    await provider.sendOrgInviteEmail('b@c.com', invite, org);
    expect(sgMail.send).toHaveBeenCalledTimes(1);
  });

  it('should send device verification email', async () => {
    const sgMail = (await import('@sendgrid/mail')).default;
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    const device = { fingerprint: 'fp', browser: 'Chrome', os: 'Win', ipAddress: '1.2.3.4' };
    await provider.sendDeviceVerificationEmail('a@b.com', device, user);
    expect(sgMail.send).toHaveBeenCalledTimes(1);
  });
});
