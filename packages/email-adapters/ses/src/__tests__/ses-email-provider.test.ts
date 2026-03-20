import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SESEmailProvider } from '../ses-email-provider.js';

// Mock the AWS SES client
const mockSend = vi.fn().mockResolvedValue({ MessageId: 'test-message-id' });

vi.mock('@aws-sdk/client-ses', () => ({
  SESClient: vi.fn().mockImplementation(() => ({
    send: mockSend,
  })),
  SendEmailCommand: vi.fn().mockImplementation((input: any) => input),
}));

describe('SESEmailProvider', () => {
  let provider: SESEmailProvider;

  beforeEach(() => {
    vi.clearAllMocks();
    provider = new SESEmailProvider({
      region: 'us-east-1',
      from: 'noreply@test.com',
      baseUrl: 'https://app.test.com',
    });
  });

  it('should have name ses', () => {
    expect(provider.name).toBe('ses');
  });

  it('should send verification email', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    await provider.sendVerificationEmail('a@b.com', 'token123', user);
    expect(mockSend).toHaveBeenCalledTimes(1);
    const call = mockSend.mock.calls[0][0];
    expect(call.Destination.ToAddresses).toContain('a@b.com');
    expect(call.Source).toBe('noreply@test.com');
    expect(call.Message.Subject.Data).toContain('erif');
  });

  it('should send password reset email', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    await provider.sendPasswordResetEmail('a@b.com', 'reset-tok', user);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('should send security alert email', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    const event = { type: 'new_login', description: 'New device', timestamp: new Date() };
    await provider.sendSecurityAlertEmail('a@b.com', event, user);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('should send welcome email', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    await provider.sendWelcomeEmail('a@b.com', user);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('should send org invite email', async () => {
    const invite = { id: 'i1', orgId: 'o1', email: 'b@c.com', role: 'member', token: 'inv-tok' } as any;
    const org = { id: 'o1', name: 'Acme' } as any;
    await provider.sendOrgInviteEmail('b@c.com', invite, org);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('should send device verification email', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    const device = { fingerprint: 'fp', browser: 'Chrome', os: 'Win', ipAddress: '1.2.3.4' };
    await provider.sendDeviceVerificationEmail('a@b.com', device, user);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });
});
