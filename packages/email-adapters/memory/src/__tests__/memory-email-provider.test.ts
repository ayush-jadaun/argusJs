import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryEmailProvider } from '../memory-email-provider.js';

describe('MemoryEmailProvider', () => {
  let email: MemoryEmailProvider;

  beforeEach(() => {
    email = new MemoryEmailProvider();
  });

  it('should store sent verification emails', async () => {
    const user = { id: '1', email: 'a@b.com', displayName: 'A' } as any;
    await email.sendVerificationEmail('a@b.com', 'token123', user);
    const sent = email.getSentEmails();
    expect(sent).toHaveLength(1);
    expect(sent[0].type).toBe('verification');
    expect(sent[0].to).toBe('a@b.com');
    expect(sent[0].token).toBe('token123');
  });

  it('should store password reset emails', async () => {
    const user = { id: '1', email: 'a@b.com', displayName: 'A' } as any;
    await email.sendPasswordResetEmail('a@b.com', 'reset-tok', user);
    const sent = email.getSentEmails();
    expect(sent).toHaveLength(1);
    expect(sent[0].type).toBe('password_reset');
  });

  it('should store security alert emails', async () => {
    const user = { id: '1', email: 'a@b.com', displayName: 'A' } as any;
    const event = { type: 'suspicious_login', description: 'New device', timestamp: new Date() };
    await email.sendSecurityAlertEmail('a@b.com', event, user);
    expect(email.getSentEmails()).toHaveLength(1);
    expect(email.getSentEmails()[0].type).toBe('security_alert');
  });

  it('should store welcome emails', async () => {
    const user = { id: '1', email: 'a@b.com', displayName: 'A' } as any;
    await email.sendWelcomeEmail('a@b.com', user);
    expect(email.getSentEmails()[0].type).toBe('welcome');
  });

  it('should store org invite emails', async () => {
    const user = { id: '1' } as any;
    const invite = { id: 'inv1', orgId: 'org1', email: 'b@c.com', role: 'member' } as any;
    const org = { id: 'org1', name: 'Acme' } as any;
    await email.sendOrgInviteEmail('b@c.com', invite, org);
    expect(email.getSentEmails()[0].type).toBe('org_invite');
  });

  it('should store device verification emails', async () => {
    const user = { id: '1', email: 'a@b.com', displayName: 'A' } as any;
    const device = { fingerprint: 'fp1', browser: 'Chrome', os: 'Windows', ipAddress: '1.2.3.4' };
    await email.sendDeviceVerificationEmail('a@b.com', device, user);
    expect(email.getSentEmails()[0].type).toBe('device_verification');
  });

  it('should accumulate multiple emails', async () => {
    const user = { id: '1', email: 'a@b.com', displayName: 'A' } as any;
    await email.sendWelcomeEmail('a@b.com', user);
    await email.sendVerificationEmail('a@b.com', 'tok', user);
    expect(email.getSentEmails()).toHaveLength(2);
  });

  it('should clear sent emails', async () => {
    const user = { id: '1', email: 'a@b.com', displayName: 'A' } as any;
    await email.sendWelcomeEmail('a@b.com', user);
    email.clear();
    expect(email.getSentEmails()).toHaveLength(0);
  });

  it('should have correct name', () => {
    expect(email.name).toBe('memory');
  });
});
