import type {
  EmailProvider,
  SecurityEvent,
  DeviceInfo,
  User,
  OrgInvite,
  Organization,
} from '@argusjs/core';

export interface SentEmail {
  type: 'verification' | 'password_reset' | 'security_alert' | 'welcome' | 'org_invite' | 'device_verification';
  to: string;
  token?: string;
  user?: User;
  event?: SecurityEvent;
  device?: DeviceInfo;
  invite?: OrgInvite;
  org?: Organization;
  sentAt: Date;
}

export class MemoryEmailProvider implements EmailProvider {
  readonly name = 'memory';
  private sent: SentEmail[] = [];

  async sendVerificationEmail(to: string, token: string, user: User): Promise<void> {
    this.sent.push({ type: 'verification', to, token, user, sentAt: new Date() });
  }

  async sendPasswordResetEmail(to: string, token: string, user: User): Promise<void> {
    this.sent.push({ type: 'password_reset', to, token, user, sentAt: new Date() });
  }

  async sendSecurityAlertEmail(to: string, event: SecurityEvent, user: User): Promise<void> {
    this.sent.push({ type: 'security_alert', to, event, user, sentAt: new Date() });
  }

  async sendWelcomeEmail(to: string, user: User): Promise<void> {
    this.sent.push({ type: 'welcome', to, user, sentAt: new Date() });
  }

  async sendOrgInviteEmail(to: string, invite: OrgInvite, org: Organization): Promise<void> {
    this.sent.push({ type: 'org_invite', to, invite, org, sentAt: new Date() });
  }

  async sendDeviceVerificationEmail(to: string, device: DeviceInfo, user: User): Promise<void> {
    this.sent.push({ type: 'device_verification', to, device, user, sentAt: new Date() });
  }

  getSentEmails(): SentEmail[] {
    return [...this.sent];
  }

  clear(): void {
    this.sent = [];
  }
}
