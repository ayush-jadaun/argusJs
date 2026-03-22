import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import type {
  EmailProvider,
  SecurityEvent,
  DeviceInfo,
  User,
  OrgInvite,
  Organization,
} from '@argusjs/core';

export interface SESConfig {
  region: string;
  from: string;
  credentials?: {
    accessKeyId: string;
    secretAccessKey: string;
  };
  baseUrl?: string;
}

export class SESEmailProvider implements EmailProvider {
  readonly name = 'ses';
  private readonly client: SESClient;
  private readonly from: string;
  private readonly baseUrl: string;

  constructor(config: SESConfig) {
    this.from = config.from;
    this.baseUrl = config.baseUrl ?? 'http://localhost:3000';
    this.client = new SESClient({
      region: config.region,
      ...(config.credentials ? { credentials: config.credentials } : {}),
    });
  }

  private async sendEmail(to: string, subject: string, html: string): Promise<void> {
    const command = new SendEmailCommand({
      Source: this.from,
      Destination: { ToAddresses: [to] },
      Message: {
        Subject: { Data: subject, Charset: 'UTF-8' },
        Body: { Html: { Data: html, Charset: 'UTF-8' } },
      },
    });
    await this.client.send(command);
  }

  async sendVerificationEmail(to: string, token: string, user: User): Promise<void> {
    await this.sendEmail(
      to,
      'Verify Your Email Address',
      `<h1>Email Verification</h1>
<p>Hi ${user.displayName},</p>
<p>Please verify your email address by clicking the link below:</p>
<p><a href="${this.baseUrl}/verify-email?token=${token}">Verify Email</a></p>
<p>If you did not create an account, please ignore this email.</p>`,
    );
  }

  async sendPasswordResetEmail(to: string, token: string, user: User): Promise<void> {
    await this.sendEmail(
      to,
      'Reset Your Password',
      `<h1>Password Reset</h1>
<p>Hi ${user.displayName},</p>
<p>You requested a password reset. Click the link below to reset your password:</p>
<p><a href="${this.baseUrl}/reset-password?token=${token}">Reset Password</a></p>
<p>If you did not request this, please ignore this email.</p>`,
    );
  }

  async sendSecurityAlertEmail(to: string, event: SecurityEvent, user: User): Promise<void> {
    await this.sendEmail(
      to,
      'Security Alert',
      `<h1>Security Alert</h1>
<p>Hi ${user.displayName},</p>
<p>We detected the following security event on your account:</p>
<p><strong>${event.type}</strong>: ${event.description}</p>
${event.ipAddress ? `<p>IP Address: ${event.ipAddress}</p>` : ''}
${event.userAgent ? `<p>User Agent: ${event.userAgent}</p>` : ''}
<p>Time: ${event.timestamp.toISOString()}</p>
<p>If this was not you, please secure your account immediately.</p>`,
    );
  }

  async sendWelcomeEmail(to: string, user: User): Promise<void> {
    await this.sendEmail(
      to,
      'Welcome!',
      `<h1>Welcome!</h1>
<p>Hi ${user.displayName},</p>
<p>Welcome to our platform! Your account has been created successfully.</p>
<p><a href="${this.baseUrl}/login">Log in to get started</a></p>`,
    );
  }

  async sendOrgInviteEmail(to: string, invite: OrgInvite, org: Organization): Promise<void> {
    await this.sendEmail(
      to,
      `You've been invited to join ${org.name}`,
      `<h1>Organization Invite</h1>
<p>You've been invited to join <strong>${org.name}</strong> as a <strong>${invite.role}</strong>.</p>
<p><a href="${this.baseUrl}/invite?token=${invite.token}">Accept Invitation</a></p>
<p>If you were not expecting this invitation, please ignore this email.</p>`,
    );
  }

  async sendDeviceVerificationEmail(to: string, device: DeviceInfo, user: User): Promise<void> {
    await this.sendEmail(
      to,
      'New Device Login Detected',
      `<h1>New Device Detected</h1>
<p>Hi ${user.displayName},</p>
<p>A login was detected from a new device:</p>
<ul>
  <li>Browser: ${device.browser}</li>
  <li>OS: ${device.os}</li>
  <li>IP Address: ${device.ipAddress}</li>
</ul>
<p>If this was not you, please secure your account immediately.</p>`,
    );
  }
}
