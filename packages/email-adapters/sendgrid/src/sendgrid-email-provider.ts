import sgMail from '@sendgrid/mail';
import type {
  EmailProvider,
  SecurityEvent,
  DeviceInfo,
  User,
  OrgInvite,
  Organization,
} from '@argus/core';

export interface SendGridConfig {
  apiKey: string;
  from: string;
  templates?: {
    verification?: string;
    passwordReset?: string;
    securityAlert?: string;
    welcome?: string;
    orgInvite?: string;
    deviceVerification?: string;
  };
  baseUrl?: string;
}

export class SendGridEmailProvider implements EmailProvider {
  readonly name = 'sendgrid';
  private readonly config: SendGridConfig;
  private readonly baseUrl: string;

  constructor(config: SendGridConfig) {
    this.config = config;
    this.baseUrl = config.baseUrl ?? 'http://localhost:3000';
    sgMail.setApiKey(config.apiKey);
  }

  async sendVerificationEmail(to: string, token: string, user: User): Promise<void> {
    const templateId = this.config.templates?.verification;

    if (templateId) {
      await sgMail.send({
        to,
        from: this.config.from,
        templateId,
        dynamicTemplateData: {
          displayName: user.displayName,
          verificationUrl: `${this.baseUrl}/verify-email?token=${token}`,
          token,
        },
      });
    } else {
      await sgMail.send({
        to,
        from: this.config.from,
        subject: 'Verify Your Email Address',
        html: `<h1>Email Verification</h1>
<p>Hi ${user.displayName},</p>
<p>Please verify your email address by clicking the link below:</p>
<p><a href="${this.baseUrl}/verify-email?token=${token}">Verify Email</a></p>
<p>If you did not create an account, please ignore this email.</p>`,
      });
    }
  }

  async sendPasswordResetEmail(to: string, token: string, user: User): Promise<void> {
    const templateId = this.config.templates?.passwordReset;

    if (templateId) {
      await sgMail.send({
        to,
        from: this.config.from,
        templateId,
        dynamicTemplateData: {
          displayName: user.displayName,
          resetUrl: `${this.baseUrl}/reset-password?token=${token}`,
          token,
        },
      });
    } else {
      await sgMail.send({
        to,
        from: this.config.from,
        subject: 'Reset Your Password',
        html: `<h1>Password Reset</h1>
<p>Hi ${user.displayName},</p>
<p>You requested a password reset. Click the link below to reset your password:</p>
<p><a href="${this.baseUrl}/reset-password?token=${token}">Reset Password</a></p>
<p>If you did not request this, please ignore this email.</p>`,
      });
    }
  }

  async sendSecurityAlertEmail(to: string, event: SecurityEvent, user: User): Promise<void> {
    const templateId = this.config.templates?.securityAlert;

    if (templateId) {
      await sgMail.send({
        to,
        from: this.config.from,
        templateId,
        dynamicTemplateData: {
          displayName: user.displayName,
          eventType: event.type,
          eventDescription: event.description,
          ipAddress: event.ipAddress,
          userAgent: event.userAgent,
          timestamp: event.timestamp.toISOString(),
        },
      });
    } else {
      await sgMail.send({
        to,
        from: this.config.from,
        subject: 'Security Alert',
        html: `<h1>Security Alert</h1>
<p>Hi ${user.displayName},</p>
<p>We detected the following security event on your account:</p>
<p><strong>${event.type}</strong>: ${event.description}</p>
${event.ipAddress ? `<p>IP Address: ${event.ipAddress}</p>` : ''}
${event.userAgent ? `<p>User Agent: ${event.userAgent}</p>` : ''}
<p>Time: ${event.timestamp.toISOString()}</p>
<p>If this was not you, please secure your account immediately.</p>`,
      });
    }
  }

  async sendWelcomeEmail(to: string, user: User): Promise<void> {
    const templateId = this.config.templates?.welcome;

    if (templateId) {
      await sgMail.send({
        to,
        from: this.config.from,
        templateId,
        dynamicTemplateData: {
          displayName: user.displayName,
          loginUrl: `${this.baseUrl}/login`,
        },
      });
    } else {
      await sgMail.send({
        to,
        from: this.config.from,
        subject: 'Welcome!',
        html: `<h1>Welcome!</h1>
<p>Hi ${user.displayName},</p>
<p>Welcome to our platform! Your account has been created successfully.</p>
<p><a href="${this.baseUrl}/login">Log in to get started</a></p>`,
      });
    }
  }

  async sendOrgInviteEmail(to: string, invite: OrgInvite, org: Organization): Promise<void> {
    const templateId = this.config.templates?.orgInvite;

    if (templateId) {
      await sgMail.send({
        to,
        from: this.config.from,
        templateId,
        dynamicTemplateData: {
          orgName: org.name,
          role: invite.role,
          inviteUrl: `${this.baseUrl}/invite?token=${invite.token}`,
        },
      });
    } else {
      await sgMail.send({
        to,
        from: this.config.from,
        subject: `You've been invited to join ${org.name}`,
        html: `<h1>Organization Invite</h1>
<p>You've been invited to join <strong>${org.name}</strong> as a <strong>${invite.role}</strong>.</p>
<p><a href="${this.baseUrl}/invite?token=${invite.token}">Accept Invitation</a></p>
<p>If you were not expecting this invitation, please ignore this email.</p>`,
      });
    }
  }

  async sendDeviceVerificationEmail(to: string, device: DeviceInfo, user: User): Promise<void> {
    const templateId = this.config.templates?.deviceVerification;

    if (templateId) {
      await sgMail.send({
        to,
        from: this.config.from,
        templateId,
        dynamicTemplateData: {
          displayName: user.displayName,
          browser: device.browser,
          os: device.os,
          ipAddress: device.ipAddress,
        },
      });
    } else {
      await sgMail.send({
        to,
        from: this.config.from,
        subject: 'New Device Login Detected',
        html: `<h1>New Device Detected</h1>
<p>Hi ${user.displayName},</p>
<p>A login was detected from a new device:</p>
<ul>
  <li>Browser: ${device.browser}</li>
  <li>OS: ${device.os}</li>
  <li>IP Address: ${device.ipAddress}</li>
</ul>
<p>If this was not you, please secure your account immediately.</p>`,
      });
    }
  }
}
