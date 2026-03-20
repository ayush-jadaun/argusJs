import type { User, OrgInvite, Organization } from '../types/entities.js';

export interface SecurityEvent {
  type: string;
  description: string;
  ipAddress?: string;
  userAgent?: string;
  timestamp: Date;
}

export interface DeviceInfo {
  fingerprint: string;
  browser: string;
  os: string;
  ipAddress: string;
}

export interface EmailProvider {
  name: string;
  init?(): Promise<void>;
  shutdown?(): Promise<void>;
  sendVerificationEmail(to: string, token: string, user: User): Promise<void>;
  sendPasswordResetEmail(to: string, token: string, user: User): Promise<void>;
  sendSecurityAlertEmail(to: string, event: SecurityEvent, user: User): Promise<void>;
  sendWelcomeEmail(to: string, user: User): Promise<void>;
  sendOrgInviteEmail(to: string, invite: OrgInvite, org: Organization): Promise<void>;
  sendDeviceVerificationEmail(to: string, device: DeviceInfo, user: User): Promise<void>;
}
