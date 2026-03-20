export interface User {
  id: string;
  email: string;
  passwordHash: string | null;
  displayName: string;
  avatarUrl: string | null;
  emailVerified: boolean;
  mfaEnabled: boolean;
  mfaMethods: string[];
  roles: string[];
  permissions: string[];
  orgId: string | null;
  orgRole: string | null;
  failedLoginAttempts: number;
  lockedUntil: Date | null;
  lastLoginAt: Date | null;
  lastLoginIp: string | null;
  emailVerifiedAt: Date | null;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
}

export interface Session {
  id: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
  deviceFingerprint: string | null;
  lastActivityAt: Date;
  expiresAt: Date;
  revoked: boolean;
  revokedAt: Date | null;
  revokedReason: string | null;
  orgId: string | null;
  createdAt: Date;
}

export interface RefreshToken {
  id: string;
  userId: string;
  sessionId: string;
  tokenHash: string;
  family: string;
  generation: number;
  revoked: boolean;
  revokedAt: Date | null;
  revokedReason: string | null;
  expiresAt: Date;
  createdAt: Date;
}

export interface PasswordResetToken {
  id: string;
  userId: string;
  tokenHash: string;
  used: boolean;
  usedAt: Date | null;
  requestedFromIp: string;
  requestedFromUa: string | null;
  expiresAt: Date;
  createdAt: Date;
}

export interface EmailVerificationToken {
  id: string;
  userId: string;
  tokenHash: string;
  used: boolean;
  usedAt: Date | null;
  expiresAt: Date;
  createdAt: Date;
}

export interface OAuthLink {
  id: string;
  userId: string;
  provider: string;
  providerUserId: string;
  email: string | null;
  displayName: string | null;
  avatarUrl: string | null;
  rawProfile: Record<string, unknown>;
  accessToken: string | null;
  refreshToken: string | null;
  tokenExpiresAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface MFASecret {
  id: string;
  userId: string;
  method: string;
  encryptedSecret: string;
  encryptedBackupCodes: string[];
  backupCodesUsed: boolean[];
  recoveryEmail: string | null;
  enabledAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface AuditLogEntry {
  id: string;
  userId: string | null;
  action: AuditAction;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  orgId: string | null;
  createdAt: Date;
}

export type AuditAction =
  | 'USER_REGISTERED'
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILED'
  | 'LOGIN_ATTEMPT_LOCKED'
  | 'LOGOUT'
  | 'LOGOUT_ALL_SESSIONS'
  | 'TOKEN_REFRESHED'
  | 'TOKEN_REUSE_DETECTED'
  | 'PASSWORD_CHANGED'
  | 'PASSWORD_RESET_REQUESTED'
  | 'PASSWORD_RESET_COMPLETED'
  | 'EMAIL_VERIFICATION_SENT'
  | 'EMAIL_VERIFIED'
  | 'MFA_ENABLED'
  | 'MFA_DISABLED'
  | 'MFA_CHALLENGE_PASSED'
  | 'MFA_CHALLENGE_FAILED'
  | 'BACKUP_CODE_USED'
  | 'OAUTH_LINKED'
  | 'OAUTH_UNLINKED'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_UNLOCKED'
  | 'ACCOUNT_DELETED'
  | 'SESSION_REVOKED'
  | 'ROLE_CHANGED'
  | 'PERMISSION_CHANGED'
  | 'SUSPICIOUS_ACTIVITY'
  | 'ADMIN_ACTION';

export interface Organization {
  id: string;
  name: string;
  slug: string;
  ownerId: string;
  plan: string;
  settings: OrgSettings;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export interface OrgSettings {
  enforceSSO: boolean;
  allowedAuthMethods: string[];
  enforceMFA: boolean;
  allowedMFAMethods: string[];
  sessionTimeout: number;
  maxSessionsPerUser: number;
  ipAllowlist: string[];
  passwordPolicy: {
    minLength: number;
    requireMFA: boolean;
    maxAge: number;
  };
}

export interface OrgMember {
  userId: string;
  orgId: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
  permissions: string[];
  joinedAt: Date;
}

export interface OrgInvite {
  id: string;
  orgId: string;
  email: string;
  role: string;
  invitedBy: string;
  token: string;
  expiresAt: Date;
  acceptedAt: Date | null;
  createdAt: Date;
}

export interface ApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  keyHash: string;
  userId: string;
  orgId: string | null;
  permissions: string[];
  rateLimit: { max: number; windowSeconds: number } | null;
  ipAllowlist: string[];
  expiresAt: Date | null;
  lastUsedAt: Date | null;
  createdAt: Date;
  revokedAt: Date | null;
}

export interface Role {
  name: string;
  description: string;
  permissions: string[];
  inherits: string[];
  isSystem: boolean;
}

export interface AccessPolicy {
  id: string;
  name: string;
  effect: 'allow' | 'deny';
  actions: string[];
  conditions: PolicyCondition[];
}

export interface PolicyCondition {
  attribute: string;
  operator: 'eq' | 'neq' | 'in' | 'not_in' | 'gt' | 'lt' | 'contains' | 'matches';
  value: unknown;
}

export interface Webhook {
  id: string;
  url: string;
  events: string[];
  secret: string;
  orgId: string | null;
  active: boolean;
  failureCount: number;
  lastTriggeredAt: Date | null;
  createdAt: Date;
}

export interface TrustedDevice {
  id: string;
  userId: string;
  fingerprint: string;
  name: string;
  browser: string;
  os: string;
  lastUsedAt: Date;
  lastIp: string;
  trustedAt: Date;
}
