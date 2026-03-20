import type { AuditAction, OrgSettings } from './entities.js';

export interface CreateUserInput {
  email: string;
  passwordHash: string | null;
  displayName: string;
  avatarUrl?: string;
  emailVerified?: boolean;
  roles?: string[];
  orgId?: string;
  orgRole?: string;
  metadata?: Record<string, unknown>;
}

export interface CreateSessionInput {
  userId: string;
  ipAddress: string;
  userAgent: string;
  deviceFingerprint?: string;
  expiresAt: Date;
  orgId?: string;
}

export interface CreateRefreshTokenInput {
  userId: string;
  sessionId: string;
  tokenHash: string;
  family: string;
  generation: number;
  expiresAt: Date;
}

export interface CreateResetTokenInput {
  userId: string;
  tokenHash: string;
  requestedFromIp: string;
  requestedFromUa?: string;
  expiresAt: Date;
}

export interface CreateVerificationInput {
  userId: string;
  tokenHash: string;
  expiresAt: Date;
}

export interface LinkOAuthInput {
  userId: string;
  provider: string;
  providerUserId: string;
  email?: string;
  displayName?: string;
  avatarUrl?: string;
  rawProfile: Record<string, unknown>;
  accessToken?: string;
  refreshToken?: string;
  tokenExpiresAt?: Date;
}

export interface SaveMFAInput {
  userId: string;
  method: string;
  encryptedSecret: string;
  encryptedBackupCodes: string[];
  backupCodesUsed: boolean[];
  recoveryEmail?: string;
}

export interface CreateOrgInput {
  name: string;
  slug: string;
  ownerId: string;
  plan?: string;
  settings?: Partial<OrgSettings>;
  metadata?: Record<string, unknown>;
}

export interface AddOrgMemberInput {
  userId: string;
  orgId: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
  permissions?: string[];
}

export interface CreateOrgInviteInput {
  orgId: string;
  email: string;
  role: string;
  invitedBy: string;
  token: string;
  expiresAt: Date;
}

export interface CreateApiKeyInput {
  name: string;
  keyPrefix: string;
  keyHash: string;
  userId: string;
  orgId?: string;
  permissions: string[];
  rateLimit?: { max: number; windowSeconds: number };
  ipAllowlist?: string[];
  expiresAt?: Date;
}

export interface CreateWebhookInput {
  url: string;
  events: string[];
  secret: string;
  orgId?: string;
}

export interface AuditLogFilter {
  userId?: string;
  action?: AuditAction;
  startDate?: Date;
  endDate?: Date;
  orgId?: string;
  limit?: number;
  offset?: number;
}

export interface UserFilter {
  search?: string;
  role?: string;
  emailVerified?: boolean;
  mfaEnabled?: boolean;
  locked?: boolean;
  orgId?: string;
  limit?: number;
  offset?: number;
}

export interface SystemStats {
  totalUsers: number;
  activeUsers: number;
  totalSessions: number;
  activeSessions: number;
  mfaAdoptionRate: number;
  lockedAccounts: number;
}

export interface UserDataExport {
  user: Record<string, unknown>;
  sessions: Record<string, unknown>[];
  oauthProviders: Record<string, unknown>[];
  auditLog: Record<string, unknown>[];
  apiKeys: Record<string, unknown>[];
  organizations: Record<string, unknown>[];
}
