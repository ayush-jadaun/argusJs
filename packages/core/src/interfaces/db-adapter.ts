import type {
  User, Session, RefreshToken, PasswordResetToken, EmailVerificationToken,
  OAuthLink, MFASecret, AuditLogEntry, Organization, OrgMember, OrgInvite,
  ApiKey, Role, AccessPolicy, Webhook, TrustedDevice,
} from '../types/entities.js';
import type {
  CreateUserInput, CreateSessionInput, CreateRefreshTokenInput, CreateResetTokenInput,
  CreateVerificationInput, LinkOAuthInput, SaveMFAInput, CreateOrgInput, AddOrgMemberInput,
  CreateOrgInviteInput, CreateApiKeyInput, CreateWebhookInput,
  AuditLogFilter, UserFilter, SystemStats, UserDataExport,
} from '../types/inputs.js';

export interface DbAdapter {
  init(): Promise<void>;
  shutdown(): Promise<void>;

  // Users
  createUser(input: CreateUserInput): Promise<User>;
  findUserByEmail(email: string): Promise<User | null>;
  findUserById(id: string): Promise<User | null>;
  updateUser(id: string, updates: Partial<User>): Promise<User>;
  softDeleteUser(id: string): Promise<void>;

  // Sessions
  createSession(input: CreateSessionInput): Promise<Session>;
  getSession(id: string): Promise<Session | null>;
  getActiveSessions(userId: string): Promise<Session[]>;
  revokeSession(id: string, reason: string): Promise<void>;
  revokeAllSessions(userId: string, reason: string, excludeSessionId?: string): Promise<void>;
  countActiveSessions(userId: string): Promise<number>;

  // Refresh Tokens
  createRefreshToken(input: CreateRefreshTokenInput): Promise<RefreshToken>;
  findRefreshTokenByHash(hash: string): Promise<RefreshToken | null>;
  revokeRefreshToken(id: string, reason: string): Promise<void>;
  revokeTokenFamily(family: string, reason: string): Promise<void>;
  revokeAllUserTokens(userId: string, reason: string): Promise<void>;

  // Password Reset
  createPasswordResetToken(input: CreateResetTokenInput): Promise<PasswordResetToken>;
  findPasswordResetByHash(hash: string): Promise<PasswordResetToken | null>;
  markResetTokenUsed(id: string): Promise<void>;
  invalidateUserResetTokens(userId: string): Promise<void>;

  // Email Verification
  createEmailVerificationToken(input: CreateVerificationInput): Promise<EmailVerificationToken>;
  findVerificationByHash(hash: string): Promise<EmailVerificationToken | null>;
  markVerificationUsed(id: string): Promise<void>;

  // OAuth
  linkOAuthProvider(input: LinkOAuthInput): Promise<OAuthLink>;
  findOAuthProvider(provider: string, providerUserId: string): Promise<OAuthLink | null>;
  getUserOAuthProviders(userId: string): Promise<OAuthLink[]>;
  unlinkOAuthProvider(userId: string, provider: string): Promise<void>;

  // MFA
  saveMFASecret(input: SaveMFAInput): Promise<MFASecret>;
  getMFASecret(userId: string): Promise<MFASecret | null>;
  deleteMFASecret(userId: string): Promise<void>;
  markBackupCodeUsed(userId: string, codeIndex: number): Promise<void>;

  // Password History
  getPasswordHistory(userId: string, limit: number): Promise<string[]>;
  addPasswordHistory(userId: string, hash: string): Promise<void>;

  // Audit Log
  writeAuditLog(entry: AuditLogEntry): Promise<void>;
  queryAuditLog(filter: AuditLogFilter): Promise<{ entries: AuditLogEntry[]; total: number }>;

  // Organizations
  createOrganization(input: CreateOrgInput): Promise<Organization>;
  getOrganization(id: string): Promise<Organization | null>;
  updateOrganization(id: string, updates: Partial<Organization>): Promise<Organization>;
  deleteOrganization(id: string): Promise<void>;
  listOrgMembers(orgId: string): Promise<OrgMember[]>;
  addOrgMember(input: AddOrgMemberInput): Promise<OrgMember>;
  updateOrgMember(orgId: string, userId: string, updates: Partial<OrgMember>): Promise<OrgMember>;
  removeOrgMember(orgId: string, userId: string): Promise<void>;

  // Org Invites
  createOrgInvite(input: CreateOrgInviteInput): Promise<OrgInvite>;
  findOrgInviteByToken(token: string): Promise<OrgInvite | null>;
  acceptOrgInvite(id: string): Promise<void>;
  listPendingInvites(orgId: string): Promise<OrgInvite[]>;

  // API Keys
  createApiKey(input: CreateApiKeyInput): Promise<ApiKey>;
  findApiKeyByHash(hash: string): Promise<ApiKey | null>;
  listApiKeys(userId: string): Promise<ApiKey[]>;
  revokeApiKey(id: string): Promise<void>;
  updateApiKeyLastUsed(id: string): Promise<void>;

  // Roles & Permissions
  createRole(role: Role): Promise<Role>;
  getRole(name: string): Promise<Role | null>;
  listRoles(): Promise<Role[]>;
  updateRole(name: string, updates: Partial<Role>): Promise<Role>;
  deleteRole(name: string): Promise<void>;

  // Access Policies
  createPolicy(policy: AccessPolicy): Promise<AccessPolicy>;
  listPolicies(): Promise<AccessPolicy[]>;
  deletePolicy(id: string): Promise<void>;

  // Webhooks
  createWebhook(input: CreateWebhookInput): Promise<Webhook>;
  listWebhooks(orgId?: string): Promise<Webhook[]>;
  updateWebhook(id: string, updates: Partial<Webhook>): Promise<Webhook>;
  deleteWebhook(id: string): Promise<void>;
  incrementWebhookFailure(id: string): Promise<void>;
  resetWebhookFailure(id: string): Promise<void>;

  // Trusted Devices
  saveTrustedDevice(device: TrustedDevice): Promise<TrustedDevice>;
  getTrustedDevices(userId: string): Promise<TrustedDevice[]>;
  removeTrustedDevice(userId: string, deviceId: string): Promise<void>;
  isTrustedDevice(userId: string, fingerprint: string): Promise<boolean>;

  // Admin
  listUsers(filter: UserFilter): Promise<{ users: User[]; total: number }>;
  getSystemStats(): Promise<SystemStats>;
  exportUserData(userId: string): Promise<UserDataExport>;
}
