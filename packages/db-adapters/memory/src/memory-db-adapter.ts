import { randomUUID } from 'node:crypto';
import type {
  DbAdapter,
  User, Session, RefreshToken, PasswordResetToken, EmailVerificationToken,
  OAuthLink, MFASecret, AuditLogEntry, Organization, OrgMember, OrgInvite,
  ApiKey, Role, AccessPolicy, Webhook, TrustedDevice,
  CreateUserInput, CreateSessionInput, CreateRefreshTokenInput, CreateResetTokenInput,
  CreateVerificationInput, LinkOAuthInput, SaveMFAInput, CreateOrgInput, AddOrgMemberInput,
  CreateOrgInviteInput, CreateApiKeyInput, CreateWebhookInput,
  AuditLogFilter, UserFilter, SystemStats, UserDataExport,
} from '@argusjs/core';

export class MemoryDbAdapter implements DbAdapter {
  private users = new Map<string, User>();
  private sessions = new Map<string, Session>();
  private refreshTokens = new Map<string, RefreshToken>();
  private passwordResetTokens = new Map<string, PasswordResetToken>();
  private emailVerificationTokens = new Map<string, EmailVerificationToken>();
  private oauthLinks = new Map<string, OAuthLink>();
  private mfaSecrets = new Map<string, MFASecret>();
  private passwordHistory = new Map<string, string[]>();
  private auditLog: AuditLogEntry[] = [];
  private organizations = new Map<string, Organization>();
  private orgMembers = new Map<string, OrgMember[]>();
  private orgInvites = new Map<string, OrgInvite>();
  private apiKeys = new Map<string, ApiKey>();
  private roles = new Map<string, Role>();
  private policies = new Map<string, AccessPolicy>();
  private webhooks = new Map<string, Webhook>();
  private trustedDevices = new Map<string, TrustedDevice>();

  // ─── Lifecycle ──────────────────────────────────────────────────────────

  async init(): Promise<void> {
    // no-op for in-memory adapter
  }

  async shutdown(): Promise<void> {
    // no-op for in-memory adapter
  }

  // ─── Users ──────────────────────────────────────────────────────────────

  async createUser(input: CreateUserInput): Promise<User> {
    // Check for duplicate email (case-insensitive), skip deleted users
    for (const user of this.users.values()) {
      if (user.email.toLowerCase() === input.email.toLowerCase() && user.deletedAt === null) {
        throw new Error(`User with email ${input.email} already exists`);
      }
    }

    const now = new Date();
    const user: User = {
      id: randomUUID(),
      email: input.email,
      passwordHash: input.passwordHash,
      displayName: input.displayName,
      avatarUrl: input.avatarUrl ?? null,
      emailVerified: input.emailVerified ?? false,
      mfaEnabled: false,
      mfaMethods: [],
      roles: input.roles ?? [],
      permissions: [],
      orgId: input.orgId ?? null,
      orgRole: input.orgRole ?? null,
      failedLoginAttempts: 0,
      lockedUntil: null,
      lastLoginAt: null,
      lastLoginIp: null,
      emailVerifiedAt: null,
      metadata: input.metadata ?? {},
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
    };

    this.users.set(user.id, user);
    return { ...user };
  }

  async findUserByEmail(email: string): Promise<User | null> {
    const lowerEmail = email.toLowerCase();
    for (const user of this.users.values()) {
      if (user.email.toLowerCase() === lowerEmail && user.deletedAt === null) {
        return { ...user };
      }
    }
    return null;
  }

  async findUserById(id: string): Promise<User | null> {
    const user = this.users.get(id);
    if (!user || user.deletedAt !== null) return null;
    return { ...user };
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User> {
    const user = this.users.get(id);
    if (!user) throw new Error(`User ${id} not found`);

    const updated: User = {
      ...user,
      ...updates,
      id: user.id, // prevent id override
      updatedAt: new Date(),
    };
    this.users.set(id, updated);
    return { ...updated };
  }

  async softDeleteUser(id: string): Promise<void> {
    const user = this.users.get(id);
    if (!user) throw new Error(`User ${id} not found`);
    user.deletedAt = new Date();
    user.updatedAt = new Date();
  }

  // ─── Sessions ───────────────────────────────────────────────────────────

  async createSession(input: CreateSessionInput): Promise<Session> {
    const now = new Date();
    const session: Session = {
      id: randomUUID(),
      userId: input.userId,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      deviceFingerprint: input.deviceFingerprint ?? null,
      lastActivityAt: now,
      expiresAt: input.expiresAt,
      revoked: false,
      revokedAt: null,
      revokedReason: null,
      orgId: input.orgId ?? null,
      createdAt: now,
    };

    this.sessions.set(session.id, session);
    return { ...session };
  }

  async getSession(id: string): Promise<Session | null> {
    const session = this.sessions.get(id);
    if (!session) return null;
    return { ...session };
  }

  async getActiveSessions(userId: string): Promise<Session[]> {
    const now = new Date();
    const result: Session[] = [];
    for (const session of this.sessions.values()) {
      if (
        session.userId === userId &&
        session.revoked === false &&
        session.expiresAt > now
      ) {
        result.push({ ...session });
      }
    }
    return result;
  }

  async revokeSession(id: string, reason: string): Promise<void> {
    const session = this.sessions.get(id);
    if (!session) throw new Error(`Session ${id} not found`);
    session.revoked = true;
    session.revokedAt = new Date();
    session.revokedReason = reason;
  }

  async revokeAllSessions(userId: string, reason: string, excludeSessionId?: string): Promise<void> {
    for (const session of this.sessions.values()) {
      if (session.userId === userId && session.id !== excludeSessionId) {
        session.revoked = true;
        session.revokedAt = new Date();
        session.revokedReason = reason;
      }
    }
  }

  async countActiveSessions(userId: string): Promise<number> {
    const active = await this.getActiveSessions(userId);
    return active.length;
  }

  // ─── Refresh Tokens ────────────────────────────────────────────────────

  async createRefreshToken(input: CreateRefreshTokenInput): Promise<RefreshToken> {
    const now = new Date();
    const token: RefreshToken = {
      id: randomUUID(),
      userId: input.userId,
      sessionId: input.sessionId,
      tokenHash: input.tokenHash,
      family: input.family,
      generation: input.generation,
      revoked: false,
      revokedAt: null,
      revokedReason: null,
      expiresAt: input.expiresAt,
      createdAt: now,
    };

    this.refreshTokens.set(token.id, token);
    return { ...token };
  }

  async findRefreshTokenByHash(hash: string): Promise<RefreshToken | null> {
    for (const token of this.refreshTokens.values()) {
      if (token.tokenHash === hash) {
        return { ...token }; // return copy — prevents external mutation of internal state
      }
    }
    return null;
  }

  async revokeRefreshToken(id: string, reason: string): Promise<void> {
    const token = this.refreshTokens.get(id);
    if (!token) throw new Error(`Refresh token ${id} not found`);
    token.revoked = true;
    token.revokedAt = new Date();
    token.revokedReason = reason;
  }

  async revokeRefreshTokenIfActive(id: string, reason: string): Promise<boolean> {
    const token = this.refreshTokens.get(id);
    if (!token || token.revoked) return false;
    token.revoked = true;
    token.revokedAt = new Date();
    token.revokedReason = reason;
    return true;
  }

  async revokeTokenFamily(family: string, reason: string): Promise<void> {
    for (const token of this.refreshTokens.values()) {
      if (token.family === family) {
        token.revoked = true;
        token.revokedAt = new Date();
        token.revokedReason = reason;
      }
    }
  }

  async revokeAllUserTokens(userId: string, reason: string): Promise<void> {
    for (const token of this.refreshTokens.values()) {
      if (token.userId === userId) {
        token.revoked = true;
        token.revokedAt = new Date();
        token.revokedReason = reason;
      }
    }
  }

  // ─── Password Reset ────────────────────────────────────────────────────

  async createPasswordResetToken(input: CreateResetTokenInput): Promise<PasswordResetToken> {
    const now = new Date();
    const token: PasswordResetToken = {
      id: randomUUID(),
      userId: input.userId,
      tokenHash: input.tokenHash,
      used: false,
      usedAt: null,
      requestedFromIp: input.requestedFromIp,
      requestedFromUa: input.requestedFromUa ?? null,
      expiresAt: input.expiresAt,
      createdAt: now,
    };

    this.passwordResetTokens.set(token.id, token);
    return { ...token };
  }

  async findPasswordResetByHash(hash: string): Promise<PasswordResetToken | null> {
    for (const token of this.passwordResetTokens.values()) {
      if (token.tokenHash === hash) {
        return { ...token };
      }
    }
    return null;
  }

  async markResetTokenUsed(id: string): Promise<void> {
    const token = this.passwordResetTokens.get(id);
    if (!token) throw new Error(`Reset token ${id} not found`);
    token.used = true;
    token.usedAt = new Date();
  }

  async invalidateUserResetTokens(userId: string): Promise<void> {
    for (const token of this.passwordResetTokens.values()) {
      if (token.userId === userId) {
        token.used = true;
        token.usedAt = new Date();
      }
    }
  }

  // ─── Email Verification ────────────────────────────────────────────────

  async createEmailVerificationToken(input: CreateVerificationInput): Promise<EmailVerificationToken> {
    const now = new Date();
    const token: EmailVerificationToken = {
      id: randomUUID(),
      userId: input.userId,
      tokenHash: input.tokenHash,
      used: false,
      usedAt: null,
      expiresAt: input.expiresAt,
      createdAt: now,
    };

    this.emailVerificationTokens.set(token.id, token);
    return { ...token };
  }

  async findVerificationByHash(hash: string): Promise<EmailVerificationToken | null> {
    for (const token of this.emailVerificationTokens.values()) {
      if (token.tokenHash === hash) {
        return { ...token };
      }
    }
    return null;
  }

  async markVerificationUsed(id: string): Promise<void> {
    const token = this.emailVerificationTokens.get(id);
    if (!token) throw new Error(`Verification token ${id} not found`);
    token.used = true;
    token.usedAt = new Date();
  }

  // ─── OAuth ──────────────────────────────────────────────────────────────

  async linkOAuthProvider(input: LinkOAuthInput): Promise<OAuthLink> {
    const now = new Date();
    const link: OAuthLink = {
      id: randomUUID(),
      userId: input.userId,
      provider: input.provider,
      providerUserId: input.providerUserId,
      email: input.email ?? null,
      displayName: input.displayName ?? null,
      avatarUrl: input.avatarUrl ?? null,
      rawProfile: input.rawProfile,
      accessToken: input.accessToken ?? null,
      refreshToken: input.refreshToken ?? null,
      tokenExpiresAt: input.tokenExpiresAt ?? null,
      createdAt: now,
      updatedAt: now,
    };

    this.oauthLinks.set(link.id, link);
    return { ...link };
  }

  async findOAuthProvider(provider: string, providerUserId: string): Promise<OAuthLink | null> {
    for (const link of this.oauthLinks.values()) {
      if (link.provider === provider && link.providerUserId === providerUserId) {
        return { ...link };
      }
    }
    return null;
  }

  async getUserOAuthProviders(userId: string): Promise<OAuthLink[]> {
    const result: OAuthLink[] = [];
    for (const link of this.oauthLinks.values()) {
      if (link.userId === userId) {
        result.push({ ...link });
      }
    }
    return result;
  }

  async unlinkOAuthProvider(userId: string, provider: string): Promise<void> {
    for (const [id, link] of this.oauthLinks.entries()) {
      if (link.userId === userId && link.provider === provider) {
        this.oauthLinks.delete(id);
      }
    }
  }

  // ─── MFA ────────────────────────────────────────────────────────────────

  async saveMFASecret(input: SaveMFAInput): Promise<MFASecret> {
    const now = new Date();
    const mfa: MFASecret = {
      id: randomUUID(),
      userId: input.userId,
      method: input.method,
      encryptedSecret: input.encryptedSecret,
      encryptedBackupCodes: [...input.encryptedBackupCodes],
      backupCodesUsed: [...input.backupCodesUsed],
      recoveryEmail: input.recoveryEmail ?? null,
      enabledAt: now,
      createdAt: now,
      updatedAt: now,
    };

    this.mfaSecrets.set(input.userId, mfa);
    return { ...mfa };
  }

  async getMFASecret(userId: string): Promise<MFASecret | null> {
    const mfa = this.mfaSecrets.get(userId);
    if (!mfa) return null;
    return { ...mfa, backupCodesUsed: [...mfa.backupCodesUsed], encryptedBackupCodes: [...mfa.encryptedBackupCodes] };
  }

  async deleteMFASecret(userId: string): Promise<void> {
    this.mfaSecrets.delete(userId);
  }

  async markBackupCodeUsed(userId: string, codeIndex: number): Promise<void> {
    const mfa = this.mfaSecrets.get(userId);
    if (!mfa) throw new Error(`MFA secret for user ${userId} not found`);
    mfa.backupCodesUsed[codeIndex] = true;
    mfa.updatedAt = new Date();
  }

  // ─── Password History ──────────────────────────────────────────────────

  async getPasswordHistory(userId: string, limit: number): Promise<string[]> {
    const history = this.passwordHistory.get(userId) ?? [];
    // Return most recent entries (end of array = most recent)
    return history.slice(-limit);
  }

  async addPasswordHistory(userId: string, hash: string): Promise<void> {
    const history = this.passwordHistory.get(userId) ?? [];
    history.push(hash);
    this.passwordHistory.set(userId, history);
  }

  // ─── Audit Log ─────────────────────────────────────────────────────────

  async writeAuditLog(entry: AuditLogEntry): Promise<void> {
    this.auditLog.push({ ...entry });
  }

  async queryAuditLog(filter: AuditLogFilter): Promise<{ entries: AuditLogEntry[]; total: number }> {
    let entries = [...this.auditLog];

    if (filter.userId !== undefined) {
      entries = entries.filter(e => e.userId === filter.userId);
    }
    if (filter.action !== undefined) {
      entries = entries.filter(e => e.action === filter.action);
    }
    if (filter.startDate !== undefined) {
      entries = entries.filter(e => e.createdAt >= filter.startDate!);
    }
    if (filter.endDate !== undefined) {
      entries = entries.filter(e => e.createdAt <= filter.endDate!);
    }
    if (filter.orgId !== undefined) {
      entries = entries.filter(e => e.orgId === filter.orgId);
    }

    const total = entries.length;
    const offset = filter.offset ?? 0;
    const limit = filter.limit ?? entries.length;
    entries = entries.slice(offset, offset + limit);

    return { entries, total };
  }

  // ─── Organizations ─────────────────────────────────────────────────────

  async createOrganization(input: CreateOrgInput): Promise<Organization> {
    const now = new Date();
    const defaultSettings = {
      enforceSSO: false,
      allowedAuthMethods: [],
      enforceMFA: false,
      allowedMFAMethods: [],
      sessionTimeout: 3600,
      maxSessionsPerUser: 5,
      ipAllowlist: [],
      passwordPolicy: {
        minLength: 8,
        requireMFA: false,
        maxAge: 90,
      },
    };

    const org: Organization = {
      id: randomUUID(),
      name: input.name,
      slug: input.slug,
      ownerId: input.ownerId,
      plan: input.plan ?? 'free',
      settings: input.settings ? { ...defaultSettings, ...input.settings } : defaultSettings,
      metadata: input.metadata ?? {},
      createdAt: now,
      updatedAt: now,
    };

    this.organizations.set(org.id, org);
    this.orgMembers.set(org.id, []);
    return { ...org };
  }

  async getOrganization(id: string): Promise<Organization | null> {
    const org = this.organizations.get(id);
    if (!org) return null;
    return { ...org };
  }

  async updateOrganization(id: string, updates: Partial<Organization>): Promise<Organization> {
    const org = this.organizations.get(id);
    if (!org) throw new Error(`Organization ${id} not found`);

    const updated: Organization = {
      ...org,
      ...updates,
      id: org.id,
      updatedAt: new Date(),
    };
    this.organizations.set(id, updated);
    return { ...updated };
  }

  async deleteOrganization(id: string): Promise<void> {
    this.organizations.delete(id);
    this.orgMembers.delete(id);
  }

  async listOrgMembers(orgId: string): Promise<OrgMember[]> {
    const members = this.orgMembers.get(orgId) ?? [];
    return members.map(m => ({ ...m }));
  }

  async addOrgMember(input: AddOrgMemberInput): Promise<OrgMember> {
    const member: OrgMember = {
      userId: input.userId,
      orgId: input.orgId,
      role: input.role,
      permissions: input.permissions ?? [],
      joinedAt: new Date(),
    };

    const members = this.orgMembers.get(input.orgId) ?? [];
    members.push(member);
    this.orgMembers.set(input.orgId, members);
    return { ...member };
  }

  async updateOrgMember(orgId: string, userId: string, updates: Partial<OrgMember>): Promise<OrgMember> {
    const members = this.orgMembers.get(orgId) ?? [];
    const idx = members.findIndex(m => m.userId === userId);
    if (idx === -1) throw new Error(`Member ${userId} not found in org ${orgId}`);

    members[idx] = { ...members[idx], ...updates, userId, orgId };
    return { ...members[idx] };
  }

  async removeOrgMember(orgId: string, userId: string): Promise<void> {
    const members = this.orgMembers.get(orgId) ?? [];
    const filtered = members.filter(m => m.userId !== userId);
    this.orgMembers.set(orgId, filtered);
  }

  // ─── Org Invites ───────────────────────────────────────────────────────

  async createOrgInvite(input: CreateOrgInviteInput): Promise<OrgInvite> {
    const now = new Date();
    const invite: OrgInvite = {
      id: randomUUID(),
      orgId: input.orgId,
      email: input.email,
      role: input.role,
      invitedBy: input.invitedBy,
      token: input.token,
      expiresAt: input.expiresAt,
      acceptedAt: null,
      createdAt: now,
    };

    this.orgInvites.set(invite.id, invite);
    return { ...invite };
  }

  async findOrgInviteByToken(token: string): Promise<OrgInvite | null> {
    for (const invite of this.orgInvites.values()) {
      if (invite.token === token) {
        return { ...invite };
      }
    }
    return null;
  }

  async acceptOrgInvite(id: string): Promise<void> {
    const invite = this.orgInvites.get(id);
    if (!invite) throw new Error(`Invite ${id} not found`);
    invite.acceptedAt = new Date();
  }

  async listPendingInvites(orgId: string): Promise<OrgInvite[]> {
    const result: OrgInvite[] = [];
    for (const invite of this.orgInvites.values()) {
      if (invite.orgId === orgId && invite.acceptedAt === null) {
        result.push({ ...invite });
      }
    }
    return result;
  }

  // ─── API Keys ──────────────────────────────────────────────────────────

  async createApiKey(input: CreateApiKeyInput): Promise<ApiKey> {
    const now = new Date();
    const key: ApiKey = {
      id: randomUUID(),
      name: input.name,
      keyPrefix: input.keyPrefix,
      keyHash: input.keyHash,
      userId: input.userId,
      orgId: input.orgId ?? null,
      permissions: [...input.permissions],
      rateLimit: input.rateLimit ?? null,
      ipAllowlist: input.ipAllowlist ?? [],
      expiresAt: input.expiresAt ?? null,
      lastUsedAt: null,
      createdAt: now,
      revokedAt: null,
    };

    this.apiKeys.set(key.id, key);
    return { ...key };
  }

  async findApiKeyByHash(hash: string): Promise<ApiKey | null> {
    for (const key of this.apiKeys.values()) {
      if (key.keyHash === hash) {
        return { ...key };
      }
    }
    return null;
  }

  async listApiKeys(userId: string): Promise<ApiKey[]> {
    const result: ApiKey[] = [];
    for (const key of this.apiKeys.values()) {
      if (key.userId === userId) {
        result.push({ ...key });
      }
    }
    return result;
  }

  async revokeApiKey(id: string): Promise<void> {
    const key = this.apiKeys.get(id);
    if (!key) throw new Error(`API key ${id} not found`);
    key.revokedAt = new Date();
  }

  async updateApiKeyLastUsed(id: string): Promise<void> {
    const key = this.apiKeys.get(id);
    if (!key) throw new Error(`API key ${id} not found`);
    key.lastUsedAt = new Date();
  }

  // ─── Roles & Permissions ──────────────────────────────────────────────

  async createRole(role: Role): Promise<Role> {
    const created: Role = { ...role };
    this.roles.set(role.name, created);
    return { ...created };
  }

  async getRole(name: string): Promise<Role | null> {
    const role = this.roles.get(name);
    if (!role) return null;
    return { ...role };
  }

  async listRoles(): Promise<Role[]> {
    return [...this.roles.values()].map(r => ({ ...r }));
  }

  async updateRole(name: string, updates: Partial<Role>): Promise<Role> {
    const role = this.roles.get(name);
    if (!role) throw new Error(`Role ${name} not found`);

    const updated: Role = { ...role, ...updates, name }; // prevent name override
    this.roles.set(name, updated);
    return { ...updated };
  }

  async deleteRole(name: string): Promise<void> {
    this.roles.delete(name);
  }

  // ─── Access Policies ──────────────────────────────────────────────────

  async createPolicy(policy: AccessPolicy): Promise<AccessPolicy> {
    const created: AccessPolicy = { ...policy };
    this.policies.set(policy.id, created);
    return { ...created };
  }

  async listPolicies(): Promise<AccessPolicy[]> {
    return [...this.policies.values()].map(p => ({ ...p }));
  }

  async deletePolicy(id: string): Promise<void> {
    this.policies.delete(id);
  }

  // ─── Webhooks ─────────────────────────────────────────────────────────

  async createWebhook(input: CreateWebhookInput): Promise<Webhook> {
    const now = new Date();
    const webhook: Webhook = {
      id: randomUUID(),
      url: input.url,
      events: [...input.events],
      secret: input.secret,
      orgId: input.orgId ?? null,
      active: true,
      failureCount: 0,
      lastTriggeredAt: null,
      createdAt: now,
    };

    this.webhooks.set(webhook.id, webhook);
    return { ...webhook };
  }

  async listWebhooks(orgId?: string): Promise<Webhook[]> {
    const result: Webhook[] = [];
    for (const webhook of this.webhooks.values()) {
      if (orgId === undefined || webhook.orgId === orgId) {
        result.push({ ...webhook });
      }
    }
    return result;
  }

  async updateWebhook(id: string, updates: Partial<Webhook>): Promise<Webhook> {
    const webhook = this.webhooks.get(id);
    if (!webhook) throw new Error(`Webhook ${id} not found`);

    const updated: Webhook = { ...webhook, ...updates, id };
    this.webhooks.set(id, updated);
    return { ...updated };
  }

  async deleteWebhook(id: string): Promise<void> {
    this.webhooks.delete(id);
  }

  async incrementWebhookFailure(id: string): Promise<void> {
    const webhook = this.webhooks.get(id);
    if (!webhook) throw new Error(`Webhook ${id} not found`);
    webhook.failureCount += 1;
  }

  async resetWebhookFailure(id: string): Promise<void> {
    const webhook = this.webhooks.get(id);
    if (!webhook) throw new Error(`Webhook ${id} not found`);
    webhook.failureCount = 0;
  }

  // ─── Trusted Devices ──────────────────────────────────────────────────

  async saveTrustedDevice(device: TrustedDevice): Promise<TrustedDevice> {
    const saved: TrustedDevice = { ...device };
    this.trustedDevices.set(device.id, saved);
    return { ...saved };
  }

  async getTrustedDevices(userId: string): Promise<TrustedDevice[]> {
    const result: TrustedDevice[] = [];
    for (const device of this.trustedDevices.values()) {
      if (device.userId === userId) {
        result.push({ ...device });
      }
    }
    return result;
  }

  async removeTrustedDevice(userId: string, deviceId: string): Promise<void> {
    const device = this.trustedDevices.get(deviceId);
    if (device && device.userId === userId) {
      this.trustedDevices.delete(deviceId);
    }
  }

  async isTrustedDevice(userId: string, fingerprint: string): Promise<boolean> {
    for (const device of this.trustedDevices.values()) {
      if (device.userId === userId && device.fingerprint === fingerprint) {
        return true;
      }
    }
    return false;
  }

  // ─── Admin ────────────────────────────────────────────────────────────

  async listUsers(filter: UserFilter): Promise<{ users: User[]; total: number }> {
    let users = [...this.users.values()].filter(u => u.deletedAt === null);

    if (filter.search !== undefined) {
      const search = filter.search.toLowerCase();
      users = users.filter(u =>
        u.email.toLowerCase().includes(search) ||
        u.displayName.toLowerCase().includes(search)
      );
    }

    if (filter.role !== undefined) {
      users = users.filter(u => u.roles.includes(filter.role!));
    }

    if (filter.emailVerified !== undefined) {
      users = users.filter(u => u.emailVerified === filter.emailVerified);
    }

    if (filter.mfaEnabled !== undefined) {
      users = users.filter(u => u.mfaEnabled === filter.mfaEnabled);
    }

    if (filter.locked !== undefined) {
      const now = new Date();
      if (filter.locked) {
        users = users.filter(u => u.lockedUntil !== null && u.lockedUntil > now);
      } else {
        users = users.filter(u => u.lockedUntil === null || u.lockedUntil <= now);
      }
    }

    if (filter.orgId !== undefined) {
      users = users.filter(u => u.orgId === filter.orgId);
    }

    const total = users.length;
    const offset = filter.offset ?? 0;
    const limit = filter.limit ?? users.length;
    users = users.slice(offset, offset + limit);

    return { users: users.map(u => ({ ...u })), total };
  }

  async getSystemStats(): Promise<SystemStats> {
    const now = new Date();
    const allUsers = [...this.users.values()].filter(u => u.deletedAt === null);
    const totalUsers = allUsers.length;
    const activeUsers = allUsers.filter(u => u.lastLoginAt !== null).length;
    const mfaUsers = allUsers.filter(u => u.mfaEnabled).length;
    const lockedAccounts = allUsers.filter(u => u.lockedUntil !== null && u.lockedUntil > now).length;

    const allSessions = [...this.sessions.values()];
    const totalSessions = allSessions.length;
    const activeSessions = allSessions.filter(s => s.revoked === false && s.expiresAt > now).length;

    return {
      totalUsers,
      activeUsers,
      totalSessions,
      activeSessions,
      mfaAdoptionRate: totalUsers > 0 ? mfaUsers / totalUsers : 0,
      lockedAccounts,
    };
  }

  async exportUserData(userId: string): Promise<UserDataExport> {
    const user = this.users.get(userId);

    // Gather sessions
    const sessions: Record<string, unknown>[] = [];
    for (const session of this.sessions.values()) {
      if (session.userId === userId) {
        sessions.push({ ...session } as unknown as Record<string, unknown>);
      }
    }

    // Gather OAuth providers
    const oauthProviders: Record<string, unknown>[] = [];
    for (const link of this.oauthLinks.values()) {
      if (link.userId === userId) {
        oauthProviders.push({ ...link } as unknown as Record<string, unknown>);
      }
    }

    // Gather audit log
    const auditLogEntries: Record<string, unknown>[] = [];
    for (const entry of this.auditLog) {
      if (entry.userId === userId) {
        auditLogEntries.push({ ...entry } as unknown as Record<string, unknown>);
      }
    }

    // Gather API keys
    const apiKeysList: Record<string, unknown>[] = [];
    for (const key of this.apiKeys.values()) {
      if (key.userId === userId) {
        apiKeysList.push({ ...key } as unknown as Record<string, unknown>);
      }
    }

    // Gather organizations
    const orgs: Record<string, unknown>[] = [];
    for (const [orgId, members] of this.orgMembers.entries()) {
      if (members.some(m => m.userId === userId)) {
        const org = this.organizations.get(orgId);
        if (org) {
          orgs.push({ ...org } as unknown as Record<string, unknown>);
        }
      }
    }

    return {
      user: (user ? { ...user } : {}) as Record<string, unknown>,
      sessions,
      oauthProviders,
      auditLog: auditLogEntries,
      apiKeys: apiKeysList,
      organizations: orgs,
    };
  }

  // Test helper: expire a refresh token by hash (mutates internal state)
  _expireRefreshTokenByHash(hash: string): void {
    for (const token of this.refreshTokens.values()) {
      if (token.tokenHash === hash) {
        token.expiresAt = new Date(Date.now() - 1000);
        return;
      }
    }
  }
}
