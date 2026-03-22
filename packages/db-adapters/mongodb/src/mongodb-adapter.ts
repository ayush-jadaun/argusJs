import { randomUUID } from 'node:crypto';
import { MongoClient, type Db, type Collection } from 'mongodb';
import type {
  DbAdapter,
  User, Session, RefreshToken, PasswordResetToken, EmailVerificationToken,
  OAuthLink, MFASecret, AuditLogEntry, Organization, OrgMember, OrgInvite,
  ApiKey, Role, AccessPolicy, Webhook, TrustedDevice,
  CreateUserInput, CreateSessionInput, CreateRefreshTokenInput, CreateResetTokenInput,
  CreateVerificationInput, LinkOAuthInput, SaveMFAInput, CreateOrgInput, AddOrgMemberInput,
  CreateOrgInviteInput, CreateApiKeyInput, CreateWebhookInput,
  AuditLogFilter, UserFilter, SystemStats, UserDataExport,
} from '@argus/core';

export interface MongoDbAdapterConfig {
  url: string;
  dbName?: string;
}

/**
 * Base document type for all collections. We store UUIDs as string _id
 * values instead of MongoDB ObjectIds.
 */
interface BaseDoc {
  _id: string;
  [key: string]: unknown;
}

// Helper: map MongoDB _id to entity id
function mapDoc<T extends { id: string }>(doc: BaseDoc | null): T | null {
  if (!doc) return null;
  const { _id, ...rest } = doc;
  return { id: _id as string, ...rest } as T;
}

function mapDocRequired<T extends { id: string }>(doc: BaseDoc | null, entityName: string): T {
  if (!doc) throw new Error(`${entityName} not found`);
  const { _id, ...rest } = doc;
  return { id: _id as string, ...rest } as T;
}

// Helper: convert entity to MongoDB document (id -> _id)
function toDoc(entity: Record<string, unknown>): BaseDoc {
  const { id, ...rest } = entity;
  return { _id: id as string, ...rest };
}

export class MongoDbAdapter implements DbAdapter {
  private client: MongoClient;
  private dbName: string;
  private db!: Db;

  // Collections — typed with BaseDoc so _id is string
  private users!: Collection<BaseDoc>;
  private sessions!: Collection<BaseDoc>;
  private refreshTokens!: Collection<BaseDoc>;
  private passwordResetTokens!: Collection<BaseDoc>;
  private emailVerificationTokens!: Collection<BaseDoc>;
  private oauthProviders!: Collection<BaseDoc>;
  private mfaSecrets!: Collection<BaseDoc>;
  private passwordHistoryColl!: Collection<BaseDoc>;
  private auditLogColl!: Collection<BaseDoc>;
  private organizations!: Collection<BaseDoc>;
  private orgMembers!: Collection<BaseDoc>;
  private orgInvites!: Collection<BaseDoc>;
  private apiKeys!: Collection<BaseDoc>;
  private roles!: Collection<BaseDoc>;
  private accessPolicies!: Collection<BaseDoc>;
  private webhooks!: Collection<BaseDoc>;
  private trustedDevices!: Collection<BaseDoc>;

  constructor(config: MongoDbAdapterConfig) {
    this.client = new MongoClient(config.url);
    this.dbName = config.dbName ?? 'argus';
  }

  // ─── Lifecycle ──────────────────────────────────────────────────────────

  async init(): Promise<void> {
    await this.client.connect();
    this.db = this.client.db(this.dbName);

    // Initialize collections
    this.users = this.db.collection<BaseDoc>('users');
    this.sessions = this.db.collection<BaseDoc>('sessions');
    this.refreshTokens = this.db.collection<BaseDoc>('refresh_tokens');
    this.passwordResetTokens = this.db.collection<BaseDoc>('password_reset_tokens');
    this.emailVerificationTokens = this.db.collection<BaseDoc>('email_verification_tokens');
    this.oauthProviders = this.db.collection<BaseDoc>('oauth_providers');
    this.mfaSecrets = this.db.collection<BaseDoc>('mfa_secrets');
    this.passwordHistoryColl = this.db.collection<BaseDoc>('password_history');
    this.auditLogColl = this.db.collection<BaseDoc>('audit_log');
    this.organizations = this.db.collection<BaseDoc>('organizations');
    this.orgMembers = this.db.collection<BaseDoc>('org_members');
    this.orgInvites = this.db.collection<BaseDoc>('org_invites');
    this.apiKeys = this.db.collection<BaseDoc>('api_keys');
    this.roles = this.db.collection<BaseDoc>('roles');
    this.accessPolicies = this.db.collection<BaseDoc>('access_policies');
    this.webhooks = this.db.collection<BaseDoc>('webhooks');
    this.trustedDevices = this.db.collection<BaseDoc>('trusted_devices');

    // Create indexes
    await Promise.all([
      this.users.createIndex({ email: 1 }, { unique: true, collation: { locale: 'en', strength: 2 } }),
      this.users.createIndex({ deletedAt: 1 }),

      this.sessions.createIndex({ userId: 1 }),
      this.sessions.createIndex({ expiresAt: 1 }),
      this.sessions.createIndex({ userId: 1, revoked: 1 }),

      this.refreshTokens.createIndex({ tokenHash: 1 }, { unique: true }),
      this.refreshTokens.createIndex({ family: 1 }),
      this.refreshTokens.createIndex({ userId: 1 }),

      this.passwordResetTokens.createIndex({ tokenHash: 1 }, { unique: true }),
      this.passwordResetTokens.createIndex({ userId: 1 }),

      this.emailVerificationTokens.createIndex({ tokenHash: 1 }, { unique: true }),

      this.oauthProviders.createIndex({ provider: 1, providerUserId: 1 }, { unique: true }),
      this.oauthProviders.createIndex({ userId: 1 }),

      this.mfaSecrets.createIndex({ userId: 1 }, { unique: true }),

      this.passwordHistoryColl.createIndex({ userId: 1 }),

      this.auditLogColl.createIndex({ userId: 1 }),
      this.auditLogColl.createIndex({ action: 1 }),
      this.auditLogColl.createIndex({ createdAt: 1 }),

      this.organizations.createIndex({ slug: 1 }, { unique: true }),

      this.orgMembers.createIndex({ orgId: 1, userId: 1 }),

      this.orgInvites.createIndex({ orgId: 1 }),
      this.orgInvites.createIndex({ token: 1 }, { unique: true }),

      this.apiKeys.createIndex({ keyHash: 1 }, { unique: true }),
      this.apiKeys.createIndex({ userId: 1 }),

      this.roles.createIndex({ name: 1 }, { unique: true }),

      this.webhooks.createIndex({ orgId: 1 }),

      this.trustedDevices.createIndex({ userId: 1, fingerprint: 1 }),
    ]);
  }

  async shutdown(): Promise<void> {
    await this.client.close();
  }

  /** Drop all documents from all collections (for testing). Not part of DbAdapter interface. */
  async truncateAll(): Promise<void> {
    const collections = await this.db.listCollections().toArray();
    await Promise.all(
      collections.map(c => this.db.collection(c.name).deleteMany({})),
    );
  }

  // ─── Users ──────────────────────────────────────────────────────────────

  async createUser(input: CreateUserInput): Promise<User> {
    const now = new Date();
    const id = randomUUID();
    const user: User = {
      id,
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

    try {
      await this.users.insertOne(toDoc(user as unknown as Record<string, unknown>));
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'code' in err && (err as { code: number }).code === 11000) {
        throw new Error(`User with email ${input.email} already exists`);
      }
      throw err;
    }

    return user;
  }

  async findUserByEmail(email: string): Promise<User | null> {
    const doc = await this.users.findOne({
      email: { $regex: new RegExp(`^${escapeRegex(email)}$`, 'i') },
      deletedAt: null,
    });
    return mapDoc<User>(doc);
  }

  async findUserById(id: string): Promise<User | null> {
    const doc = await this.users.findOne({ _id: id, deletedAt: null });
    return mapDoc<User>(doc);
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User> {
    const { id: _ignoreId, ...updateFields } = updates as Record<string, unknown>;
    (updateFields as Record<string, unknown>).updatedAt = new Date();

    const result = await this.users.findOneAndUpdate(
      { _id: id },
      { $set: updateFields },
      { returnDocument: 'after' },
    );

    return mapDocRequired<User>(result, `User ${id}`);
  }

  async softDeleteUser(id: string): Promise<void> {
    const now = new Date();
    const result = await this.users.updateOne(
      { _id: id },
      { $set: { deletedAt: now, updatedAt: now } },
    );
    if (result.matchedCount === 0) throw new Error(`User ${id} not found`);
  }

  // ─── Sessions ───────────────────────────────────────────────────────────

  async createSession(input: CreateSessionInput): Promise<Session> {
    const now = new Date();
    const id = randomUUID();
    const session: Session = {
      id,
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

    await this.sessions.insertOne(toDoc(session as unknown as Record<string, unknown>));
    return session;
  }

  async getSession(id: string): Promise<Session | null> {
    const doc = await this.sessions.findOne({ _id: id });
    return mapDoc<Session>(doc);
  }

  async getActiveSessions(userId: string): Promise<Session[]> {
    const now = new Date();
    const docs = await this.sessions.find({
      userId,
      revoked: false,
      expiresAt: { $gt: now },
    }).toArray();
    return docs.map(d => mapDoc<Session>(d)!);
  }

  async revokeSession(id: string, reason: string): Promise<void> {
    const result = await this.sessions.updateOne(
      { _id: id },
      { $set: { revoked: true, revokedAt: new Date(), revokedReason: reason } },
    );
    if (result.matchedCount === 0) throw new Error(`Session ${id} not found`);
  }

  async revokeAllSessions(userId: string, reason: string, excludeSessionId?: string): Promise<void> {
    const filter: Record<string, unknown> = { userId };
    if (excludeSessionId) {
      filter._id = { $ne: excludeSessionId };
    }
    await this.sessions.updateMany(filter, {
      $set: { revoked: true, revokedAt: new Date(), revokedReason: reason },
    });
  }

  async countActiveSessions(userId: string): Promise<number> {
    const now = new Date();
    return this.sessions.countDocuments({
      userId,
      revoked: false,
      expiresAt: { $gt: now },
    });
  }

  // ─── Refresh Tokens ────────────────────────────────────────────────────

  async createRefreshToken(input: CreateRefreshTokenInput): Promise<RefreshToken> {
    const now = new Date();
    const id = randomUUID();
    const token: RefreshToken = {
      id,
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

    await this.refreshTokens.insertOne(toDoc(token as unknown as Record<string, unknown>));
    return token;
  }

  async findRefreshTokenByHash(hash: string): Promise<RefreshToken | null> {
    const doc = await this.refreshTokens.findOne({ tokenHash: hash });
    return mapDoc<RefreshToken>(doc);
  }

  async revokeRefreshToken(id: string, reason: string): Promise<void> {
    const result = await this.refreshTokens.updateOne(
      { _id: id },
      { $set: { revoked: true, revokedAt: new Date(), revokedReason: reason } },
    );
    if (result.matchedCount === 0) throw new Error(`Refresh token ${id} not found`);
  }

  async revokeRefreshTokenIfActive(id: string, reason: string): Promise<boolean> {
    const result = await this.refreshTokens.findOneAndUpdate(
      { _id: id, revoked: false },
      { $set: { revoked: true, revokedAt: new Date(), revokedReason: reason } },
    );
    return result !== null;
  }

  async revokeTokenFamily(family: string, reason: string): Promise<void> {
    await this.refreshTokens.updateMany(
      { family },
      { $set: { revoked: true, revokedAt: new Date(), revokedReason: reason } },
    );
  }

  async revokeAllUserTokens(userId: string, reason: string): Promise<void> {
    await this.refreshTokens.updateMany(
      { userId },
      { $set: { revoked: true, revokedAt: new Date(), revokedReason: reason } },
    );
  }

  // ─── Password Reset ────────────────────────────────────────────────────

  async createPasswordResetToken(input: CreateResetTokenInput): Promise<PasswordResetToken> {
    const now = new Date();
    const id = randomUUID();
    const token: PasswordResetToken = {
      id,
      userId: input.userId,
      tokenHash: input.tokenHash,
      used: false,
      usedAt: null,
      requestedFromIp: input.requestedFromIp,
      requestedFromUa: input.requestedFromUa ?? null,
      expiresAt: input.expiresAt,
      createdAt: now,
    };

    await this.passwordResetTokens.insertOne(toDoc(token as unknown as Record<string, unknown>));
    return token;
  }

  async findPasswordResetByHash(hash: string): Promise<PasswordResetToken | null> {
    const doc = await this.passwordResetTokens.findOne({ tokenHash: hash });
    return mapDoc<PasswordResetToken>(doc);
  }

  async markResetTokenUsed(id: string): Promise<void> {
    const result = await this.passwordResetTokens.updateOne(
      { _id: id },
      { $set: { used: true, usedAt: new Date() } },
    );
    if (result.matchedCount === 0) throw new Error(`Reset token ${id} not found`);
  }

  async invalidateUserResetTokens(userId: string): Promise<void> {
    await this.passwordResetTokens.updateMany(
      { userId },
      { $set: { used: true, usedAt: new Date() } },
    );
  }

  // ─── Email Verification ────────────────────────────────────────────────

  async createEmailVerificationToken(input: CreateVerificationInput): Promise<EmailVerificationToken> {
    const now = new Date();
    const id = randomUUID();
    const token: EmailVerificationToken = {
      id,
      userId: input.userId,
      tokenHash: input.tokenHash,
      used: false,
      usedAt: null,
      expiresAt: input.expiresAt,
      createdAt: now,
    };

    await this.emailVerificationTokens.insertOne(toDoc(token as unknown as Record<string, unknown>));
    return token;
  }

  async findVerificationByHash(hash: string): Promise<EmailVerificationToken | null> {
    const doc = await this.emailVerificationTokens.findOne({ tokenHash: hash });
    return mapDoc<EmailVerificationToken>(doc);
  }

  async markVerificationUsed(id: string): Promise<void> {
    const result = await this.emailVerificationTokens.updateOne(
      { _id: id },
      { $set: { used: true, usedAt: new Date() } },
    );
    if (result.matchedCount === 0) throw new Error(`Verification token ${id} not found`);
  }

  // ─── OAuth ──────────────────────────────────────────────────────────────

  async linkOAuthProvider(input: LinkOAuthInput): Promise<OAuthLink> {
    const now = new Date();
    const id = randomUUID();
    const link: OAuthLink = {
      id,
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

    await this.oauthProviders.insertOne(toDoc(link as unknown as Record<string, unknown>));
    return link;
  }

  async findOAuthProvider(provider: string, providerUserId: string): Promise<OAuthLink | null> {
    const doc = await this.oauthProviders.findOne({ provider, providerUserId });
    return mapDoc<OAuthLink>(doc);
  }

  async getUserOAuthProviders(userId: string): Promise<OAuthLink[]> {
    const docs = await this.oauthProviders.find({ userId }).toArray();
    return docs.map(d => mapDoc<OAuthLink>(d)!);
  }

  async unlinkOAuthProvider(userId: string, provider: string): Promise<void> {
    await this.oauthProviders.deleteMany({ userId, provider });
  }

  // ─── MFA ────────────────────────────────────────────────────────────────

  async saveMFASecret(input: SaveMFAInput): Promise<MFASecret> {
    const now = new Date();
    const id = randomUUID();
    const mfa: MFASecret = {
      id,
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

    // Upsert: replace existing MFA secret for this user
    await this.mfaSecrets.replaceOne(
      { userId: input.userId },
      toDoc(mfa as unknown as Record<string, unknown>),
      { upsert: true },
    );

    return mfa;
  }

  async getMFASecret(userId: string): Promise<MFASecret | null> {
    const doc = await this.mfaSecrets.findOne({ userId });
    return mapDoc<MFASecret>(doc);
  }

  async deleteMFASecret(userId: string): Promise<void> {
    await this.mfaSecrets.deleteMany({ userId });
  }

  async markBackupCodeUsed(userId: string, codeIndex: number): Promise<void> {
    const result = await this.mfaSecrets.updateOne(
      { userId },
      { $set: { [`backupCodesUsed.${codeIndex}`]: true, updatedAt: new Date() } },
    );
    if (result.matchedCount === 0) throw new Error(`MFA secret for user ${userId} not found`);
  }

  // ─── Password History ──────────────────────────────────────────────────

  async getPasswordHistory(userId: string, limit: number): Promise<string[]> {
    const docs = await this.passwordHistoryColl
      .find({ userId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .toArray();
    return docs.map(d => d.hash as string);
  }

  async addPasswordHistory(userId: string, hash: string): Promise<void> {
    await this.passwordHistoryColl.insertOne({
      _id: randomUUID(),
      userId,
      hash,
      createdAt: new Date(),
    });
  }

  // ─── Audit Log ─────────────────────────────────────────────────────────

  async writeAuditLog(entry: AuditLogEntry): Promise<void> {
    await this.auditLogColl.insertOne(toDoc(entry as unknown as Record<string, unknown>));
  }

  async queryAuditLog(filter: AuditLogFilter): Promise<{ entries: AuditLogEntry[]; total: number }> {
    const query: Record<string, unknown> = {};

    if (filter.userId !== undefined) query.userId = filter.userId;
    if (filter.action !== undefined) query.action = filter.action;
    if (filter.orgId !== undefined) query.orgId = filter.orgId;
    if (filter.startDate !== undefined || filter.endDate !== undefined) {
      const createdAt: Record<string, unknown> = {};
      if (filter.startDate !== undefined) createdAt.$gte = filter.startDate;
      if (filter.endDate !== undefined) createdAt.$lte = filter.endDate;
      query.createdAt = createdAt;
    }

    const total = await this.auditLogColl.countDocuments(query);
    const offset = filter.offset ?? 0;
    const limit = filter.limit ?? 100;

    const docs = await this.auditLogColl
      .find(query)
      .sort({ createdAt: -1 })
      .skip(offset)
      .limit(limit)
      .toArray();

    return {
      entries: docs.map(d => mapDoc<AuditLogEntry>(d)!),
      total,
    };
  }

  // ─── Organizations ─────────────────────────────────────────────────────

  async createOrganization(input: CreateOrgInput): Promise<Organization> {
    const now = new Date();
    const id = randomUUID();
    const defaultSettings = {
      enforceSSO: false,
      allowedAuthMethods: [] as string[],
      enforceMFA: false,
      allowedMFAMethods: [] as string[],
      sessionTimeout: 3600,
      maxSessionsPerUser: 5,
      ipAllowlist: [] as string[],
      passwordPolicy: {
        minLength: 8,
        requireMFA: false,
        maxAge: 90,
      },
    };

    const org: Organization = {
      id,
      name: input.name,
      slug: input.slug,
      ownerId: input.ownerId,
      plan: input.plan ?? 'free',
      settings: input.settings ? { ...defaultSettings, ...input.settings } : defaultSettings,
      metadata: input.metadata ?? {},
      createdAt: now,
      updatedAt: now,
    };

    await this.organizations.insertOne(toDoc(org as unknown as Record<string, unknown>));
    return org;
  }

  async getOrganization(id: string): Promise<Organization | null> {
    const doc = await this.organizations.findOne({ _id: id });
    return mapDoc<Organization>(doc);
  }

  async updateOrganization(id: string, updates: Partial<Organization>): Promise<Organization> {
    const { id: _ignoreId, ...updateFields } = updates as Record<string, unknown>;
    (updateFields as Record<string, unknown>).updatedAt = new Date();

    const result = await this.organizations.findOneAndUpdate(
      { _id: id },
      { $set: updateFields },
      { returnDocument: 'after' },
    );

    return mapDocRequired<Organization>(result, `Organization ${id}`);
  }

  async deleteOrganization(id: string): Promise<void> {
    await this.organizations.deleteOne({ _id: id });
    await this.orgMembers.deleteMany({ orgId: id });
  }

  async listOrgMembers(orgId: string): Promise<OrgMember[]> {
    const docs = await this.orgMembers.find({ orgId }).toArray();
    return docs.map(d => {
      const { _id, ...rest } = d;
      return rest as unknown as OrgMember;
    });
  }

  async addOrgMember(input: AddOrgMemberInput): Promise<OrgMember> {
    const member: OrgMember = {
      userId: input.userId,
      orgId: input.orgId,
      role: input.role,
      permissions: input.permissions ?? [],
      joinedAt: new Date(),
    };

    await this.orgMembers.insertOne({
      _id: randomUUID(),
      ...member,
    } as BaseDoc);

    return member;
  }

  async updateOrgMember(orgId: string, userId: string, updates: Partial<OrgMember>): Promise<OrgMember> {
    const { userId: _u, orgId: _o, ...updateFields } = updates as Record<string, unknown>;

    const result = await this.orgMembers.findOneAndUpdate(
      { orgId, userId },
      { $set: updateFields },
      { returnDocument: 'after' },
    );

    if (!result) throw new Error(`Member ${userId} not found in org ${orgId}`);
    const { _id, ...rest } = result;
    return rest as unknown as OrgMember;
  }

  async removeOrgMember(orgId: string, userId: string): Promise<void> {
    await this.orgMembers.deleteMany({ orgId, userId });
  }

  // ─── Org Invites ───────────────────────────────────────────────────────

  async createOrgInvite(input: CreateOrgInviteInput): Promise<OrgInvite> {
    const now = new Date();
    const id = randomUUID();
    const invite: OrgInvite = {
      id,
      orgId: input.orgId,
      email: input.email,
      role: input.role,
      invitedBy: input.invitedBy,
      token: input.token,
      expiresAt: input.expiresAt,
      acceptedAt: null,
      createdAt: now,
    };

    await this.orgInvites.insertOne(toDoc(invite as unknown as Record<string, unknown>));
    return invite;
  }

  async findOrgInviteByToken(token: string): Promise<OrgInvite | null> {
    const doc = await this.orgInvites.findOne({ token });
    return mapDoc<OrgInvite>(doc);
  }

  async acceptOrgInvite(id: string): Promise<void> {
    const result = await this.orgInvites.updateOne(
      { _id: id },
      { $set: { acceptedAt: new Date() } },
    );
    if (result.matchedCount === 0) throw new Error(`Invite ${id} not found`);
  }

  async listPendingInvites(orgId: string): Promise<OrgInvite[]> {
    const docs = await this.orgInvites.find({ orgId, acceptedAt: null }).toArray();
    return docs.map(d => mapDoc<OrgInvite>(d)!);
  }

  // ─── API Keys ──────────────────────────────────────────────────────────

  async createApiKey(input: CreateApiKeyInput): Promise<ApiKey> {
    const now = new Date();
    const id = randomUUID();
    const key: ApiKey = {
      id,
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

    await this.apiKeys.insertOne(toDoc(key as unknown as Record<string, unknown>));
    return key;
  }

  async findApiKeyByHash(hash: string): Promise<ApiKey | null> {
    const doc = await this.apiKeys.findOne({ keyHash: hash });
    return mapDoc<ApiKey>(doc);
  }

  async listApiKeys(userId: string): Promise<ApiKey[]> {
    const docs = await this.apiKeys.find({ userId }).toArray();
    return docs.map(d => mapDoc<ApiKey>(d)!);
  }

  async revokeApiKey(id: string): Promise<void> {
    const result = await this.apiKeys.updateOne(
      { _id: id },
      { $set: { revokedAt: new Date() } },
    );
    if (result.matchedCount === 0) throw new Error(`API key ${id} not found`);
  }

  async updateApiKeyLastUsed(id: string): Promise<void> {
    const result = await this.apiKeys.updateOne(
      { _id: id },
      { $set: { lastUsedAt: new Date() } },
    );
    if (result.matchedCount === 0) throw new Error(`API key ${id} not found`);
  }

  // ─── Roles & Permissions ──────────────────────────────────────────────

  async createRole(role: Role): Promise<Role> {
    await this.roles.insertOne({ _id: role.name, ...role } as BaseDoc);
    return { ...role };
  }

  async getRole(name: string): Promise<Role | null> {
    const doc = await this.roles.findOne({ _id: name });
    if (!doc) return null;
    const { _id, ...rest } = doc;
    return rest as unknown as Role;
  }

  async listRoles(): Promise<Role[]> {
    const docs = await this.roles.find().toArray();
    return docs.map(d => {
      const { _id, ...rest } = d;
      return rest as unknown as Role;
    });
  }

  async updateRole(name: string, updates: Partial<Role>): Promise<Role> {
    const { name: _n, ...updateFields } = updates as Record<string, unknown>;

    const result = await this.roles.findOneAndUpdate(
      { _id: name },
      { $set: updateFields },
      { returnDocument: 'after' },
    );

    if (!result) throw new Error(`Role ${name} not found`);
    const { _id, ...rest } = result;
    return rest as unknown as Role;
  }

  async deleteRole(name: string): Promise<void> {
    await this.roles.deleteOne({ _id: name });
  }

  // ─── Access Policies ──────────────────────────────────────────────────

  async createPolicy(policy: AccessPolicy): Promise<AccessPolicy> {
    await this.accessPolicies.insertOne(toDoc(policy as unknown as Record<string, unknown>));
    return { ...policy };
  }

  async listPolicies(): Promise<AccessPolicy[]> {
    const docs = await this.accessPolicies.find().toArray();
    return docs.map(d => mapDoc<AccessPolicy>(d)!);
  }

  async deletePolicy(id: string): Promise<void> {
    await this.accessPolicies.deleteOne({ _id: id });
  }

  // ─── Webhooks ─────────────────────────────────────────────────────────

  async createWebhook(input: CreateWebhookInput): Promise<Webhook> {
    const now = new Date();
    const id = randomUUID();
    const webhook: Webhook = {
      id,
      url: input.url,
      events: [...input.events],
      secret: input.secret,
      orgId: input.orgId ?? null,
      active: true,
      failureCount: 0,
      lastTriggeredAt: null,
      createdAt: now,
    };

    await this.webhooks.insertOne(toDoc(webhook as unknown as Record<string, unknown>));
    return webhook;
  }

  async listWebhooks(orgId?: string): Promise<Webhook[]> {
    const query: Record<string, unknown> = {};
    if (orgId !== undefined) query.orgId = orgId;

    const docs = await this.webhooks.find(query).toArray();
    return docs.map(d => mapDoc<Webhook>(d)!);
  }

  async updateWebhook(id: string, updates: Partial<Webhook>): Promise<Webhook> {
    const { id: _ignoreId, ...updateFields } = updates as Record<string, unknown>;

    const result = await this.webhooks.findOneAndUpdate(
      { _id: id },
      { $set: updateFields },
      { returnDocument: 'after' },
    );

    return mapDocRequired<Webhook>(result, `Webhook ${id}`);
  }

  async deleteWebhook(id: string): Promise<void> {
    await this.webhooks.deleteOne({ _id: id });
  }

  async incrementWebhookFailure(id: string): Promise<void> {
    const result = await this.webhooks.updateOne(
      { _id: id },
      { $inc: { failureCount: 1 } } as unknown as Record<string, unknown>,
    );
    if (result.matchedCount === 0) throw new Error(`Webhook ${id} not found`);
  }

  async resetWebhookFailure(id: string): Promise<void> {
    const result = await this.webhooks.updateOne(
      { _id: id },
      { $set: { failureCount: 0 } },
    );
    if (result.matchedCount === 0) throw new Error(`Webhook ${id} not found`);
  }

  // ─── Trusted Devices ──────────────────────────────────────────────────

  async saveTrustedDevice(device: TrustedDevice): Promise<TrustedDevice> {
    const saved = { ...device };
    await this.trustedDevices.replaceOne(
      { _id: device.id },
      toDoc(saved as unknown as Record<string, unknown>),
      { upsert: true },
    );
    return saved;
  }

  async getTrustedDevices(userId: string): Promise<TrustedDevice[]> {
    const docs = await this.trustedDevices.find({ userId }).toArray();
    return docs.map(d => mapDoc<TrustedDevice>(d)!);
  }

  async removeTrustedDevice(userId: string, deviceId: string): Promise<void> {
    await this.trustedDevices.deleteOne({ _id: deviceId, userId });
  }

  async isTrustedDevice(userId: string, fingerprint: string): Promise<boolean> {
    const count = await this.trustedDevices.countDocuments({ userId, fingerprint });
    return count > 0;
  }

  // ─── Admin ────────────────────────────────────────────────────────────

  async listUsers(filter: UserFilter): Promise<{ users: User[]; total: number }> {
    const query: Record<string, unknown> = { deletedAt: null };

    if (filter.search !== undefined) {
      const searchRegex = new RegExp(escapeRegex(filter.search), 'i');
      query.$or = [
        { email: { $regex: searchRegex } },
        { displayName: { $regex: searchRegex } },
      ];
    }

    if (filter.role !== undefined) {
      query.roles = filter.role;
    }

    if (filter.emailVerified !== undefined) {
      query.emailVerified = filter.emailVerified;
    }

    if (filter.mfaEnabled !== undefined) {
      query.mfaEnabled = filter.mfaEnabled;
    }

    if (filter.locked !== undefined) {
      const now = new Date();
      if (filter.locked) {
        query.lockedUntil = { $ne: null, $gt: now };
      } else {
        const existing = (query.$and ?? []) as Record<string, unknown>[];
        existing.push({ $or: [{ lockedUntil: null }, { lockedUntil: { $lte: now } }] });
        query.$and = existing;
      }
    }

    if (filter.orgId !== undefined) {
      query.orgId = filter.orgId;
    }

    const total = await this.users.countDocuments(query);
    const offset = filter.offset ?? 0;
    const limit = filter.limit ?? 100;

    const docs = await this.users
      .find(query)
      .skip(offset)
      .limit(limit)
      .toArray();

    return {
      users: docs.map(d => mapDoc<User>(d)!),
      total,
    };
  }

  async getSystemStats(): Promise<SystemStats> {
    const now = new Date();

    const totalUsers = await this.users.countDocuments({ deletedAt: null });
    const activeUsers = await this.users.countDocuments({ deletedAt: null, lastLoginAt: { $ne: null } });
    const mfaUsers = await this.users.countDocuments({ deletedAt: null, mfaEnabled: true });
    const lockedAccounts = await this.users.countDocuments({
      deletedAt: null,
      lockedUntil: { $ne: null, $gt: now },
    });

    const totalSessions = await this.sessions.countDocuments({});
    const activeSessions = await this.sessions.countDocuments({
      revoked: false,
      expiresAt: { $gt: now },
    });

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
    const userDoc = await this.users.findOne({ _id: userId });
    const user = userDoc ? (mapDoc<User>(userDoc) as unknown as Record<string, unknown>) : {};

    const sessionDocs = await this.sessions.find({ userId }).toArray();
    const sessions = sessionDocs.map(d => mapDoc<Session>(d) as unknown as Record<string, unknown>);

    const oauthDocs = await this.oauthProviders.find({ userId }).toArray();
    const oauthProvidersList = oauthDocs.map(d => mapDoc<OAuthLink>(d) as unknown as Record<string, unknown>);

    const auditDocs = await this.auditLogColl.find({ userId }).toArray();
    const auditLogEntries = auditDocs.map(d => mapDoc<AuditLogEntry>(d) as unknown as Record<string, unknown>);

    const apiKeyDocs = await this.apiKeys.find({ userId }).toArray();
    const apiKeysList = apiKeyDocs.map(d => mapDoc<ApiKey>(d) as unknown as Record<string, unknown>);

    // Find orgs where user is a member
    const memberDocs = await this.orgMembers.find({ userId }).toArray();
    const orgIds = memberDocs.map(d => d.orgId as string);
    const orgDocs = orgIds.length > 0
      ? await this.organizations.find({ _id: { $in: orgIds } }).toArray()
      : [];
    const orgs = orgDocs.map(d => mapDoc<Organization>(d) as unknown as Record<string, unknown>);

    return {
      user,
      sessions,
      oauthProviders: oauthProvidersList,
      auditLog: auditLogEntries,
      apiKeys: apiKeysList,
      organizations: orgs,
    };
  }
}

/** Escape special regex characters in a string */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
