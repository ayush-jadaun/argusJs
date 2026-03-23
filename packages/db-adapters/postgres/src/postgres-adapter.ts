import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import { sql, eq, and, or, ilike, isNull, gte, lte, desc, count as countFn } from 'drizzle-orm';
import type { PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import type {
  DbAdapter,
  User, Session, RefreshToken, PasswordResetToken, EmailVerificationToken,
  OAuthLink, MFASecret, AuditLogEntry, Organization, OrgMember, OrgInvite,
  ApiKey, Role, AccessPolicy, Webhook, TrustedDevice, OrgSettings,
  CreateUserInput, CreateSessionInput, CreateRefreshTokenInput, CreateResetTokenInput,
  CreateVerificationInput, LinkOAuthInput, SaveMFAInput, CreateOrgInput, AddOrgMemberInput,
  CreateOrgInviteInput, CreateApiKeyInput, CreateWebhookInput,
  AuditLogFilter, UserFilter, SystemStats, UserDataExport,
} from '@argusjs/core';

import * as schema from './schema/index.js';

export interface PostgresAdapterConfig {
  connectionString?: string;
  host?: string;
  port?: number;
  database?: string;
  user?: string;
  password?: string;
  /** Maximum number of connections in the pool (default: 10) */
  max?: number;
  /** Seconds before an idle connection is closed (default: 30) */
  idleTimeout?: number;
  /** Seconds to wait for a new connection (default: 10) */
  connectTimeout?: number;
}

export class PostgresAdapter implements DbAdapter {
  private client!: postgres.Sql;
  private db!: PostgresJsDatabase<typeof schema>;
  private config: PostgresAdapterConfig;

  constructor(config: PostgresAdapterConfig) {
    this.config = config;
  }

  async init(): Promise<void> {
    // NOTE: Prepared statements — Drizzle ORM with postgres.js automatically uses
    // prepared statements for all parameterized queries (tagged template literals).
    // The postgres.js driver sends Parse/Bind/Execute at the protocol level, so
    // repeated queries reuse the server-side prepared plan. There is no additional
    // `prepare` option needed; this is the default behavior.
    // See: https://github.com/porsager/postgres#tagged-template-queries
    const poolOptions = {
      max: this.config.max ?? 10,
      idle_timeout: this.config.idleTimeout ?? 30,
      connect_timeout: this.config.connectTimeout ?? 10,
      // prepare: true is implicit — postgres.js prepares all tagged template queries
    };

    if (this.config.connectionString) {
      this.client = postgres(this.config.connectionString, poolOptions);
    } else {
      this.client = postgres({
        host: this.config.host ?? 'localhost',
        port: this.config.port ?? 5432,
        database: this.config.database ?? 'postgres',
        user: this.config.user ?? 'postgres',
        password: this.config.password ?? 'postgres',
        ...poolOptions,
      });
    }

    this.db = drizzle(this.client, { schema });

    // Create schema and tables using raw SQL
    await this.createSchemaAndTables();
  }

  async shutdown(): Promise<void> {
    await this.client.end();
  }

  async truncateAll(): Promise<void> {
    await this.db.execute(sql`
      TRUNCATE TABLE
        auth.trusted_devices,
        auth.webhooks,
        auth.access_policies,
        auth.roles,
        auth.api_keys,
        auth.org_invites,
        auth.org_members,
        auth.organizations,
        auth.audit_log,
        auth.password_history,
        auth.mfa_secrets,
        auth.oauth_providers,
        auth.email_verification_tokens,
        auth.password_reset_tokens,
        auth.refresh_tokens,
        auth.sessions,
        auth.rate_limit_overrides,
        auth.users
      CASCADE
    `);
  }

  private async createSchemaAndTables(): Promise<void> {
    await this.db.execute(sql`CREATE SCHEMA IF NOT EXISTS auth`);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255),
        display_name VARCHAR(100) NOT NULL,
        avatar_url VARCHAR(2048),
        email_verified BOOLEAN NOT NULL DEFAULT false,
        mfa_enabled BOOLEAN NOT NULL DEFAULT false,
        mfa_methods TEXT[] NOT NULL DEFAULT '{}',
        roles TEXT[] NOT NULL DEFAULT '{}',
        permissions TEXT[] NOT NULL DEFAULT '{}',
        org_id UUID,
        org_role VARCHAR(50),
        failed_login_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TIMESTAMPTZ,
        last_login_at TIMESTAMPTZ,
        last_login_ip VARCHAR(45),
        email_verified_at TIMESTAMPTZ,
        metadata JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at TIMESTAMPTZ
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent VARCHAR(512) NOT NULL,
        device_fingerprint VARCHAR(255),
        last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT false,
        revoked_at TIMESTAMPTZ,
        revoked_reason VARCHAR(255),
        org_id UUID,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.refresh_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        session_id UUID NOT NULL,
        token_hash VARCHAR(255) NOT NULL UNIQUE,
        family VARCHAR(255) NOT NULL,
        generation INTEGER NOT NULL DEFAULT 0,
        revoked BOOLEAN NOT NULL DEFAULT false,
        revoked_at TIMESTAMPTZ,
        revoked_reason VARCHAR(255),
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.password_reset_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        token_hash VARCHAR(255) NOT NULL UNIQUE,
        used BOOLEAN NOT NULL DEFAULT false,
        used_at TIMESTAMPTZ,
        requested_from_ip VARCHAR(45) NOT NULL,
        requested_from_ua VARCHAR(512),
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.email_verification_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        token_hash VARCHAR(255) NOT NULL UNIQUE,
        used BOOLEAN NOT NULL DEFAULT false,
        used_at TIMESTAMPTZ,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.oauth_providers (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        provider VARCHAR(50) NOT NULL,
        provider_user_id VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        display_name VARCHAR(100),
        avatar_url VARCHAR(2048),
        raw_profile JSONB NOT NULL DEFAULT '{}',
        access_token VARCHAR(2048),
        refresh_token VARCHAR(2048),
        token_expires_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.mfa_secrets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL UNIQUE,
        method VARCHAR(50) NOT NULL,
        encrypted_secret VARCHAR(1024) NOT NULL,
        encrypted_backup_codes TEXT[] NOT NULL DEFAULT '{}',
        backup_codes_used BOOLEAN[] NOT NULL DEFAULT '{}',
        recovery_email VARCHAR(255),
        enabled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.password_history (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.audit_log (
        id VARCHAR(255) PRIMARY KEY,
        user_id UUID,
        action VARCHAR(100) NOT NULL,
        ip_address VARCHAR(45),
        user_agent VARCHAR(512),
        metadata JSONB NOT NULL DEFAULT '{}',
        org_id UUID,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.organizations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        slug VARCHAR(255) NOT NULL UNIQUE,
        owner_id UUID NOT NULL,
        plan VARCHAR(50) NOT NULL DEFAULT 'free',
        settings JSONB NOT NULL DEFAULT '{}',
        metadata JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.org_members (
        user_id UUID NOT NULL,
        org_id UUID NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'member',
        permissions TEXT[] NOT NULL DEFAULT '{}',
        joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (user_id, org_id)
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.org_invites (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        org_id UUID NOT NULL,
        email VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        invited_by UUID NOT NULL,
        token VARCHAR(512) NOT NULL UNIQUE,
        expires_at TIMESTAMPTZ NOT NULL,
        accepted_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.api_keys (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        key_prefix VARCHAR(20) NOT NULL,
        key_hash VARCHAR(255) NOT NULL UNIQUE,
        user_id UUID NOT NULL,
        org_id UUID,
        permissions TEXT[] NOT NULL DEFAULT '{}',
        rate_limit JSONB,
        ip_allowlist TEXT[] NOT NULL DEFAULT '{}',
        expires_at TIMESTAMPTZ,
        last_used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        revoked_at TIMESTAMPTZ
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.roles (
        name VARCHAR(100) PRIMARY KEY,
        description VARCHAR(500) NOT NULL DEFAULT '',
        permissions TEXT[] NOT NULL DEFAULT '{}',
        inherits TEXT[] NOT NULL DEFAULT '{}',
        is_system BOOLEAN NOT NULL DEFAULT false
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.access_policies (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        effect VARCHAR(10) NOT NULL,
        actions TEXT[] NOT NULL DEFAULT '{}',
        conditions JSONB NOT NULL DEFAULT '[]'
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.webhooks (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        url VARCHAR(2048) NOT NULL,
        events TEXT[] NOT NULL DEFAULT '{}',
        secret VARCHAR(512) NOT NULL,
        org_id UUID,
        active BOOLEAN NOT NULL DEFAULT true,
        failure_count INTEGER NOT NULL DEFAULT 0,
        last_triggered_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.trusted_devices (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        fingerprint VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        browser VARCHAR(100) NOT NULL,
        os VARCHAR(100) NOT NULL,
        last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_ip VARCHAR(45) NOT NULL,
        trusted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth.rate_limit_overrides (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        key VARCHAR(255) NOT NULL UNIQUE,
        max_requests INTEGER NOT NULL,
        window_seconds INTEGER NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
  }

  // ─── Helpers ────────────────────────────────────────────────────────────

  private mapUser(row: typeof schema.users.$inferSelect): User {
    return {
      id: row.id,
      email: row.email,
      passwordHash: row.passwordHash ?? null,
      displayName: row.displayName,
      avatarUrl: row.avatarUrl ?? null,
      emailVerified: row.emailVerified,
      mfaEnabled: row.mfaEnabled,
      mfaMethods: row.mfaMethods ?? [],
      roles: row.roles ?? [],
      permissions: row.permissions ?? [],
      orgId: row.orgId ?? null,
      orgRole: row.orgRole ?? null,
      failedLoginAttempts: row.failedLoginAttempts,
      lockedUntil: row.lockedUntil ?? null,
      lastLoginAt: row.lastLoginAt ?? null,
      lastLoginIp: row.lastLoginIp ?? null,
      emailVerifiedAt: row.emailVerifiedAt ?? null,
      metadata: (row.metadata ?? {}) as Record<string, unknown>,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      deletedAt: row.deletedAt ?? null,
    };
  }

  private mapSession(row: typeof schema.sessions.$inferSelect): Session {
    return {
      id: row.id,
      userId: row.userId,
      ipAddress: row.ipAddress,
      userAgent: row.userAgent,
      deviceFingerprint: row.deviceFingerprint ?? null,
      lastActivityAt: row.lastActivityAt,
      expiresAt: row.expiresAt,
      revoked: row.revoked,
      revokedAt: row.revokedAt ?? null,
      revokedReason: row.revokedReason ?? null,
      orgId: row.orgId ?? null,
      createdAt: row.createdAt,
    };
  }

  private mapRefreshToken(row: typeof schema.refreshTokens.$inferSelect): RefreshToken {
    return {
      id: row.id,
      userId: row.userId,
      sessionId: row.sessionId,
      tokenHash: row.tokenHash,
      family: row.family,
      generation: row.generation,
      revoked: row.revoked,
      revokedAt: row.revokedAt ?? null,
      revokedReason: row.revokedReason ?? null,
      expiresAt: row.expiresAt,
      createdAt: row.createdAt,
    };
  }

  private mapPasswordResetToken(row: typeof schema.passwordResetTokens.$inferSelect): PasswordResetToken {
    return {
      id: row.id,
      userId: row.userId,
      tokenHash: row.tokenHash,
      used: row.used,
      usedAt: row.usedAt ?? null,
      requestedFromIp: row.requestedFromIp,
      requestedFromUa: row.requestedFromUa ?? null,
      expiresAt: row.expiresAt,
      createdAt: row.createdAt,
    };
  }

  private mapEmailVerificationToken(row: typeof schema.emailVerificationTokens.$inferSelect): EmailVerificationToken {
    return {
      id: row.id,
      userId: row.userId,
      tokenHash: row.tokenHash,
      used: row.used,
      usedAt: row.usedAt ?? null,
      expiresAt: row.expiresAt,
      createdAt: row.createdAt,
    };
  }

  private mapOAuthLink(row: typeof schema.oauthProviders.$inferSelect): OAuthLink {
    return {
      id: row.id,
      userId: row.userId,
      provider: row.provider,
      providerUserId: row.providerUserId,
      email: row.email ?? null,
      displayName: row.displayName ?? null,
      avatarUrl: row.avatarUrl ?? null,
      rawProfile: (row.rawProfile ?? {}) as Record<string, unknown>,
      accessToken: row.accessToken ?? null,
      refreshToken: row.refreshToken ?? null,
      tokenExpiresAt: row.tokenExpiresAt ?? null,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  private mapMFASecret(row: typeof schema.mfaSecrets.$inferSelect): MFASecret {
    return {
      id: row.id,
      userId: row.userId,
      method: row.method,
      encryptedSecret: row.encryptedSecret,
      encryptedBackupCodes: row.encryptedBackupCodes ?? [],
      backupCodesUsed: row.backupCodesUsed ?? [],
      recoveryEmail: row.recoveryEmail ?? null,
      enabledAt: row.enabledAt,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  private mapAuditLogEntry(row: typeof schema.auditLog.$inferSelect): AuditLogEntry {
    return {
      id: row.id,
      userId: row.userId ?? null,
      action: row.action as AuditLogEntry['action'],
      ipAddress: row.ipAddress ?? null,
      userAgent: row.userAgent ?? null,
      metadata: (row.metadata ?? {}) as Record<string, unknown>,
      orgId: row.orgId ?? null,
      createdAt: row.createdAt,
    };
  }

  private mapOrganization(row: typeof schema.organizations.$inferSelect): Organization {
    const defaultSettings: OrgSettings = {
      enforceSSO: false,
      allowedAuthMethods: [],
      enforceMFA: false,
      allowedMFAMethods: [],
      sessionTimeout: 3600,
      maxSessionsPerUser: 5,
      ipAllowlist: [],
      passwordPolicy: { minLength: 8, requireMFA: false, maxAge: 90 },
    };
    return {
      id: row.id,
      name: row.name,
      slug: row.slug,
      ownerId: row.ownerId,
      plan: row.plan,
      settings: { ...defaultSettings, ...(row.settings as Partial<OrgSettings>) },
      metadata: (row.metadata ?? {}) as Record<string, unknown>,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  private mapOrgMember(row: typeof schema.orgMembers.$inferSelect): OrgMember {
    return {
      userId: row.userId,
      orgId: row.orgId,
      role: row.role as OrgMember['role'],
      permissions: row.permissions ?? [],
      joinedAt: row.joinedAt,
    };
  }

  private mapOrgInvite(row: typeof schema.orgInvites.$inferSelect): OrgInvite {
    return {
      id: row.id,
      orgId: row.orgId,
      email: row.email,
      role: row.role,
      invitedBy: row.invitedBy,
      token: row.token,
      expiresAt: row.expiresAt,
      acceptedAt: row.acceptedAt ?? null,
      createdAt: row.createdAt,
    };
  }

  private mapApiKey(row: typeof schema.apiKeys.$inferSelect): ApiKey {
    return {
      id: row.id,
      name: row.name,
      keyPrefix: row.keyPrefix,
      keyHash: row.keyHash,
      userId: row.userId,
      orgId: row.orgId ?? null,
      permissions: row.permissions ?? [],
      rateLimit: (row.rateLimit as { max: number; windowSeconds: number }) ?? null,
      ipAllowlist: row.ipAllowlist ?? [],
      expiresAt: row.expiresAt ?? null,
      lastUsedAt: row.lastUsedAt ?? null,
      createdAt: row.createdAt,
      revokedAt: row.revokedAt ?? null,
    };
  }

  private mapRole(row: typeof schema.roles.$inferSelect): Role {
    return {
      name: row.name,
      description: row.description,
      permissions: row.permissions ?? [],
      inherits: row.inherits ?? [],
      isSystem: row.isSystem,
    };
  }

  private mapAccessPolicy(row: typeof schema.accessPolicies.$inferSelect): AccessPolicy {
    return {
      id: row.id,
      name: row.name,
      effect: row.effect as AccessPolicy['effect'],
      actions: row.actions ?? [],
      conditions: (row.conditions ?? []) as AccessPolicy['conditions'],
    };
  }

  private mapWebhook(row: typeof schema.webhooks.$inferSelect): Webhook {
    return {
      id: row.id,
      url: row.url,
      events: row.events ?? [],
      secret: row.secret,
      orgId: row.orgId ?? null,
      active: row.active,
      failureCount: row.failureCount,
      lastTriggeredAt: row.lastTriggeredAt ?? null,
      createdAt: row.createdAt,
    };
  }

  private mapTrustedDevice(row: typeof schema.trustedDevices.$inferSelect): TrustedDevice {
    return {
      id: row.id,
      userId: row.userId,
      fingerprint: row.fingerprint,
      name: row.name,
      browser: row.browser,
      os: row.os,
      lastUsedAt: row.lastUsedAt,
      lastIp: row.lastIp,
      trustedAt: row.trustedAt,
    };
  }

  // ─── Users ──────────────────────────────────────────────────────────────

  async createUser(input: CreateUserInput): Promise<User> {
    const now = new Date();
    const [row] = await this.db.insert(schema.users).values({
      email: input.email,
      passwordHash: input.passwordHash,
      displayName: input.displayName,
      avatarUrl: input.avatarUrl ?? null,
      emailVerified: input.emailVerified ?? false,
      roles: input.roles ?? [],
      orgId: input.orgId ?? null,
      orgRole: input.orgRole ?? null,
      metadata: input.metadata ?? {},
      createdAt: now,
      updatedAt: now,
    }).returning();
    return this.mapUser(row);
  }

  async findUserByEmail(email: string): Promise<User | null> {
    const rows = await this.db.select().from(schema.users).where(
      and(
        ilike(schema.users.email, email),
        isNull(schema.users.deletedAt),
      )
    ).limit(1);
    if (rows.length === 0) return null;
    return this.mapUser(rows[0]);
  }

  async findUserById(id: string): Promise<User | null> {
    const rows = await this.db.select().from(schema.users).where(
      and(
        eq(schema.users.id, id),
        isNull(schema.users.deletedAt),
      )
    ).limit(1);
    if (rows.length === 0) return null;
    return this.mapUser(rows[0]);
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User> {
    // Build update object, excluding id and mapping fields
    const updateData: Record<string, unknown> = { updatedAt: new Date() };
    if (updates.email !== undefined) updateData.email = updates.email;
    if (updates.passwordHash !== undefined) updateData.passwordHash = updates.passwordHash;
    if (updates.displayName !== undefined) updateData.displayName = updates.displayName;
    if (updates.avatarUrl !== undefined) updateData.avatarUrl = updates.avatarUrl;
    if (updates.emailVerified !== undefined) updateData.emailVerified = updates.emailVerified;
    if (updates.mfaEnabled !== undefined) updateData.mfaEnabled = updates.mfaEnabled;
    if (updates.mfaMethods !== undefined) updateData.mfaMethods = updates.mfaMethods;
    if (updates.roles !== undefined) updateData.roles = updates.roles;
    if (updates.permissions !== undefined) updateData.permissions = updates.permissions;
    if (updates.orgId !== undefined) updateData.orgId = updates.orgId;
    if (updates.orgRole !== undefined) updateData.orgRole = updates.orgRole;
    if (updates.failedLoginAttempts !== undefined) updateData.failedLoginAttempts = updates.failedLoginAttempts;
    if (updates.lockedUntil !== undefined) updateData.lockedUntil = updates.lockedUntil;
    if (updates.lastLoginAt !== undefined) updateData.lastLoginAt = updates.lastLoginAt;
    if (updates.lastLoginIp !== undefined) updateData.lastLoginIp = updates.lastLoginIp;
    if (updates.emailVerifiedAt !== undefined) updateData.emailVerifiedAt = updates.emailVerifiedAt;
    if (updates.metadata !== undefined) updateData.metadata = updates.metadata;
    if (updates.deletedAt !== undefined) updateData.deletedAt = updates.deletedAt;

    const [row] = await this.db.update(schema.users)
      .set(updateData)
      .where(eq(schema.users.id, id))
      .returning();

    if (!row) throw new Error(`User ${id} not found`);
    return this.mapUser(row);
  }

  async softDeleteUser(id: string): Promise<void> {
    const now = new Date();
    const result = await this.db.update(schema.users)
      .set({ deletedAt: now, updatedAt: now })
      .where(eq(schema.users.id, id))
      .returning({ id: schema.users.id });

    if (result.length === 0) throw new Error(`User ${id} not found`);
  }

  // ─── Sessions ───────────────────────────────────────────────────────────

  async createSession(input: CreateSessionInput): Promise<Session> {
    const now = new Date();
    const [row] = await this.db.insert(schema.sessions).values({
      userId: input.userId,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      deviceFingerprint: input.deviceFingerprint ?? null,
      lastActivityAt: now,
      expiresAt: input.expiresAt,
      orgId: input.orgId ?? null,
      createdAt: now,
    }).returning();
    return this.mapSession(row);
  }

  async getSession(id: string): Promise<Session | null> {
    const rows = await this.db.select().from(schema.sessions)
      .where(eq(schema.sessions.id, id))
      .limit(1);
    if (rows.length === 0) return null;
    return this.mapSession(rows[0]);
  }

  async getActiveSessions(userId: string): Promise<Session[]> {
    const now = new Date();
    const rows = await this.db.select().from(schema.sessions).where(
      and(
        eq(schema.sessions.userId, userId),
        eq(schema.sessions.revoked, false),
        gte(schema.sessions.expiresAt, now),
      )
    );
    return rows.map(r => this.mapSession(r));
  }

  async revokeSession(id: string, reason: string): Promise<void> {
    const now = new Date();
    const result = await this.db.update(schema.sessions)
      .set({ revoked: true, revokedAt: now, revokedReason: reason })
      .where(eq(schema.sessions.id, id))
      .returning({ id: schema.sessions.id });
    if (result.length === 0) throw new Error(`Session ${id} not found`);
  }

  async revokeAllSessions(userId: string, reason: string, excludeSessionId?: string): Promise<void> {
    const now = new Date();
    const conditions = [eq(schema.sessions.userId, userId)];
    if (excludeSessionId) {
      // We use raw SQL for != since drizzle doesn't have a neq helper in all versions
      conditions.push(sql`${schema.sessions.id} != ${excludeSessionId}`);
    }
    await this.db.update(schema.sessions)
      .set({ revoked: true, revokedAt: now, revokedReason: reason })
      .where(and(...conditions));
  }

  async countActiveSessions(userId: string): Promise<number> {
    const now = new Date();
    const result = await this.db.select({ count: countFn() }).from(schema.sessions).where(
      and(
        eq(schema.sessions.userId, userId),
        eq(schema.sessions.revoked, false),
        gte(schema.sessions.expiresAt, now),
      )
    );
    return Number(result[0].count);
  }

  // ─── Refresh Tokens ────────────────────────────────────────────────────

  async createRefreshToken(input: CreateRefreshTokenInput): Promise<RefreshToken> {
    const now = new Date();
    const [row] = await this.db.insert(schema.refreshTokens).values({
      userId: input.userId,
      sessionId: input.sessionId,
      tokenHash: input.tokenHash,
      family: input.family,
      generation: input.generation,
      expiresAt: input.expiresAt,
      createdAt: now,
    }).returning();
    return this.mapRefreshToken(row);
  }

  async findRefreshTokenByHash(hash: string): Promise<RefreshToken | null> {
    // Must return revoked tokens too — the refresh pipeline checks revoked
    // status to detect token reuse attacks
    const rows = await this.db.select().from(schema.refreshTokens).where(
      eq(schema.refreshTokens.tokenHash, hash),
    ).limit(1);
    if (rows.length === 0) return null;
    return this.mapRefreshToken(rows[0]);
  }

  async revokeRefreshToken(id: string, reason: string): Promise<void> {
    const now = new Date();
    const result = await this.db.update(schema.refreshTokens)
      .set({ revoked: true, revokedAt: now, revokedReason: reason })
      .where(eq(schema.refreshTokens.id, id))
      .returning({ id: schema.refreshTokens.id });
    if (result.length === 0) throw new Error(`Refresh token ${id} not found`);
  }

  async revokeRefreshTokenIfActive(id: string, reason: string): Promise<boolean> {
    const now = new Date();
    const result = await this.db.update(schema.refreshTokens)
      .set({ revoked: true, revokedAt: now, revokedReason: reason })
      .where(and(
        eq(schema.refreshTokens.id, id),
        eq(schema.refreshTokens.revoked, false),
      ))
      .returning({ id: schema.refreshTokens.id });
    return result.length > 0;
  }

  async revokeTokenFamily(family: string, reason: string): Promise<void> {
    const now = new Date();
    await this.db.update(schema.refreshTokens)
      .set({ revoked: true, revokedAt: now, revokedReason: reason })
      .where(eq(schema.refreshTokens.family, family));
  }

  async revokeAllUserTokens(userId: string, reason: string): Promise<void> {
    const now = new Date();
    await this.db.update(schema.refreshTokens)
      .set({ revoked: true, revokedAt: now, revokedReason: reason })
      .where(eq(schema.refreshTokens.userId, userId));
  }

  // ─── Password Reset ────────────────────────────────────────────────────

  async createPasswordResetToken(input: CreateResetTokenInput): Promise<PasswordResetToken> {
    const now = new Date();
    const [row] = await this.db.insert(schema.passwordResetTokens).values({
      userId: input.userId,
      tokenHash: input.tokenHash,
      requestedFromIp: input.requestedFromIp,
      requestedFromUa: input.requestedFromUa ?? null,
      expiresAt: input.expiresAt,
      createdAt: now,
    }).returning();
    return this.mapPasswordResetToken(row);
  }

  async findPasswordResetByHash(hash: string): Promise<PasswordResetToken | null> {
    const rows = await this.db.select().from(schema.passwordResetTokens).where(
      eq(schema.passwordResetTokens.tokenHash, hash)
    ).limit(1);
    if (rows.length === 0) return null;
    return this.mapPasswordResetToken(rows[0]);
  }

  async markResetTokenUsed(id: string): Promise<void> {
    await this.db.update(schema.passwordResetTokens)
      .set({ used: true, usedAt: new Date() })
      .where(eq(schema.passwordResetTokens.id, id));
  }

  async invalidateUserResetTokens(userId: string): Promise<void> {
    await this.db.update(schema.passwordResetTokens)
      .set({ used: true, usedAt: new Date() })
      .where(eq(schema.passwordResetTokens.userId, userId));
  }

  // ─── Email Verification ────────────────────────────────────────────────

  async createEmailVerificationToken(input: CreateVerificationInput): Promise<EmailVerificationToken> {
    const now = new Date();
    const [row] = await this.db.insert(schema.emailVerificationTokens).values({
      userId: input.userId,
      tokenHash: input.tokenHash,
      expiresAt: input.expiresAt,
      createdAt: now,
    }).returning();
    return this.mapEmailVerificationToken(row);
  }

  async findVerificationByHash(hash: string): Promise<EmailVerificationToken | null> {
    const rows = await this.db.select().from(schema.emailVerificationTokens).where(
      eq(schema.emailVerificationTokens.tokenHash, hash)
    ).limit(1);
    if (rows.length === 0) return null;
    return this.mapEmailVerificationToken(rows[0]);
  }

  async markVerificationUsed(id: string): Promise<void> {
    await this.db.update(schema.emailVerificationTokens)
      .set({ used: true, usedAt: new Date() })
      .where(eq(schema.emailVerificationTokens.id, id));
  }

  // ─── OAuth ──────────────────────────────────────────────────────────────

  async linkOAuthProvider(input: LinkOAuthInput): Promise<OAuthLink> {
    const now = new Date();
    const [row] = await this.db.insert(schema.oauthProviders).values({
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
    }).returning();
    return this.mapOAuthLink(row);
  }

  async findOAuthProvider(provider: string, providerUserId: string): Promise<OAuthLink | null> {
    const rows = await this.db.select().from(schema.oauthProviders).where(
      and(
        eq(schema.oauthProviders.provider, provider),
        eq(schema.oauthProviders.providerUserId, providerUserId),
      )
    ).limit(1);
    if (rows.length === 0) return null;
    return this.mapOAuthLink(rows[0]);
  }

  async getUserOAuthProviders(userId: string): Promise<OAuthLink[]> {
    const rows = await this.db.select().from(schema.oauthProviders)
      .where(eq(schema.oauthProviders.userId, userId));
    return rows.map(r => this.mapOAuthLink(r));
  }

  async unlinkOAuthProvider(userId: string, provider: string): Promise<void> {
    await this.db.delete(schema.oauthProviders).where(
      and(
        eq(schema.oauthProviders.userId, userId),
        eq(schema.oauthProviders.provider, provider),
      )
    );
  }

  // ─── MFA ────────────────────────────────────────────────────────────────

  async saveMFASecret(input: SaveMFAInput): Promise<MFASecret> {
    const now = new Date();
    const [row] = await this.db.insert(schema.mfaSecrets).values({
      userId: input.userId,
      method: input.method,
      encryptedSecret: input.encryptedSecret,
      encryptedBackupCodes: input.encryptedBackupCodes,
      backupCodesUsed: input.backupCodesUsed,
      recoveryEmail: input.recoveryEmail ?? null,
      enabledAt: now,
      createdAt: now,
      updatedAt: now,
    }).returning();
    return this.mapMFASecret(row);
  }

  async getMFASecret(userId: string): Promise<MFASecret | null> {
    const rows = await this.db.select().from(schema.mfaSecrets)
      .where(eq(schema.mfaSecrets.userId, userId))
      .limit(1);
    if (rows.length === 0) return null;
    return this.mapMFASecret(rows[0]);
  }

  async deleteMFASecret(userId: string): Promise<void> {
    await this.db.delete(schema.mfaSecrets)
      .where(eq(schema.mfaSecrets.userId, userId));
  }

  async markBackupCodeUsed(userId: string, codeIndex: number): Promise<void> {
    // Get current state, update the array, save back
    const mfa = await this.getMFASecret(userId);
    if (!mfa) throw new Error(`MFA secret for user ${userId} not found`);
    const newUsed = [...mfa.backupCodesUsed];
    newUsed[codeIndex] = true;
    await this.db.update(schema.mfaSecrets)
      .set({ backupCodesUsed: newUsed, updatedAt: new Date() })
      .where(eq(schema.mfaSecrets.userId, userId));
  }

  // ─── Password History ──────────────────────────────────────────────────

  async getPasswordHistory(userId: string, limit: number): Promise<string[]> {
    const rows = await this.db.select().from(schema.passwordHistory)
      .where(eq(schema.passwordHistory.userId, userId))
      .orderBy(desc(schema.passwordHistory.createdAt))
      .limit(limit);
    return rows.map(r => r.passwordHash);
  }

  async addPasswordHistory(userId: string, hash: string): Promise<void> {
    await this.db.insert(schema.passwordHistory).values({
      userId,
      passwordHash: hash,
    });
  }

  // ─── Audit Log ─────────────────────────────────────────────────────────

  async writeAuditLog(entry: AuditLogEntry): Promise<void> {
    await this.db.insert(schema.auditLog).values({
      id: entry.id,
      userId: entry.userId,
      action: entry.action,
      ipAddress: entry.ipAddress,
      userAgent: entry.userAgent,
      metadata: entry.metadata,
      orgId: entry.orgId,
      createdAt: entry.createdAt,
    });
  }

  async queryAuditLog(filter: AuditLogFilter): Promise<{ entries: AuditLogEntry[]; total: number }> {
    const conditions = [];

    if (filter.userId !== undefined) {
      conditions.push(eq(schema.auditLog.userId, filter.userId));
    }
    if (filter.action !== undefined) {
      conditions.push(eq(schema.auditLog.action, filter.action));
    }
    if (filter.startDate !== undefined) {
      conditions.push(gte(schema.auditLog.createdAt, filter.startDate));
    }
    if (filter.endDate !== undefined) {
      conditions.push(lte(schema.auditLog.createdAt, filter.endDate));
    }
    if (filter.orgId !== undefined) {
      conditions.push(eq(schema.auditLog.orgId, filter.orgId));
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    // Get total count
    const countResult = await this.db.select({ count: countFn() })
      .from(schema.auditLog)
      .where(whereClause);
    const total = Number(countResult[0].count);

    // Get entries with pagination
    let query = this.db.select().from(schema.auditLog)
      .where(whereClause)
      .orderBy(desc(schema.auditLog.createdAt))
      .$dynamic();

    if (filter.offset !== undefined) {
      query = query.offset(filter.offset);
    }
    if (filter.limit !== undefined) {
      query = query.limit(filter.limit);
    }

    const rows = await query;
    return { entries: rows.map(r => this.mapAuditLogEntry(r)), total };
  }

  // ─── Organizations ─────────────────────────────────────────────────────

  async createOrganization(input: CreateOrgInput): Promise<Organization> {
    const now = new Date();
    const defaultSettings: OrgSettings = {
      enforceSSO: false,
      allowedAuthMethods: [],
      enforceMFA: false,
      allowedMFAMethods: [],
      sessionTimeout: 3600,
      maxSessionsPerUser: 5,
      ipAllowlist: [],
      passwordPolicy: { minLength: 8, requireMFA: false, maxAge: 90 },
    };
    const settings = input.settings ? { ...defaultSettings, ...input.settings } : defaultSettings;

    const [row] = await this.db.insert(schema.organizations).values({
      name: input.name,
      slug: input.slug,
      ownerId: input.ownerId,
      plan: input.plan ?? 'free',
      settings,
      metadata: input.metadata ?? {},
      createdAt: now,
      updatedAt: now,
    }).returning();
    return this.mapOrganization(row);
  }

  async getOrganization(id: string): Promise<Organization | null> {
    const rows = await this.db.select().from(schema.organizations)
      .where(eq(schema.organizations.id, id))
      .limit(1);
    if (rows.length === 0) return null;
    return this.mapOrganization(rows[0]);
  }

  async updateOrganization(id: string, updates: Partial<Organization>): Promise<Organization> {
    const updateData: Record<string, unknown> = { updatedAt: new Date() };
    if (updates.name !== undefined) updateData.name = updates.name;
    if (updates.slug !== undefined) updateData.slug = updates.slug;
    if (updates.ownerId !== undefined) updateData.ownerId = updates.ownerId;
    if (updates.plan !== undefined) updateData.plan = updates.plan;
    if (updates.settings !== undefined) updateData.settings = updates.settings;
    if (updates.metadata !== undefined) updateData.metadata = updates.metadata;

    const [row] = await this.db.update(schema.organizations)
      .set(updateData)
      .where(eq(schema.organizations.id, id))
      .returning();
    if (!row) throw new Error(`Organization ${id} not found`);
    return this.mapOrganization(row);
  }

  async deleteOrganization(id: string): Promise<void> {
    // Delete org members first
    await this.db.delete(schema.orgMembers).where(eq(schema.orgMembers.orgId, id));
    await this.db.delete(schema.organizations).where(eq(schema.organizations.id, id));
  }

  async listOrgMembers(orgId: string): Promise<OrgMember[]> {
    const rows = await this.db.select().from(schema.orgMembers)
      .where(eq(schema.orgMembers.orgId, orgId));
    return rows.map(r => this.mapOrgMember(r));
  }

  async addOrgMember(input: AddOrgMemberInput): Promise<OrgMember> {
    const [row] = await this.db.insert(schema.orgMembers).values({
      userId: input.userId,
      orgId: input.orgId,
      role: input.role,
      permissions: input.permissions ?? [],
      joinedAt: new Date(),
    }).returning();
    return this.mapOrgMember(row);
  }

  async updateOrgMember(orgId: string, userId: string, updates: Partial<OrgMember>): Promise<OrgMember> {
    const updateData: Record<string, unknown> = {};
    if (updates.role !== undefined) updateData.role = updates.role;
    if (updates.permissions !== undefined) updateData.permissions = updates.permissions;

    const [row] = await this.db.update(schema.orgMembers)
      .set(updateData)
      .where(and(
        eq(schema.orgMembers.orgId, orgId),
        eq(schema.orgMembers.userId, userId),
      ))
      .returning();
    if (!row) throw new Error(`Member ${userId} not found in org ${orgId}`);
    return this.mapOrgMember(row);
  }

  async removeOrgMember(orgId: string, userId: string): Promise<void> {
    await this.db.delete(schema.orgMembers).where(
      and(
        eq(schema.orgMembers.orgId, orgId),
        eq(schema.orgMembers.userId, userId),
      )
    );
  }

  // ─── Org Invites ───────────────────────────────────────────────────────

  async createOrgInvite(input: CreateOrgInviteInput): Promise<OrgInvite> {
    const now = new Date();
    const [row] = await this.db.insert(schema.orgInvites).values({
      orgId: input.orgId,
      email: input.email,
      role: input.role,
      invitedBy: input.invitedBy,
      token: input.token,
      expiresAt: input.expiresAt,
      createdAt: now,
    }).returning();
    return this.mapOrgInvite(row);
  }

  async findOrgInviteByToken(token: string): Promise<OrgInvite | null> {
    const rows = await this.db.select().from(schema.orgInvites)
      .where(eq(schema.orgInvites.token, token))
      .limit(1);
    if (rows.length === 0) return null;
    return this.mapOrgInvite(rows[0]);
  }

  async acceptOrgInvite(id: string): Promise<void> {
    await this.db.update(schema.orgInvites)
      .set({ acceptedAt: new Date() })
      .where(eq(schema.orgInvites.id, id));
  }

  async listPendingInvites(orgId: string): Promise<OrgInvite[]> {
    const rows = await this.db.select().from(schema.orgInvites).where(
      and(
        eq(schema.orgInvites.orgId, orgId),
        isNull(schema.orgInvites.acceptedAt),
      )
    );
    return rows.map(r => this.mapOrgInvite(r));
  }

  // ─── API Keys ──────────────────────────────────────────────────────────

  async createApiKey(input: CreateApiKeyInput): Promise<ApiKey> {
    const now = new Date();
    const [row] = await this.db.insert(schema.apiKeys).values({
      name: input.name,
      keyPrefix: input.keyPrefix,
      keyHash: input.keyHash,
      userId: input.userId,
      orgId: input.orgId ?? null,
      permissions: input.permissions,
      rateLimit: input.rateLimit ?? null,
      ipAllowlist: input.ipAllowlist ?? [],
      expiresAt: input.expiresAt ?? null,
      createdAt: now,
    }).returning();
    return this.mapApiKey(row);
  }

  async findApiKeyByHash(hash: string): Promise<ApiKey | null> {
    const rows = await this.db.select().from(schema.apiKeys).where(
      eq(schema.apiKeys.keyHash, hash)
    ).limit(1);
    if (rows.length === 0) return null;
    return this.mapApiKey(rows[0]);
  }

  async listApiKeys(userId: string): Promise<ApiKey[]> {
    const rows = await this.db.select().from(schema.apiKeys)
      .where(eq(schema.apiKeys.userId, userId));
    return rows.map(r => this.mapApiKey(r));
  }

  async revokeApiKey(id: string): Promise<void> {
    await this.db.update(schema.apiKeys)
      .set({ revokedAt: new Date() })
      .where(eq(schema.apiKeys.id, id));
  }

  async updateApiKeyLastUsed(id: string): Promise<void> {
    await this.db.update(schema.apiKeys)
      .set({ lastUsedAt: new Date() })
      .where(eq(schema.apiKeys.id, id));
  }

  // ─── Roles & Permissions ──────────────────────────────────────────────

  async createRole(role: Role): Promise<Role> {
    const [row] = await this.db.insert(schema.roles).values({
      name: role.name,
      description: role.description,
      permissions: role.permissions,
      inherits: role.inherits,
      isSystem: role.isSystem,
    }).returning();
    return this.mapRole(row);
  }

  async getRole(name: string): Promise<Role | null> {
    const rows = await this.db.select().from(schema.roles)
      .where(eq(schema.roles.name, name))
      .limit(1);
    if (rows.length === 0) return null;
    return this.mapRole(rows[0]);
  }

  async listRoles(): Promise<Role[]> {
    const rows = await this.db.select().from(schema.roles);
    return rows.map(r => this.mapRole(r));
  }

  async updateRole(name: string, updates: Partial<Role>): Promise<Role> {
    const updateData: Record<string, unknown> = {};
    if (updates.description !== undefined) updateData.description = updates.description;
    if (updates.permissions !== undefined) updateData.permissions = updates.permissions;
    if (updates.inherits !== undefined) updateData.inherits = updates.inherits;
    if (updates.isSystem !== undefined) updateData.isSystem = updates.isSystem;

    const [row] = await this.db.update(schema.roles)
      .set(updateData)
      .where(eq(schema.roles.name, name))
      .returning();
    if (!row) throw new Error(`Role ${name} not found`);
    return this.mapRole(row);
  }

  async deleteRole(name: string): Promise<void> {
    await this.db.delete(schema.roles).where(eq(schema.roles.name, name));
  }

  // ─── Access Policies ──────────────────────────────────────────────────

  async createPolicy(policy: AccessPolicy): Promise<AccessPolicy> {
    const [row] = await this.db.insert(schema.accessPolicies).values({
      id: policy.id,
      name: policy.name,
      effect: policy.effect,
      actions: policy.actions,
      conditions: policy.conditions,
    }).returning();
    return this.mapAccessPolicy(row);
  }

  async listPolicies(): Promise<AccessPolicy[]> {
    const rows = await this.db.select().from(schema.accessPolicies);
    return rows.map(r => this.mapAccessPolicy(r));
  }

  async deletePolicy(id: string): Promise<void> {
    await this.db.delete(schema.accessPolicies).where(eq(schema.accessPolicies.id, id));
  }

  // ─── Webhooks ─────────────────────────────────────────────────────────

  async createWebhook(input: CreateWebhookInput): Promise<Webhook> {
    const now = new Date();
    const [row] = await this.db.insert(schema.webhooks).values({
      url: input.url,
      events: input.events,
      secret: input.secret,
      orgId: input.orgId ?? null,
      createdAt: now,
    }).returning();
    return this.mapWebhook(row);
  }

  async listWebhooks(orgId?: string): Promise<Webhook[]> {
    if (orgId !== undefined) {
      const rows = await this.db.select().from(schema.webhooks)
        .where(eq(schema.webhooks.orgId, orgId));
      return rows.map(r => this.mapWebhook(r));
    }
    const rows = await this.db.select().from(schema.webhooks);
    return rows.map(r => this.mapWebhook(r));
  }

  async updateWebhook(id: string, updates: Partial<Webhook>): Promise<Webhook> {
    const updateData: Record<string, unknown> = {};
    if (updates.url !== undefined) updateData.url = updates.url;
    if (updates.events !== undefined) updateData.events = updates.events;
    if (updates.secret !== undefined) updateData.secret = updates.secret;
    if (updates.orgId !== undefined) updateData.orgId = updates.orgId;
    if (updates.active !== undefined) updateData.active = updates.active;
    if (updates.failureCount !== undefined) updateData.failureCount = updates.failureCount;
    if (updates.lastTriggeredAt !== undefined) updateData.lastTriggeredAt = updates.lastTriggeredAt;

    const [row] = await this.db.update(schema.webhooks)
      .set(updateData)
      .where(eq(schema.webhooks.id, id))
      .returning();
    if (!row) throw new Error(`Webhook ${id} not found`);
    return this.mapWebhook(row);
  }

  async deleteWebhook(id: string): Promise<void> {
    await this.db.delete(schema.webhooks).where(eq(schema.webhooks.id, id));
  }

  async incrementWebhookFailure(id: string): Promise<void> {
    await this.db.execute(sql`
      UPDATE auth.webhooks SET failure_count = failure_count + 1 WHERE id = ${id}
    `);
  }

  async resetWebhookFailure(id: string): Promise<void> {
    await this.db.update(schema.webhooks)
      .set({ failureCount: 0 })
      .where(eq(schema.webhooks.id, id));
  }

  // ─── Trusted Devices ──────────────────────────────────────────────────

  async saveTrustedDevice(device: TrustedDevice): Promise<TrustedDevice> {
    const [row] = await this.db.insert(schema.trustedDevices).values({
      id: device.id,
      userId: device.userId,
      fingerprint: device.fingerprint,
      name: device.name,
      browser: device.browser,
      os: device.os,
      lastUsedAt: device.lastUsedAt,
      lastIp: device.lastIp,
      trustedAt: device.trustedAt,
    }).returning();
    return this.mapTrustedDevice(row);
  }

  async getTrustedDevices(userId: string): Promise<TrustedDevice[]> {
    const rows = await this.db.select().from(schema.trustedDevices)
      .where(eq(schema.trustedDevices.userId, userId));
    return rows.map(r => this.mapTrustedDevice(r));
  }

  async removeTrustedDevice(userId: string, deviceId: string): Promise<void> {
    await this.db.delete(schema.trustedDevices).where(
      and(
        eq(schema.trustedDevices.id, deviceId),
        eq(schema.trustedDevices.userId, userId),
      )
    );
  }

  async isTrustedDevice(userId: string, fingerprint: string): Promise<boolean> {
    const rows = await this.db.select({ id: schema.trustedDevices.id })
      .from(schema.trustedDevices)
      .where(
        and(
          eq(schema.trustedDevices.userId, userId),
          eq(schema.trustedDevices.fingerprint, fingerprint),
        )
      ).limit(1);
    return rows.length > 0;
  }

  // ─── Admin ────────────────────────────────────────────────────────────

  async listUsers(filter: UserFilter): Promise<{ users: User[]; total: number }> {
    const conditions = [isNull(schema.users.deletedAt)];

    if (filter.search !== undefined) {
      const searchPattern = `%${filter.search}%`;
      conditions.push(
        or(
          ilike(schema.users.email, searchPattern),
          ilike(schema.users.displayName, searchPattern),
        )!
      );
    }

    if (filter.role !== undefined) {
      conditions.push(sql`${filter.role} = ANY(${schema.users.roles})`);
    }

    if (filter.emailVerified !== undefined) {
      conditions.push(eq(schema.users.emailVerified, filter.emailVerified));
    }

    if (filter.mfaEnabled !== undefined) {
      conditions.push(eq(schema.users.mfaEnabled, filter.mfaEnabled));
    }

    if (filter.locked !== undefined) {
      const now = new Date();
      if (filter.locked) {
        conditions.push(gte(schema.users.lockedUntil, now));
      } else {
        conditions.push(
          or(
            isNull(schema.users.lockedUntil),
            lte(schema.users.lockedUntil, now),
          )!
        );
      }
    }

    if (filter.orgId !== undefined) {
      conditions.push(eq(schema.users.orgId, filter.orgId));
    }

    const whereClause = and(...conditions);

    // Get total count
    const countResult = await this.db.select({ count: countFn() })
      .from(schema.users)
      .where(whereClause);
    const total = Number(countResult[0].count);

    // Get users with pagination
    let query = this.db.select().from(schema.users)
      .where(whereClause)
      .$dynamic();

    if (filter.offset !== undefined) {
      query = query.offset(filter.offset);
    }
    if (filter.limit !== undefined) {
      query = query.limit(filter.limit);
    }

    const rows = await query;
    return { users: rows.map(r => this.mapUser(r)), total };
  }

  async getSystemStats(): Promise<SystemStats> {
    const now = new Date();

    // Total users (not deleted)
    const totalUsersResult = await this.db.select({ count: countFn() })
      .from(schema.users)
      .where(isNull(schema.users.deletedAt));
    const totalUsers = Number(totalUsersResult[0].count);

    // Active users (have logged in at least once)
    const activeUsersResult = await this.db.select({ count: countFn() })
      .from(schema.users)
      .where(and(
        isNull(schema.users.deletedAt),
        sql`${schema.users.lastLoginAt} IS NOT NULL`,
      ));
    const activeUsers = Number(activeUsersResult[0].count);

    // Total sessions
    const totalSessionsResult = await this.db.select({ count: countFn() })
      .from(schema.sessions);
    const totalSessions = Number(totalSessionsResult[0].count);

    // Active sessions
    const activeSessionsResult = await this.db.select({ count: countFn() })
      .from(schema.sessions)
      .where(and(
        eq(schema.sessions.revoked, false),
        gte(schema.sessions.expiresAt, now),
      ));
    const activeSessions = Number(activeSessionsResult[0].count);

    // MFA adoption
    const mfaUsersResult = await this.db.select({ count: countFn() })
      .from(schema.users)
      .where(and(
        isNull(schema.users.deletedAt),
        eq(schema.users.mfaEnabled, true),
      ));
    const mfaUsers = Number(mfaUsersResult[0].count);

    // Locked accounts
    const lockedResult = await this.db.select({ count: countFn() })
      .from(schema.users)
      .where(and(
        isNull(schema.users.deletedAt),
        gte(schema.users.lockedUntil, now),
      ));
    const lockedAccounts = Number(lockedResult[0].count);

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
    // Get user
    const userRows = await this.db.select().from(schema.users)
      .where(eq(schema.users.id, userId)).limit(1);
    const user = userRows.length > 0 ? (userRows[0] as unknown as Record<string, unknown>) : {};

    // Get sessions
    const sessionRows = await this.db.select().from(schema.sessions)
      .where(eq(schema.sessions.userId, userId));

    // Get OAuth providers
    const oauthRows = await this.db.select().from(schema.oauthProviders)
      .where(eq(schema.oauthProviders.userId, userId));

    // Get audit log
    const auditRows = await this.db.select().from(schema.auditLog)
      .where(eq(schema.auditLog.userId, userId));

    // Get API keys
    const apiKeyRows = await this.db.select().from(schema.apiKeys)
      .where(eq(schema.apiKeys.userId, userId));

    // Get organizations the user is a member of
    const memberRows = await this.db.select().from(schema.orgMembers)
      .where(eq(schema.orgMembers.userId, userId));
    const orgs: Record<string, unknown>[] = [];
    for (const member of memberRows) {
      const orgRows = await this.db.select().from(schema.organizations)
        .where(eq(schema.organizations.id, member.orgId)).limit(1);
      if (orgRows.length > 0) {
        orgs.push(orgRows[0] as unknown as Record<string, unknown>);
      }
    }

    return {
      user,
      sessions: sessionRows as unknown as Record<string, unknown>[],
      oauthProviders: oauthRows as unknown as Record<string, unknown>[],
      auditLog: auditRows as unknown as Record<string, unknown>[],
      apiKeys: apiKeyRows as unknown as Record<string, unknown>[],
      organizations: orgs,
    };
  }
}
