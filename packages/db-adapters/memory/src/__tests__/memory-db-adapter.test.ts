import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryDbAdapter } from '../memory-db-adapter.js';
import type {
  User, Session, RefreshToken, PasswordResetToken, EmailVerificationToken,
  OAuthLink, MFASecret, AuditLogEntry, Organization, OrgMember, OrgInvite,
  ApiKey, Role, AccessPolicy, Webhook, TrustedDevice,
  CreateUserInput, CreateSessionInput, CreateRefreshTokenInput, CreateResetTokenInput,
  CreateVerificationInput, LinkOAuthInput, SaveMFAInput, CreateOrgInput, AddOrgMemberInput,
  CreateOrgInviteInput, CreateApiKeyInput, CreateWebhookInput,
} from '@argus/core';

describe('MemoryDbAdapter', () => {
  let db: MemoryDbAdapter;

  beforeEach(async () => {
    db = new MemoryDbAdapter();
    await db.init();
  });

  // ─── Users ────────────────────────────────────────────────────────────────

  describe('Users', () => {
    const userInput: CreateUserInput = {
      email: 'alice@example.com',
      passwordHash: '$2b$10$hashedpassword',
      displayName: 'Alice Smith',
    };

    it('should create a user with generated id and timestamps', async () => {
      const user = await db.createUser(userInput);
      expect(user.id).toBeDefined();
      expect(user.email).toBe('alice@example.com');
      expect(user.displayName).toBe('Alice Smith');
      expect(user.passwordHash).toBe('$2b$10$hashedpassword');
      expect(user.createdAt).toBeInstanceOf(Date);
      expect(user.updatedAt).toBeInstanceOf(Date);
      expect(user.deletedAt).toBeNull();
      expect(user.emailVerified).toBe(false);
      expect(user.mfaEnabled).toBe(false);
      expect(user.roles).toEqual([]);
      expect(user.permissions).toEqual([]);
      expect(user.failedLoginAttempts).toBe(0);
      expect(user.lockedUntil).toBeNull();
    });

    it('should find user by email (case-insensitive)', async () => {
      await db.createUser(userInput);
      const found = await db.findUserByEmail('ALICE@EXAMPLE.COM');
      expect(found).not.toBeNull();
      expect(found!.email).toBe('alice@example.com');
    });

    it('should find user by id', async () => {
      const created = await db.createUser(userInput);
      const found = await db.findUserById(created.id);
      expect(found).not.toBeNull();
      expect(found!.id).toBe(created.id);
    });

    it('should update a user', async () => {
      const created = await db.createUser(userInput);
      const updated = await db.updateUser(created.id, { displayName: 'Alice Updated', mfaEnabled: true });
      expect(updated.displayName).toBe('Alice Updated');
      expect(updated.mfaEnabled).toBe(true);
      expect(updated.updatedAt.getTime()).toBeGreaterThanOrEqual(created.updatedAt.getTime());
    });

    it('should soft delete a user', async () => {
      const created = await db.createUser(userInput);
      await db.softDeleteUser(created.id);
      const found = await db.findUserById(created.id);
      expect(found).toBeNull();
    });

    it('should not find deleted user by email', async () => {
      const created = await db.createUser(userInput);
      await db.softDeleteUser(created.id);
      const found = await db.findUserByEmail('alice@example.com');
      expect(found).toBeNull();
    });

    it('should throw on duplicate email', async () => {
      await db.createUser(userInput);
      await expect(db.createUser(userInput)).rejects.toThrow();
    });

    it('should return null for non-existent user', async () => {
      const found = await db.findUserById('non-existent-id');
      expect(found).toBeNull();
    });
  });

  // ─── Sessions ─────────────────────────────────────────────────────────────

  describe('Sessions', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await db.createUser({ email: 'bob@example.com', passwordHash: 'hash', displayName: 'Bob' });
      userId = user.id;
    });

    const sessionInput = (uid: string, opts?: Partial<CreateSessionInput>): CreateSessionInput => ({
      userId: uid,
      ipAddress: '192.168.1.1',
      userAgent: 'TestBrowser/1.0',
      expiresAt: new Date(Date.now() + 3600_000),
      ...opts,
    });

    it('should create and get a session', async () => {
      const session = await db.createSession(sessionInput(userId));
      expect(session.id).toBeDefined();
      expect(session.userId).toBe(userId);
      expect(session.revoked).toBe(false);

      const fetched = await db.getSession(session.id);
      expect(fetched).not.toBeNull();
      expect(fetched!.id).toBe(session.id);
    });

    it('should get active sessions (skip revoked and expired)', async () => {
      const active = await db.createSession(sessionInput(userId));
      const expired = await db.createSession(sessionInput(userId, { expiresAt: new Date(Date.now() - 1000) }));
      const revoked = await db.createSession(sessionInput(userId));
      await db.revokeSession(revoked.id, 'test');

      const activeSessions = await db.getActiveSessions(userId);
      expect(activeSessions).toHaveLength(1);
      expect(activeSessions[0].id).toBe(active.id);
    });

    it('should revoke a session with a reason', async () => {
      const session = await db.createSession(sessionInput(userId));
      await db.revokeSession(session.id, 'user-logout');

      const fetched = await db.getSession(session.id);
      expect(fetched!.revoked).toBe(true);
      expect(fetched!.revokedReason).toBe('user-logout');
      expect(fetched!.revokedAt).toBeInstanceOf(Date);
    });

    it('should revokeAll with exclude', async () => {
      const s1 = await db.createSession(sessionInput(userId));
      const s2 = await db.createSession(sessionInput(userId));
      const s3 = await db.createSession(sessionInput(userId));

      await db.revokeAllSessions(userId, 'security', s2.id);

      const s1Fetched = await db.getSession(s1.id);
      const s2Fetched = await db.getSession(s2.id);
      const s3Fetched = await db.getSession(s3.id);

      expect(s1Fetched!.revoked).toBe(true);
      expect(s2Fetched!.revoked).toBe(false);
      expect(s3Fetched!.revoked).toBe(true);
    });

    it('should count active sessions', async () => {
      await db.createSession(sessionInput(userId));
      await db.createSession(sessionInput(userId));
      const expired = await db.createSession(sessionInput(userId, { expiresAt: new Date(Date.now() - 1000) }));

      const count = await db.countActiveSessions(userId);
      expect(count).toBe(2);
    });
  });

  // ─── Refresh Tokens ──────────────────────────────────────────────────────

  describe('Refresh Tokens', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await db.createUser({ email: 'charlie@example.com', passwordHash: 'hash', displayName: 'Charlie' });
      userId = user.id;
    });

    const tokenInput = (uid: string, opts?: Partial<CreateRefreshTokenInput>): CreateRefreshTokenInput => ({
      userId: uid,
      sessionId: 'session-1',
      tokenHash: 'hash-' + Math.random().toString(36).slice(2),
      family: 'family-1',
      generation: 1,
      expiresAt: new Date(Date.now() + 3600_000),
      ...opts,
    });

    it('should create and find by hash', async () => {
      const input = tokenInput(userId, { tokenHash: 'unique-hash-1' });
      const token = await db.createRefreshToken(input);
      expect(token.id).toBeDefined();
      expect(token.tokenHash).toBe('unique-hash-1');

      const found = await db.findRefreshTokenByHash('unique-hash-1');
      expect(found).not.toBeNull();
      expect(found!.id).toBe(token.id);
    });

    it('should revoke a refresh token', async () => {
      const token = await db.createRefreshToken(tokenInput(userId, { tokenHash: 'hash-to-revoke' }));
      await db.revokeRefreshToken(token.id, 'rotation');

      const found = await db.findRefreshTokenByHash('hash-to-revoke');
      expect(found!.revoked).toBe(true);
      expect(found!.revokedReason).toBe('rotation');
    });

    it('should revoke entire token family', async () => {
      await db.createRefreshToken(tokenInput(userId, { family: 'fam-a', tokenHash: 'h1' }));
      await db.createRefreshToken(tokenInput(userId, { family: 'fam-a', tokenHash: 'h2', generation: 2 }));
      await db.createRefreshToken(tokenInput(userId, { family: 'fam-b', tokenHash: 'h3' }));

      await db.revokeTokenFamily('fam-a', 'reuse-detected');

      const t1 = await db.findRefreshTokenByHash('h1');
      const t2 = await db.findRefreshTokenByHash('h2');
      const t3 = await db.findRefreshTokenByHash('h3');
      expect(t1!.revoked).toBe(true);
      expect(t2!.revoked).toBe(true);
      expect(t3!.revoked).toBe(false);
    });

    it('should revoke all user tokens', async () => {
      await db.createRefreshToken(tokenInput(userId, { tokenHash: 'u1' }));
      await db.createRefreshToken(tokenInput(userId, { tokenHash: 'u2' }));

      await db.revokeAllUserTokens(userId, 'logout-all');

      const t1 = await db.findRefreshTokenByHash('u1');
      const t2 = await db.findRefreshTokenByHash('u2');
      expect(t1!.revoked).toBe(true);
      expect(t2!.revoked).toBe(true);
    });
  });

  // ─── Password Reset ──────────────────────────────────────────────────────

  describe('Password Reset', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await db.createUser({ email: 'dave@example.com', passwordHash: 'hash', displayName: 'Dave' });
      userId = user.id;
    });

    const resetInput = (uid: string, opts?: Partial<CreateResetTokenInput>): CreateResetTokenInput => ({
      userId: uid,
      tokenHash: 'reset-hash-' + Math.random().toString(36).slice(2),
      requestedFromIp: '10.0.0.1',
      expiresAt: new Date(Date.now() + 3600_000),
      ...opts,
    });

    it('should create and find by hash', async () => {
      const input = resetInput(userId, { tokenHash: 'reset-unique' });
      const token = await db.createPasswordResetToken(input);
      expect(token.id).toBeDefined();
      expect(token.used).toBe(false);

      const found = await db.findPasswordResetByHash('reset-unique');
      expect(found).not.toBeNull();
      expect(found!.id).toBe(token.id);
    });

    it('should mark token as used', async () => {
      const token = await db.createPasswordResetToken(resetInput(userId, { tokenHash: 'reset-use' }));
      await db.markResetTokenUsed(token.id);

      const found = await db.findPasswordResetByHash('reset-use');
      expect(found!.used).toBe(true);
      expect(found!.usedAt).toBeInstanceOf(Date);
    });

    it('should invalidate all user reset tokens', async () => {
      await db.createPasswordResetToken(resetInput(userId, { tokenHash: 'ra' }));
      await db.createPasswordResetToken(resetInput(userId, { tokenHash: 'rb' }));

      await db.invalidateUserResetTokens(userId);

      const a = await db.findPasswordResetByHash('ra');
      const b = await db.findPasswordResetByHash('rb');
      expect(a!.used).toBe(true);
      expect(b!.used).toBe(true);
    });
  });

  // ─── Email Verification ──────────────────────────────────────────────────

  describe('Email Verification', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await db.createUser({ email: 'eve@example.com', passwordHash: 'hash', displayName: 'Eve' });
      userId = user.id;
    });

    it('should create and find by hash', async () => {
      const token = await db.createEmailVerificationToken({
        userId,
        tokenHash: 'verify-hash-1',
        expiresAt: new Date(Date.now() + 3600_000),
      });
      expect(token.id).toBeDefined();
      expect(token.used).toBe(false);

      const found = await db.findVerificationByHash('verify-hash-1');
      expect(found).not.toBeNull();
      expect(found!.userId).toBe(userId);
    });

    it('should mark as used', async () => {
      const token = await db.createEmailVerificationToken({
        userId,
        tokenHash: 'verify-use',
        expiresAt: new Date(Date.now() + 3600_000),
      });
      await db.markVerificationUsed(token.id);

      const found = await db.findVerificationByHash('verify-use');
      expect(found!.used).toBe(true);
      expect(found!.usedAt).toBeInstanceOf(Date);
    });

    it('should return null for non-existent hash', async () => {
      const found = await db.findVerificationByHash('non-existent');
      expect(found).toBeNull();
    });
  });

  // ─── OAuth ────────────────────────────────────────────────────────────────

  describe('OAuth', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await db.createUser({ email: 'frank@example.com', passwordHash: null, displayName: 'Frank' });
      userId = user.id;
    });

    const oauthInput = (uid: string, opts?: Partial<LinkOAuthInput>): LinkOAuthInput => ({
      userId: uid,
      provider: 'google',
      providerUserId: 'google-123',
      rawProfile: { sub: 'google-123' },
      ...opts,
    });

    it('should link and find an OAuth provider', async () => {
      const link = await db.linkOAuthProvider(oauthInput(userId));
      expect(link.id).toBeDefined();
      expect(link.provider).toBe('google');

      const found = await db.findOAuthProvider('google', 'google-123');
      expect(found).not.toBeNull();
      expect(found!.userId).toBe(userId);
    });

    it('should get all user OAuth providers', async () => {
      await db.linkOAuthProvider(oauthInput(userId));
      await db.linkOAuthProvider(oauthInput(userId, { provider: 'github', providerUserId: 'gh-456' }));

      const providers = await db.getUserOAuthProviders(userId);
      expect(providers).toHaveLength(2);
      expect(providers.map(p => p.provider).sort()).toEqual(['github', 'google']);
    });

    it('should unlink an OAuth provider', async () => {
      await db.linkOAuthProvider(oauthInput(userId));
      await db.unlinkOAuthProvider(userId, 'google');

      const found = await db.findOAuthProvider('google', 'google-123');
      expect(found).toBeNull();
    });
  });

  // ─── MFA ──────────────────────────────────────────────────────────────────

  describe('MFA', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await db.createUser({ email: 'grace@example.com', passwordHash: 'hash', displayName: 'Grace' });
      userId = user.id;
    });

    const mfaInput = (uid: string): SaveMFAInput => ({
      userId: uid,
      method: 'totp',
      encryptedSecret: 'enc-secret-123',
      encryptedBackupCodes: ['code1', 'code2', 'code3', 'code4', 'code5'],
      backupCodesUsed: [false, false, false, false, false],
    });

    it('should save and get MFA secret', async () => {
      const mfa = await db.saveMFASecret(mfaInput(userId));
      expect(mfa.userId).toBe(userId);
      expect(mfa.method).toBe('totp');

      const found = await db.getMFASecret(userId);
      expect(found).not.toBeNull();
      expect(found!.encryptedSecret).toBe('enc-secret-123');
    });

    it('should delete MFA secret', async () => {
      await db.saveMFASecret(mfaInput(userId));
      await db.deleteMFASecret(userId);

      const found = await db.getMFASecret(userId);
      expect(found).toBeNull();
    });

    it('should mark backup code as used', async () => {
      await db.saveMFASecret(mfaInput(userId));
      await db.markBackupCodeUsed(userId, 2);

      const found = await db.getMFASecret(userId);
      expect(found!.backupCodesUsed[2]).toBe(true);
      expect(found!.backupCodesUsed[0]).toBe(false);
    });
  });

  // ─── Password History ────────────────────────────────────────────────────

  describe('Password History', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await db.createUser({ email: 'henry@example.com', passwordHash: 'hash', displayName: 'Henry' });
      userId = user.id;
    });

    it('should add and get password history', async () => {
      await db.addPasswordHistory(userId, 'hash-1');
      await db.addPasswordHistory(userId, 'hash-2');
      await db.addPasswordHistory(userId, 'hash-3');

      const history = await db.getPasswordHistory(userId, 10);
      expect(history).toHaveLength(3);
    });

    it('should respect limit', async () => {
      await db.addPasswordHistory(userId, 'hash-1');
      await db.addPasswordHistory(userId, 'hash-2');
      await db.addPasswordHistory(userId, 'hash-3');
      await db.addPasswordHistory(userId, 'hash-4');
      await db.addPasswordHistory(userId, 'hash-5');

      const history = await db.getPasswordHistory(userId, 3);
      expect(history).toHaveLength(3);
      // Should return most recent first
      expect(history).toContain('hash-5');
      expect(history).toContain('hash-4');
      expect(history).toContain('hash-3');
    });

    it('should return empty array for user with no history', async () => {
      const history = await db.getPasswordHistory(userId, 10);
      expect(history).toEqual([]);
    });
  });

  // ─── Audit Log ────────────────────────────────────────────────────────────

  describe('Audit Log', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await db.createUser({ email: 'iris@example.com', passwordHash: 'hash', displayName: 'Iris' });
      userId = user.id;
    });

    it('should write and query audit log entries', async () => {
      const entry: AuditLogEntry = {
        id: 'audit-1',
        userId,
        action: 'LOGIN_SUCCESS',
        ipAddress: '10.0.0.1',
        userAgent: 'TestBrowser',
        metadata: {},
        orgId: null,
        createdAt: new Date(),
      };
      await db.writeAuditLog(entry);

      const result = await db.queryAuditLog({});
      expect(result.entries).toHaveLength(1);
      expect(result.total).toBe(1);
      expect(result.entries[0].action).toBe('LOGIN_SUCCESS');
    });

    it('should filter by userId and action', async () => {
      await db.writeAuditLog({
        id: 'a1', userId, action: 'LOGIN_SUCCESS', ipAddress: null, userAgent: null, metadata: {}, orgId: null, createdAt: new Date(),
      });
      await db.writeAuditLog({
        id: 'a2', userId, action: 'LOGIN_FAILED', ipAddress: null, userAgent: null, metadata: {}, orgId: null, createdAt: new Date(),
      });
      await db.writeAuditLog({
        id: 'a3', userId: 'other-user', action: 'LOGIN_SUCCESS', ipAddress: null, userAgent: null, metadata: {}, orgId: null, createdAt: new Date(),
      });

      const byUser = await db.queryAuditLog({ userId });
      expect(byUser.entries).toHaveLength(2);

      const byAction = await db.queryAuditLog({ action: 'LOGIN_SUCCESS' });
      expect(byAction.entries).toHaveLength(2);

      const combined = await db.queryAuditLog({ userId, action: 'LOGIN_SUCCESS' });
      expect(combined.entries).toHaveLength(1);
    });

    it('should filter by date range', async () => {
      const old = new Date('2024-01-01');
      const recent = new Date('2025-06-01');

      await db.writeAuditLog({
        id: 'd1', userId, action: 'LOGIN_SUCCESS', ipAddress: null, userAgent: null, metadata: {}, orgId: null, createdAt: old,
      });
      await db.writeAuditLog({
        id: 'd2', userId, action: 'LOGIN_SUCCESS', ipAddress: null, userAgent: null, metadata: {}, orgId: null, createdAt: recent,
      });

      const result = await db.queryAuditLog({ startDate: new Date('2025-01-01') });
      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].id).toBe('d2');

      const result2 = await db.queryAuditLog({ endDate: new Date('2024-06-01') });
      expect(result2.entries).toHaveLength(1);
      expect(result2.entries[0].id).toBe('d1');
    });

    it('should support limit and offset', async () => {
      for (let i = 0; i < 10; i++) {
        await db.writeAuditLog({
          id: `l${i}`, userId, action: 'LOGIN_SUCCESS', ipAddress: null, userAgent: null, metadata: {}, orgId: null, createdAt: new Date(),
        });
      }

      const page1 = await db.queryAuditLog({ limit: 3, offset: 0 });
      expect(page1.entries).toHaveLength(3);
      expect(page1.total).toBe(10);

      const page2 = await db.queryAuditLog({ limit: 3, offset: 3 });
      expect(page2.entries).toHaveLength(3);
    });
  });

  // ─── Organizations ────────────────────────────────────────────────────────

  describe('Organizations', () => {
    let ownerId: string;

    beforeEach(async () => {
      const user = await db.createUser({ email: 'jack@example.com', passwordHash: 'hash', displayName: 'Jack' });
      ownerId = user.id;
    });

    const orgInput = (uid: string): CreateOrgInput => ({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: uid,
    });

    it('should create and get an organization', async () => {
      const org = await db.createOrganization(orgInput(ownerId));
      expect(org.id).toBeDefined();
      expect(org.name).toBe('Acme Corp');
      expect(org.slug).toBe('acme-corp');

      const found = await db.getOrganization(org.id);
      expect(found).not.toBeNull();
      expect(found!.name).toBe('Acme Corp');
    });

    it('should update an organization', async () => {
      const org = await db.createOrganization(orgInput(ownerId));
      const updated = await db.updateOrganization(org.id, { name: 'Acme Inc' });
      expect(updated.name).toBe('Acme Inc');
      expect(updated.slug).toBe('acme-corp');
    });

    it('should delete an organization', async () => {
      const org = await db.createOrganization(orgInput(ownerId));
      await db.deleteOrganization(org.id);

      const found = await db.getOrganization(org.id);
      expect(found).toBeNull();
    });

    it('should manage org members', async () => {
      const org = await db.createOrganization(orgInput(ownerId));
      const member = await db.addOrgMember({ userId: ownerId, orgId: org.id, role: 'owner' });
      expect(member.userId).toBe(ownerId);
      expect(member.role).toBe('owner');

      const user2 = await db.createUser({ email: 'kate@example.com', passwordHash: 'hash', displayName: 'Kate' });
      await db.addOrgMember({ userId: user2.id, orgId: org.id, role: 'member' });

      const members = await db.listOrgMembers(org.id);
      expect(members).toHaveLength(2);

      const updated = await db.updateOrgMember(org.id, user2.id, { role: 'admin' });
      expect(updated.role).toBe('admin');

      await db.removeOrgMember(org.id, user2.id);
      const remaining = await db.listOrgMembers(org.id);
      expect(remaining).toHaveLength(1);
    });

    it('should manage org invites', async () => {
      const org = await db.createOrganization(orgInput(ownerId));
      const invite = await db.createOrgInvite({
        orgId: org.id,
        email: 'invited@example.com',
        role: 'member',
        invitedBy: ownerId,
        token: 'invite-token-1',
        expiresAt: new Date(Date.now() + 86400_000),
      });
      expect(invite.id).toBeDefined();

      const found = await db.findOrgInviteByToken('invite-token-1');
      expect(found).not.toBeNull();
      expect(found!.email).toBe('invited@example.com');

      const pending = await db.listPendingInvites(org.id);
      expect(pending).toHaveLength(1);

      await db.acceptOrgInvite(invite.id);
      const accepted = await db.findOrgInviteByToken('invite-token-1');
      expect(accepted!.acceptedAt).toBeInstanceOf(Date);

      // Accepted invite should not be pending
      const pendingAfter = await db.listPendingInvites(org.id);
      expect(pendingAfter).toHaveLength(0);
    });
  });

  // ─── API Keys ─────────────────────────────────────────────────────────────

  describe('API Keys', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await db.createUser({ email: 'leo@example.com', passwordHash: 'hash', displayName: 'Leo' });
      userId = user.id;
    });

    const apiKeyInput = (uid: string, opts?: Partial<CreateApiKeyInput>): CreateApiKeyInput => ({
      name: 'My Key',
      keyPrefix: 'ak_',
      keyHash: 'keyhash-' + Math.random().toString(36).slice(2),
      userId: uid,
      permissions: ['read', 'write'],
      ...opts,
    });

    it('should create and find by hash', async () => {
      const key = await db.createApiKey(apiKeyInput(userId, { keyHash: 'find-me' }));
      expect(key.id).toBeDefined();
      expect(key.name).toBe('My Key');

      const found = await db.findApiKeyByHash('find-me');
      expect(found).not.toBeNull();
      expect(found!.id).toBe(key.id);
    });

    it('should list API keys for a user', async () => {
      await db.createApiKey(apiKeyInput(userId, { keyHash: 'kh1' }));
      await db.createApiKey(apiKeyInput(userId, { keyHash: 'kh2', name: 'Key 2' }));

      const keys = await db.listApiKeys(userId);
      expect(keys).toHaveLength(2);
    });

    it('should revoke an API key', async () => {
      const key = await db.createApiKey(apiKeyInput(userId, { keyHash: 'revoke-me' }));
      await db.revokeApiKey(key.id);

      const found = await db.findApiKeyByHash('revoke-me');
      expect(found!.revokedAt).toBeInstanceOf(Date);
    });

    it('should update last used timestamp', async () => {
      const key = await db.createApiKey(apiKeyInput(userId, { keyHash: 'usage' }));
      expect(key.lastUsedAt).toBeNull();

      await db.updateApiKeyLastUsed(key.id);

      const found = await db.findApiKeyByHash('usage');
      expect(found!.lastUsedAt).toBeInstanceOf(Date);
    });
  });

  // ─── Roles ────────────────────────────────────────────────────────────────

  describe('Roles', () => {
    const roleInput: Role = {
      name: 'admin',
      description: 'Administrator role',
      permissions: ['read', 'write', 'delete'],
      inherits: [],
      isSystem: false,
    };

    it('should create and get a role', async () => {
      const role = await db.createRole(roleInput);
      expect(role.name).toBe('admin');

      const found = await db.getRole('admin');
      expect(found).not.toBeNull();
      expect(found!.permissions).toEqual(['read', 'write', 'delete']);
    });

    it('should list all roles', async () => {
      await db.createRole(roleInput);
      await db.createRole({ ...roleInput, name: 'editor', permissions: ['read', 'write'] });

      const roles = await db.listRoles();
      expect(roles).toHaveLength(2);
    });

    it('should update a role', async () => {
      await db.createRole(roleInput);
      const updated = await db.updateRole('admin', { description: 'Super admin', permissions: ['*'] });
      expect(updated.description).toBe('Super admin');
      expect(updated.permissions).toEqual(['*']);
    });

    it('should delete a role', async () => {
      await db.createRole(roleInput);
      await db.deleteRole('admin');

      const found = await db.getRole('admin');
      expect(found).toBeNull();
    });
  });

  // ─── Access Policies ─────────────────────────────────────────────────────

  describe('Access Policies', () => {
    it('should create and list policies', async () => {
      const policy: AccessPolicy = {
        id: 'pol-1',
        name: 'Allow read',
        effect: 'allow',
        actions: ['read'],
        conditions: [],
      };
      const created = await db.createPolicy(policy);
      expect(created.id).toBe('pol-1');

      const policies = await db.listPolicies();
      expect(policies).toHaveLength(1);
    });

    it('should delete a policy', async () => {
      const policy: AccessPolicy = {
        id: 'pol-del',
        name: 'Temp policy',
        effect: 'deny',
        actions: ['delete'],
        conditions: [],
      };
      await db.createPolicy(policy);
      await db.deletePolicy('pol-del');

      const policies = await db.listPolicies();
      expect(policies).toHaveLength(0);
    });

    it('should handle multiple policies', async () => {
      await db.createPolicy({ id: 'p1', name: 'P1', effect: 'allow', actions: ['read'], conditions: [] });
      await db.createPolicy({ id: 'p2', name: 'P2', effect: 'deny', actions: ['write'], conditions: [] });
      await db.createPolicy({ id: 'p3', name: 'P3', effect: 'allow', actions: ['*'], conditions: [] });

      const policies = await db.listPolicies();
      expect(policies).toHaveLength(3);

      await db.deletePolicy('p2');
      const remaining = await db.listPolicies();
      expect(remaining).toHaveLength(2);
    });
  });

  // ─── Webhooks ─────────────────────────────────────────────────────────────

  describe('Webhooks', () => {
    it('should create and list webhooks', async () => {
      const webhook = await db.createWebhook({
        url: 'https://example.com/hook',
        events: ['user.created'],
        secret: 'wh-secret',
      });
      expect(webhook.id).toBeDefined();
      expect(webhook.active).toBe(true);
      expect(webhook.failureCount).toBe(0);

      const list = await db.listWebhooks();
      expect(list).toHaveLength(1);
    });

    it('should update a webhook', async () => {
      const webhook = await db.createWebhook({
        url: 'https://example.com/hook',
        events: ['user.created'],
        secret: 'wh-secret',
      });

      const updated = await db.updateWebhook(webhook.id, { active: false, events: ['user.created', 'user.deleted'] });
      expect(updated.active).toBe(false);
      expect(updated.events).toEqual(['user.created', 'user.deleted']);
    });

    it('should track failures and reset', async () => {
      const webhook = await db.createWebhook({
        url: 'https://example.com/hook',
        events: ['user.created'],
        secret: 'wh-secret',
      });

      await db.incrementWebhookFailure(webhook.id);
      await db.incrementWebhookFailure(webhook.id);
      await db.incrementWebhookFailure(webhook.id);

      const list = await db.listWebhooks();
      expect(list[0].failureCount).toBe(3);

      await db.resetWebhookFailure(webhook.id);
      const listAfter = await db.listWebhooks();
      expect(listAfter[0].failureCount).toBe(0);
    });

    it('should delete a webhook', async () => {
      const webhook = await db.createWebhook({
        url: 'https://example.com/hook',
        events: ['user.created'],
        secret: 'wh-secret',
      });
      await db.deleteWebhook(webhook.id);

      const list = await db.listWebhooks();
      expect(list).toHaveLength(0);
    });

    it('should filter webhooks by orgId', async () => {
      await db.createWebhook({ url: 'https://a.com/hook', events: ['e1'], secret: 's1', orgId: 'org-1' });
      await db.createWebhook({ url: 'https://b.com/hook', events: ['e2'], secret: 's2', orgId: 'org-2' });
      await db.createWebhook({ url: 'https://c.com/hook', events: ['e3'], secret: 's3' });

      const org1 = await db.listWebhooks('org-1');
      expect(org1).toHaveLength(1);
      expect(org1[0].url).toBe('https://a.com/hook');
    });
  });

  // ─── Trusted Devices ─────────────────────────────────────────────────────

  describe('Trusted Devices', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await db.createUser({ email: 'mary@example.com', passwordHash: 'hash', displayName: 'Mary' });
      userId = user.id;
    });

    const device = (uid: string, opts?: Partial<TrustedDevice>): TrustedDevice => ({
      id: 'dev-' + Math.random().toString(36).slice(2),
      userId: uid,
      fingerprint: 'fp-abc123',
      name: 'Chrome on Mac',
      browser: 'Chrome',
      os: 'macOS',
      lastUsedAt: new Date(),
      lastIp: '10.0.0.1',
      trustedAt: new Date(),
      ...opts,
    });

    it('should save and check trusted device', async () => {
      await db.saveTrustedDevice(device(userId, { fingerprint: 'fp-trusted' }));
      const trusted = await db.isTrustedDevice(userId, 'fp-trusted');
      expect(trusted).toBe(true);

      const notTrusted = await db.isTrustedDevice(userId, 'fp-unknown');
      expect(notTrusted).toBe(false);
    });

    it('should get all trusted devices for user', async () => {
      await db.saveTrustedDevice(device(userId, { id: 'd1', fingerprint: 'fp1' }));
      await db.saveTrustedDevice(device(userId, { id: 'd2', fingerprint: 'fp2' }));

      const devices = await db.getTrustedDevices(userId);
      expect(devices).toHaveLength(2);
    });

    it('should remove a trusted device', async () => {
      await db.saveTrustedDevice(device(userId, { id: 'to-remove', fingerprint: 'fp-rem' }));
      await db.removeTrustedDevice(userId, 'to-remove');

      const trusted = await db.isTrustedDevice(userId, 'fp-rem');
      expect(trusted).toBe(false);

      const devices = await db.getTrustedDevices(userId);
      expect(devices).toHaveLength(0);
    });
  });

  // ─── Admin ────────────────────────────────────────────────────────────────

  describe('Admin', () => {
    it('should list users with search', async () => {
      await db.createUser({ email: 'alice@example.com', passwordHash: 'h', displayName: 'Alice Smith' });
      await db.createUser({ email: 'bob@example.com', passwordHash: 'h', displayName: 'Bob Jones' });
      await db.createUser({ email: 'carol@example.com', passwordHash: 'h', displayName: 'Carol Smith' });

      const result = await db.listUsers({ search: 'smith' });
      expect(result.users).toHaveLength(2);
      expect(result.total).toBe(2);
    });

    it('should list users with pagination', async () => {
      for (let i = 0; i < 15; i++) {
        await db.createUser({ email: `user${i}@example.com`, passwordHash: 'h', displayName: `User ${i}` });
      }

      const page1 = await db.listUsers({ limit: 5, offset: 0 });
      expect(page1.users).toHaveLength(5);
      expect(page1.total).toBe(15);

      const page2 = await db.listUsers({ limit: 5, offset: 5 });
      expect(page2.users).toHaveLength(5);

      const page3 = await db.listUsers({ limit: 5, offset: 10 });
      expect(page3.users).toHaveLength(5);
    });

    it('should filter users by role and emailVerified', async () => {
      const u1 = await db.createUser({ email: 'admin1@example.com', passwordHash: 'h', displayName: 'Admin', roles: ['admin'] });
      await db.updateUser(u1.id, { emailVerified: true });
      const u2 = await db.createUser({ email: 'user1@example.com', passwordHash: 'h', displayName: 'User', roles: ['user'] });

      const admins = await db.listUsers({ role: 'admin' });
      expect(admins.users).toHaveLength(1);
      expect(admins.users[0].email).toBe('admin1@example.com');

      const verified = await db.listUsers({ emailVerified: true });
      expect(verified.users).toHaveLength(1);
    });

    it('should filter users by locked status', async () => {
      const u1 = await db.createUser({ email: 'locked@example.com', passwordHash: 'h', displayName: 'Locked' });
      await db.updateUser(u1.id, { lockedUntil: new Date(Date.now() + 3600_000) });
      await db.createUser({ email: 'unlocked@example.com', passwordHash: 'h', displayName: 'Unlocked' });

      const locked = await db.listUsers({ locked: true });
      expect(locked.users).toHaveLength(1);
      expect(locked.users[0].email).toBe('locked@example.com');
    });

    it('should get system stats', async () => {
      await db.createUser({ email: 's1@example.com', passwordHash: 'h', displayName: 'S1' });
      const u2 = await db.createUser({ email: 's2@example.com', passwordHash: 'h', displayName: 'S2' });
      await db.updateUser(u2.id, { mfaEnabled: true });
      const u3 = await db.createUser({ email: 's3@example.com', passwordHash: 'h', displayName: 'S3' });
      await db.softDeleteUser(u3.id);

      const s1 = await db.createSession({
        userId: u2.id,
        ipAddress: '10.0.0.1',
        userAgent: 'Test',
        expiresAt: new Date(Date.now() + 3600_000),
      });

      const stats = await db.getSystemStats();
      expect(stats.totalUsers).toBe(2); // excluding deleted
      expect(stats.totalSessions).toBe(1);
      expect(stats.activeSessions).toBe(1);
      expect(stats.mfaAdoptionRate).toBeGreaterThan(0);
    });

    it('should export user data', async () => {
      const user = await db.createUser({ email: 'export@example.com', passwordHash: 'h', displayName: 'Export' });
      await db.createSession({
        userId: user.id,
        ipAddress: '10.0.0.1',
        userAgent: 'Test',
        expiresAt: new Date(Date.now() + 3600_000),
      });
      await db.linkOAuthProvider({
        userId: user.id,
        provider: 'google',
        providerUserId: 'g-1',
        rawProfile: {},
      });
      await db.writeAuditLog({
        id: 'exp-audit',
        userId: user.id,
        action: 'LOGIN_SUCCESS',
        ipAddress: '10.0.0.1',
        userAgent: 'Test',
        metadata: {},
        orgId: null,
        createdAt: new Date(),
      });

      const exported = await db.exportUserData(user.id);
      expect(exported.user).toBeDefined();
      expect((exported.user as any).email).toBe('export@example.com');
      expect(exported.sessions).toHaveLength(1);
      expect(exported.oauthProviders).toHaveLength(1);
      expect(exported.auditLog).toHaveLength(1);
    });

    it('should filter users by orgId', async () => {
      await db.createUser({ email: 'org1@example.com', passwordHash: 'h', displayName: 'Org1', orgId: 'org-a' });
      await db.createUser({ email: 'org2@example.com', passwordHash: 'h', displayName: 'Org2', orgId: 'org-b' });

      const result = await db.listUsers({ orgId: 'org-a' });
      expect(result.users).toHaveLength(1);
      expect(result.users[0].email).toBe('org1@example.com');
    });

    it('should filter by mfaEnabled', async () => {
      const u1 = await db.createUser({ email: 'mfa1@example.com', passwordHash: 'h', displayName: 'MFA1' });
      await db.updateUser(u1.id, { mfaEnabled: true });
      await db.createUser({ email: 'nomfa@example.com', passwordHash: 'h', displayName: 'NoMFA' });

      const mfaUsers = await db.listUsers({ mfaEnabled: true });
      expect(mfaUsers.users).toHaveLength(1);
      expect(mfaUsers.users[0].email).toBe('mfa1@example.com');
    });
  });
});
