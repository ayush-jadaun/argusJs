import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { PostgresAdapter } from '../postgres-adapter.js';

describe('PostgresAdapter (integration)', () => {
  let db: PostgresAdapter;

  beforeAll(async () => {
    db = new PostgresAdapter({
      connectionString: 'postgres://postgres:postgres@localhost:5434/postgres',
    });
    await db.init();
  });

  afterAll(async () => {
    await db.shutdown();
  });

  // Before each test, clean all tables
  beforeEach(async () => {
    await db.truncateAll();
  });

  describe('Users', () => {
    it('should create and find user by id', async () => {
      const user = await db.createUser({
        email: 'test@example.com',
        passwordHash: 'hash123',
        displayName: 'Test User',
      });
      expect(user.id).toBeDefined();
      expect(user.email).toBe('test@example.com');
      const found = await db.findUserById(user.id);
      expect(found).not.toBeNull();
      expect(found!.email).toBe('test@example.com');
    });

    it('should find user by email case-insensitively', async () => {
      await db.createUser({ email: 'Alice@Example.COM', passwordHash: 'h', displayName: 'Alice' });
      const found = await db.findUserByEmail('alice@example.com');
      expect(found).not.toBeNull();
    });

    it('should soft delete and not find deleted users', async () => {
      const user = await db.createUser({ email: 'del@test.com', passwordHash: 'h', displayName: 'Del' });
      await db.softDeleteUser(user.id);
      expect(await db.findUserById(user.id)).toBeNull();
      expect(await db.findUserByEmail('del@test.com')).toBeNull();
    });

    it('should update user', async () => {
      const user = await db.createUser({ email: 'upd@test.com', passwordHash: 'h', displayName: 'Old' });
      const updated = await db.updateUser(user.id, { displayName: 'New' });
      expect(updated.displayName).toBe('New');
    });
  });

  describe('Sessions', () => {
    it('should create and get active sessions', async () => {
      const user = await db.createUser({ email: 'sess@test.com', passwordHash: 'h', displayName: 'S' });
      const session = await db.createSession({
        userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test',
        expiresAt: new Date(Date.now() + 86400000),
      });
      expect(session.id).toBeDefined();
      const active = await db.getActiveSessions(user.id);
      expect(active.length).toBe(1);
    });

    it('should revoke session', async () => {
      const user = await db.createUser({ email: 'rev@test.com', passwordHash: 'h', displayName: 'R' });
      const session = await db.createSession({
        userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test',
        expiresAt: new Date(Date.now() + 86400000),
      });
      await db.revokeSession(session.id, 'logout');
      const active = await db.getActiveSessions(user.id);
      expect(active.length).toBe(0);
    });
  });

  describe('Refresh Tokens', () => {
    it('should create and find by hash', async () => {
      const user = await db.createUser({ email: 'rt@test.com', passwordHash: 'h', displayName: 'RT' });
      const session = await db.createSession({
        userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test',
        expiresAt: new Date(Date.now() + 86400000),
      });
      const token = await db.createRefreshToken({
        userId: user.id, sessionId: session.id, tokenHash: 'abc123',
        family: 'fam-1', generation: 0, expiresAt: new Date(Date.now() + 86400000),
      });
      const found = await db.findRefreshTokenByHash('abc123');
      expect(found).not.toBeNull();
      expect(found!.family).toBe('fam-1');
    });

    it('should revoke token family', async () => {
      const user = await db.createUser({ email: 'rtf@test.com', passwordHash: 'h', displayName: 'RTF' });
      const session = await db.createSession({
        userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test',
        expiresAt: new Date(Date.now() + 86400000),
      });
      await db.createRefreshToken({ userId: user.id, sessionId: session.id, tokenHash: 'h1', family: 'fam-x', generation: 0, expiresAt: new Date(Date.now() + 86400000) });
      await db.createRefreshToken({ userId: user.id, sessionId: session.id, tokenHash: 'h2', family: 'fam-x', generation: 1, expiresAt: new Date(Date.now() + 86400000) });
      await db.revokeTokenFamily('fam-x', 'reuse_detected');
      expect(await db.findRefreshTokenByHash('h1')).toBeNull();
      expect(await db.findRefreshTokenByHash('h2')).toBeNull();
    });
  });

  describe('Audit Log', () => {
    it('should write and query', async () => {
      const user = await db.createUser({ email: 'audit@test.com', passwordHash: 'h', displayName: 'A' });
      await db.writeAuditLog({ id: 'al-1', userId: user.id, action: 'LOGIN_SUCCESS', ipAddress: '1.2.3.4', userAgent: 'test', metadata: {}, orgId: null, createdAt: new Date() });
      const result = await db.queryAuditLog({ userId: user.id });
      expect(result.entries.length).toBe(1);
      expect(result.entries[0].action).toBe('LOGIN_SUCCESS');
    });
  });

  // Add at least one test per remaining domain:
  // Password Reset, Email Verification, OAuth, MFA, Password History,
  // Organizations, API Keys, Roles, Webhooks, Trusted Devices, Admin

  describe('Password Reset', () => {
    it('should create and find password reset token', async () => {
      const user = await db.createUser({ email: 'pr@test.com', passwordHash: 'h', displayName: 'PR' });
      const token = await db.createPasswordResetToken({
        userId: user.id, tokenHash: 'reset-hash-1', requestedFromIp: '1.2.3.4', expiresAt: new Date(Date.now() + 3600000),
      });
      expect(token.id).toBeDefined();
      const found = await db.findPasswordResetByHash('reset-hash-1');
      expect(found).not.toBeNull();
      expect(found!.userId).toBe(user.id);
    });

    it('should mark reset token used', async () => {
      const user = await db.createUser({ email: 'pru@test.com', passwordHash: 'h', displayName: 'PRU' });
      const token = await db.createPasswordResetToken({
        userId: user.id, tokenHash: 'reset-used', requestedFromIp: '1.2.3.4', expiresAt: new Date(Date.now() + 3600000),
      });
      await db.markResetTokenUsed(token.id);
      const found = await db.findPasswordResetByHash('reset-used');
      expect(found!.used).toBe(true);
    });
  });

  describe('Email Verification', () => {
    it('should create and find verification token', async () => {
      const user = await db.createUser({ email: 'ev@test.com', passwordHash: 'h', displayName: 'EV' });
      const token = await db.createEmailVerificationToken({
        userId: user.id, tokenHash: 'verify-hash', expiresAt: new Date(Date.now() + 3600000),
      });
      expect(token.id).toBeDefined();
      const found = await db.findVerificationByHash('verify-hash');
      expect(found).not.toBeNull();
      expect(found!.userId).toBe(user.id);
    });
  });

  describe('OAuth', () => {
    it('should link and find OAuth provider', async () => {
      const user = await db.createUser({ email: 'oauth@test.com', passwordHash: 'h', displayName: 'OAuth' });
      const link = await db.linkOAuthProvider({
        userId: user.id, provider: 'google', providerUserId: 'g-123',
        rawProfile: { name: 'Test' },
      });
      expect(link.id).toBeDefined();
      const found = await db.findOAuthProvider('google', 'g-123');
      expect(found).not.toBeNull();
      expect(found!.userId).toBe(user.id);
    });

    it('should unlink OAuth provider', async () => {
      const user = await db.createUser({ email: 'oauth2@test.com', passwordHash: 'h', displayName: 'OAuth2' });
      await db.linkOAuthProvider({
        userId: user.id, provider: 'github', providerUserId: 'gh-123',
        rawProfile: {},
      });
      await db.unlinkOAuthProvider(user.id, 'github');
      const found = await db.findOAuthProvider('github', 'gh-123');
      expect(found).toBeNull();
    });
  });

  describe('MFA', () => {
    it('should save and get MFA secret', async () => {
      const user = await db.createUser({ email: 'mfa@test.com', passwordHash: 'h', displayName: 'MFA' });
      const mfa = await db.saveMFASecret({
        userId: user.id, method: 'totp', encryptedSecret: 'enc-secret',
        encryptedBackupCodes: ['c1', 'c2'], backupCodesUsed: [false, false],
      });
      expect(mfa.method).toBe('totp');
      const found = await db.getMFASecret(user.id);
      expect(found).not.toBeNull();
      expect(found!.encryptedSecret).toBe('enc-secret');
    });

    it('should mark backup code used', async () => {
      const user = await db.createUser({ email: 'mfa2@test.com', passwordHash: 'h', displayName: 'MFA2' });
      await db.saveMFASecret({
        userId: user.id, method: 'totp', encryptedSecret: 'enc',
        encryptedBackupCodes: ['c1', 'c2'], backupCodesUsed: [false, false],
      });
      await db.markBackupCodeUsed(user.id, 0);
      const mfa = await db.getMFASecret(user.id);
      expect(mfa!.backupCodesUsed[0]).toBe(true);
      expect(mfa!.backupCodesUsed[1]).toBe(false);
    });
  });

  describe('Password History', () => {
    it('should add and retrieve password history', async () => {
      const user = await db.createUser({ email: 'ph@test.com', passwordHash: 'h', displayName: 'PH' });
      await db.addPasswordHistory(user.id, 'hash-1');
      await db.addPasswordHistory(user.id, 'hash-2');
      const history = await db.getPasswordHistory(user.id, 10);
      expect(history.length).toBe(2);
      // Most recent first
      expect(history[0]).toBe('hash-2');
    });
  });

  describe('Organizations', () => {
    it('should create and get organization', async () => {
      const user = await db.createUser({ email: 'org@test.com', passwordHash: 'h', displayName: 'Org' });
      const org = await db.createOrganization({
        name: 'Test Org', slug: 'test-org', ownerId: user.id,
      });
      expect(org.id).toBeDefined();
      const found = await db.getOrganization(org.id);
      expect(found).not.toBeNull();
      expect(found!.name).toBe('Test Org');
    });

    it('should add and list org members', async () => {
      const user = await db.createUser({ email: 'orgm@test.com', passwordHash: 'h', displayName: 'OrgM' });
      const org = await db.createOrganization({
        name: 'Members Org', slug: 'members-org', ownerId: user.id,
      });
      await db.addOrgMember({ userId: user.id, orgId: org.id, role: 'owner' });
      const members = await db.listOrgMembers(org.id);
      expect(members.length).toBe(1);
      expect(members[0].role).toBe('owner');
    });
  });

  describe('Org Invites', () => {
    it('should create and find invite by token', async () => {
      const user = await db.createUser({ email: 'inv@test.com', passwordHash: 'h', displayName: 'Inv' });
      const org = await db.createOrganization({
        name: 'Invite Org', slug: 'invite-org', ownerId: user.id,
      });
      const invite = await db.createOrgInvite({
        orgId: org.id, email: 'invitee@test.com', role: 'member',
        invitedBy: user.id, token: 'invite-token-123', expiresAt: new Date(Date.now() + 86400000),
      });
      const found = await db.findOrgInviteByToken('invite-token-123');
      expect(found).not.toBeNull();
      expect(found!.email).toBe('invitee@test.com');
    });
  });

  describe('API Keys', () => {
    it('should create and find API key by hash', async () => {
      const user = await db.createUser({ email: 'ak@test.com', passwordHash: 'h', displayName: 'AK' });
      const key = await db.createApiKey({
        name: 'Test Key', keyPrefix: 'ak_', keyHash: 'key-hash-123',
        userId: user.id, permissions: ['read'],
      });
      expect(key.id).toBeDefined();
      const found = await db.findApiKeyByHash('key-hash-123');
      expect(found).not.toBeNull();
      expect(found!.name).toBe('Test Key');
    });

    it('should revoke API key', async () => {
      const user = await db.createUser({ email: 'akr@test.com', passwordHash: 'h', displayName: 'AKR' });
      const key = await db.createApiKey({
        name: 'Revoke Key', keyPrefix: 'ak_', keyHash: 'key-revoke',
        userId: user.id, permissions: ['read'],
      });
      await db.revokeApiKey(key.id);
      const found = await db.findApiKeyByHash('key-revoke');
      expect(found!.revokedAt).not.toBeNull();
    });
  });

  describe('Roles', () => {
    it('should create and get role', async () => {
      const role = await db.createRole({
        name: 'editor', description: 'Can edit', permissions: ['edit'],
        inherits: ['viewer'], isSystem: false,
      });
      expect(role.name).toBe('editor');
      const found = await db.getRole('editor');
      expect(found).not.toBeNull();
      expect(found!.permissions).toEqual(['edit']);
    });

    it('should list and delete roles', async () => {
      await db.createRole({ name: 'r1', description: '', permissions: [], inherits: [], isSystem: false });
      await db.createRole({ name: 'r2', description: '', permissions: [], inherits: [], isSystem: false });
      const list = await db.listRoles();
      expect(list.length).toBe(2);
      await db.deleteRole('r1');
      const afterDelete = await db.listRoles();
      expect(afterDelete.length).toBe(1);
    });
  });

  describe('Access Policies', () => {
    it('should create and list policies', async () => {
      await db.createPolicy({
        id: 'pol-1', name: 'Allow Read', effect: 'allow',
        actions: ['read'], conditions: [],
      });
      const list = await db.listPolicies();
      expect(list.length).toBe(1);
      expect(list[0].name).toBe('Allow Read');
    });
  });

  describe('Webhooks', () => {
    it('should create and list webhooks', async () => {
      const webhook = await db.createWebhook({
        url: 'https://example.com/hook', events: ['user.created'],
        secret: 'wh-secret',
      });
      expect(webhook.id).toBeDefined();
      const list = await db.listWebhooks();
      expect(list.length).toBe(1);
    });

    it('should increment and reset failure count', async () => {
      const webhook = await db.createWebhook({
        url: 'https://example.com/hook2', events: ['user.deleted'],
        secret: 'wh-secret-2',
      });
      await db.incrementWebhookFailure(webhook.id);
      await db.incrementWebhookFailure(webhook.id);
      let list = await db.listWebhooks();
      expect(list[0].failureCount).toBe(2);
      await db.resetWebhookFailure(webhook.id);
      list = await db.listWebhooks();
      expect(list[0].failureCount).toBe(0);
    });
  });

  describe('Trusted Devices', () => {
    it('should save and check trusted device', async () => {
      const user = await db.createUser({ email: 'td@test.com', passwordHash: 'h', displayName: 'TD' });
      const now = new Date();
      await db.saveTrustedDevice({
        id: 'dev-1', userId: user.id, fingerprint: 'fp-123',
        name: 'Chrome', browser: 'Chrome', os: 'Windows',
        lastUsedAt: now, lastIp: '1.2.3.4', trustedAt: now,
      });
      const isTrusted = await db.isTrustedDevice(user.id, 'fp-123');
      expect(isTrusted).toBe(true);
      const isNotTrusted = await db.isTrustedDevice(user.id, 'fp-other');
      expect(isNotTrusted).toBe(false);
    });

    it('should remove trusted device', async () => {
      const user = await db.createUser({ email: 'td2@test.com', passwordHash: 'h', displayName: 'TD2' });
      const now = new Date();
      await db.saveTrustedDevice({
        id: 'dev-2', userId: user.id, fingerprint: 'fp-456',
        name: 'Firefox', browser: 'Firefox', os: 'Linux',
        lastUsedAt: now, lastIp: '5.6.7.8', trustedAt: now,
      });
      await db.removeTrustedDevice(user.id, 'dev-2');
      const devices = await db.getTrustedDevices(user.id);
      expect(devices.length).toBe(0);
    });
  });

  describe('Admin', () => {
    it('should list users with filters', async () => {
      await db.createUser({ email: 'admin1@test.com', passwordHash: 'h', displayName: 'Admin One' });
      await db.createUser({ email: 'admin2@test.com', passwordHash: 'h', displayName: 'Admin Two' });
      const result = await db.listUsers({ search: 'admin' });
      expect(result.total).toBe(2);
      expect(result.users.length).toBe(2);
    });

    it('should get system stats', async () => {
      await db.createUser({ email: 'stat@test.com', passwordHash: 'h', displayName: 'Stat' });
      const stats = await db.getSystemStats();
      expect(stats.totalUsers).toBe(1);
      expect(stats.activeSessions).toBe(0);
    });

    it('should export user data', async () => {
      const user = await db.createUser({ email: 'export@test.com', passwordHash: 'h', displayName: 'Export' });
      const data = await db.exportUserData(user.id);
      expect(data.user).toBeDefined();
      expect(data.sessions).toEqual([]);
    });
  });
});
