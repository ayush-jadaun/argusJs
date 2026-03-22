import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { MongoDbAdapter } from '../mongodb-adapter.js';

const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost:27017';
const DB_NAME = 'argus_test_' + Date.now();

describe('MongoDbAdapter', () => {
  let db: MongoDbAdapter;
  let connected = false;

  beforeAll(async () => {
    try {
      db = new MongoDbAdapter({ url: MONGO_URL, dbName: DB_NAME });
      await db.init();
      connected = true;
    } catch {
      console.warn('MongoDB not available, skipping integration tests');
    }
  });

  afterAll(async () => {
    if (connected) {
      await db.truncateAll();
      await db.shutdown();
    }
  });

  beforeEach(async () => {
    if (!connected) return;
    await db.truncateAll();
  });

  describe('Users', () => {
    it('should create and find user by id', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'test@example.com', passwordHash: 'hash', displayName: 'Test' });
      expect(user.id).toBeDefined();
      const found = await db.findUserById(user.id);
      expect(found).not.toBeNull();
      expect(found!.email).toBe('test@example.com');
    });

    it('should find by email case-insensitively', async () => {
      if (!connected) return;
      await db.createUser({ email: 'Alice@Example.COM', passwordHash: 'h', displayName: 'Alice' });
      const found = await db.findUserByEmail('alice@example.com');
      expect(found).not.toBeNull();
    });

    it('should soft delete', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'del@test.com', passwordHash: 'h', displayName: 'Del' });
      await db.softDeleteUser(user.id);
      expect(await db.findUserById(user.id)).toBeNull();
    });

    it('should update user', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'upd@test.com', passwordHash: 'h', displayName: 'Old' });
      const updated = await db.updateUser(user.id, { displayName: 'New' });
      expect(updated.displayName).toBe('New');
    });

    it('should reject duplicate email', async () => {
      if (!connected) return;
      await db.createUser({ email: 'dup@test.com', passwordHash: 'h', displayName: 'A' });
      await expect(db.createUser({ email: 'dup@test.com', passwordHash: 'h', displayName: 'B' }))
        .rejects.toThrow(/already exists/);
    });
  });

  describe('Sessions', () => {
    it('should create and get active sessions', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 's@test.com', passwordHash: 'h', displayName: 'S' });
      await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
      const sessions = await db.getActiveSessions(user.id);
      expect(sessions.length).toBe(1);
    });

    it('should revoke session', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'r@test.com', passwordHash: 'h', displayName: 'R' });
      const session = await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
      await db.revokeSession(session.id, 'logout');
      const active = await db.getActiveSessions(user.id);
      expect(active.length).toBe(0);
    });

    it('should get session by id', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'gs@test.com', passwordHash: 'h', displayName: 'GS' });
      const session = await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
      const found = await db.getSession(session.id);
      expect(found).not.toBeNull();
      expect(found!.userId).toBe(user.id);
    });

    it('should revoke all sessions', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'ra@test.com', passwordHash: 'h', displayName: 'RA' });
      const s1 = await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
      await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test2', expiresAt: new Date(Date.now() + 86400000) });
      await db.revokeAllSessions(user.id, 'logout-all', s1.id);
      const active = await db.getActiveSessions(user.id);
      expect(active.length).toBe(1);
      expect(active[0].id).toBe(s1.id);
    });

    it('should count active sessions', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'cas@test.com', passwordHash: 'h', displayName: 'CAS' });
      await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
      await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test2', expiresAt: new Date(Date.now() + 86400000) });
      const count = await db.countActiveSessions(user.id);
      expect(count).toBe(2);
    });
  });

  describe('Refresh Tokens', () => {
    it('should create and find by hash', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'rt@test.com', passwordHash: 'h', displayName: 'RT' });
      const session = await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
      await db.createRefreshToken({ userId: user.id, sessionId: session.id, tokenHash: 'abc', family: 'f1', generation: 0, expiresAt: new Date(Date.now() + 86400000) });
      const found = await db.findRefreshTokenByHash('abc');
      expect(found).not.toBeNull();
    });

    it('should revoke token family', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'rtf@test.com', passwordHash: 'h', displayName: 'RTF' });
      const session = await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
      await db.createRefreshToken({ userId: user.id, sessionId: session.id, tokenHash: 'h1', family: 'fx', generation: 0, expiresAt: new Date(Date.now() + 86400000) });
      await db.createRefreshToken({ userId: user.id, sessionId: session.id, tokenHash: 'h2', family: 'fx', generation: 1, expiresAt: new Date(Date.now() + 86400000) });
      await db.revokeTokenFamily('fx', 'reuse');
      // Both should now show as revoked (findByHash returns revoked tokens too)
      const t1 = await db.findRefreshTokenByHash('h1');
      const t2 = await db.findRefreshTokenByHash('h2');
      expect(t1!.revoked).toBe(true);
      expect(t2!.revoked).toBe(true);
    });

    it('should atomically revoke if active', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'atomic@test.com', passwordHash: 'h', displayName: 'A' });
      const session = await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
      const token = await db.createRefreshToken({ userId: user.id, sessionId: session.id, tokenHash: 'at1', family: 'af', generation: 0, expiresAt: new Date(Date.now() + 86400000) });
      const first = await db.revokeRefreshTokenIfActive(token.id, 'rotated');
      expect(first).toBe(true);
      const second = await db.revokeRefreshTokenIfActive(token.id, 'rotated');
      expect(second).toBe(false);
    });

    it('should revoke all user tokens', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'raut@test.com', passwordHash: 'h', displayName: 'RAUT' });
      const session = await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
      await db.createRefreshToken({ userId: user.id, sessionId: session.id, tokenHash: 'ut1', family: 'uf1', generation: 0, expiresAt: new Date(Date.now() + 86400000) });
      await db.createRefreshToken({ userId: user.id, sessionId: session.id, tokenHash: 'ut2', family: 'uf2', generation: 0, expiresAt: new Date(Date.now() + 86400000) });
      await db.revokeAllUserTokens(user.id, 'logout-all');
      const t1 = await db.findRefreshTokenByHash('ut1');
      const t2 = await db.findRefreshTokenByHash('ut2');
      expect(t1!.revoked).toBe(true);
      expect(t2!.revoked).toBe(true);
    });
  });

  describe('Password Reset', () => {
    it('should create and find by hash', async () => {
      if (!connected) return;
      const token = await db.createPasswordResetToken({ userId: 'u1', tokenHash: 'rh1', requestedFromIp: '1.2.3.4', expiresAt: new Date(Date.now() + 86400000) });
      const found = await db.findPasswordResetByHash('rh1');
      expect(found).not.toBeNull();
      expect(found!.id).toBe(token.id);
    });

    it('should mark token used', async () => {
      if (!connected) return;
      const token = await db.createPasswordResetToken({ userId: 'u1', tokenHash: 'rh2', requestedFromIp: '1.2.3.4', expiresAt: new Date(Date.now() + 86400000) });
      await db.markResetTokenUsed(token.id);
      const found = await db.findPasswordResetByHash('rh2');
      expect(found!.used).toBe(true);
    });

    it('should invalidate all user reset tokens', async () => {
      if (!connected) return;
      await db.createPasswordResetToken({ userId: 'u2', tokenHash: 'rh3', requestedFromIp: '1.2.3.4', expiresAt: new Date(Date.now() + 86400000) });
      await db.createPasswordResetToken({ userId: 'u2', tokenHash: 'rh4', requestedFromIp: '1.2.3.4', expiresAt: new Date(Date.now() + 86400000) });
      await db.invalidateUserResetTokens('u2');
      const t1 = await db.findPasswordResetByHash('rh3');
      const t2 = await db.findPasswordResetByHash('rh4');
      expect(t1!.used).toBe(true);
      expect(t2!.used).toBe(true);
    });
  });

  describe('Email Verification', () => {
    it('should create and find by hash', async () => {
      if (!connected) return;
      const token = await db.createEmailVerificationToken({ userId: 'u1', tokenHash: 'vh1', expiresAt: new Date(Date.now() + 86400000) });
      const found = await db.findVerificationByHash('vh1');
      expect(found).not.toBeNull();
      expect(found!.id).toBe(token.id);
    });

    it('should mark verification used', async () => {
      if (!connected) return;
      const token = await db.createEmailVerificationToken({ userId: 'u1', tokenHash: 'vh2', expiresAt: new Date(Date.now() + 86400000) });
      await db.markVerificationUsed(token.id);
      const found = await db.findVerificationByHash('vh2');
      expect(found!.used).toBe(true);
    });
  });

  describe('OAuth', () => {
    it('should link and find provider', async () => {
      if (!connected) return;
      await db.linkOAuthProvider({ userId: 'u1', provider: 'google', providerUserId: 'g123', rawProfile: {} });
      const found = await db.findOAuthProvider('google', 'g123');
      expect(found).not.toBeNull();
      expect(found!.userId).toBe('u1');
    });

    it('should get user providers', async () => {
      if (!connected) return;
      await db.linkOAuthProvider({ userId: 'u1', provider: 'google', providerUserId: 'g1', rawProfile: {} });
      await db.linkOAuthProvider({ userId: 'u1', provider: 'github', providerUserId: 'gh1', rawProfile: {} });
      const providers = await db.getUserOAuthProviders('u1');
      expect(providers.length).toBe(2);
    });

    it('should unlink provider', async () => {
      if (!connected) return;
      await db.linkOAuthProvider({ userId: 'u1', provider: 'google', providerUserId: 'g2', rawProfile: {} });
      await db.unlinkOAuthProvider('u1', 'google');
      const found = await db.findOAuthProvider('google', 'g2');
      expect(found).toBeNull();
    });
  });

  describe('MFA', () => {
    it('should save and get MFA secret', async () => {
      if (!connected) return;
      await db.saveMFASecret({ userId: 'u1', method: 'totp', encryptedSecret: 'sec', encryptedBackupCodes: ['b1', 'b2'], backupCodesUsed: [false, false] });
      const mfa = await db.getMFASecret('u1');
      expect(mfa).not.toBeNull();
      expect(mfa!.method).toBe('totp');
    });

    it('should delete MFA secret', async () => {
      if (!connected) return;
      await db.saveMFASecret({ userId: 'u2', method: 'totp', encryptedSecret: 'sec', encryptedBackupCodes: ['b1'], backupCodesUsed: [false] });
      await db.deleteMFASecret('u2');
      expect(await db.getMFASecret('u2')).toBeNull();
    });

    it('should mark backup code used', async () => {
      if (!connected) return;
      await db.saveMFASecret({ userId: 'u3', method: 'totp', encryptedSecret: 'sec', encryptedBackupCodes: ['b1', 'b2'], backupCodesUsed: [false, false] });
      await db.markBackupCodeUsed('u3', 0);
      const mfa = await db.getMFASecret('u3');
      expect(mfa!.backupCodesUsed[0]).toBe(true);
      expect(mfa!.backupCodesUsed[1]).toBe(false);
    });
  });

  describe('Password History', () => {
    it('should add and get password history', async () => {
      if (!connected) return;
      await db.addPasswordHistory('u1', 'hash1');
      await db.addPasswordHistory('u1', 'hash2');
      await db.addPasswordHistory('u1', 'hash3');
      const history = await db.getPasswordHistory('u1', 2);
      expect(history.length).toBe(2);
    });
  });

  describe('Audit Log', () => {
    it('should write and query', async () => {
      if (!connected) return;
      await db.writeAuditLog({ id: 'a1', userId: 'u1', action: 'LOGIN_SUCCESS', ipAddress: '1.2.3.4', userAgent: 'test', metadata: {}, orgId: null, createdAt: new Date() });
      const result = await db.queryAuditLog({ userId: 'u1' });
      expect(result.entries.length).toBe(1);
      expect(result.entries[0].action).toBe('LOGIN_SUCCESS');
    });

    it('should filter by action', async () => {
      if (!connected) return;
      await db.writeAuditLog({ id: 'a2', userId: 'u1', action: 'LOGIN_SUCCESS', ipAddress: '1.2.3.4', userAgent: 'test', metadata: {}, orgId: null, createdAt: new Date() });
      await db.writeAuditLog({ id: 'a3', userId: 'u1', action: 'LOGOUT', ipAddress: '1.2.3.4', userAgent: 'test', metadata: {}, orgId: null, createdAt: new Date() });
      const result = await db.queryAuditLog({ userId: 'u1', action: 'LOGOUT' });
      expect(result.entries.length).toBe(1);
      expect(result.total).toBe(1);
    });

    it('should paginate', async () => {
      if (!connected) return;
      for (let i = 0; i < 10; i++) {
        await db.writeAuditLog({ id: `ap${i}`, userId: 'u1', action: 'LOGIN_SUCCESS', ipAddress: '1.2.3.4', userAgent: 'test', metadata: {}, orgId: null, createdAt: new Date() });
      }
      const result = await db.queryAuditLog({ userId: 'u1', limit: 3, offset: 0 });
      expect(result.entries.length).toBe(3);
      expect(result.total).toBe(10);
    });
  });

  describe('Organizations', () => {
    it('should create and get org', async () => {
      if (!connected) return;
      const org = await db.createOrganization({ name: 'Acme', slug: 'acme', ownerId: 'u1' });
      expect(org.id).toBeDefined();
      const found = await db.getOrganization(org.id);
      expect(found!.name).toBe('Acme');
    });

    it('should update org', async () => {
      if (!connected) return;
      const org = await db.createOrganization({ name: 'Old', slug: 'old-org', ownerId: 'u1' });
      const updated = await db.updateOrganization(org.id, { name: 'New' });
      expect(updated.name).toBe('New');
    });

    it('should delete org', async () => {
      if (!connected) return;
      const org = await db.createOrganization({ name: 'Del', slug: 'del-org', ownerId: 'u1' });
      await db.deleteOrganization(org.id);
      expect(await db.getOrganization(org.id)).toBeNull();
    });

    it('should manage org members', async () => {
      if (!connected) return;
      const org = await db.createOrganization({ name: 'Mem', slug: 'mem-org', ownerId: 'u1' });
      await db.addOrgMember({ orgId: org.id, userId: 'u1', role: 'owner' });
      await db.addOrgMember({ orgId: org.id, userId: 'u2', role: 'member' });
      const members = await db.listOrgMembers(org.id);
      expect(members.length).toBe(2);
      await db.updateOrgMember(org.id, 'u2', { role: 'admin' });
      const updated = await db.listOrgMembers(org.id);
      expect(updated.find(m => m.userId === 'u2')!.role).toBe('admin');
      await db.removeOrgMember(org.id, 'u2');
      const afterRemove = await db.listOrgMembers(org.id);
      expect(afterRemove.length).toBe(1);
    });
  });

  describe('Org Invites', () => {
    it('should create and find invite by token', async () => {
      if (!connected) return;
      const invite = await db.createOrgInvite({ orgId: 'o1', email: 'inv@test.com', role: 'member', invitedBy: 'u1', token: 'tok1', expiresAt: new Date(Date.now() + 86400000) });
      const found = await db.findOrgInviteByToken('tok1');
      expect(found).not.toBeNull();
      expect(found!.id).toBe(invite.id);
    });

    it('should accept invite', async () => {
      if (!connected) return;
      const invite = await db.createOrgInvite({ orgId: 'o1', email: 'acc@test.com', role: 'member', invitedBy: 'u1', token: 'tok2', expiresAt: new Date(Date.now() + 86400000) });
      await db.acceptOrgInvite(invite.id);
      const found = await db.findOrgInviteByToken('tok2');
      expect(found!.acceptedAt).not.toBeNull();
    });

    it('should list pending invites', async () => {
      if (!connected) return;
      await db.createOrgInvite({ orgId: 'o2', email: 'p1@test.com', role: 'member', invitedBy: 'u1', token: 'tok3', expiresAt: new Date(Date.now() + 86400000) });
      await db.createOrgInvite({ orgId: 'o2', email: 'p2@test.com', role: 'member', invitedBy: 'u1', token: 'tok4', expiresAt: new Date(Date.now() + 86400000) });
      const pending = await db.listPendingInvites('o2');
      expect(pending.length).toBe(2);
    });
  });

  describe('API Keys', () => {
    it('should create and find by hash', async () => {
      if (!connected) return;
      const key = await db.createApiKey({ name: 'Test', keyPrefix: 'argus_pk_', keyHash: 'keyhash1', userId: 'u1', permissions: ['read:users'] });
      const found = await db.findApiKeyByHash('keyhash1');
      expect(found).not.toBeNull();
      expect(found!.name).toBe('Test');
    });

    it('should list user api keys', async () => {
      if (!connected) return;
      await db.createApiKey({ name: 'K1', keyPrefix: 'argus_pk_', keyHash: 'kh1', userId: 'u1', permissions: ['read:users'] });
      await db.createApiKey({ name: 'K2', keyPrefix: 'argus_pk_', keyHash: 'kh2', userId: 'u1', permissions: ['write:users'] });
      const keys = await db.listApiKeys('u1');
      expect(keys.length).toBe(2);
    });

    it('should revoke api key', async () => {
      if (!connected) return;
      const key = await db.createApiKey({ name: 'Rev', keyPrefix: 'argus_pk_', keyHash: 'kh3', userId: 'u1', permissions: [] });
      await db.revokeApiKey(key.id);
      const found = await db.findApiKeyByHash('kh3');
      expect(found!.revokedAt).not.toBeNull();
    });

    it('should update last used', async () => {
      if (!connected) return;
      const key = await db.createApiKey({ name: 'Use', keyPrefix: 'argus_pk_', keyHash: 'kh4', userId: 'u1', permissions: [] });
      await db.updateApiKeyLastUsed(key.id);
      const found = await db.findApiKeyByHash('kh4');
      expect(found!.lastUsedAt).not.toBeNull();
    });
  });

  describe('Roles & Permissions', () => {
    it('should create and get role', async () => {
      if (!connected) return;
      await db.createRole({ name: 'admin', description: 'Admin role', permissions: ['*'], inherits: [], isSystem: true });
      const role = await db.getRole('admin');
      expect(role).not.toBeNull();
      expect(role!.permissions).toContain('*');
    });

    it('should list roles', async () => {
      if (!connected) return;
      await db.createRole({ name: 'user', description: 'User role', permissions: ['read'], inherits: [], isSystem: false });
      await db.createRole({ name: 'moderator', description: 'Mod role', permissions: ['read', 'write'], inherits: ['user'], isSystem: false });
      const roles = await db.listRoles();
      expect(roles.length).toBe(2);
    });

    it('should update role', async () => {
      if (!connected) return;
      await db.createRole({ name: 'editor', description: 'Edit role', permissions: ['read'], inherits: [], isSystem: false });
      const updated = await db.updateRole('editor', { permissions: ['read', 'write'] });
      expect(updated.permissions).toContain('write');
    });

    it('should delete role', async () => {
      if (!connected) return;
      await db.createRole({ name: 'temp', description: 'Temp', permissions: [], inherits: [], isSystem: false });
      await db.deleteRole('temp');
      expect(await db.getRole('temp')).toBeNull();
    });
  });

  describe('Access Policies', () => {
    it('should create and list policies', async () => {
      if (!connected) return;
      await db.createPolicy({ id: 'p1', name: 'Allow read', effect: 'allow', actions: ['read'], conditions: [] });
      await db.createPolicy({ id: 'p2', name: 'Deny write', effect: 'deny', actions: ['write'], conditions: [] });
      const policies = await db.listPolicies();
      expect(policies.length).toBe(2);
    });

    it('should delete policy', async () => {
      if (!connected) return;
      await db.createPolicy({ id: 'p3', name: 'Temp', effect: 'allow', actions: ['read'], conditions: [] });
      await db.deletePolicy('p3');
      const policies = await db.listPolicies();
      expect(policies.find(p => p.id === 'p3')).toBeUndefined();
    });
  });

  describe('Webhooks', () => {
    it('should create and list webhooks', async () => {
      if (!connected) return;
      await db.createWebhook({ url: 'https://example.com/hook', events: ['user.created'], secret: 's1' });
      const webhooks = await db.listWebhooks();
      expect(webhooks.length).toBe(1);
    });

    it('should update webhook', async () => {
      if (!connected) return;
      const wh = await db.createWebhook({ url: 'https://example.com/hook2', events: ['user.created'], secret: 's2' });
      const updated = await db.updateWebhook(wh.id, { active: false });
      expect(updated.active).toBe(false);
    });

    it('should delete webhook', async () => {
      if (!connected) return;
      const wh = await db.createWebhook({ url: 'https://example.com/hook3', events: ['user.created'], secret: 's3' });
      await db.deleteWebhook(wh.id);
      const webhooks = await db.listWebhooks();
      expect(webhooks.find(w => w.id === wh.id)).toBeUndefined();
    });

    it('should increment and reset failure count', async () => {
      if (!connected) return;
      const wh = await db.createWebhook({ url: 'https://example.com/hook4', events: ['user.created'], secret: 's4' });
      await db.incrementWebhookFailure(wh.id);
      await db.incrementWebhookFailure(wh.id);
      let found = (await db.listWebhooks()).find(w => w.id === wh.id)!;
      expect(found.failureCount).toBe(2);
      await db.resetWebhookFailure(wh.id);
      found = (await db.listWebhooks()).find(w => w.id === wh.id)!;
      expect(found.failureCount).toBe(0);
    });
  });

  describe('Trusted Devices', () => {
    it('should save and check trust', async () => {
      if (!connected) return;
      await db.saveTrustedDevice({ id: 'd1', userId: 'u1', fingerprint: 'fp1', name: 'Laptop', browser: 'Chrome', os: 'Win', lastUsedAt: new Date(), lastIp: '1.1.1.1', trustedAt: new Date() });
      expect(await db.isTrustedDevice('u1', 'fp1')).toBe(true);
      expect(await db.isTrustedDevice('u1', 'unknown')).toBe(false);
    });

    it('should get trusted devices', async () => {
      if (!connected) return;
      await db.saveTrustedDevice({ id: 'd2', userId: 'u2', fingerprint: 'fp2', name: 'Phone', browser: 'Safari', os: 'iOS', lastUsedAt: new Date(), lastIp: '2.2.2.2', trustedAt: new Date() });
      const devices = await db.getTrustedDevices('u2');
      expect(devices.length).toBe(1);
      expect(devices[0].name).toBe('Phone');
    });

    it('should remove trusted device', async () => {
      if (!connected) return;
      await db.saveTrustedDevice({ id: 'd3', userId: 'u3', fingerprint: 'fp3', name: 'Tablet', browser: 'Chrome', os: 'Android', lastUsedAt: new Date(), lastIp: '3.3.3.3', trustedAt: new Date() });
      await db.removeTrustedDevice('u3', 'd3');
      expect(await db.isTrustedDevice('u3', 'fp3')).toBe(false);
    });
  });

  describe('Admin', () => {
    it('should list users with pagination', async () => {
      if (!connected) return;
      for (let i = 0; i < 5; i++) {
        await db.createUser({ email: `user${i}@test.com`, passwordHash: 'h', displayName: `User ${i}` });
      }
      const result = await db.listUsers({ limit: 3, offset: 0 });
      expect(result.users.length).toBe(3);
      expect(result.total).toBe(5);
    });

    it('should search users', async () => {
      if (!connected) return;
      await db.createUser({ email: 'alice@test.com', passwordHash: 'h', displayName: 'Alice Wonder' });
      await db.createUser({ email: 'bob@test.com', passwordHash: 'h', displayName: 'Bob Builder' });
      const result = await db.listUsers({ search: 'alice' });
      expect(result.users.length).toBe(1);
      expect(result.users[0].email).toBe('alice@test.com');
    });

    it('should get system stats', async () => {
      if (!connected) return;
      await db.createUser({ email: 'stat@test.com', passwordHash: 'h', displayName: 'Stat' });
      const stats = await db.getSystemStats();
      expect(stats.totalUsers).toBeGreaterThanOrEqual(1);
    });

    it('should export user data', async () => {
      if (!connected) return;
      const user = await db.createUser({ email: 'export@test.com', passwordHash: 'h', displayName: 'Export' });
      await db.createSession({ userId: user.id, ipAddress: '1.2.3.4', userAgent: 'test', expiresAt: new Date(Date.now() + 86400000) });
      const data = await db.exportUserData(user.id);
      expect(data.user).toBeDefined();
      expect(data.sessions.length).toBe(1);
    });
  });
});
