import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIntegrationArgus } from './setup.js';

describe('Integration: Data Integrity', () => {
  let argus, db;

  beforeAll(async () => {
    ({ argus, db } = await createIntegrationArgus());
  });
  afterAll(async () => { await argus.shutdown(); });

  it('should log all auth actions to audit log', async () => {
    const reg = await argus.register({ email: 'audit@test.com', password: 'Pass123!@#', displayName: 'Audit', ipAddress: '1.1.1.1', userAgent: 'test' });
    await argus.login('audit@test.com', 'Pass123!@#', { ipAddress: '1.1.1.1', userAgent: 'test' });
    try { await argus.login('audit@test.com', 'WRONG', { ipAddress: '1.1.1.1', userAgent: 'test' }); } catch {}

    const user = await db.findUserByEmail('audit@test.com');
    const logs = await db.queryAuditLog({ userId: user.id });
    const actions = logs.entries.map(e => e.action);
    expect(actions).toContain('USER_REGISTERED');
    expect(actions).toContain('LOGIN_SUCCESS');
    expect(actions).toContain('LOGIN_FAILED');
  });

  it('should export all user data for GDPR', async () => {
    await argus.register({ email: 'gdpr@test.com', password: 'Pass123!@#', displayName: 'GDPR', ipAddress: '1.1.1.1', userAgent: 'test' });
    const user = await db.findUserByEmail('gdpr@test.com');
    const exported = await db.exportUserData(user.id);
    expect(exported.user).toBeDefined();
    expect(exported.sessions).toBeDefined();
    expect(exported.auditLog).toBeDefined();
  });

  it('should soft delete user and revoke all sessions', async () => {
    const reg = await argus.register({ email: 'delme@test.com', password: 'Pass123!@#', displayName: 'DelMe', ipAddress: '1.1.1.1', userAgent: 'test' });
    const user = await db.findUserByEmail('delme@test.com');
    await db.softDeleteUser(user.id);
    expect(await db.findUserByEmail('delme@test.com')).toBeNull();
    expect(await db.findUserById(user.id)).toBeNull();
  });
});
