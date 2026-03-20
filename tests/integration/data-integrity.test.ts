import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIntegrationArgus } from './setup.js';

describe('Integration: Data Integrity', () => {
  let argus: any, db: any;
  const suffix = Date.now();

  beforeAll(async () => {
    ({ argus, db } = await createIntegrationArgus());
  });
  afterAll(async () => { await argus.shutdown(); });

  it('should log all auth actions to audit log', async () => {
    const email = `audit_${suffix}@test.com`;
    await argus.register({ email, password: 'Pass123!@#', displayName: 'Audit', ipAddress: '1.1.1.1', userAgent: 'test' });
    await argus.login(email, 'Pass123!@#', { ipAddress: '1.1.1.1', userAgent: 'test' });
    try { await argus.login(email, 'WRONG', { ipAddress: '1.1.1.1', userAgent: 'test' }); } catch {}

    const user = await db.findUserByEmail(email);
    const logs = await db.queryAuditLog({ userId: user.id });
    const actions = logs.entries.map((e: any) => e.action);
    expect(actions).toContain('USER_REGISTERED');
    expect(actions).toContain('LOGIN_SUCCESS');
    expect(actions).toContain('LOGIN_FAILED');
  });

  it('should export all user data for GDPR', async () => {
    const email = `gdpr_${suffix}@test.com`;
    await argus.register({ email, password: 'Pass123!@#', displayName: 'GDPR', ipAddress: '1.1.1.1', userAgent: 'test' });
    const user = await db.findUserByEmail(email);
    const exported = await db.exportUserData(user.id);
    expect(exported.user).toBeDefined();
    expect(exported.sessions).toBeDefined();
    expect(exported.auditLog).toBeDefined();
  });

  it('should soft delete user and revoke all sessions', async () => {
    const email = `delme_${suffix}@test.com`;
    await argus.register({ email, password: 'Pass123!@#', displayName: 'DelMe', ipAddress: '1.1.1.1', userAgent: 'test' });
    const user = await db.findUserByEmail(email);
    await db.softDeleteUser(user.id);
    expect(await db.findUserByEmail(email)).toBeNull();
    expect(await db.findUserById(user.id)).toBeNull();
  });
});
