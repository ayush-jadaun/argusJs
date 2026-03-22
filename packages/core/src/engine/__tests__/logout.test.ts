import { describe, it, expect, vi } from 'vitest';
import { createTestArgus } from './helpers.js';

describe('Argus.logout', () => {
  it('should revoke current session', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    const user = await db.findUserByEmail('alice@example.com');
    const sessions = await db.getActiveSessions(user!.id);
    expect(sessions.length).toBe(1);
    await argus.logout(user!.id, sessions[0].id);
    const after = await db.getActiveSessions(user!.id);
    expect(after.length).toBe(0);
  });

  it('should revoke all sessions with allDevices', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    const user = await db.findUserByEmail('alice@example.com');
    // Login again to create second session
    await argus.login('alice@example.com', 'strongpass123', { ipAddress: '2.2.2.2', userAgent: 'agent2' });
    const before = await db.getActiveSessions(user!.id);
    expect(before.length).toBe(2);
    await argus.logout(user!.id, before[0].id, { allDevices: true });
    const after = await db.getActiveSessions(user!.id);
    expect(after.length).toBe(0);
  });

  it('should emit user.logout event', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    const user = await db.findUserByEmail('alice@example.com');
    const sessions = await db.getActiveSessions(user!.id);
    const handler = vi.fn();
    argus.on('user.logout', handler);
    await argus.logout(user!.id, sessions[0].id);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('should write audit log on logout', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();
    await argus.register({ email: 'alice@example.com', password: 'strongpass123', displayName: 'Alice', ipAddress: '1.2.3.4', userAgent: 'test' });
    const user = await db.findUserByEmail('alice@example.com');
    const sessions = await db.getActiveSessions(user!.id);
    await argus.logout(user!.id, sessions[0].id);
    const logs = await db.queryAuditLog({ action: 'LOGOUT' });
    expect(logs.entries.length).toBe(1);
  });
});
