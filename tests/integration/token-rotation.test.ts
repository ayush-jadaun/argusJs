import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIntegrationArgus } from './setup.js';

describe('Integration: Token Rotation', () => {
  let argus, db;

  beforeAll(async () => {
    ({ argus, db } = await createIntegrationArgus());
  });
  afterAll(async () => { await argus.shutdown(); });

  it('should rotate refresh tokens', async () => {
    const reg = await argus.register({ email: 'rot@test.com', password: 'Pass123!@#', displayName: 'Rot', ipAddress: '1.1.1.1', userAgent: 'test' });
    const r1 = await argus.refresh(reg.refreshToken);
    expect(r1.refreshToken).not.toBe(reg.refreshToken);
    const r2 = await argus.refresh(r1.refreshToken);
    expect(r2.refreshToken).not.toBe(r1.refreshToken);
  });

  it('should detect token reuse and revoke all sessions', async () => {
    const reg = await argus.register({ email: 'reuse@test.com', password: 'Pass123!@#', displayName: 'Reuse', ipAddress: '1.1.1.1', userAgent: 'test' });
    const oldToken = reg.refreshToken;
    await argus.refresh(oldToken);
    await expect(argus.refresh(oldToken)).rejects.toThrow('reuse detected');
    const user = await db.findUserByEmail('reuse@test.com');
    const sessions = await db.getActiveSessions(user.id);
    expect(sessions.length).toBe(0);
  });
});
