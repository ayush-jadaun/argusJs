import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIntegrationArgus } from './setup.js';

describe('Integration: Concurrent Access', () => {
  let argus, db;

  beforeAll(async () => {
    ({ argus, db } = await createIntegrationArgus());
  });
  afterAll(async () => { await argus.shutdown(); });

  it('should enforce session limit under concurrent logins', async () => {
    const reg = await argus.register({ email: 'concurrent@test.com', password: 'Pass123!@#', displayName: 'Conc', ipAddress: '1.1.1.1', userAgent: 'test' });
    // Login 10 times — session limit is 5
    const promises = Array.from({ length: 10 }, (_, i) =>
      argus.login('concurrent@test.com', 'Pass123!@#', { ipAddress: `${i}.0.0.1`, userAgent: `agent-${i}` })
    );
    await Promise.allSettled(promises);
    const user = await db.findUserByEmail('concurrent@test.com');
    const sessions = await db.getActiveSessions(user.id);
    expect(sessions.length).toBeLessThanOrEqual(5);
  });

  it('should reject duplicate email registration', async () => {
    await argus.register({ email: 'dup@test.com', password: 'Pass123!@#', displayName: 'Dup1', ipAddress: '1.1.1.1', userAgent: 'test' });
    await expect(
      argus.register({ email: 'dup@test.com', password: 'Pass123!@#', displayName: 'Dup2', ipAddress: '2.2.2.2', userAgent: 'test' })
    ).rejects.toThrow('Email is already registered');
  });
});
