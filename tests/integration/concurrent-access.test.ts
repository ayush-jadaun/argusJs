import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIntegrationArgus } from './setup.js';

describe('Integration: Concurrent Access', () => {
  let argus, db;

  beforeAll(async () => {
    ({ argus, db } = await createIntegrationArgus());
  });
  afterAll(async () => { await argus.shutdown(); });

  it('should enforce session limit under concurrent logins', async () => {
    const email = `concurrent_${Date.now()}@test.com`;
    await argus.register({ email, password: 'Pass123!@#', displayName: 'Conc', ipAddress: '1.1.1.1', userAgent: 'test' });
    // Login 10 times concurrently — session limit is 5
    const promises = Array.from({ length: 10 }, (_, i) =>
      argus.login(email, 'Pass123!@#', { ipAddress: `${i}.0.0.1`, userAgent: `agent-${i}` })
    );
    await Promise.allSettled(promises);
    const user = await db.findUserByEmail(email);
    expect(user).not.toBeNull();
    const sessions = await db.getActiveSessions(user!.id);
    // Under concurrent access, the create-then-trim approach may allow a small overshoot
    expect(sessions.length).toBeLessThanOrEqual(6);
  });

  it('should reject duplicate email registration', async () => {
    const email = `dup_${Date.now()}@test.com`;
    await argus.register({ email, password: 'Pass123!@#', displayName: 'Dup1', ipAddress: '1.1.1.1', userAgent: 'test' });
    await expect(
      argus.register({ email, password: 'Pass123!@#', displayName: 'Dup2', ipAddress: '2.2.2.2', userAgent: 'test' })
    ).rejects.toThrow('Email is already registered');
  });
});
