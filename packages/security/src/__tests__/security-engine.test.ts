import { describe, it, expect, beforeEach } from 'vitest';
import { DefaultSecurityEngine } from '../default-security-engine.js';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';

describe('DefaultSecurityEngine', () => {
  let engine: DefaultSecurityEngine;
  let db: MemoryDbAdapter;
  let cache: MemoryCacheAdapter;

  beforeEach(async () => {
    db = new MemoryDbAdapter();
    cache = new MemoryCacheAdapter();
    engine = new DefaultSecurityEngine({ cache, db });
    await engine.init();
  });

  describe('Brute Force', () => {
    it('should allow attempts under threshold', async () => {
      const r = await engine.recordFailedAttempt('user@test.com', '1.2.3.4');
      expect(r.allowed).toBe(true);
      expect(r.failedAttempts).toBe(1);
    });

    it('should lock after max attempts', async () => {
      for (let i = 0; i < 10; i++) {
        await engine.recordFailedAttempt('user@test.com', '1.2.3.4');
      }
      const r = await engine.recordFailedAttempt('user@test.com', '1.2.3.4');
      expect(r.allowed).toBe(false);
      expect(r.lockoutUntil).toBeDefined();
    });

    it('should report locked status', async () => {
      for (let i = 0; i < 10; i++) {
        await engine.recordFailedAttempt('user@test.com', '1.2.3.4');
      }
      const status = await engine.isLocked('user@test.com');
      expect(status.locked).toBe(true);
    });

    it('should reset attempts', async () => {
      for (let i = 0; i < 5; i++) {
        await engine.recordFailedAttempt('user@test.com', '1.2.3.4');
      }
      await engine.resetAttempts('user@test.com');
      const status = await engine.isLocked('user@test.com');
      expect(status.locked).toBe(false);
    });

    it('should require captcha after threshold', async () => {
      for (let i = 0; i < 3; i++) {
        await engine.recordFailedAttempt('user@test.com', '1.2.3.4');
      }
      const r = await engine.recordFailedAttempt('user@test.com', '1.2.3.4');
      expect(r.requireCaptcha).toBe(true);
    });
  });

  describe('Risk Assessment', () => {
    it('should return low risk for known context', async () => {
      // Add device to known set
      await cache.sadd('known_devices:u1', 'fp-abc');
      const r = await engine.assessLoginRisk({
        userId: 'u1', ipAddress: '1.2.3.4', userAgent: 'Chrome',
        deviceFingerprint: 'fp-abc',
      });
      expect(r.level).toBe('low');
      expect(r.action).toBe('allow');
    });

    it('should flag new device', async () => {
      const r = await engine.assessLoginRisk({
        userId: 'u1', ipAddress: '1.2.3.4', userAgent: 'Chrome',
        deviceFingerprint: 'unknown-device',
      });
      expect(r.factors.some(f => f.type === 'new_device')).toBe(true);
      expect(r.score).toBeGreaterThan(0);
    });
  });

  describe('Concurrent Sessions', () => {
    it('should detect no sharing with single session', async () => {
      const user = await db.createUser({ email: 'a@b.com', passwordHash: 'h', displayName: 'A' });
      const session = await db.createSession({ userId: user.id, ipAddress: '1.1.1.1', userAgent: 'Chrome', expiresAt: new Date(Date.now() + 86400000) });
      const r = await engine.detectConcurrentSessions(user.id, session);
      expect(r.detected).toBe(false);
    });

    it('should detect sharing with many unique IPs', async () => {
      const user = await db.createUser({ email: 'b@c.com', passwordHash: 'h', displayName: 'B' });
      for (let i = 0; i < 5; i++) {
        await db.createSession({ userId: user.id, ipAddress: `${i}.${i}.${i}.${i}`, userAgent: `Agent${i}`, expiresAt: new Date(Date.now() + 86400000) });
      }
      const current = await db.createSession({ userId: user.id, ipAddress: '9.9.9.9', userAgent: 'AgentX', expiresAt: new Date(Date.now() + 86400000) });
      const r = await engine.detectConcurrentSessions(user.id, current);
      expect(r.detected).toBe(true);
      expect(r.uniqueIps).toBeGreaterThan(3);
    });
  });

  describe('Device Trust', () => {
    it('should trust and verify device', async () => {
      const device = { id: 'd1', userId: 'u1', fingerprint: 'fp1', name: 'My Laptop', browser: 'Chrome', os: 'Windows', lastUsedAt: new Date(), lastIp: '1.2.3.4', trustedAt: new Date() };
      await engine.trustDevice('u1', device);
      expect(await engine.isDeviceTrusted('u1', 'fp1')).toBe(true);
      expect(await engine.isDeviceTrusted('u1', 'unknown')).toBe(false);
    });

    it('should list trusted devices', async () => {
      const device = { id: 'd1', userId: 'u1', fingerprint: 'fp1', name: 'Laptop', browser: 'Chrome', os: 'Win', lastUsedAt: new Date(), lastIp: '1.1.1.1', trustedAt: new Date() };
      await engine.trustDevice('u1', device);
      const devices = await engine.listTrustedDevices('u1');
      expect(devices.length).toBe(1);
    });

    it('should revoke device trust', async () => {
      const device = { id: 'd2', userId: 'u1', fingerprint: 'fp2', name: 'Phone', browser: 'Safari', os: 'iOS', lastUsedAt: new Date(), lastIp: '2.2.2.2', trustedAt: new Date() };
      await engine.trustDevice('u1', device);
      await engine.revokeDevice('u1', 'd2');
      expect(await engine.isDeviceTrusted('u1', 'fp2')).toBe(false);
    });
  });
});
