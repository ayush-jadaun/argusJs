import { describe, it, expect } from 'vitest';
import { createTestArgus } from './helpers.js';

describe('Argus.apiKeys', () => {
  it('should create an API key and return rawKey starting with argus_pk_', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'dev@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Developer',
    });

    const { apiKey, rawKey } = await argus.apiKeys.create(user.id, {
      name: 'My Key',
      permissions: ['read:data'],
    });

    expect(rawKey).toMatch(/^argus_pk_/);
    expect(apiKey.name).toBe('My Key');
    expect(apiKey.userId).toBe(user.id);
    expect(apiKey.permissions).toContain('read:data');
    expect(apiKey.revokedAt).toBeNull();
  });

  it('should validate with correct key and return user', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'dev@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Developer',
    });

    const { rawKey } = await argus.apiKeys.create(user.id, {
      name: 'My Key',
      permissions: ['read:data'],
    });

    const result = await argus.apiKeys.validate(rawKey);
    expect(result).not.toBeNull();
    expect(result!.user.id).toBe(user.id);
    expect(result!.apiKey.name).toBe('My Key');
  });

  it('should return null for wrong key', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'dev@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Developer',
    });

    await argus.apiKeys.create(user.id, {
      name: 'My Key',
      permissions: ['read:data'],
    });

    const result = await argus.apiKeys.validate('argus_pk_wrongkeywrongkeywrongkey');
    expect(result).toBeNull();
  });

  it('should revoke a key and make it invalid', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'dev@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Developer',
    });

    const { apiKey, rawKey } = await argus.apiKeys.create(user.id, {
      name: 'My Key',
      permissions: ['read:data'],
    });

    await argus.apiKeys.revoke(apiKey.id);

    const result = await argus.apiKeys.validate(rawKey);
    expect(result).toBeNull();
  });

  it('should list API keys for a user', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'dev@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Developer',
    });

    await argus.apiKeys.create(user.id, {
      name: 'Key 1',
      permissions: ['read:data'],
    });

    await argus.apiKeys.create(user.id, {
      name: 'Key 2',
      permissions: ['write:data'],
    });

    const keys = await argus.apiKeys.list(user.id);
    expect(keys.length).toBe(2);
    expect(keys.map(k => k.name).sort()).toEqual(['Key 1', 'Key 2']);
  });

  it('should return null for expired key', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'dev@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Developer',
    });

    const { rawKey } = await argus.apiKeys.create(user.id, {
      name: 'Expired Key',
      permissions: ['read:data'],
      expiresAt: new Date(Date.now() - 1000), // already expired
    });

    const result = await argus.apiKeys.validate(rawKey);
    expect(result).toBeNull();
  });

  it('should write audit log on create', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'dev@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Developer',
    });

    await argus.apiKeys.create(user.id, {
      name: 'Audited Key',
      permissions: ['read:data'],
    });

    const logs = await db.queryAuditLog({ action: 'ADMIN_ACTION' });
    expect(logs.entries.some(e => (e.metadata as Record<string, unknown>).subAction === 'apikey.created')).toBe(true);
  });
});
