import { describe, it, expect } from 'vitest';
import { createTestArgus } from './helpers.js';
import { AuthorizationEngine } from '../authorization.js';
import { MemoryDbAdapter } from '@argus/db-memory';

describe('AuthorizationEngine', () => {
  // ─── Permission Matching ──────────────────────────────────────────

  describe('matchesPermission', () => {
    const db = new MemoryDbAdapter();
    const engine = new AuthorizationEngine(db);

    it('should match exact permissions', () => {
      expect(engine.matchesPermission('read:users', 'read:users')).toBe(true);
    });

    it('should not match different permissions', () => {
      expect(engine.matchesPermission('read:users', 'write:users')).toBe(false);
    });

    it('should match global wildcard', () => {
      expect(engine.matchesPermission('*', 'read:users')).toBe(true);
      expect(engine.matchesPermission('*', 'admin:settings')).toBe(true);
    });

    it('should match namespace wildcard', () => {
      expect(engine.matchesPermission('admin:*', 'admin:users')).toBe(true);
      expect(engine.matchesPermission('admin:*', 'admin:settings')).toBe(true);
    });

    it('should not match different namespace with wildcard', () => {
      expect(engine.matchesPermission('admin:*', 'read:users')).toBe(false);
    });

    it('should match read:own exactly', () => {
      expect(engine.matchesPermission('read:own', 'read:own')).toBe(true);
    });
  });

  // ─── Role Inheritance ─────────────────────────────────────────────

  describe('resolvePermissions', () => {
    it('should resolve permissions from a single role', async () => {
      const db = new MemoryDbAdapter();
      await db.init();
      const engine = new AuthorizationEngine(db);

      await db.createRole({
        name: 'viewer',
        description: 'Can view',
        permissions: ['read:posts', 'read:comments'],
        inherits: [],
        isSystem: false,
      });

      const viewerRole = await db.getRole('viewer');
      const perms = await engine.resolvePermissions([viewerRole!]);
      expect(perms).toContain('read:posts');
      expect(perms).toContain('read:comments');
      expect(perms.length).toBe(2);
    });

    it('should resolve inherited permissions', async () => {
      const db = new MemoryDbAdapter();
      await db.init();
      const engine = new AuthorizationEngine(db);

      await db.createRole({
        name: 'viewer',
        description: 'Can view',
        permissions: ['read:posts'],
        inherits: [],
        isSystem: false,
      });

      await db.createRole({
        name: 'editor',
        description: 'Can edit',
        permissions: ['write:posts'],
        inherits: ['viewer'],
        isSystem: false,
      });

      const editorRole = await db.getRole('editor');
      const perms = await engine.resolvePermissions([editorRole!]);
      expect(perms).toContain('write:posts');
      expect(perms).toContain('read:posts');
    });

    it('should resolve deep inheritance chains', async () => {
      const db = new MemoryDbAdapter();
      await db.init();
      const engine = new AuthorizationEngine(db);

      await db.createRole({
        name: 'viewer',
        description: 'Can view',
        permissions: ['read:posts'],
        inherits: [],
        isSystem: false,
      });

      await db.createRole({
        name: 'editor',
        description: 'Can edit',
        permissions: ['write:posts'],
        inherits: ['viewer'],
        isSystem: false,
      });

      await db.createRole({
        name: 'admin',
        description: 'Full access',
        permissions: ['admin:settings'],
        inherits: ['editor'],
        isSystem: false,
      });

      const adminRole = await db.getRole('admin');
      const perms = await engine.resolvePermissions([adminRole!]);
      expect(perms).toContain('admin:settings');
      expect(perms).toContain('write:posts');
      expect(perms).toContain('read:posts');
    });

    it('should handle circular inheritance without infinite loop', async () => {
      const db = new MemoryDbAdapter();
      await db.init();
      const engine = new AuthorizationEngine(db);

      await db.createRole({
        name: 'roleA',
        description: 'A',
        permissions: ['perm:a'],
        inherits: ['roleB'],
        isSystem: false,
      });

      await db.createRole({
        name: 'roleB',
        description: 'B',
        permissions: ['perm:b'],
        inherits: ['roleA'],
        isSystem: false,
      });

      const roleA = await db.getRole('roleA');
      const perms = await engine.resolvePermissions([roleA!]);
      expect(perms).toContain('perm:a');
      expect(perms).toContain('perm:b');
    });
  });

  // ─── ABAC Condition Evaluation ────────────────────────────────────

  describe('evaluateCondition', () => {
    const db = new MemoryDbAdapter();
    const engine = new AuthorizationEngine(db);

    it('should evaluate eq condition', () => {
      expect(engine.evaluateCondition({ attribute: 'role', operator: 'eq', value: 'admin' }, { role: 'admin' })).toBe(true);
      expect(engine.evaluateCondition({ attribute: 'role', operator: 'eq', value: 'admin' }, { role: 'user' })).toBe(false);
    });

    it('should evaluate neq condition', () => {
      expect(engine.evaluateCondition({ attribute: 'role', operator: 'neq', value: 'admin' }, { role: 'user' })).toBe(true);
      expect(engine.evaluateCondition({ attribute: 'role', operator: 'neq', value: 'admin' }, { role: 'admin' })).toBe(false);
    });

    it('should evaluate in condition', () => {
      expect(engine.evaluateCondition({ attribute: 'env', operator: 'in', value: ['prod', 'staging'] }, { env: 'prod' })).toBe(true);
      expect(engine.evaluateCondition({ attribute: 'env', operator: 'in', value: ['prod', 'staging'] }, { env: 'dev' })).toBe(false);
    });

    it('should evaluate not_in condition', () => {
      expect(engine.evaluateCondition({ attribute: 'env', operator: 'not_in', value: ['prod', 'staging'] }, { env: 'dev' })).toBe(true);
      expect(engine.evaluateCondition({ attribute: 'env', operator: 'not_in', value: ['prod', 'staging'] }, { env: 'prod' })).toBe(false);
    });

    it('should evaluate gt condition', () => {
      expect(engine.evaluateCondition({ attribute: 'age', operator: 'gt', value: 18 }, { age: 21 })).toBe(true);
      expect(engine.evaluateCondition({ attribute: 'age', operator: 'gt', value: 18 }, { age: 16 })).toBe(false);
    });

    it('should evaluate lt condition', () => {
      expect(engine.evaluateCondition({ attribute: 'age', operator: 'lt', value: 18 }, { age: 16 })).toBe(true);
      expect(engine.evaluateCondition({ attribute: 'age', operator: 'lt', value: 18 }, { age: 21 })).toBe(false);
    });

    it('should evaluate contains condition', () => {
      expect(engine.evaluateCondition({ attribute: 'email', operator: 'contains', value: '@corp.com' }, { email: 'user@corp.com' })).toBe(true);
      expect(engine.evaluateCondition({ attribute: 'email', operator: 'contains', value: '@corp.com' }, { email: 'user@other.com' })).toBe(false);
    });

    it('should evaluate matches condition (regex)', () => {
      expect(engine.evaluateCondition({ attribute: 'ip', operator: 'matches', value: '^10\\.0\\.' }, { ip: '10.0.1.5' })).toBe(true);
      expect(engine.evaluateCondition({ attribute: 'ip', operator: 'matches', value: '^10\\.0\\.' }, { ip: '192.168.1.1' })).toBe(false);
    });
  });

  // ─── Full authorize() ─────────────────────────────────────────────

  describe('authorize', () => {
    it('should allow user with direct permission', async () => {
      const { argus, db } = createTestArgus();
      await argus.init();

      const user = await db.createUser({
        email: 'admin@example.com',
        passwordHash: 'hashed_pass',
        displayName: 'Admin',
      });
      await db.updateUser(user.id, { permissions: ['admin:users'] });

      const result = await argus.authorize(user.id, 'admin:users');
      expect(result).toBe(true);
    });

    it('should deny user without permission', async () => {
      const { argus, db } = createTestArgus();
      await argus.init();

      const user = await db.createUser({
        email: 'basic@example.com',
        passwordHash: 'hashed_pass',
        displayName: 'Basic',
      });

      const result = await argus.authorize(user.id, 'admin:users');
      expect(result).toBe(false);
    });

    it('should allow based on role permissions', async () => {
      const { argus, db } = createTestArgus();
      await argus.init();

      await db.createRole({
        name: 'editor',
        description: 'Can edit',
        permissions: ['write:posts', 'read:posts'],
        inherits: [],
        isSystem: false,
      });

      const user = await db.createUser({
        email: 'editor@example.com',
        passwordHash: 'hashed_pass',
        displayName: 'Editor',
        roles: ['editor'],
      });

      const result = await argus.authorize(user.id, 'write:posts');
      expect(result).toBe(true);
    });

    it('should allow based on inherited role permissions', async () => {
      const { argus, db } = createTestArgus();
      await argus.init();

      await db.createRole({
        name: 'viewer',
        description: 'Can view',
        permissions: ['read:posts'],
        inherits: [],
        isSystem: false,
      });

      await db.createRole({
        name: 'editor',
        description: 'Can edit',
        permissions: ['write:posts'],
        inherits: ['viewer'],
        isSystem: false,
      });

      const user = await db.createUser({
        email: 'editor@example.com',
        passwordHash: 'hashed_pass',
        displayName: 'Editor',
        roles: ['editor'],
      });

      const result = await argus.authorize(user.id, 'read:posts');
      expect(result).toBe(true);
    });

    it('should allow with wildcard permission', async () => {
      const { argus, db } = createTestArgus();
      await argus.init();

      const user = await db.createUser({
        email: 'super@example.com',
        passwordHash: 'hashed_pass',
        displayName: 'Super',
      });
      await db.updateUser(user.id, { permissions: ['*'] });

      const result = await argus.authorize(user.id, 'anything:here');
      expect(result).toBe(true);
    });

    it('should deny based on deny policy even if role allows', async () => {
      const { argus, db } = createTestArgus();
      await argus.init();

      await db.createRole({
        name: 'editor',
        description: 'Can edit',
        permissions: ['write:posts'],
        inherits: [],
        isSystem: false,
      });

      const user = await db.createUser({
        email: 'editor@example.com',
        passwordHash: 'hashed_pass',
        displayName: 'Editor',
        roles: ['editor'],
      });

      // But a deny policy blocks it in certain context
      await db.createPolicy({
        id: 'deny-weekend',
        name: 'Deny on weekend',
        effect: 'deny',
        actions: ['write:posts'],
        conditions: [{ attribute: 'dayOfWeek', operator: 'in', value: ['saturday', 'sunday'] }],
      });

      // On saturday, should be denied
      const result = await argus.authorize(user.id, 'write:posts', { dayOfWeek: 'saturday' });
      expect(result).toBe(false);
    });

    it('should allow via ABAC policy', async () => {
      const { argus, db } = createTestArgus();
      await argus.init();

      const user = await db.createUser({
        email: 'user@example.com',
        passwordHash: 'hashed_pass',
        displayName: 'User',
      });

      // No role or direct permission, but an ABAC allow policy
      await db.createPolicy({
        id: 'allow-internal',
        name: 'Allow internal IPs',
        effect: 'allow',
        actions: ['read:reports'],
        conditions: [{ attribute: 'ip', operator: 'matches', value: '^10\\.' }],
      });

      const allowed = await argus.authorize(user.id, 'read:reports', { ip: '10.0.1.5' });
      expect(allowed).toBe(true);

      const denied = await argus.authorize(user.id, 'read:reports', { ip: '192.168.1.1' });
      expect(denied).toBe(false);
    });

    it('should return false for nonexistent user', async () => {
      const { argus } = createTestArgus();
      await argus.init();

      const result = await argus.authorize('nonexistent', 'anything');
      expect(result).toBe(false);
    });
  });

  // ─── Roles CRUD via Argus ─────────────────────────────────────────

  describe('Argus.roles', () => {
    it('should create, get, list, update, and delete roles', async () => {
      const { argus } = createTestArgus();
      await argus.init();

      const created = await argus.roles.create({
        name: 'moderator',
        description: 'Can moderate',
        permissions: ['moderate:posts'],
        inherits: [],
        isSystem: false,
      });
      expect(created.name).toBe('moderator');

      const fetched = await argus.roles.get('moderator');
      expect(fetched.permissions).toContain('moderate:posts');

      const listed = await argus.roles.list();
      expect(listed.length).toBe(1);

      const updated = await argus.roles.update('moderator', { description: 'Updated' });
      expect(updated.description).toBe('Updated');

      await argus.roles.delete('moderator');
      await expect(argus.roles.get('moderator')).rejects.toThrow('Role not found');
    });
  });
});
