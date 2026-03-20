import { describe, it, expect, vi } from 'vitest';
import { createTestArgus } from './helpers.js';

describe('Argus.orgs', () => {
  // ─── Create ─────────────────────────────────────────────────────────

  it('should create an organization', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const org = await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: user.id,
    });

    expect(org.name).toBe('Acme Corp');
    expect(org.slug).toBe('acme-corp');
    expect(org.ownerId).toBe(user.id);
    expect(org.plan).toBe('free');
    expect(org.id).toBeDefined();
  });

  it('should add the owner as a member on create', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const org = await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: user.id,
    });

    const members = await argus.orgs.listMembers(org.id);
    expect(members.length).toBe(1);
    expect(members[0].userId).toBe(user.id);
    expect(members[0].role).toBe('owner');
  });

  it('should emit org.created event', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const handler = vi.fn();
    argus.on('org.created', handler);

    await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: user.id,
    });

    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('should write audit log on create', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: user.id,
    });

    const logs = await db.queryAuditLog({ action: 'ADMIN_ACTION' });
    expect(logs.entries.length).toBeGreaterThanOrEqual(1);
    expect(logs.entries.some(e => (e.metadata as Record<string, unknown>).subAction === 'org.created')).toBe(true);
  });

  // ─── Get ────────────────────────────────────────────────────────────

  it('should get an organization by id', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const org = await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: user.id,
    });

    const found = await argus.orgs.get(org.id);
    expect(found.id).toBe(org.id);
    expect(found.name).toBe('Acme Corp');
  });

  it('should throw NOT_FOUND for nonexistent org', async () => {
    const { argus } = createTestArgus();
    await argus.init();

    await expect(argus.orgs.get('nonexistent')).rejects.toThrow('Organization not found');
  });

  // ─── Update ─────────────────────────────────────────────────────────

  it('should update an organization', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const org = await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: user.id,
    });

    const updated = await argus.orgs.update(org.id, { name: 'Acme Inc' });
    expect(updated.name).toBe('Acme Inc');
  });

  // ─── Delete ─────────────────────────────────────────────────────────

  it('should delete an organization', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const user = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const org = await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: user.id,
    });

    await argus.orgs.delete(org.id);
    await expect(argus.orgs.get(org.id)).rejects.toThrow('Organization not found');
  });

  // ─── Members CRUD ───────────────────────────────────────────────────

  it('should add a member to an organization', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const owner = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const member = await db.createUser({
      email: 'member@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Member',
    });

    const org = await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: owner.id,
    });

    const added = await argus.orgs.addMember({
      userId: member.id,
      orgId: org.id,
      role: 'member',
    });

    expect(added.userId).toBe(member.id);
    expect(added.role).toBe('member');

    const members = await argus.orgs.listMembers(org.id);
    expect(members.length).toBe(2);
  });

  it('should update a member role', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const owner = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const member = await db.createUser({
      email: 'member@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Member',
    });

    const org = await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: owner.id,
    });

    await argus.orgs.addMember({
      userId: member.id,
      orgId: org.id,
      role: 'member',
    });

    const updated = await argus.orgs.updateMember(org.id, member.id, { role: 'admin' });
    expect(updated.role).toBe('admin');
  });

  it('should remove a member from an organization', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const owner = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const member = await db.createUser({
      email: 'member@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Member',
    });

    const org = await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: owner.id,
    });

    await argus.orgs.addMember({
      userId: member.id,
      orgId: org.id,
      role: 'member',
    });

    await argus.orgs.removeMember(org.id, member.id);
    const members = await argus.orgs.listMembers(org.id);
    expect(members.length).toBe(1);
    expect(members[0].userId).toBe(owner.id);
  });

  // ─── Invites ────────────────────────────────────────────────────────

  it('should create and list invites', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const owner = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const org = await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: owner.id,
    });

    const invite = await argus.orgs.createInvite({
      orgId: org.id,
      email: 'new@example.com',
      role: 'member',
      invitedBy: owner.id,
    });

    expect(invite.email).toBe('new@example.com');
    expect(invite.role).toBe('member');
    expect(invite.orgId).toBe(org.id);
    expect(invite.token).toBeDefined();

    const invites = await argus.orgs.listInvites(org.id);
    expect(invites.length).toBe(1);
    expect(invites[0].email).toBe('new@example.com');
  });

  it('should accept an invite and add the user as member', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const owner = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const invitedUser = await db.createUser({
      email: 'invited@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Invited',
    });

    const org = await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: owner.id,
    });

    const invite = await argus.orgs.createInvite({
      orgId: org.id,
      email: 'invited@example.com',
      role: 'member',
      invitedBy: owner.id,
    });

    await argus.orgs.acceptInvite(invite.token);

    const members = await argus.orgs.listMembers(org.id);
    expect(members.length).toBe(2);
    expect(members.some(m => m.userId === invitedUser.id)).toBe(true);
  });

  // ─── Settings ───────────────────────────────────────────────────────

  it('should update organization settings', async () => {
    const { argus, db } = createTestArgus();
    await argus.init();

    const owner = await db.createUser({
      email: 'owner@example.com',
      passwordHash: 'hashed_pass',
      displayName: 'Owner',
    });

    const org = await argus.orgs.create({
      name: 'Acme Corp',
      slug: 'acme-corp',
      ownerId: owner.id,
    });

    const updated = await argus.orgs.updateSettings(org.id, { enforceMFA: true });
    expect(updated.settings.enforceMFA).toBe(true);
  });
});
