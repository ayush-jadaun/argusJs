import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { requireAuth } from '../middleware/auth.js';
import { requireAdmin } from '../middleware/admin.js';

function toUserResponse(user: any) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    emailVerified: user.emailVerified,
    mfaEnabled: user.mfaEnabled,
    mfaMethods: user.mfaMethods,
    roles: user.roles,
    permissions: user.permissions,
    orgId: user.orgId,
    orgRole: user.orgRole,
    failedLoginAttempts: user.failedLoginAttempts,
    lockedUntil: user.lockedUntil instanceof Date ? user.lockedUntil.toISOString() : user.lockedUntil,
    lastLoginAt: user.lastLoginAt instanceof Date ? user.lastLoginAt.toISOString() : user.lastLoginAt,
    lastLoginIp: user.lastLoginIp,
    metadata: user.metadata,
    createdAt: user.createdAt instanceof Date ? user.createdAt.toISOString() : user.createdAt,
    updatedAt: user.updatedAt instanceof Date ? user.updatedAt.toISOString() : user.updatedAt,
    deletedAt: user.deletedAt instanceof Date ? user.deletedAt.toISOString() : user.deletedAt,
  };
}

export async function adminRoutes(app: FastifyInstance): Promise<void> {
  // All admin routes require auth + admin
  app.addHook('onRequest', requireAuth);
  app.addHook('onRequest', requireAdmin);

  // ─── User Management ──────────────────────────────────────────────

  // GET /v1/admin/users — list users with filters
  app.get('/v1/admin/users', async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as {
      search?: string;
      role?: string;
      emailVerified?: string;
      mfaEnabled?: string;
      locked?: string;
      orgId?: string;
      limit?: string;
      offset?: string;
    };

    const db = (request.server.argus as any).db;

    const filter: Record<string, unknown> = {};
    if (query.search) filter.search = query.search;
    if (query.role) filter.role = query.role;
    if (query.emailVerified !== undefined) filter.emailVerified = query.emailVerified === 'true';
    if (query.mfaEnabled !== undefined) filter.mfaEnabled = query.mfaEnabled === 'true';
    if (query.locked !== undefined) filter.locked = query.locked === 'true';
    if (query.orgId) filter.orgId = query.orgId;
    if (query.limit) filter.limit = parseInt(query.limit, 10);
    if (query.offset) filter.offset = parseInt(query.offset, 10);

    const result = await db.listUsers(filter);

    return reply.status(200).send({
      users: result.users.map(toUserResponse),
      total: result.total,
      limit: filter.limit ?? 50,
      offset: filter.offset ?? 0,
    });
  });

  // GET /v1/admin/users/:id — get user by id
  app.get('/v1/admin/users/:id', async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const db = (request.server.argus as any).db;

    const user = await db.findUserById(id);
    if (!user) {
      return reply.status(404).send({
        error: {
          code: 'NOT_FOUND',
          message: 'User not found',
          statusCode: 404,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }

    return reply.status(200).send({ user: toUserResponse(user) });
  });

  // PATCH /v1/admin/users/:id — update user
  app.patch('/v1/admin/users/:id', async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const body = request.body as Record<string, unknown>;
    const db = (request.server.argus as any).db;

    const allowedFields = [
      'displayName', 'roles', 'permissions', 'emailVerified',
      'mfaEnabled', 'lockedUntil', 'orgId', 'orgRole', 'metadata',
    ];

    const updates: Record<string, unknown> = {};
    for (const field of allowedFields) {
      if (body[field] !== undefined) {
        updates[field] = body[field];
      }
    }

    const user = await db.updateUser(id, updates);

    return reply.status(200).send({ user: toUserResponse(user) });
  });

  // DELETE /v1/admin/users/:id — soft delete user
  app.delete('/v1/admin/users/:id', async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const db = (request.server.argus as any).db;

    await db.softDeleteUser(id);
    await db.revokeAllSessions(id, 'admin_deleted');

    return reply.status(204).send();
  });

  // POST /v1/admin/users/:id/unlock — unlock user account
  app.post('/v1/admin/users/:id/unlock', async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const db = (request.server.argus as any).db;

    const user = await db.updateUser(id, {
      lockedUntil: null,
      failedLoginAttempts: 0,
    });

    return reply.status(200).send({ user: toUserResponse(user) });
  });

  // POST /v1/admin/users/:id/reset-mfa — reset MFA for user
  app.post('/v1/admin/users/:id/reset-mfa', async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const db = (request.server.argus as any).db;

    await db.deleteMFASecret(id);
    await db.updateUser(id, { mfaEnabled: false, mfaMethods: [] });

    return reply.status(200).send({ message: 'MFA reset successfully' });
  });

  // POST /v1/admin/users/:id/reset-password — trigger password reset for user
  app.post('/v1/admin/users/:id/reset-password', async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const db = (request.server.argus as any).db;
    const argus = request.server.argus;

    const user = await db.findUserById(id);
    if (!user) {
      return reply.status(404).send({
        error: {
          code: 'NOT_FOUND',
          message: 'User not found',
          statusCode: 404,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }

    await argus.forgotPassword(user.email, request.ip, request.headers['user-agent'] ?? '');

    return reply.status(200).send({ message: 'Password reset email sent' });
  });

  // POST /v1/admin/impersonate — impersonate a user
  app.post('/v1/admin/impersonate', async (request: FastifyRequest, reply: FastifyReply) => {
    const { userId } = request.body as { userId: string };
    const db = (request.server.argus as any).db;
    const token = (request.server.argus as any).token;

    const targetUser = await db.findUserById(userId);
    if (!targetUser) {
      return reply.status(404).send({
        error: {
          code: 'NOT_FOUND',
          message: 'User not found',
          statusCode: 404,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }

    // Get the admin user info
    const adminUser = await db.findUserById(request.user!.sub);

    // Sign a short-lived access token (15 min) with impersonation claims
    const claims = {
      iss: 'argus',
      sub: targetUser.id,
      aud: ['argus'],
      exp: Math.floor(Date.now() / 1000) + 900, // 15 minutes
      iat: Math.floor(Date.now() / 1000),
      jti: `imp_${Date.now()}`,
      email: targetUser.email,
      emailVerified: targetUser.emailVerified,
      roles: targetUser.roles,
      permissions: targetUser.permissions,
      sessionId: request.user!.sessionId,
      impersonator: {
        id: adminUser?.id ?? request.user!.sub,
        email: adminUser?.email ?? request.user!.email,
        roles: adminUser?.roles ?? request.user!.roles,
      },
      isImpersonation: true,
    };

    const accessToken = await token.signAccessToken(claims);

    return reply.status(200).send({
      accessToken,
      expiresIn: 900,
      tokenType: 'Bearer',
      impersonating: {
        id: targetUser.id,
        email: targetUser.email,
        displayName: targetUser.displayName,
      },
    });
  });

  // ─── Audit Log ────────────────────────────────────────────────────

  // GET /v1/admin/audit-log — query audit log
  app.get('/v1/admin/audit-log', async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as {
      userId?: string;
      action?: string;
      startDate?: string;
      endDate?: string;
      orgId?: string;
      limit?: string;
      offset?: string;
    };

    const db = (request.server.argus as any).db;

    const filter: Record<string, unknown> = {};
    if (query.userId) filter.userId = query.userId;
    if (query.action) filter.action = query.action;
    if (query.startDate) filter.startDate = new Date(query.startDate);
    if (query.endDate) filter.endDate = new Date(query.endDate);
    if (query.orgId) filter.orgId = query.orgId;
    if (query.limit) filter.limit = parseInt(query.limit, 10);
    if (query.offset) filter.offset = parseInt(query.offset, 10);

    const result = await db.queryAuditLog(filter);

    return reply.status(200).send({
      entries: result.entries.map((e: any) => ({
        id: e.id,
        userId: e.userId,
        action: e.action,
        ipAddress: e.ipAddress,
        userAgent: e.userAgent,
        metadata: e.metadata,
        orgId: e.orgId,
        createdAt: e.createdAt instanceof Date ? e.createdAt.toISOString() : e.createdAt,
      })),
      total: result.total,
    });
  });

  // ─── System Stats ─────────────────────────────────────────────────

  // GET /v1/admin/stats — get system stats
  app.get('/v1/admin/stats', async (request: FastifyRequest, reply: FastifyReply) => {
    const db = (request.server.argus as any).db;

    const stats = await db.getSystemStats();

    return reply.status(200).send({ stats });
  });

  // ─── Sessions ─────────────────────────────────────────────────────

  // GET /v1/admin/sessions — list all sessions
  app.get('/v1/admin/sessions', async (request: FastifyRequest, reply: FastifyReply) => {
    const db = (request.server.argus as any).db;

    // List all users, then get sessions for each
    const { users } = await db.listUsers({ limit: 10000 });
    const allSessions: any[] = [];

    for (const user of users) {
      const sessions = await db.getActiveSessions(user.id);
      for (const s of sessions) {
        allSessions.push({
          id: s.id,
          userId: s.userId,
          ipAddress: s.ipAddress,
          userAgent: s.userAgent,
          createdAt: s.createdAt instanceof Date ? s.createdAt.toISOString() : s.createdAt,
          lastActivityAt: s.lastActivityAt instanceof Date ? s.lastActivityAt.toISOString() : s.lastActivityAt,
          expiresAt: s.expiresAt instanceof Date ? s.expiresAt.toISOString() : s.expiresAt,
          userEmail: user.email,
        });
      }
    }

    return reply.status(200).send({ sessions: allSessions, total: allSessions.length });
  });

  // ─── Roles ────────────────────────────────────────────────────────

  // GET /v1/admin/roles — list roles
  app.get('/v1/admin/roles', async (request: FastifyRequest, reply: FastifyReply) => {
    const roles = await request.server.argus.roles.list();
    return reply.status(200).send({ roles });
  });

  // POST /v1/admin/roles — create role
  app.post('/v1/admin/roles', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as { name: string; description: string; permissions: string[]; inherits?: string[]; isSystem?: boolean };

    const role = await request.server.argus.roles.create({
      name: body.name,
      description: body.description,
      permissions: body.permissions,
      inherits: body.inherits ?? [],
      isSystem: body.isSystem ?? false,
    });

    return reply.status(201).send({ role });
  });

  // PATCH /v1/admin/roles/:name — update role
  app.patch('/v1/admin/roles/:name', async (request: FastifyRequest, reply: FastifyReply) => {
    const { name } = request.params as { name: string };
    const body = request.body as Partial<{ description: string; permissions: string[]; inherits: string[] }>;

    const role = await request.server.argus.roles.update(name, body);

    return reply.status(200).send({ role });
  });

  // DELETE /v1/admin/roles/:name — delete role
  app.delete('/v1/admin/roles/:name', async (request: FastifyRequest, reply: FastifyReply) => {
    const { name } = request.params as { name: string };

    await request.server.argus.roles.delete(name);

    return reply.status(204).send();
  });
}
