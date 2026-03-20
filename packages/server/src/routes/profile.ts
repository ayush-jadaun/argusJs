import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { requireAuth } from '../middleware/auth.js';

export async function profileRoutes(app: FastifyInstance): Promise<void> {
  // All profile routes require auth
  app.addHook('onRequest', requireAuth);

  // GET /v1/auth/me
  app.get('/v1/auth/me', async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    const argus = request.server.argus;
    const db = (argus as any).db;

    const user = await db.findUserById(userId);
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

    return reply.status(200).send({
      user: toUserResponse(user),
    });
  });

  // PATCH /v1/auth/me
  app.patch('/v1/auth/me', async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    const argus = request.server.argus;
    const db = (argus as any).db;

    const body = request.body as { displayName?: string; avatarUrl?: string };
    const updates: Record<string, unknown> = {};

    if (body.displayName !== undefined) {
      updates.displayName = body.displayName;
    }
    if (body.avatarUrl !== undefined) {
      updates.avatarUrl = body.avatarUrl;
    }

    const user = await db.updateUser(userId, updates);

    return reply.status(200).send({
      user: toUserResponse(user),
    });
  });

  // DELETE /v1/auth/me
  app.delete('/v1/auth/me', async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    const argus = request.server.argus;
    const db = (argus as any).db;

    await db.softDeleteUser(userId);
    await db.revokeAllSessions(userId, 'account_deleted');

    return reply.status(204).send();
  });

  // GET /v1/auth/me/export
  app.get('/v1/auth/me/export', async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    const argus = request.server.argus;
    const db = (argus as any).db;

    const data = await db.exportUserData(userId);

    return reply.status(200).send(data);
  });
}

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
    orgId: user.orgId,
    orgRole: user.orgRole,
    metadata: user.metadata,
    createdAt: user.createdAt instanceof Date ? user.createdAt.toISOString() : user.createdAt,
    updatedAt: user.updatedAt instanceof Date ? user.updatedAt.toISOString() : user.updatedAt,
  };
}
