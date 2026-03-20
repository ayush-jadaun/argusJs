import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { requireAuth } from '../middleware/auth.js';

export async function sessionRoutes(app: FastifyInstance): Promise<void> {
  // All session routes require auth
  app.addHook('onRequest', requireAuth);

  // GET /v1/auth/sessions
  app.get('/v1/auth/sessions', async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    const currentSessionId = request.user!.sessionId;
    const argus = request.server.argus;
    const db = (argus as any).db;

    const sessions = await db.getActiveSessions(userId);

    const sessionResponses = sessions.map((s: any) => ({
      id: s.id,
      ipAddress: s.ipAddress,
      userAgent: s.userAgent,
      createdAt: s.createdAt instanceof Date ? s.createdAt.toISOString() : s.createdAt,
      lastActivityAt: s.lastActivityAt instanceof Date ? s.lastActivityAt.toISOString() : s.lastActivityAt,
      isCurrent: s.id === currentSessionId,
    }));

    return reply.status(200).send({ sessions: sessionResponses });
  });

  // DELETE /v1/auth/sessions/:id
  app.delete('/v1/auth/sessions/:id', async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    const { id: sessionId } = request.params as { id: string };
    const argus = request.server.argus;
    const db = (argus as any).db;

    // Verify the session belongs to the user
    const session = await db.getSession(sessionId);
    if (!session || session.userId !== userId) {
      return reply.status(404).send({
        error: {
          code: 'NOT_FOUND',
          message: 'Session not found',
          statusCode: 404,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }

    await db.revokeSession(sessionId, 'user_revoked');

    return reply.status(204).send();
  });

  // GET /v1/auth/devices
  app.get('/v1/auth/devices', async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    const argus = request.server.argus;
    const security = (argus as any).security;

    if (!security) {
      return reply.status(200).send({ devices: [] });
    }

    const devices = await security.listTrustedDevices(userId);

    return reply.status(200).send({ devices });
  });

  // POST /v1/auth/devices/:id/trust
  app.post('/v1/auth/devices/:id/trust', async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    const { id: deviceId } = request.params as { id: string };
    const argus = request.server.argus;
    const security = (argus as any).security;

    if (!security) {
      return reply.status(400).send({
        error: {
          code: 'NOT_FOUND',
          message: 'Security engine not configured',
          statusCode: 400,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }

    const device = await security.trustDevice(userId, { id: deviceId, userId });

    return reply.status(200).send({ device });
  });

  // DELETE /v1/auth/devices/:id
  app.delete('/v1/auth/devices/:id', async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    const { id: deviceId } = request.params as { id: string };
    const argus = request.server.argus;
    const security = (argus as any).security;

    if (!security) {
      return reply.status(400).send({
        error: {
          code: 'NOT_FOUND',
          message: 'Security engine not configured',
          statusCode: 400,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }

    await security.revokeDevice(userId, deviceId);

    return reply.status(204).send();
  });
}
