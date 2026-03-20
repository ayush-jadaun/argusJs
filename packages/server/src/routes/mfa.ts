import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { requireAuth } from '../middleware/auth.js';

const setupSchema = {
  body: {
    type: 'object',
    required: ['method'],
    properties: {
      method: { type: 'string', minLength: 1 },
    },
  },
};

const verifySetupSchema = {
  body: {
    type: 'object',
    required: ['method', 'code'],
    properties: {
      method: { type: 'string', minLength: 1 },
      code: { type: 'string', minLength: 1 },
    },
  },
};

const verifySchema = {
  body: {
    type: 'object',
    required: ['mfaToken', 'code', 'method'],
    properties: {
      mfaToken: { type: 'string', minLength: 1 },
      code: { type: 'string', minLength: 1 },
      method: { type: 'string', minLength: 1 },
    },
  },
};

const disableSchema = {
  body: {
    type: 'object',
    required: ['code'],
    properties: {
      code: { type: 'string', minLength: 1 },
    },
  },
};

const backupCodesSchema = {
  body: {
    type: 'object',
    required: ['code'],
    properties: {
      code: { type: 'string', minLength: 1 },
    },
  },
};

export async function mfaRoutes(app: FastifyInstance): Promise<void> {
  app.post('/v1/auth/mfa/setup', { schema: setupSchema, preHandler: [requireAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { method } = request.body as { method: string };
    const userId = request.user!.sub;

    const result = await request.server.argus.mfa.setup(userId, method);

    return reply.status(200).send(result);
  });

  app.post('/v1/auth/mfa/verify-setup', { schema: verifySetupSchema, preHandler: [requireAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { method, code } = request.body as { method: string; code: string };
    const userId = request.user!.sub;

    await request.server.argus.mfa.verifySetup(userId, method, code);

    return reply.status(200).send({ success: true });
  });

  app.post('/v1/auth/mfa/verify', { schema: verifySchema }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { mfaToken, code, method } = request.body as { mfaToken: string; code: string; method: string };
    const ip = request.ip;
    const userAgent = request.headers['user-agent'] ?? '';

    const result = await request.server.argus.mfa.verifyLogin(mfaToken, code, method, {
      ipAddress: ip,
      userAgent,
    });

    return reply.status(200).send(result);
  });

  app.post('/v1/auth/mfa/disable', { schema: disableSchema, preHandler: [requireAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { code } = request.body as { code: string };
    const userId = request.user!.sub;

    await request.server.argus.mfa.disable(userId, code);

    return reply.status(204).send();
  });

  app.get('/v1/auth/mfa/backup-codes', { schema: { querystring: { type: 'object', required: ['code'], properties: { code: { type: 'string', minLength: 1 } } } }, preHandler: [requireAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { code } = request.query as { code: string };
    const userId = request.user!.sub;

    const codes = await request.server.argus.mfa.regenerateBackupCodes(userId, code);

    return reply.status(200).send({ backupCodes: codes });
  });
}
