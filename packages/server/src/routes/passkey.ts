import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { requireAuth } from '../middleware/auth.js';

export async function passkeyRoutes(app: FastifyInstance): Promise<void> {
  app.post('/v1/auth/passkey/register/start', { preHandler: [requireAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    const result = await request.server.argus.passkey.registerStart(userId);
    return reply.status(200).send(result);
  });

  app.post('/v1/auth/passkey/register/finish', {
    schema: { body: { type: 'object', required: ['credentialId', 'publicKey'], properties: { credentialId: { type: 'string', minLength: 1 }, publicKey: { type: 'string', minLength: 1 }, counter: { type: 'number' }, transports: { type: 'array', items: { type: 'string' } } } } },
    preHandler: [requireAuth],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    const { credentialId, publicKey, counter, transports } = request.body as { credentialId: string; publicKey: string; counter?: number; transports?: string[] };
    await request.server.argus.passkey.registerFinish(userId, { credentialId, publicKey, counter: counter ?? 0, transports });
    return reply.status(200).send({ success: true });
  });

  app.post('/v1/auth/passkey/login/start', {
    schema: { body: { type: 'object', required: ['email'], properties: { email: { type: 'string', format: 'email' } } } },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { email } = request.body as { email: string };
    const result = await request.server.argus.passkey.loginStart(email);
    return reply.status(200).send(result);
  });

  app.post('/v1/auth/passkey/login/finish', {
    schema: { body: { type: 'object', required: ['email', 'credentialId'], properties: { email: { type: 'string', format: 'email' }, credentialId: { type: 'string', minLength: 1 }, authenticatorData: { type: 'string' }, clientDataJSON: { type: 'string' }, signature: { type: 'string' }, counter: { type: 'number' } } } },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { email, credentialId, authenticatorData, clientDataJSON, signature, counter } = request.body as { email: string; credentialId: string; authenticatorData?: string; clientDataJSON?: string; signature?: string; counter?: number };
    const ip = request.ip;
    const userAgent = request.headers['user-agent'] ?? '';
    const result = await request.server.argus.passkey.loginFinish(email, { credentialId, authenticatorData, clientDataJSON, signature, counter }, { ipAddress: ip, userAgent });
    return reply.status(200).send(result);
  });
}
