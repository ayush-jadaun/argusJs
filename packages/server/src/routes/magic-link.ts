import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

export async function magicLinkRoutes(app: FastifyInstance): Promise<void> {
  app.post('/v1/auth/magic-link/send', {
    schema: { body: { type: 'object', required: ['email'], properties: { email: { type: 'string', format: 'email' } } } },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { email } = request.body as { email: string };
    await request.server.argus.magicLink.sendLink(email, request.ip);
    return reply.status(200).send({ message: 'If an account exists, a magic link has been sent.' });
  });

  app.post('/v1/auth/magic-link/verify', {
    schema: { body: { type: 'object', required: ['token'], properties: { token: { type: 'string', minLength: 1 } } } },
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { token } = request.body as { token: string };
    const result = await request.server.argus.magicLink.verifyLink(token, { ipAddress: request.ip, userAgent: request.headers['user-agent'] ?? '' });
    return reply.status(200).send(result);
  });
}
