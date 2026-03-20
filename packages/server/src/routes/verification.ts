import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { requireAuth } from '../middleware/auth.js';

export async function verificationRoutes(app: FastifyInstance): Promise<void> {
  // POST /v1/auth/verify-email
  app.post('/v1/auth/verify-email', async (request: FastifyRequest, reply: FastifyReply) => {
    const { token } = request.body as { token?: string };

    if (!token || typeof token !== 'string') {
      return reply.status(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Missing or invalid token',
          statusCode: 400,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }

    await request.server.argus.verifyEmail(token);
    return reply.status(200).send({ message: 'Email verified successfully' });
  });

  // POST /v1/auth/resend-verification
  app.post('/v1/auth/resend-verification', { preHandler: requireAuth }, async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = request.user!.sub;
    await request.server.argus.resendVerification(userId);
    return reply.status(202).send({ message: 'Verification email sent' });
  });
}
