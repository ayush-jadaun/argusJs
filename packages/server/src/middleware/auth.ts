import type { FastifyRequest, FastifyReply } from 'fastify';
import type { AccessTokenClaims } from '@argus/core';

// Type augmentation
declare module 'fastify' {
  interface FastifyRequest {
    user?: AccessTokenClaims;
    requestId?: string;
  }
}

export async function requireAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const header = request.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    reply.status(401).send({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Missing or invalid authorization header',
        statusCode: 401,
        requestId: request.requestId ?? request.id,
        timestamp: new Date().toISOString(),
      },
    });
    return;
  }

  const token = header.slice(7);
  try {
    const claims = await request.server.argus.verifyToken(token);
    request.user = claims;
  } catch {
    reply.status(401).send({
      error: {
        code: 'INVALID_TOKEN',
        message: 'Access token is invalid or expired',
        statusCode: 401,
        requestId: request.requestId ?? request.id,
        timestamp: new Date().toISOString(),
      },
    });
  }
}
