import type { FastifyRequest, FastifyReply } from 'fastify';

const ADMIN_ROLES = ['admin', 'super_admin'];

export async function requireAdmin(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  // requireAuth must run before this middleware so request.user is populated
  if (!request.user) {
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

  const hasAdminRole = request.user.roles.some((role: string) => ADMIN_ROLES.includes(role));
  if (!hasAdminRole) {
    reply.status(403).send({
      error: {
        code: 'FORBIDDEN',
        message: 'Admin access required',
        statusCode: 403,
        requestId: request.requestId ?? request.id,
        timestamp: new Date().toISOString(),
      },
    });
  }
}
