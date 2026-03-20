import type { FastifyRequest, FastifyReply } from 'fastify';

export function createRateLimiter(limit: number, windowSeconds: number) {
  return async function rateLimit(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const argus = request.server.argus;
    // Rate limiter may not be configured
    if (!(argus as any).rateLimiter) return;

    const key = `${request.routeOptions.url}:${request.ip}`;
    const result = await (argus as any).rateLimiter.check(key, limit, windowSeconds);

    reply.header('X-RateLimit-Limit', result.limit);
    reply.header('X-RateLimit-Remaining', result.remaining);
    reply.header('X-RateLimit-Reset', result.resetAt);

    if (!result.allowed) {
      reply.header('Retry-After', result.retryAfter);
      reply.status(429).send({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: `Too many requests. Retry after ${result.retryAfter}s`,
          statusCode: 429,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }
  };
}
