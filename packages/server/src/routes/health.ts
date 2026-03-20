import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

export async function healthRoutes(app: FastifyInstance): Promise<void> {
  // GET /v1/health
  app.get('/v1/health', async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(200).send({
      status: 'ok',
      timestamp: new Date().toISOString(),
    });
  });

  // GET /v1/health/live
  app.get('/v1/health/live', async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(200).send({ status: 'ok' });
  });

  // GET /v1/health/ready
  app.get('/v1/health/ready', async (request: FastifyRequest, reply: FastifyReply) => {
    const argus = request.server.argus;
    const cache = (argus as any).cache;
    const db = (argus as any).db;

    try {
      // Check cache health
      const cacheOk = cache.healthCheck ? await cache.healthCheck() : true;

      // Check DB health by performing a simple operation
      let dbOk = true;
      try {
        await db.getSystemStats();
      } catch {
        dbOk = false;
      }

      if (cacheOk && dbOk) {
        return reply.status(200).send({
          status: 'ok',
          checks: { db: 'ok', cache: 'ok' },
        });
      }

      return reply.status(503).send({
        status: 'degraded',
        checks: {
          db: dbOk ? 'ok' : 'failing',
          cache: cacheOk ? 'ok' : 'failing',
        },
      });
    } catch {
      return reply.status(503).send({
        status: 'failing',
        checks: { db: 'unknown', cache: 'unknown' },
      });
    }
  });
}
