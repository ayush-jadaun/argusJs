import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

export async function jwksRoutes(app: FastifyInstance): Promise<void> {
  // GET /.well-known/jwks.json
  app.get('/.well-known/jwks.json', async (request: FastifyRequest, reply: FastifyReply) => {
    const argus = request.server.argus;
    const token = (argus as any).token;

    const jwks = token.getJWKS();

    return reply
      .header('Cache-Control', 'public, max-age=3600')
      .status(200)
      .send(jwks);
  });
}
