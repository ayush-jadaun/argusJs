import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

// In-memory JWKS cache — public keys rarely change, so avoid recomputing on every request.
let jwksCache: { data: any; cachedAt: number } | null = null;
const JWKS_CACHE_TTL = 3600_000; // 1 hour

function getCachedJWKS(tokenProvider: any): any {
  const now = Date.now();
  if (jwksCache && (now - jwksCache.cachedAt) < JWKS_CACHE_TTL) {
    return jwksCache.data;
  }
  const jwks = tokenProvider.getJWKS();
  jwksCache = { data: jwks, cachedAt: now };
  return jwks;
}

export async function jwksRoutes(app: FastifyInstance): Promise<void> {
  // GET /.well-known/jwks.json
  app.get('/.well-known/jwks.json', async (request: FastifyRequest, reply: FastifyReply) => {
    const argus = request.server.argus;
    const token = (argus as any).token;

    const jwks = getCachedJWKS(token);

    return reply
      .header('Cache-Control', 'public, max-age=3600')
      .status(200)
      .send(jwks);
  });
}
