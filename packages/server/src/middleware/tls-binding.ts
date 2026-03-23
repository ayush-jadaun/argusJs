import type { FastifyRequest, FastifyReply } from 'fastify';
import type { TLSSocket } from 'node:tls';

/**
 * Extract TLS client certificate fingerprint from the request.
 * Returns the SHA-256 fingerprint if a peer certificate is present, null otherwise.
 */
export function extractTLSFingerprint(request: FastifyRequest): string | null {
  try {
    const socket = request.raw.socket as TLSSocket;
    if (typeof socket.getPeerCertificate === 'function') {
      const cert = socket.getPeerCertificate();
      if (cert && cert.fingerprint256) {
        return cert.fingerprint256;
      }
    }
  } catch {
    // Not a TLS socket or no peer certificate — that's fine
  }
  return null;
}

/**
 * Middleware that verifies the TLS fingerprint for authenticated requests
 * when session.bindToTLSFingerprint is enabled.
 * Must run AFTER requireAuth (needs request.user).
 */
export async function verifyTLSBinding(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  // Only check if user is authenticated and TLS binding is enabled
  if (!request.user) return;

  const argus = request.server.argus;
  if (!argus) return;

  const sessionId = request.user.sessionId;
  const tlsFingerprint = extractTLSFingerprint(request);

  const valid = await argus.verifySessionTLS(sessionId, tlsFingerprint);
  if (!valid) {
    reply.status(403).send({
      error: {
        code: 'FORBIDDEN',
        message: 'TLS certificate fingerprint does not match session binding',
        statusCode: 403,
        requestId: request.requestId ?? request.id,
        timestamp: new Date().toISOString(),
      },
    });
  }
}
