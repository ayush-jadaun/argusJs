import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import compress from '@fastify/compress';
import type { Argus } from '@argusjs/core';
import { errorHandler } from './plugins/error-handler.js';
import { requestId } from './plugins/request-id.js';
import { authRoutes } from './routes/auth.js';
import { passwordRoutes } from './routes/password.js';
import { verificationRoutes } from './routes/verification.js';
import { profileRoutes } from './routes/profile.js';
import { sessionRoutes } from './routes/sessions.js';
import { healthRoutes } from './routes/health.js';
import { jwksRoutes } from './routes/jwks.js';
import { adminRoutes } from './routes/admin.js';
import { mfaRoutes } from './routes/mfa.js';
import { passkeyRoutes } from './routes/passkey.js';
import { magicLinkRoutes } from './routes/magic-link.js';
import { scimRoutes } from './routes/scim.js';

export interface CreateAppOptions {
  argus: Argus;
  cors?: { origin?: string | string[] | boolean };
  logger?: boolean | object;
}

export async function createApp(options: CreateAppOptions): Promise<FastifyInstance> {
  const app = Fastify({
    logger: options.logger ?? true,
    trustProxy: true,
    requestTimeout: 10000,
    bodyLimit: 1048576, // 1 MB
  });

  // Decorate with Argus instance
  app.decorate('argus', options.argus);

  // Plugins
  await app.register(cors, { origin: options.cors?.origin ?? true });
  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(compress, { threshold: 1024 }); // compress responses > 1KB

  // Custom plugins
  app.addHook('onRequest', requestId);
  app.setErrorHandler(errorHandler);

  // Routes
  await app.register(authRoutes);
  await app.register(passwordRoutes);
  await app.register(verificationRoutes);
  await app.register(profileRoutes);
  await app.register(sessionRoutes);
  await app.register(healthRoutes);
  await app.register(jwksRoutes);
  await app.register(adminRoutes);
  await app.register(mfaRoutes);
  await app.register(passkeyRoutes);
  await app.register(magicLinkRoutes);
  await app.register(scimRoutes);

  return app;
}

// Type augmentation for Fastify
declare module 'fastify' {
  interface FastifyInstance {
    argus: Argus;
  }
}
