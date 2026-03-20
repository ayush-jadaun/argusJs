import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import type { Argus } from '@argus/core';
import { errorHandler } from './plugins/error-handler.js';
import { requestId } from './plugins/request-id.js';
import { authRoutes } from './routes/auth.js';
import { passwordRoutes } from './routes/password.js';
import { verificationRoutes } from './routes/verification.js';
import { profileRoutes } from './routes/profile.js';
import { sessionRoutes } from './routes/sessions.js';
import { healthRoutes } from './routes/health.js';
import { jwksRoutes } from './routes/jwks.js';

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

  return app;
}

// Type augmentation for Fastify
declare module 'fastify' {
  interface FastifyInstance {
    argus: Argus;
  }
}
