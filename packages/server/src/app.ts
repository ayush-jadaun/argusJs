import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import type { Argus } from '@argus/core';
import { errorHandler } from './plugins/error-handler.js';
import { requestId } from './plugins/request-id.js';

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

  // Routes will be registered by individual route modules
  // They are added later by importing and calling registerAuthRoutes(app), etc.

  return app;
}

// Type augmentation for Fastify
declare module 'fastify' {
  interface FastifyInstance {
    argus: Argus;
  }
}
