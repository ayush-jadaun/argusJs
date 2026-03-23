import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { requireAuth } from '../middleware/auth.js';

// Response schema for fast-json-stringify serialization (Fastify uses this automatically)
const authUserSchema = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    email: { type: 'string' },
    displayName: { type: 'string' },
    emailVerified: { type: 'boolean' },
    mfaEnabled: { type: 'boolean' },
    roles: { type: 'array', items: { type: 'string' } },
    createdAt: { type: 'string' },
    updatedAt: { type: 'string' },
  },
} as const;

const authTokenResponseSchema = {
  type: 'object',
  properties: {
    user: authUserSchema,
    accessToken: { type: 'string' },
    refreshToken: { type: 'string' },
    expiresIn: { type: 'number' },
    tokenType: { type: 'string' },
    // MFA challenge fields (returned when MFA is required)
    mfaRequired: { type: 'boolean' },
    mfaToken: { type: 'string' },
    mfaMethods: { type: 'array', items: { type: 'string' } },
  },
} as const;

const registerSchema = {
  body: {
    type: 'object',
    required: ['email', 'password', 'displayName'],
    properties: {
      email: { type: 'string', format: 'email' },
      password: { type: 'string', minLength: 1 },
      displayName: { type: 'string', minLength: 1, maxLength: 100 },
    },
  },
  response: {
    201: authTokenResponseSchema,
  },
};

const loginSchema = {
  body: {
    type: 'object',
    required: ['email', 'password'],
    properties: {
      email: { type: 'string', format: 'email' },
      password: { type: 'string', minLength: 1 },
    },
  },
  response: {
    200: authTokenResponseSchema,
  },
};

const refreshSchema = {
  body: {
    type: 'object',
    required: ['refreshToken'],
    properties: {
      refreshToken: { type: 'string', minLength: 1 },
    },
  },
  response: {
    200: authTokenResponseSchema,
  },
};

const logoutSchema = {
  body: {
    type: 'object',
    properties: {
      allDevices: { type: 'boolean' },
    },
  },
};

export async function authRoutes(app: FastifyInstance): Promise<void> {
  app.post('/v1/auth/register', { schema: registerSchema }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { email, password, displayName } = request.body as { email: string; password: string; displayName: string };
    const ip = request.ip;
    const userAgent = request.headers['user-agent'] ?? '';

    const result = await request.server.argus.register({
      email,
      password,
      displayName,
      ipAddress: ip,
      userAgent,
    });

    return reply.status(201).send(result);
  });

  app.post('/v1/auth/login', { schema: loginSchema }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { email, password } = request.body as { email: string; password: string };
    const ip = request.ip;
    const userAgent = request.headers['user-agent'] ?? '';

    const result = await request.server.argus.login(email, password, {
      ipAddress: ip,
      userAgent,
    });

    return reply.status(200).send(result);
  });

  app.post('/v1/auth/refresh', { schema: refreshSchema }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { refreshToken } = request.body as { refreshToken: string };

    const result = await request.server.argus.refresh(refreshToken);

    return reply.status(200).send(result);
  });

  app.post('/v1/auth/logout', { schema: logoutSchema, preHandler: [requireAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { allDevices } = (request.body as { allDevices?: boolean }) ?? {};
    const userId = request.user!.sub;
    const sessionId = request.user!.sessionId;

    await request.server.argus.logout(userId, sessionId, { allDevices });

    return reply.status(204).send();
  });
}
