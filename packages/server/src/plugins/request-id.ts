import type { FastifyRequest, FastifyReply, HookHandlerDoneFunction } from 'fastify';
import { randomUUID } from 'node:crypto';

export function requestId(request: FastifyRequest, reply: FastifyReply, done: HookHandlerDoneFunction): void {
  const id = (request.headers['x-request-id'] as string) || randomUUID();
  (request as any).requestId = id;
  reply.header('X-Request-Id', id);
  done();
}
