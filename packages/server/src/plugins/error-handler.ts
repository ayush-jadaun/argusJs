import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { ArgusError } from '@argus/core';

export function errorHandler(error: FastifyError, request: FastifyRequest, reply: FastifyReply): void {
  if (error instanceof ArgusError) {
    reply.status(error.statusCode).send({
      error: {
        code: error.code,
        message: error.message,
        statusCode: error.statusCode,
        details: error.details,
        requestId: (request as any).requestId ?? request.id,
        timestamp: new Date().toISOString(),
      },
    });
    return;
  }

  // Fastify validation errors
  if (error.validation) {
    reply.status(400).send({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Request validation failed',
        statusCode: 400,
        details: error.validation.map(v => ({
          field: v.instancePath || 'body',
          message: v.message || 'Invalid value',
          code: v.keyword || 'invalid',
        })),
        requestId: (request as any).requestId ?? request.id,
        timestamp: new Date().toISOString(),
      },
    });
    return;
  }

  // Unknown errors
  request.log.error(error);
  reply.status(500).send({
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected error occurred',
      statusCode: 500,
      requestId: (request as any).requestId ?? request.id,
      timestamp: new Date().toISOString(),
    },
  });
}
