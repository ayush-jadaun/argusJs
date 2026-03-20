import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { requireAuth } from '../middleware/auth.js';

const forgotPasswordSchema = {
  body: {
    type: 'object',
    required: ['email'],
    properties: {
      email: { type: 'string', format: 'email' },
    },
  },
};

const resetPasswordSchema = {
  body: {
    type: 'object',
    required: ['token', 'newPassword'],
    properties: {
      token: { type: 'string', minLength: 1 },
      newPassword: { type: 'string', minLength: 1 },
    },
  },
};

const changePasswordSchema = {
  body: {
    type: 'object',
    required: ['currentPassword', 'newPassword'],
    properties: {
      currentPassword: { type: 'string', minLength: 1 },
      newPassword: { type: 'string', minLength: 1 },
    },
  },
};

export async function passwordRoutes(app: FastifyInstance): Promise<void> {
  app.post('/v1/auth/forgot-password', { schema: forgotPasswordSchema }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { email } = request.body as { email: string };
    const ip = request.ip;
    const userAgent = request.headers['user-agent'];

    await request.server.argus.forgotPassword(email, ip, userAgent);

    return reply.status(202).send({ message: 'If the email is registered, a reset link has been sent.' });
  });

  app.post('/v1/auth/reset-password', { schema: resetPasswordSchema }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { token, newPassword } = request.body as { token: string; newPassword: string };
    const ip = request.ip;

    await request.server.argus.resetPassword(token, newPassword, ip);

    return reply.status(200).send({ message: 'Password has been reset successfully.' });
  });

  app.post('/v1/auth/change-password', { schema: changePasswordSchema, preHandler: [requireAuth] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { currentPassword, newPassword } = request.body as { currentPassword: string; newPassword: string };
    const userId = request.user!.sub;
    const sessionId = request.user!.sessionId;
    const ip = request.ip;
    const userAgent = request.headers['user-agent'] ?? '';
    const argus = request.server.argus;

    // Access the internal components via the argus instance
    // We need to: verify current password, validate new password, hash it, update user, revoke other sessions
    const db = (argus as any).db;
    const hasher = (argus as any).hasher;
    const config = (argus as any).config;
    const passwordPolicy = (argus as any).passwordPolicy;
    const emitter = (argus as any).emitter;
    const email = (argus as any).email;

    // 1. Get user from DB
    const user = await db.findUserById(userId);
    if (!user) {
      return reply.status(404).send({
        error: {
          code: 'NOT_FOUND',
          message: 'User not found',
          statusCode: 404,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }

    // 2. Verify current password
    if (!user.passwordHash) {
      return reply.status(401).send({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid current password',
          statusCode: 401,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }

    const valid = await hasher.verify(currentPassword, user.passwordHash);
    if (!valid) {
      return reply.status(401).send({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid current password',
          statusCode: 401,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }

    // 3. Validate new password length
    const minLength = config.password?.minLength ?? 8;
    const maxLength = config.password?.maxLength ?? 128;
    if (newPassword.length < minLength || newPassword.length > maxLength) {
      return reply.status(422).send({
        error: {
          code: 'WEAK_PASSWORD',
          message: `Password must be between ${minLength} and ${maxLength} characters`,
          statusCode: 422,
          requestId: request.requestId ?? request.id,
          timestamp: new Date().toISOString(),
        },
      });
    }

    // 4. Run password policies if configured
    if (passwordPolicy) {
      for (const policy of passwordPolicy) {
        const result = await policy.validate(newPassword, { email: user.email, displayName: user.displayName });
        if (!result.valid) {
          return reply.status(422).send({
            error: {
              code: 'WEAK_PASSWORD',
              message: `Password does not meet strength requirements: ${result.reasons.join(', ')}`,
              statusCode: 422,
              requestId: request.requestId ?? request.id,
              timestamp: new Date().toISOString(),
            },
          });
        }
      }
    }

    // 5. Check password history
    const historyCount = config.password?.historyCount ?? 0;
    if (historyCount > 0) {
      const history = await db.getPasswordHistory(userId, historyCount);
      for (const oldHash of history) {
        const matches = await hasher.verify(newPassword, oldHash);
        if (matches) {
          return reply.status(422).send({
            error: {
              code: 'PASSWORD_RECENTLY_USED',
              message: 'Cannot reuse a recent password',
              statusCode: 422,
              requestId: request.requestId ?? request.id,
              timestamp: new Date().toISOString(),
            },
          });
        }
      }
    }

    // 6. Hash new password
    const newPasswordHash = await hasher.hash(newPassword);

    // 7. Add old password to history
    await db.addPasswordHistory(userId, user.passwordHash);

    // 8. Update user's password
    await db.updateUser(userId, { passwordHash: newPasswordHash });

    // 9. Revoke all other sessions (keep current)
    await db.revokeAllSessions(userId, 'password_change', sessionId);

    // 10. Revoke all refresh tokens for user (except current session's)
    // Since we can't selectively revoke by session, revoke all then user will re-auth
    // Actually, the current session stays valid via the access token
    await db.revokeAllUserTokens(userId, 'password_change');

    // 11. Send security alert email if configured
    if (email) {
      await email.sendSecurityAlertEmail(user.email, {
        type: 'password_change',
        description: 'Your password has been changed',
        ipAddress: ip,
        timestamp: new Date(),
      }, user);
    }

    // 12. Write audit
    if (config.audit?.enabled) {
      const { generateUUID } = await import('@argus/core');
      await db.writeAuditLog({
        id: generateUUID(),
        userId,
        action: 'PASSWORD_CHANGED',
        ipAddress: ip,
        userAgent,
        metadata: {},
        orgId: null,
        createdAt: new Date(),
      });
    }

    // 13. Emit event
    await emitter.emit('user.password_changed', {
      userId,
      timestamp: new Date(),
    });

    return reply.status(200).send({ message: 'Password has been changed successfully.' });
  });
}
