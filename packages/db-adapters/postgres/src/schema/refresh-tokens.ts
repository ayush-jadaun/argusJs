import { uuid, varchar, boolean, timestamp, integer } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const refreshTokens = authSchema.table('refresh_tokens', {
  id: uuid('id').defaultRandom().primaryKey(),
  userId: uuid('user_id').notNull(),
  sessionId: uuid('session_id').notNull(),
  tokenHash: varchar('token_hash', { length: 255 }).notNull().unique(),
  family: varchar('family', { length: 255 }).notNull(),
  generation: integer('generation').notNull().default(0),
  revoked: boolean('revoked').notNull().default(false),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  revokedReason: varchar('revoked_reason', { length: 255 }),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
