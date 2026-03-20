import { uuid, varchar, boolean, timestamp } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const passwordResetTokens = authSchema.table('password_reset_tokens', {
  id: uuid('id').defaultRandom().primaryKey(),
  userId: uuid('user_id').notNull(),
  tokenHash: varchar('token_hash', { length: 255 }).notNull().unique(),
  used: boolean('used').notNull().default(false),
  usedAt: timestamp('used_at', { withTimezone: true }),
  requestedFromIp: varchar('requested_from_ip', { length: 45 }).notNull(),
  requestedFromUa: varchar('requested_from_ua', { length: 512 }),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
