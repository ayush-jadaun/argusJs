import { uuid, varchar, boolean, timestamp } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const sessions = authSchema.table('sessions', {
  id: uuid('id').defaultRandom().primaryKey(),
  userId: uuid('user_id').notNull(),
  ipAddress: varchar('ip_address', { length: 45 }).notNull(),
  userAgent: varchar('user_agent', { length: 512 }).notNull(),
  deviceFingerprint: varchar('device_fingerprint', { length: 255 }),
  lastActivityAt: timestamp('last_activity_at', { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  revoked: boolean('revoked').notNull().default(false),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  revokedReason: varchar('revoked_reason', { length: 255 }),
  orgId: uuid('org_id'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
