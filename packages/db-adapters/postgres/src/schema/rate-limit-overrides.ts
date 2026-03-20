import { uuid, varchar, integer, timestamp } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const rateLimitOverrides = authSchema.table('rate_limit_overrides', {
  id: uuid('id').defaultRandom().primaryKey(),
  key: varchar('key', { length: 255 }).notNull().unique(),
  maxRequests: integer('max_requests').notNull(),
  windowSeconds: integer('window_seconds').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});
