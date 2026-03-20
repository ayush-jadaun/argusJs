import { uuid, varchar, text, boolean, integer, timestamp } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const webhooks = authSchema.table('webhooks', {
  id: uuid('id').defaultRandom().primaryKey(),
  url: varchar('url', { length: 2048 }).notNull(),
  events: text('events').array().notNull().default([]),
  secret: varchar('secret', { length: 512 }).notNull(),
  orgId: uuid('org_id'),
  active: boolean('active').notNull().default(true),
  failureCount: integer('failure_count').notNull().default(0),
  lastTriggeredAt: timestamp('last_triggered_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
