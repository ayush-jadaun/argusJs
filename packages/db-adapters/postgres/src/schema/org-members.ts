import { uuid, varchar, text, timestamp, primaryKey } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const orgMembers = authSchema.table('org_members', {
  userId: uuid('user_id').notNull(),
  orgId: uuid('org_id').notNull(),
  role: varchar('role', { length: 50 }).notNull().default('member'),
  permissions: text('permissions').array().notNull().default([]),
  joinedAt: timestamp('joined_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  primaryKey({ columns: [table.userId, table.orgId] }),
]);
