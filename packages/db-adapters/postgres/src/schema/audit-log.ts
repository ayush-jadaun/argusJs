import { uuid, varchar, timestamp, jsonb } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const auditLog = authSchema.table('audit_log', {
  id: varchar('id', { length: 255 }).primaryKey(),
  userId: uuid('user_id'),
  action: varchar('action', { length: 100 }).notNull(),
  ipAddress: varchar('ip_address', { length: 45 }),
  userAgent: varchar('user_agent', { length: 512 }),
  metadata: jsonb('metadata').notNull().default({}),
  orgId: uuid('org_id'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
