import { varchar, timestamp } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const trustedDevices = authSchema.table('trusted_devices', {
  id: varchar('id', { length: 255 }).primaryKey(),
  userId: varchar('user_id', { length: 255 }).notNull(),
  fingerprint: varchar('fingerprint', { length: 255 }).notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  browser: varchar('browser', { length: 100 }).notNull(),
  os: varchar('os', { length: 100 }).notNull(),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }).notNull().defaultNow(),
  lastIp: varchar('last_ip', { length: 45 }).notNull(),
  trustedAt: timestamp('trusted_at', { withTimezone: true }).notNull().defaultNow(),
});
