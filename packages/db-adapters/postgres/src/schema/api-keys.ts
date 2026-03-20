import { uuid, varchar, text, timestamp, jsonb } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const apiKeys = authSchema.table('api_keys', {
  id: uuid('id').defaultRandom().primaryKey(),
  name: varchar('name', { length: 255 }).notNull(),
  keyPrefix: varchar('key_prefix', { length: 20 }).notNull(),
  keyHash: varchar('key_hash', { length: 255 }).notNull().unique(),
  userId: uuid('user_id').notNull(),
  orgId: uuid('org_id'),
  permissions: text('permissions').array().notNull().default([]),
  rateLimit: jsonb('rate_limit'),
  ipAllowlist: text('ip_allowlist').array().notNull().default([]),
  expiresAt: timestamp('expires_at', { withTimezone: true }),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
});
