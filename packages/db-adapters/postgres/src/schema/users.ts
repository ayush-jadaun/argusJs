import { pgSchema, uuid, varchar, boolean, timestamp, text, jsonb, integer } from 'drizzle-orm/pg-core';

export const authSchema = pgSchema('auth');

export const users = authSchema.table('users', {
  id: uuid('id').defaultRandom().primaryKey(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: varchar('password_hash', { length: 255 }),
  displayName: varchar('display_name', { length: 100 }).notNull(),
  avatarUrl: varchar('avatar_url', { length: 2048 }),
  emailVerified: boolean('email_verified').notNull().default(false),
  mfaEnabled: boolean('mfa_enabled').notNull().default(false),
  mfaMethods: text('mfa_methods').array().notNull().default([]),
  roles: text('roles').array().notNull().default([]),
  permissions: text('permissions').array().notNull().default([]),
  orgId: uuid('org_id'),
  orgRole: varchar('org_role', { length: 50 }),
  failedLoginAttempts: integer('failed_login_attempts').notNull().default(0),
  lockedUntil: timestamp('locked_until', { withTimezone: true }),
  lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
  lastLoginIp: varchar('last_login_ip', { length: 45 }),
  emailVerifiedAt: timestamp('email_verified_at', { withTimezone: true }),
  metadata: jsonb('metadata').notNull().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  deletedAt: timestamp('deleted_at', { withTimezone: true }),
});
