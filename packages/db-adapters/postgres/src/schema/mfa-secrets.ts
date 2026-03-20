import { uuid, varchar, text, boolean, timestamp } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const mfaSecrets = authSchema.table('mfa_secrets', {
  id: uuid('id').defaultRandom().primaryKey(),
  userId: uuid('user_id').notNull().unique(),
  method: varchar('method', { length: 50 }).notNull(),
  encryptedSecret: varchar('encrypted_secret', { length: 1024 }).notNull(),
  encryptedBackupCodes: text('encrypted_backup_codes').array().notNull().default([]),
  backupCodesUsed: boolean('backup_codes_used').array().notNull().default([]),
  recoveryEmail: varchar('recovery_email', { length: 255 }),
  enabledAt: timestamp('enabled_at', { withTimezone: true }).notNull().defaultNow(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});
