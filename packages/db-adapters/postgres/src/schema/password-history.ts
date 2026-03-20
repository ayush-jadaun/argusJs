import { uuid, varchar, timestamp, serial } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const passwordHistory = authSchema.table('password_history', {
  id: serial('id').primaryKey(),
  userId: uuid('user_id').notNull(),
  passwordHash: varchar('password_hash', { length: 255 }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
