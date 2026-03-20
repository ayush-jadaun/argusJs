import { varchar, text, jsonb } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const accessPolicies = authSchema.table('access_policies', {
  id: varchar('id', { length: 255 }).primaryKey(),
  name: varchar('name', { length: 255 }).notNull(),
  effect: varchar('effect', { length: 10 }).notNull(),
  actions: text('actions').array().notNull().default([]),
  conditions: jsonb('conditions').notNull().default([]),
});
