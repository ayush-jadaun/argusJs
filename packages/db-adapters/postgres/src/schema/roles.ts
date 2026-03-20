import { varchar, text, boolean } from 'drizzle-orm/pg-core';
import { authSchema } from './users.js';

export const roles = authSchema.table('roles', {
  name: varchar('name', { length: 100 }).primaryKey(),
  description: varchar('description', { length: 500 }).notNull().default(''),
  permissions: text('permissions').array().notNull().default([]),
  inherits: text('inherits').array().notNull().default([]),
  isSystem: boolean('is_system').notNull().default(false),
});
