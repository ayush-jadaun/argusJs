#!/usr/bin/env node
/**
 * User Export Script for ArgusJS
 *
 * Exports all users to CSV or JSON format.
 *
 * Usage:
 *   pnpm users:export --format csv --output users.csv
 *   pnpm users:export --format json --output users.json
 *   pnpm users:export --format csv --output users.csv --api-url http://localhost:3100 --api-key argus_pk_xxx
 */

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

interface ExportedUser {
  id: string;
  email: string;
  displayName: string;
  emailVerified: boolean;
  mfaEnabled: boolean;
  roles: string[];
  orgId: string | null;
  lockedUntil: string | null;
  lastLoginAt: string | null;
  createdAt: string;
}

function parseArgs(): { format: string; output: string; apiUrl: string; apiKey: string } {
  const args = process.argv.slice(2);
  let format = 'json';
  let output = '';
  let apiUrl = process.env.ARGUS_API_URL || 'http://localhost:3100';
  let apiKey = process.env.ARGUS_API_KEY || '';

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--format': format = args[++i] ?? 'json'; break;
      case '--output': output = args[++i] ?? ''; break;
      case '--api-url': apiUrl = args[++i] ?? apiUrl; break;
      case '--api-key': apiKey = args[++i] ?? apiKey; break;
    }
  }

  if (!output) {
    output = format === 'csv' ? 'users-export.csv' : 'users-export.json';
  }

  if (!apiKey) {
    console.error('API key required. Pass --api-key or set ARGUS_API_KEY env var.');
    process.exit(1);
  }

  return { format, output, apiUrl, apiKey };
}

async function fetchAllUsers(apiUrl: string, apiKey: string): Promise<ExportedUser[]> {
  const allUsers: ExportedUser[] = [];
  const limit = 100;
  let offset = 0;
  let total = Infinity;

  while (offset < total) {
    const res = await fetch(`${apiUrl}/v1/admin/users?limit=${limit}&offset=${offset}`, {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(`API error: ${body?.error?.message ?? `HTTP ${res.status}`}`);
    }

    const data = await res.json() as { users: ExportedUser[]; total: number };
    allUsers.push(...data.users);
    total = data.total;
    offset += limit;

    process.stdout.write(`\rFetched ${allUsers.length}/${total} users`);
  }

  console.log('');
  return allUsers;
}

function toCSV(users: ExportedUser[]): string {
  const headers = [
    'id', 'email', 'displayName', 'emailVerified', 'mfaEnabled',
    'roles', 'orgId', 'lockedUntil', 'lastLoginAt', 'createdAt',
  ];

  const lines = [headers.join(',')];

  for (const user of users) {
    const values = [
      user.id,
      user.email,
      `"${(user.displayName || '').replace(/"/g, '""')}"`,
      String(user.emailVerified ?? false),
      String(user.mfaEnabled ?? false),
      `"${(user.roles || []).join(';')}"`,
      user.orgId ?? '',
      user.lockedUntil ?? '',
      user.lastLoginAt ?? '',
      user.createdAt ?? '',
    ];
    lines.push(values.join(','));
  }

  return lines.join('\n');
}

function toJSON(users: ExportedUser[]): string {
  return JSON.stringify({
    exportedAt: new Date().toISOString(),
    total: users.length,
    users,
  }, null, 2);
}

async function main(): Promise<void> {
  const { format, output, apiUrl, apiKey } = parseArgs();

  console.log(`Exporting users as ${format.toUpperCase()} to ${output}`);
  console.log(`API URL: ${apiUrl}`);

  const users = await fetchAllUsers(apiUrl, apiKey);

  if (users.length === 0) {
    console.log('No users to export.');
    return;
  }

  const content = format === 'csv' ? toCSV(users) : toJSON(users);

  const outputPath = resolve(process.cwd(), output);
  writeFileSync(outputPath, content, 'utf-8');

  console.log(`\nExported ${users.length} users to ${outputPath}`);
}

main().catch(err => {
  console.error('Export failed:', err);
  process.exit(1);
});
