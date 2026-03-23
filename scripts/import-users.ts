#!/usr/bin/env node
/**
 * User Import Script for ArgusJS
 *
 * Reads CSV or JSON file and bulk creates users via the admin API.
 *
 * Usage:
 *   pnpm users:import --file users.csv --format csv
 *   pnpm users:import --file users.json --format json
 *   pnpm users:import --file users.csv --format csv --api-url http://localhost:3100 --api-key argus_pk_xxx
 *
 * CSV format (first row is header):
 *   email,displayName,roles,password
 *   user@example.com,John Doe,user,optional-password
 *
 * JSON format:
 *   [{ "email": "user@example.com", "displayName": "John", "roles": ["user"] }]
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

interface UserRecord {
  email: string;
  displayName: string;
  roles?: string[];
  password?: string;
  emailVerified?: boolean;
  metadata?: Record<string, unknown>;
}

interface ImportResult {
  total: number;
  created: number;
  skipped: number;
  errors: Array<{ email: string; error: string }>;
}

function parseArgs(): { file: string; format: string; apiUrl: string; apiKey: string } {
  const args = process.argv.slice(2);
  let file = '';
  let format = '';
  let apiUrl = process.env.ARGUS_API_URL || 'http://localhost:3100';
  let apiKey = process.env.ARGUS_API_KEY || '';

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--file': file = args[++i] ?? ''; break;
      case '--format': format = args[++i] ?? ''; break;
      case '--api-url': apiUrl = args[++i] ?? apiUrl; break;
      case '--api-key': apiKey = args[++i] ?? apiKey; break;
    }
  }

  if (!file) {
    console.error('Usage: pnpm users:import --file <path> --format <csv|json> [--api-url URL] [--api-key KEY]');
    process.exit(1);
  }

  if (!format) {
    // Auto-detect from extension
    format = file.endsWith('.json') ? 'json' : 'csv';
  }

  return { file, format, apiUrl, apiKey };
}

function parseCSV(content: string): UserRecord[] {
  const lines = content.trim().split('\n');
  if (lines.length < 2) return [];

  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
  const users: UserRecord[] = [];

  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(',').map(v => v.trim());
    const record: Record<string, string> = {};
    headers.forEach((h, idx) => { record[h] = values[idx] ?? ''; });

    users.push({
      email: record.email || '',
      displayName: record.displayname || record.display_name || record.name || record.email || '',
      roles: record.roles ? record.roles.split(';').map(r => r.trim()) : ['user'],
      password: record.password || undefined,
      emailVerified: record.emailverified === 'true' || record.email_verified === 'true',
      metadata: {},
    });
  }

  return users.filter(u => u.email);
}

function parseJSON(content: string): UserRecord[] {
  const data = JSON.parse(content);
  const items = Array.isArray(data) ? data : data.users ?? [];

  return items.map((item: any) => ({
    email: item.email || '',
    displayName: item.displayName || item.display_name || item.name || item.email || '',
    roles: Array.isArray(item.roles) ? item.roles : ['user'],
    password: item.password || undefined,
    emailVerified: item.emailVerified ?? item.email_verified ?? false,
    metadata: item.metadata || {},
  })).filter((u: UserRecord) => u.email);
}

async function importUser(
  user: UserRecord,
  apiUrl: string,
  apiKey: string,
): Promise<{ success: boolean; error?: string }> {
  try {
    // Use admin API to create user if api key is available
    // Otherwise use the register endpoint
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    if (user.password) {
      // Register via public API
      const res = await fetch(`${apiUrl}/v1/auth/register`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          email: user.email,
          password: user.password,
          displayName: user.displayName,
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = body?.error?.message ?? `HTTP ${res.status}`;
        if (msg.includes('already') || res.status === 409) {
          return { success: false, error: 'already exists' };
        }
        return { success: false, error: msg };
      }
      return { success: true };
    } else {
      // Create via admin API (no password)
      if (!apiKey) {
        return { success: false, error: 'API key required for passwordless import' };
      }

      const res = await fetch(`${apiUrl}/v1/admin/users`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          email: user.email,
          displayName: user.displayName,
          roles: user.roles,
          emailVerified: user.emailVerified,
          metadata: user.metadata,
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = body?.error?.message ?? `HTTP ${res.status}`;
        if (msg.includes('already') || res.status === 409) {
          return { success: false, error: 'already exists' };
        }
        return { success: false, error: msg };
      }
      return { success: true };
    }
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

async function main(): Promise<void> {
  const { file, format, apiUrl, apiKey } = parseArgs();

  const filePath = resolve(process.cwd(), file);
  console.log(`Reading ${format.toUpperCase()} file: ${filePath}`);

  let content: string;
  try {
    content = readFileSync(filePath, 'utf-8');
  } catch (err) {
    console.error(`Failed to read file: ${(err as Error).message}`);
    process.exit(1);
  }

  const users = format === 'json' ? parseJSON(content) : parseCSV(content);
  console.log(`Found ${users.length} users to import`);

  if (users.length === 0) {
    console.log('No users to import.');
    return;
  }

  const result: ImportResult = { total: users.length, created: 0, skipped: 0, errors: [] };

  // Process in batches of 10
  const batchSize = 10;
  for (let i = 0; i < users.length; i += batchSize) {
    const batch = users.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(user => importUser(user, apiUrl, apiKey)),
    );

    for (let j = 0; j < batch.length; j++) {
      const r = results[j];
      if (r.success) {
        result.created++;
      } else if (r.error === 'already exists') {
        result.skipped++;
      } else {
        result.errors.push({ email: batch[j].email, error: r.error ?? 'unknown' });
      }
    }

    const progress = Math.min(i + batchSize, users.length);
    process.stdout.write(`\rProgress: ${progress}/${users.length}`);
  }

  console.log('\n\n--- Import Summary ---');
  console.log(`Total:   ${result.total}`);
  console.log(`Created: ${result.created}`);
  console.log(`Skipped: ${result.skipped} (already exist)`);
  console.log(`Errors:  ${result.errors.length}`);

  if (result.errors.length > 0) {
    console.log('\nErrors:');
    for (const err of result.errors.slice(0, 20)) {
      console.log(`  ${err.email}: ${err.error}`);
    }
    if (result.errors.length > 20) {
      console.log(`  ... and ${result.errors.length - 20} more`);
    }
  }
}

main().catch(err => {
  console.error('Import failed:', err);
  process.exit(1);
});
