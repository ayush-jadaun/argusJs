import bcrypt from 'bcrypt';
import type { PasswordHasher } from '@argusjs/core';

export interface BcryptConfig {
  rounds?: number; // default 12
}

export class BcryptHasher implements PasswordHasher {
  name = 'bcrypt';
  private rounds: number;

  constructor(config?: BcryptConfig) {
    this.rounds = config?.rounds ?? 12;
  }

  async hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.rounds);
  }

  async verify(password: string, hash: string): Promise<boolean> {
    try {
      return await bcrypt.compare(password, hash);
    } catch {
      return false;
    }
  }

  needsRehash(hash: string): boolean {
    const match = hash.match(/^\$2[aby]\$(\d+)\$/);
    if (!match) return true;
    return parseInt(match[1], 10) !== this.rounds;
  }
}
