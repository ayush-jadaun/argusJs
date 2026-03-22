import argon2 from 'argon2';
import type { PasswordHasher } from '@argusjs/core';

export interface Argon2Config {
  memoryCost?: number;    // KB, default 65536 (64MB)
  timeCost?: number;      // iterations, default 3
  parallelism?: number;   // threads per hash, default 4
  useWorkerThreads?: boolean;  // default true (uses libuv thread pool)
  workerPoolSize?: number;     // default: number of CPU cores
}

export class Argon2Hasher implements PasswordHasher {
  name = 'argon2id';
  private memoryCost: number;
  private timeCost: number;
  private parallelism: number;

  constructor(config?: Argon2Config) {
    this.memoryCost = config?.memoryCost ?? 65536;
    this.timeCost = config?.timeCost ?? 3;
    this.parallelism = config?.parallelism ?? 4;
  }

  async hash(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: this.memoryCost,
      timeCost: this.timeCost,
      parallelism: this.parallelism,
    });
  }

  async verify(password: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }

  needsRehash(hash: string): boolean {
    try {
      return argon2.needsRehash(hash, {
        memoryCost: this.memoryCost,
        timeCost: this.timeCost,
      });
    } catch {
      return true;
    }
  }
}
