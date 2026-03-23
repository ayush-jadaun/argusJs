import argon2 from 'argon2';
import type { PasswordHasher } from '@argusjs/core';
import { HashWorkerPool } from './worker-pool.js';

export interface Argon2Config {
  memoryCost?: number;    // KB, default 65536 (64MB)
  timeCost?: number;      // iterations, default 3
  parallelism?: number;   // threads per hash, default 4
  useWorkerThreads?: boolean;  // default true (uses libuv thread pool)
  workerPoolSize?: number;     // default: number of CPU cores
  /** Use a dedicated worker thread pool to avoid event-loop starvation under heavy load */
  useWorkerPool?: boolean;     // default false
  /** Number of workers in the dedicated pool (default: 4) */
  workerPoolThreads?: number;
}

export class Argon2Hasher implements PasswordHasher {
  name = 'argon2id';
  private memoryCost: number;
  private timeCost: number;
  private parallelism: number;
  private useWorkerPool: boolean;
  private workerPoolThreads: number;
  private pool: HashWorkerPool | null = null;

  constructor(config?: Argon2Config) {
    this.memoryCost = config?.memoryCost ?? 65536;
    this.timeCost = config?.timeCost ?? 3;
    this.parallelism = config?.parallelism ?? 4;
    this.useWorkerPool = config?.useWorkerPool ?? false;
    this.workerPoolThreads = config?.workerPoolThreads ?? 4;
  }

  private ensurePool(): HashWorkerPool {
    if (!this.pool) {
      this.pool = new HashWorkerPool(this.workerPoolThreads);
      this.pool.init();
    }
    return this.pool;
  }

  async hash(password: string): Promise<string> {
    if (this.useWorkerPool) {
      const pool = this.ensurePool();
      return pool.exec({
        op: 'hash',
        password,
        memoryCost: this.memoryCost,
        timeCost: this.timeCost,
        parallelism: this.parallelism,
      });
    }
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: this.memoryCost,
      timeCost: this.timeCost,
      parallelism: this.parallelism,
    });
  }

  async verify(password: string, hash: string): Promise<boolean> {
    if (this.useWorkerPool) {
      try {
        const pool = this.ensurePool();
        return await pool.exec({ op: 'verify', password, hash });
      } catch {
        return false;
      }
    }
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

  /** Shut down the worker pool (if active). Call during graceful shutdown. */
  async shutdown(): Promise<void> {
    if (this.pool) {
      await this.pool.shutdown();
      this.pool = null;
    }
  }
}
