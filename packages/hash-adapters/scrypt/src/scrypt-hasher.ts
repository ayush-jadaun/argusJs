import { scrypt, randomBytes, timingSafeEqual, type BinaryLike, type ScryptOptions } from 'node:crypto';
import type { PasswordHasher } from '@argus/core';

function scryptAsync(password: BinaryLike, salt: BinaryLike, keylen: number, options: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, options, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

export interface ScryptConfig {
  cost?: number;           // N, default 16384
  blockSize?: number;      // r, default 8
  parallelization?: number; // p, default 1
  keyLength?: number;      // default 64
}

export class ScryptHasher implements PasswordHasher {
  name = 'scrypt';
  private cost: number;
  private blockSize: number;
  private parallelization: number;
  private keyLength: number;

  constructor(config?: ScryptConfig) {
    this.cost = config?.cost ?? 16384;
    this.blockSize = config?.blockSize ?? 8;
    this.parallelization = config?.parallelization ?? 1;
    this.keyLength = config?.keyLength ?? 64;
  }

  async hash(password: string): Promise<string> {
    const salt = randomBytes(16);
    const derived = await scryptAsync(password, salt, this.keyLength, {
      N: this.cost, r: this.blockSize, p: this.parallelization,
    });
    return `${salt.toString('hex')}:${derived.toString('hex')}`;
  }

  async verify(password: string, hash: string): Promise<boolean> {
    const [saltHex, keyHex] = hash.split(':');
    if (!saltHex || !keyHex) return false;
    const salt = Buffer.from(saltHex, 'hex');
    const existingKey = Buffer.from(keyHex, 'hex');
    const derived = await scryptAsync(password, salt, existingKey.length, {
      N: this.cost, r: this.blockSize, p: this.parallelization,
    });
    return timingSafeEqual(existingKey, derived);
  }
}
