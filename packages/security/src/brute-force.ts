import type { CacheAdapter, BruteForceResult, LockStatus } from '@argusjs/core';

export interface BruteForceConfig {
  maxAttempts: number;
  lockoutDuration: number;
  captchaThreshold: number;
  windowSeconds: number;
}

const DEFAULTS: BruteForceConfig = {
  maxAttempts: 10,
  lockoutDuration: 1800,
  captchaThreshold: 3,
  windowSeconds: 900,
};

export class BruteForceProtection {
  private config: BruteForceConfig;

  constructor(
    private cache: CacheAdapter,
    config?: Partial<BruteForceConfig>,
  ) {
    this.config = { ...DEFAULTS, ...config };
  }

  async recordFailedAttempt(identifier: string, ip: string): Promise<BruteForceResult> {
    const lockKey = `lock:${identifier}`;

    // Check if already locked
    const lockUntil = await this.cache.get(lockKey);
    if (lockUntil) {
      return {
        allowed: false,
        failedAttempts: this.config.maxAttempts,
        maxAttempts: this.config.maxAttempts,
        lockoutUntil: new Date(parseInt(lockUntil, 10)),
        requireCaptcha: true,
      };
    }

    const accountKey = `bf:account:${identifier}`;
    const ipKey = `bf:ip:${ip}`;

    // Increment counters
    const accountCount = await this.cache.incr(accountKey, this.config.windowSeconds);
    await this.cache.incr(ipKey, this.config.windowSeconds);

    // Check if max attempts exceeded
    if (accountCount >= this.config.maxAttempts) {
      const lockoutUntil = Date.now() + this.config.lockoutDuration * 1000;
      await this.cache.set(lockKey, String(lockoutUntil), this.config.lockoutDuration);
      return {
        allowed: false,
        failedAttempts: accountCount,
        maxAttempts: this.config.maxAttempts,
        lockoutUntil: new Date(lockoutUntil),
        requireCaptcha: true,
      };
    }

    return {
      allowed: true,
      failedAttempts: accountCount,
      maxAttempts: this.config.maxAttempts,
      requireCaptcha: accountCount >= this.config.captchaThreshold,
    };
  }

  async isLocked(identifier: string): Promise<LockStatus> {
    const lockKey = `lock:${identifier}`;
    const lockUntil = await this.cache.get(lockKey);
    if (lockUntil) {
      return { locked: true, until: new Date(parseInt(lockUntil, 10)) };
    }
    return { locked: false };
  }

  async resetAttempts(identifier: string): Promise<void> {
    const accountKey = `bf:account:${identifier}`;
    const lockKey = `lock:${identifier}`;
    await this.cache.del(accountKey);
    await this.cache.del(lockKey);
  }
}
