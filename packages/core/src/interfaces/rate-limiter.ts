import type { RateLimitResult } from '../types/responses.js';

export interface RateLimiter {
  init?(): Promise<void>;
  shutdown?(): Promise<void>;
  check(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult>;
  reset(key: string): Promise<void>;
}
