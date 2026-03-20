export interface CacheAdapter {
  init(): Promise<void>;
  shutdown(): Promise<void>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  del(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
  incr(key: string, ttlSeconds: number): Promise<number>;
  sadd(key: string, member: string): Promise<void>;
  sismember(key: string, member: string): Promise<boolean>;
  smembers(key: string): Promise<string[]>;
  healthCheck(): Promise<boolean>;
}
