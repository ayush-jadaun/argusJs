import type { CacheAdapter, DbAdapter, TrustedDevice } from '@argusjs/core';

export class DeviceTrust {
  constructor(
    private db: DbAdapter,
    private cache: CacheAdapter,
  ) {}

  async isTrusted(userId: string, fingerprint: string): Promise<boolean> {
    // Check cache first
    const cacheKey = `trusted_devices:${userId}`;
    const cached = await this.cache.sismember(cacheKey, fingerprint);
    if (cached) return true;

    // Fall back to DB
    const trusted = await this.db.isTrustedDevice(userId, fingerprint);
    if (trusted) {
      // Populate cache for next time
      await this.cache.sadd(cacheKey, fingerprint);
    }
    return trusted;
  }

  async trust(userId: string, device: TrustedDevice): Promise<TrustedDevice> {
    const saved = await this.db.saveTrustedDevice(device);
    const cacheKey = `trusted_devices:${userId}`;
    await this.cache.sadd(cacheKey, device.fingerprint);
    return saved;
  }

  async revoke(userId: string, deviceId: string): Promise<void> {
    // Get the device first so we know the fingerprint to remove from cache
    const devices = await this.db.getTrustedDevices(userId);
    const device = devices.find(d => d.id === deviceId);

    await this.db.removeTrustedDevice(userId, deviceId);

    if (device) {
      // Remove from cache - delete the whole set and re-populate
      const cacheKey = `trusted_devices:${userId}`;
      await this.cache.del(cacheKey);
      // Re-populate cache with remaining devices
      const remaining = await this.db.getTrustedDevices(userId);
      for (const d of remaining) {
        await this.cache.sadd(cacheKey, d.fingerprint);
      }
    }
  }

  async listTrustedDevices(userId: string): Promise<TrustedDevice[]> {
    return this.db.getTrustedDevices(userId);
  }
}
