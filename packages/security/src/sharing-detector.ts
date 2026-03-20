import type { DbAdapter, SharingDetection, Session } from '@argus/core';

export interface SharingConfig {
  maxConcurrentIPs: number;
  maxConcurrentDevices: number;
  action: 'allow' | 'challenge' | 'block';
}

const DEFAULTS: SharingConfig = {
  maxConcurrentIPs: 3,
  maxConcurrentDevices: 5,
  action: 'challenge',
};

export class SharingDetector {
  private config: SharingConfig;

  constructor(
    private db: DbAdapter,
    config?: Partial<SharingConfig>,
  ) {
    this.config = { ...DEFAULTS, ...config };
  }

  async detect(userId: string, _currentSession: Session): Promise<SharingDetection> {
    const activeSessions = await this.db.getActiveSessions(userId);

    const uniqueIps = new Set<string>();
    const uniqueDevices = new Set<string>();

    for (const session of activeSessions) {
      uniqueIps.add(session.ipAddress);
      uniqueDevices.add(session.userAgent);
    }

    const detected =
      uniqueIps.size > this.config.maxConcurrentIPs ||
      uniqueDevices.size > this.config.maxConcurrentDevices;

    return {
      detected,
      activeSessions: activeSessions.length,
      uniqueIps: uniqueIps.size,
      uniqueDevices: uniqueDevices.size,
      action: detected ? this.config.action : 'allow',
    };
  }
}
