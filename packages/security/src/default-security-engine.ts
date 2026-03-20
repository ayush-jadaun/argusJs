import type {
  CacheAdapter, DbAdapter, SecurityEngine,
  LoginRiskContext, RiskAssessment, Session, TrustedDevice,
  SharingDetection, BruteForceResult, LockStatus,
} from '@argus/core';
import { BruteForceProtection } from './brute-force.js';
import { AnomalyDetector } from './anomaly-detector.js';
import { SharingDetector } from './sharing-detector.js';
import { DeviceTrust } from './device-trust.js';

export interface SecurityConfig {
  bruteForce?: {
    maxAttempts?: number;
    lockoutDuration?: number;
    captchaThreshold?: number;
    windowSeconds?: number;
  };
  sharing?: {
    maxConcurrentIPs?: number;
    maxConcurrentDevices?: number;
    action?: 'allow' | 'challenge' | 'block';
  };
  risk?: {
    newDeviceScore?: number;
    newGeoScore?: number;
    unusualTimeScore?: number;
    torExitScore?: number;
    challengeThreshold?: number;
    blockThreshold?: number;
  };
}

export interface SecurityEngineOptions {
  cache: CacheAdapter;
  db: DbAdapter;
  config?: SecurityConfig;
}

export class DefaultSecurityEngine implements SecurityEngine {
  private bruteForce: BruteForceProtection;
  private anomalyDetector: AnomalyDetector;
  private sharingDetector: SharingDetector;
  private deviceTrust: DeviceTrust;

  constructor(options: SecurityEngineOptions) {
    const { cache, db, config } = options;

    this.bruteForce = new BruteForceProtection(cache, config?.bruteForce);
    this.anomalyDetector = new AnomalyDetector(cache, config?.risk);
    this.sharingDetector = new SharingDetector(db, config?.sharing);
    this.deviceTrust = new DeviceTrust(db, cache);
  }

  async init(): Promise<void> {
    // No-op: adapters are initialized externally
  }

  async shutdown(): Promise<void> {
    // No-op: adapters are shut down externally
  }

  // ─── Risk Assessment ────────────────────────────────────────────────────

  async assessLoginRisk(context: LoginRiskContext): Promise<RiskAssessment> {
    return this.anomalyDetector.assessRisk(context);
  }

  async assessSessionRisk(session: Session): Promise<RiskAssessment> {
    // Assess risk based on session properties
    const context: LoginRiskContext = {
      userId: session.userId,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      deviceFingerprint: session.deviceFingerprint ?? undefined,
    };
    return this.anomalyDetector.assessRisk(context);
  }

  // ─── Device Trust ──────────────────────────────────────────────────────

  async isDeviceTrusted(userId: string, fingerprint: string): Promise<boolean> {
    return this.deviceTrust.isTrusted(userId, fingerprint);
  }

  async trustDevice(userId: string, device: TrustedDevice): Promise<TrustedDevice> {
    return this.deviceTrust.trust(userId, device);
  }

  async revokeDevice(userId: string, deviceId: string): Promise<void> {
    return this.deviceTrust.revoke(userId, deviceId);
  }

  async listTrustedDevices(userId: string): Promise<TrustedDevice[]> {
    return this.deviceTrust.listTrustedDevices(userId);
  }

  // ─── Concurrent Sessions ──────────────────────────────────────────────

  async detectConcurrentSessions(userId: string, currentSession: Session): Promise<SharingDetection> {
    return this.sharingDetector.detect(userId, currentSession);
  }

  // ─── Brute Force ──────────────────────────────────────────────────────

  async recordFailedAttempt(identifier: string, ip: string): Promise<BruteForceResult> {
    return this.bruteForce.recordFailedAttempt(identifier, ip);
  }

  async isLocked(identifier: string): Promise<LockStatus> {
    return this.bruteForce.isLocked(identifier);
  }

  async resetAttempts(identifier: string): Promise<void> {
    return this.bruteForce.resetAttempts(identifier);
  }
}
