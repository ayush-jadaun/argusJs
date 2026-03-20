import type { Session, TrustedDevice } from '../types/entities.js';

export interface GeoLocation {
  country: string;
  region?: string;
  city?: string;
  lat: number;
  lon: number;
}

export interface LoginRiskContext {
  userId: string;
  ipAddress: string;
  userAgent: string;
  deviceFingerprint?: string;
  geoLocation?: GeoLocation;
}

export interface RiskFactor {
  type: string;
  score: number;
  description: string;
}

export interface RiskAssessment {
  score: number;
  level: 'low' | 'medium' | 'high' | 'critical';
  factors: RiskFactor[];
  action: 'allow' | 'challenge' | 'block';
}

export interface SharingDetection {
  detected: boolean;
  activeSessions: number;
  uniqueIps: number;
  uniqueDevices: number;
  action: 'allow' | 'challenge' | 'block';
}

export interface BruteForceResult {
  allowed: boolean;
  failedAttempts: number;
  maxAttempts: number;
  lockoutUntil?: Date;
  requireCaptcha: boolean;
}

export interface LockStatus {
  locked: boolean;
  until?: Date;
}

export interface SecurityEngine {
  init(): Promise<void>;
  shutdown(): Promise<void>;

  assessLoginRisk(context: LoginRiskContext): Promise<RiskAssessment>;
  assessSessionRisk(session: Session): Promise<RiskAssessment>;

  isDeviceTrusted(userId: string, fingerprint: string): Promise<boolean>;
  trustDevice(userId: string, device: TrustedDevice): Promise<TrustedDevice>;
  revokeDevice(userId: string, deviceId: string): Promise<void>;
  listTrustedDevices(userId: string): Promise<TrustedDevice[]>;

  detectConcurrentSessions(userId: string, currentSession: Session): Promise<SharingDetection>;

  recordFailedAttempt(identifier: string, ip: string): Promise<BruteForceResult>;
  isLocked(identifier: string): Promise<LockStatus>;
  resetAttempts(identifier: string): Promise<void>;
}
