import type { CacheAdapter, LoginRiskContext, RiskAssessment, RiskFactor } from '@argusjs/core';

export interface RiskConfig {
  newDeviceScore: number;
  newGeoScore: number;
  unusualTimeScore: number;
  torExitScore: number;
  challengeThreshold: number;
  blockThreshold: number;
}

const DEFAULTS: RiskConfig = {
  newDeviceScore: 20,
  newGeoScore: 30,
  unusualTimeScore: 10,
  torExitScore: 40,
  challengeThreshold: 50,
  blockThreshold: 75,
};

export class AnomalyDetector {
  private config: RiskConfig;

  constructor(
    private cache: CacheAdapter,
    config?: Partial<RiskConfig>,
  ) {
    this.config = { ...DEFAULTS, ...config };
  }

  async assessRisk(context: LoginRiskContext): Promise<RiskAssessment> {
    const factors: RiskFactor[] = [];
    let score = 0;

    // Check new device
    if (context.deviceFingerprint) {
      const knownDevicesKey = `known_devices:${context.userId}`;
      const isKnown = await this.cache.sismember(knownDevicesKey, context.deviceFingerprint);
      if (!isKnown) {
        score += this.config.newDeviceScore;
        factors.push({
          type: 'new_device',
          score: this.config.newDeviceScore,
          description: 'Login from an unrecognized device',
        });
      }
    }

    // Check new geo location
    if (context.geoLocation) {
      const knownGeosKey = `known_geos:${context.userId}`;
      const geoKey = `${context.geoLocation.country}:${context.geoLocation.region ?? ''}`;
      const isKnownGeo = await this.cache.sismember(knownGeosKey, geoKey);
      if (!isKnownGeo) {
        score += this.config.newGeoScore;
        factors.push({
          type: 'new_geo',
          score: this.config.newGeoScore,
          description: `Login from new location: ${context.geoLocation.country}`,
        });
      }
    }

    // Determine level
    let level: RiskAssessment['level'];
    if (score <= 25) {
      level = 'low';
    } else if (score <= 50) {
      level = 'medium';
    } else if (score <= 75) {
      level = 'high';
    } else {
      level = 'critical';
    }

    // Determine action
    let action: RiskAssessment['action'];
    if (score >= this.config.blockThreshold) {
      action = 'block';
    } else if (score >= this.config.challengeThreshold) {
      action = 'challenge';
    } else {
      action = 'allow';
    }

    return { score, level, factors, action };
  }
}
