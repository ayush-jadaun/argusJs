import * as jose from 'jose';
import type { TokenProvider, JsonWebKeySet } from '@argus/core';
import type { AccessTokenClaims } from '@argus/core';

export interface HS256Config {
  secret: string;
  issuer?: string;
  audience?: string[];
  accessTokenTTL?: number;
  mfaTokenTTL?: number;
}

export class HS256TokenProvider implements TokenProvider {
  private readonly config: HS256Config;
  private secretKey!: Uint8Array;

  constructor(config: HS256Config) {
    this.config = config;
  }

  async init(): Promise<void> {
    this.secretKey = new TextEncoder().encode(this.config.secret);
  }

  async signAccessToken(payload: AccessTokenClaims): Promise<string> {
    const { iss, sub, aud, exp, iat, jti, ...rest } = payload;
    return new jose.SignJWT({ ...rest })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(this.config.issuer ?? 'argus')
      .setSubject(sub)
      .setAudience(this.config.audience ?? ['argus'])
      .setExpirationTime(exp)
      .setIssuedAt(iat)
      .setJti(jti)
      .sign(this.secretKey);
  }

  async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    const { payload } = await jose.jwtVerify(token, this.secretKey, {
      issuer: this.config.issuer,
      audience: this.config.audience,
    });
    return payload as unknown as AccessTokenClaims;
  }

  async signMFAToken(userId: string): Promise<string> {
    const ttl = this.config.mfaTokenTTL ?? 300;
    return new jose.SignJWT({ userId, purpose: 'mfa' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(this.config.issuer ?? 'argus')
      .setExpirationTime(Math.floor(Date.now() / 1000) + ttl)
      .setIssuedAt()
      .sign(this.secretKey);
  }

  async verifyMFAToken(token: string): Promise<{ userId: string }> {
    const { payload } = await jose.jwtVerify(token, this.secretKey, {
      issuer: this.config.issuer ?? 'argus',
    });
    if (payload.purpose !== 'mfa') {
      throw new Error('Invalid MFA token: wrong purpose');
    }
    return { userId: payload.userId as string };
  }

  // HS256 uses a symmetric secret — it cannot be published in a JWKS endpoint
  getJWKS(): JsonWebKeySet {
    return { keys: [] };
  }
}
