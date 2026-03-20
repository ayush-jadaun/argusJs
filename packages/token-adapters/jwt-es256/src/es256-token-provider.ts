import * as jose from 'jose';
import type { TokenProvider, JsonWebKeySet, JsonWebKey } from '@argus/core';
import type { AccessTokenClaims } from '@argus/core';

export interface ES256Config {
  privateKey?: string;
  keyId?: string;
  issuer?: string;
  audience?: string[];
  accessTokenTTL?: number;
  mfaTokenTTL?: number;
}

export class ES256TokenProvider implements TokenProvider {
  private readonly config: ES256Config;
  private signingKey!: CryptoKey;
  private verifyKey!: CryptoKey;
  private publicJWK!: JsonWebKey;
  private kid!: string;

  constructor(config: ES256Config = {}) {
    this.config = config;
  }

  async init(): Promise<void> {
    if (this.config.privateKey) {
      this.signingKey = await jose.importPKCS8(this.config.privateKey, 'ES256');
      const jwk = await jose.exportJWK(this.signingKey);
      // Derive public key by importing JWK without the private component
      const { d: _d, ...publicJwkData } = jwk;
      this.verifyKey = await jose.importJWK({ ...publicJwkData, alg: 'ES256' }, 'ES256') as CryptoKey;
      this.kid = this.config.keyId ?? crypto.randomUUID();
      this.publicJWK = {
        kty: publicJwkData.kty!,
        crv: publicJwkData.crv,
        x: publicJwkData.x,
        y: publicJwkData.y,
        use: 'sig',
        alg: 'ES256',
        kid: this.kid,
      };
    } else {
      const { publicKey, privateKey } = await jose.generateKeyPair('ES256', {
        extractable: true,
      });
      this.signingKey = privateKey;
      this.verifyKey = publicKey;
      this.kid = this.config.keyId ?? crypto.randomUUID();
      const jwk = await jose.exportJWK(publicKey);
      this.publicJWK = {
        kty: jwk.kty!,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
        use: 'sig',
        alg: 'ES256',
        kid: this.kid,
      };
    }
  }

  async signAccessToken(payload: AccessTokenClaims): Promise<string> {
    const { iss, sub, aud, exp, iat, jti, ...rest } = payload;
    return new jose.SignJWT({ ...rest })
      .setProtectedHeader({ alg: 'ES256', kid: this.kid })
      .setIssuer(iss)
      .setSubject(sub)
      .setAudience(aud)
      .setExpirationTime(exp)
      .setIssuedAt(iat)
      .setJti(jti)
      .sign(this.signingKey);
  }

  async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    const { payload } = await jose.jwtVerify(token, this.verifyKey, {
      issuer: this.config.issuer,
      audience: this.config.audience,
    });
    return payload as unknown as AccessTokenClaims;
  }

  async signMFAToken(userId: string): Promise<string> {
    const ttl = this.config.mfaTokenTTL ?? 300;
    return new jose.SignJWT({ userId, purpose: 'mfa' })
      .setProtectedHeader({ alg: 'ES256', kid: this.kid })
      .setIssuer(this.config.issuer ?? 'argus')
      .setExpirationTime(Math.floor(Date.now() / 1000) + ttl)
      .setIssuedAt()
      .sign(this.signingKey);
  }

  async verifyMFAToken(token: string): Promise<{ userId: string }> {
    const { payload } = await jose.jwtVerify(token, this.verifyKey, {
      issuer: this.config.issuer ?? 'argus',
    });
    if (payload.purpose !== 'mfa') {
      throw new Error('Invalid MFA token: wrong purpose');
    }
    return { userId: payload.userId as string };
  }

  getJWKS(): JsonWebKeySet {
    return { keys: [this.publicJWK] };
  }
}
