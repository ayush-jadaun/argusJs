import {
  generateKeyPair,
  SignJWT,
  jwtVerify,
  importPKCS8,
  exportJWK,
  exportSPKI,
  importSPKI,
} from 'jose';
import type {
  TokenProvider,
  JsonWebKeySet,
  JsonWebKey,
  AccessTokenClaims,
} from '@argusjs/core';

export interface RS256Config {
  privateKey?: string;
  keyId?: string;
  issuer?: string;
  audience?: string[];
  accessTokenTTL?: number;
  refreshTokenTTL?: number;
  mfaTokenTTL?: number;
}

export class RS256TokenProvider implements TokenProvider {
  private readonly config: Required<
    Pick<RS256Config, 'keyId' | 'issuer' | 'audience' | 'accessTokenTTL' | 'mfaTokenTTL'>
  > & Pick<RS256Config, 'privateKey' | 'refreshTokenTTL'>;

  private privateKey!: CryptoKey;
  private publicKey!: CryptoKey;
  private jwk!: JsonWebKey;

  constructor(config: RS256Config = {}) {
    this.config = {
      privateKey: config.privateKey,
      keyId: config.keyId ?? 'key-1',
      issuer: config.issuer ?? 'argus',
      audience: config.audience ?? ['argus'],
      accessTokenTTL: config.accessTokenTTL ?? 900,
      refreshTokenTTL: config.refreshTokenTTL,
      mfaTokenTTL: config.mfaTokenTTL ?? 300,
    };
  }

  async init(): Promise<void> {
    if (this.config.privateKey) {
      this.privateKey = await importPKCS8(this.config.privateKey, 'RS256');
      const spki = await exportSPKI(
        await this.derivePublicKey(this.config.privateKey),
      );
      this.publicKey = await importSPKI(spki, 'RS256');
    } else {
      const pair = await generateKeyPair('RS256', { extractable: true });
      this.privateKey = pair.privateKey;
      this.publicKey = pair.publicKey;
    }

    const pubJwk = await exportJWK(this.publicKey);
    this.jwk = {
      kty: pubJwk.kty!,
      n: pubJwk.n,
      e: pubJwk.e,
      alg: 'RS256',
      use: 'sig',
      kid: this.config.keyId,
    };
  }

  async shutdown(): Promise<void> {
    // no-op
  }

  async signAccessToken(payload: AccessTokenClaims): Promise<string> {
    const jwt = new SignJWT({
      email: payload.email,
      emailVerified: payload.emailVerified,
      roles: payload.roles,
      permissions: payload.permissions,
      sessionId: payload.sessionId,
      ...(payload.orgId !== undefined && { orgId: payload.orgId }),
      ...(payload.orgRole !== undefined && { orgRole: payload.orgRole }),
    })
      .setProtectedHeader({ alg: 'RS256', kid: this.config.keyId })
      .setSubject(payload.sub)
      .setIssuer(this.config.issuer)
      .setAudience(this.config.audience)
      .setIssuedAt(payload.iat)
      .setExpirationTime(payload.exp)
      .setJti(payload.jti);

    return jwt.sign(this.privateKey);
  }

  async verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: this.config.issuer,
      audience: this.config.audience,
    });

    return {
      iss: payload.iss!,
      sub: payload.sub!,
      aud: payload.aud as string[],
      exp: payload.exp!,
      iat: payload.iat!,
      jti: payload.jti!,
      email: payload.email as string,
      emailVerified: payload.emailVerified as boolean,
      roles: payload.roles as string[],
      permissions: payload.permissions as string[],
      sessionId: payload.sessionId as string,
      ...(payload.orgId !== undefined && { orgId: payload.orgId as string }),
      ...(payload.orgRole !== undefined && { orgRole: payload.orgRole as string }),
    };
  }

  async signMFAToken(userId: string): Promise<string> {
    return new SignJWT({ type: 'mfa' })
      .setProtectedHeader({ alg: 'RS256', kid: this.config.keyId })
      .setSubject(userId)
      .setIssuer(this.config.issuer)
      .setIssuedAt()
      .setExpirationTime(`${this.config.mfaTokenTTL}s`)
      .sign(this.privateKey);
  }

  async verifyMFAToken(token: string): Promise<{ userId: string }> {
    const { payload } = await jwtVerify(token, this.publicKey, {
      issuer: this.config.issuer,
    });

    if (payload.type !== 'mfa') {
      throw new Error('Invalid MFA token: wrong type');
    }

    return { userId: payload.sub! };
  }

  getJWKS(): JsonWebKeySet {
    return {
      keys: [this.jwk],
    };
  }

  async rotateKeys(): Promise<void> {
    const pair = await generateKeyPair('RS256', { extractable: true });
    this.privateKey = pair.privateKey;
    this.publicKey = pair.publicKey;

    const kidNum = parseInt(this.config.keyId.replace(/\D/g, '') || '1', 10);
    this.config.keyId = `key-${kidNum + 1}`;

    const pubJwk = await exportJWK(this.publicKey);
    this.jwk = {
      kty: pubJwk.kty!,
      n: pubJwk.n,
      e: pubJwk.e,
      alg: 'RS256',
      use: 'sig',
      kid: this.config.keyId,
    };
  }

  private async derivePublicKey(pem: string): Promise<CryptoKey> {
    const privKey = await importPKCS8(pem, 'RS256');
    const jwk = await exportJWK(privKey);
    // Remove private key components to get public key JWK
    delete jwk.d;
    delete jwk.p;
    delete jwk.q;
    delete jwk.dp;
    delete jwk.dq;
    delete jwk.qi;
    const { importJWK } = await import('jose');
    return importJWK(jwk, 'RS256') as Promise<CryptoKey>;
  }
}
