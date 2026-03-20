import type { AccessTokenClaims } from '../types/responses.js';

export interface JsonWebKeySet {
  keys: JsonWebKey[];
}

export interface JsonWebKey {
  kty: string;
  use?: string;
  alg?: string;
  kid?: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
}

export interface TokenProvider {
  init(): Promise<void>;
  shutdown?(): Promise<void>;
  signAccessToken(payload: AccessTokenClaims): Promise<string>;
  verifyAccessToken(token: string): Promise<AccessTokenClaims>;
  signMFAToken(userId: string): Promise<string>;
  verifyMFAToken(token: string): Promise<{ userId: string }>;
  getJWKS(): JsonWebKeySet;
  rotateKeys?(): Promise<void>;
}
