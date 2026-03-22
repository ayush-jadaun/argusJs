import type { OAuthProviderAdapter, OAuthTokens, OAuthUserProfile } from '@argusjs/core';
import { createPrivateKey, SignJWT } from './jwt-utils.js';

export interface AppleOAuthConfig {
  clientId: string;
  teamId: string;
  keyId: string;
  privateKey: string;
  scopes?: string[];
}

const AUTHORIZATION_URL = 'https://appleid.apple.com/auth/authorize';
const TOKEN_URL = 'https://appleid.apple.com/auth/token';
const DEFAULT_SCOPES = ['name', 'email'];

export class AppleOAuth implements OAuthProviderAdapter {
  readonly name = 'apple';
  private readonly clientId: string;
  private readonly teamId: string;
  private readonly keyId: string;
  private readonly privateKey: string;
  private readonly scopes: string[];

  constructor(config: AppleOAuthConfig) {
    this.clientId = config.clientId;
    this.teamId = config.teamId;
    this.keyId = config.keyId;
    this.privateKey = config.privateKey;
    this.scopes = config.scopes ?? DEFAULT_SCOPES;
  }

  getAuthorizationUrl(state: string, redirectUri: string, codeChallenge?: string): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: this.scopes.join(' '),
      state,
      response_mode: 'form_post',
    });

    if (codeChallenge) {
      params.set('code_challenge', codeChallenge);
      params.set('code_challenge_method', 'S256');
    }

    return `${AUTHORIZATION_URL}?${params.toString()}`;
  }

  async exchangeCode(code: string, redirectUri: string, codeVerifier?: string): Promise<OAuthTokens> {
    const clientSecret = await this.generateClientSecret();

    const body: Record<string, string> = {
      client_id: this.clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    };

    if (codeVerifier) {
      body.code_verifier = codeVerifier;
    }

    const response = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Apple token exchange failed: ${error}`);
    }

    const data = await response.json() as Record<string, unknown>;

    return {
      accessToken: data.access_token as string,
      refreshToken: data.refresh_token as string | undefined,
      idToken: data.id_token as string | undefined,
      expiresIn: data.expires_in as number,
      tokenType: data.token_type as string,
    };
  }

  async getUserProfile(tokens: OAuthTokens): Promise<OAuthUserProfile> {
    // Apple provides user info via the id_token (JWT), not a userinfo endpoint
    if (!tokens.idToken) {
      throw new Error('Apple OAuth requires an id_token to extract user profile');
    }

    const payload = this.decodeIdToken(tokens.idToken);

    return {
      id: payload.sub as string,
      email: (payload.email as string) ?? '',
      displayName: (payload.email as string) ?? '',
      raw: payload,
    };
  }

  private decodeIdToken(idToken: string): Record<string, unknown> {
    const parts = idToken.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid id_token format');
    }
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload);
  }

  private async generateClientSecret(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return SignJWT(
      {
        iss: this.teamId,
        iat: now,
        exp: now + 15777000, // ~6 months
        aud: 'https://appleid.apple.com',
        sub: this.clientId,
      },
      this.privateKey,
      this.keyId,
    );
  }
}
