import type { OAuthProviderAdapter, OAuthTokens, OAuthUserProfile } from '@argusjs/core';

export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  scopes?: string[];
}

const AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo';
const DEFAULT_SCOPES = ['openid', 'email', 'profile'];

export class GoogleOAuth implements OAuthProviderAdapter {
  readonly name = 'google';
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly scopes: string[];

  constructor(config: GoogleOAuthConfig) {
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.scopes = config.scopes ?? DEFAULT_SCOPES;
  }

  getAuthorizationUrl(state: string, redirectUri: string, codeChallenge?: string): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: this.scopes.join(' '),
      state,
      access_type: 'offline',
      prompt: 'consent',
    });

    if (codeChallenge) {
      params.set('code_challenge', codeChallenge);
      params.set('code_challenge_method', 'S256');
    }

    return `${AUTHORIZATION_URL}?${params.toString()}`;
  }

  async exchangeCode(code: string, redirectUri: string, codeVerifier?: string): Promise<OAuthTokens> {
    const body: Record<string, string> = {
      client_id: this.clientId,
      client_secret: this.clientSecret,
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
      throw new Error(`Google token exchange failed: ${error}`);
    }

    const data = await response.json() as Record<string, unknown>;

    return {
      accessToken: data.access_token as string,
      refreshToken: data.refresh_token as string | undefined,
      idToken: data.id_token as string | undefined,
      expiresIn: data.expires_in as number,
      tokenType: data.token_type as string,
      scope: data.scope as string | undefined,
    };
  }

  async getUserProfile(tokens: OAuthTokens): Promise<OAuthUserProfile> {
    const response = await fetch(USERINFO_URL, {
      headers: { Authorization: `Bearer ${tokens.accessToken}` },
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Google userinfo request failed: ${error}`);
    }

    const data = await response.json() as Record<string, unknown>;

    return {
      id: String(data.id),
      email: data.email as string,
      displayName: data.name as string,
      avatarUrl: data.picture as string | undefined,
      raw: data,
    };
  }
}
