import type { OAuthProviderAdapter, OAuthTokens, OAuthUserProfile } from '@argus/core';

export interface MicrosoftOAuthConfig {
  clientId: string;
  clientSecret: string;
  tenant?: string;
  scopes?: string[];
}

const DEFAULT_TENANT = 'common';
const DEFAULT_SCOPES = ['openid', 'email', 'profile'];
const GRAPH_ME_URL = 'https://graph.microsoft.com/v1.0/me';

function getAuthorizationUrl(tenant: string): string {
  return `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`;
}

function getTokenUrl(tenant: string): string {
  return `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
}

export class MicrosoftOAuth implements OAuthProviderAdapter {
  readonly name = 'microsoft';
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly tenant: string;
  private readonly scopes: string[];

  constructor(config: MicrosoftOAuthConfig) {
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.tenant = config.tenant ?? DEFAULT_TENANT;
    this.scopes = config.scopes ?? DEFAULT_SCOPES;
  }

  getAuthorizationUrl(state: string, redirectUri: string, codeChallenge?: string): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: this.scopes.join(' '),
      state,
    });

    if (codeChallenge) {
      params.set('code_challenge', codeChallenge);
      params.set('code_challenge_method', 'S256');
    }

    return `${getAuthorizationUrl(this.tenant)}?${params.toString()}`;
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

    const response = await fetch(getTokenUrl(this.tenant), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Microsoft token exchange failed: ${error}`);
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
    const response = await fetch(GRAPH_ME_URL, {
      headers: { Authorization: `Bearer ${tokens.accessToken}` },
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Microsoft user profile request failed: ${error}`);
    }

    const data = await response.json() as Record<string, unknown>;

    return {
      id: data.id as string,
      email: (data.mail as string | null) ?? (data.userPrincipalName as string),
      displayName: data.displayName as string,
      raw: data,
    };
  }
}
