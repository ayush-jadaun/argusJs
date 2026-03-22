import type { OAuthProviderAdapter, OAuthTokens, OAuthUserProfile } from '@argusjs/core';

export interface CustomOAuthConfig {
  name?: string;
  discoveryUrl: string;
  clientId: string;
  clientSecret: string;
  scopes?: string[];
}

interface OIDCDiscoveryDocument {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  issuer: string;
  jwks_uri?: string;
  scopes_supported?: string[];
}

export class CustomOAuth implements OAuthProviderAdapter {
  readonly name: string;
  private readonly discoveryUrl: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly scopes: string[];
  private endpoints: OIDCDiscoveryDocument | null = null;

  constructor(config: CustomOAuthConfig) {
    this.name = config.name ?? 'custom';
    this.discoveryUrl = config.discoveryUrl;
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.scopes = config.scopes ?? ['openid', 'email', 'profile'];
  }

  async init(): Promise<void> {
    const url = this.discoveryUrl.endsWith('/.well-known/openid-configuration')
      ? this.discoveryUrl
      : `${this.discoveryUrl.replace(/\/$/, '')}/.well-known/openid-configuration`;

    const response = await fetch(url);

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OIDC discovery failed for ${this.name}: ${error}`);
    }

    this.endpoints = await response.json() as OIDCDiscoveryDocument;
  }

  private getEndpoints(): OIDCDiscoveryDocument {
    if (!this.endpoints) {
      throw new Error(`CustomOAuth(${this.name}): init() must be called before using this provider`);
    }
    return this.endpoints;
  }

  getAuthorizationUrl(state: string, redirectUri: string, codeChallenge?: string): string {
    const endpoints = this.getEndpoints();

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

    return `${endpoints.authorization_endpoint}?${params.toString()}`;
  }

  async exchangeCode(code: string, redirectUri: string, codeVerifier?: string): Promise<OAuthTokens> {
    const endpoints = this.getEndpoints();

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

    const response = await fetch(endpoints.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`${this.name} token exchange failed: ${error}`);
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
    const endpoints = this.getEndpoints();

    const response = await fetch(endpoints.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${tokens.accessToken}` },
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`${this.name} userinfo request failed: ${error}`);
    }

    const data = await response.json() as Record<string, unknown>;

    return {
      id: String(data.sub ?? data.id),
      email: (data.email as string) ?? '',
      displayName: (data.name as string | null) ?? (data.preferred_username as string | null) ?? '',
      avatarUrl: data.picture as string | undefined,
      raw: data,
    };
  }
}
