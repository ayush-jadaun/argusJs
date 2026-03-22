import type { OAuthProviderAdapter, OAuthTokens, OAuthUserProfile } from '@argusjs/core';

export interface DiscordOAuthConfig {
  clientId: string;
  clientSecret: string;
  scopes?: string[];
}

const AUTHORIZATION_URL = 'https://discord.com/oauth2/authorize';
const TOKEN_URL = 'https://discord.com/api/oauth2/token';
const USER_URL = 'https://discord.com/api/users/@me';
const DEFAULT_SCOPES = ['identify', 'email'];

export class DiscordOAuth implements OAuthProviderAdapter {
  readonly name = 'discord';
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly scopes: string[];

  constructor(config: DiscordOAuthConfig) {
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
      throw new Error(`Discord token exchange failed: ${error}`);
    }

    const data = await response.json() as Record<string, unknown>;

    return {
      accessToken: data.access_token as string,
      refreshToken: data.refresh_token as string | undefined,
      expiresIn: data.expires_in as number,
      tokenType: data.token_type as string,
      scope: data.scope as string | undefined,
    };
  }

  async getUserProfile(tokens: OAuthTokens): Promise<OAuthUserProfile> {
    const response = await fetch(USER_URL, {
      headers: { Authorization: `Bearer ${tokens.accessToken}` },
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Discord user profile request failed: ${error}`);
    }

    const data = await response.json() as Record<string, unknown>;

    const avatarHash = data.avatar as string | null;
    const userId = data.id as string;
    const avatarUrl = avatarHash
      ? `https://cdn.discordapp.com/avatars/${userId}/${avatarHash}.png`
      : undefined;

    return {
      id: userId,
      email: (data.email as string) ?? '',
      displayName: (data.global_name as string | null) ?? (data.username as string),
      avatarUrl,
      raw: data,
    };
  }
}
