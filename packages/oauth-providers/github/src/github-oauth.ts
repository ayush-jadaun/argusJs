import type { OAuthProviderAdapter, OAuthTokens, OAuthUserProfile } from '@argus/core';

export interface GitHubOAuthConfig {
  clientId: string;
  clientSecret: string;
  scopes?: string[];
}

const AUTHORIZATION_URL = 'https://github.com/login/oauth/authorize';
const TOKEN_URL = 'https://github.com/login/oauth/access_token';
const USER_URL = 'https://api.github.com/user';
const EMAILS_URL = 'https://api.github.com/user/emails';
const DEFAULT_SCOPES = ['user:email'];

export class GitHubOAuth implements OAuthProviderAdapter {
  readonly name = 'github';
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly scopes: string[];

  constructor(config: GitHubOAuthConfig) {
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.scopes = config.scopes ?? DEFAULT_SCOPES;
  }

  getAuthorizationUrl(state: string, redirectUri: string, codeChallenge?: string): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: redirectUri,
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
    };

    if (codeVerifier) {
      body.code_verifier = codeVerifier;
    }

    const response = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`GitHub token exchange failed: ${error}`);
    }

    const data = await response.json() as Record<string, unknown>;

    if (data.error) {
      throw new Error(`GitHub token exchange failed: ${data.error_description ?? data.error}`);
    }

    return {
      accessToken: data.access_token as string,
      refreshToken: data.refresh_token as string | undefined,
      expiresIn: (data.expires_in as number | undefined) ?? 0,
      tokenType: (data.token_type as string | undefined) ?? 'bearer',
      scope: data.scope as string | undefined,
    };
  }

  async getUserProfile(tokens: OAuthTokens): Promise<OAuthUserProfile> {
    const headers = {
      Authorization: `Bearer ${tokens.accessToken}`,
      Accept: 'application/json',
    };

    const [userResponse, emailsResponse] = await Promise.all([
      fetch(USER_URL, { headers }),
      fetch(EMAILS_URL, { headers }),
    ]);

    if (!userResponse.ok) {
      const error = await userResponse.text();
      throw new Error(`GitHub user request failed: ${error}`);
    }

    const userData = await userResponse.json() as Record<string, unknown>;

    let email = userData.email as string | null;

    if (!email && emailsResponse.ok) {
      const emails = await emailsResponse.json() as Array<{ email: string; primary: boolean; verified: boolean }>;
      const primaryEmail = emails.find(e => e.primary && e.verified);
      email = primaryEmail?.email ?? emails[0]?.email ?? null;
    }

    return {
      id: String(userData.id),
      email: email ?? '',
      displayName: (userData.name as string | null) ?? (userData.login as string),
      avatarUrl: userData.avatar_url as string | undefined,
      raw: userData,
    };
  }
}
