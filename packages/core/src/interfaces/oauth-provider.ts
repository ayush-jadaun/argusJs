import type { OAuthTokens, OAuthUserProfile } from '../types/responses.js';

export interface OAuthProviderAdapter {
  name: string;
  init?(): Promise<void>;
  getAuthorizationUrl(state: string, redirectUri: string, codeChallenge?: string): string;
  exchangeCode(code: string, redirectUri: string, codeVerifier?: string): Promise<OAuthTokens>;
  getUserProfile(tokens: OAuthTokens): Promise<OAuthUserProfile>;
}
