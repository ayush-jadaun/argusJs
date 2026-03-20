export interface AuthResponse {
  user: UserResponse;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

export interface UserResponse {
  id: string;
  email: string;
  displayName: string;
  avatarUrl: string | null;
  emailVerified: boolean;
  mfaEnabled: boolean;
  mfaMethods: string[];
  roles: string[];
  orgId: string | null;
  orgRole: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface MFAChallengeResponse {
  mfaRequired: true;
  mfaToken: string;
  mfaMethods: string[];
  expiresIn: number;
}

export interface SessionResponse {
  id: string;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
  lastActivityAt: string;
  isCurrent: boolean;
}

export interface MFASetupData {
  secret: string;
  qrCodeUrl?: string;
  backupCodes: string[];
  expiresIn: number;
}

export interface OAuthTokens {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresIn: number;
  tokenType: string;
  scope?: string;
}

export interface OAuthUserProfile {
  id: string;
  email: string;
  displayName: string;
  avatarUrl?: string;
  raw: Record<string, unknown>;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
}

export interface PasswordPolicyResult {
  valid: boolean;
  score?: number;
  reasons: string[];
  suggestions?: string[];
}

export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string[];
  exp: number;
  iat: number;
  jti: string;
  email: string;
  emailVerified: boolean;
  roles: string[];
  permissions: string[];
  orgId?: string;
  orgRole?: string;
  sessionId: string;
}
