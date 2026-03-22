export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'UNAUTHORIZED'
  | 'INVALID_CREDENTIALS'
  | 'INVALID_TOKEN'
  | 'INVALID_REFRESH_TOKEN'
  | 'REFRESH_TOKEN_REUSE_DETECTED'
  | 'SESSION_EXPIRED'
  | 'MFA_REQUIRED'
  | 'INVALID_MFA_CODE'
  | 'INVALID_MFA_TOKEN'
  | 'MFA_ALREADY_ENABLED'
  | 'MFA_NOT_ENABLED'
  | 'EMAIL_NOT_VERIFIED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'EMAIL_ALREADY_EXISTS'
  | 'WEAK_PASSWORD'
  | 'BREACHED_PASSWORD'
  | 'PASSWORD_RECENTLY_USED'
  | 'ACCOUNT_LOCKED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'OAUTH_FAILED'
  | 'PROVIDER_NOT_CONFIGURED'
  | 'PROVIDER_ALREADY_LINKED'
  | 'CANNOT_UNLINK_ONLY_AUTH'
  | 'INTERNAL_SERVER_ERROR';

export interface ErrorResponse {
  error: {
    code: ErrorCode;
    message: string;
    statusCode: number;
    details?: ValidationError[];
    requestId: string;
    timestamp: string;
  };
}

export interface ValidationError {
  field: string;
  message: string;
  code: string;
  received?: string;
}

export class ArgusError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: ValidationError[];

  constructor(code: ErrorCode, message: string, statusCode: number, details?: ValidationError[]) {
    super(message);
    this.name = 'ArgusError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export const Errors = {
  validation: (details: ValidationError[]) =>
    new ArgusError('VALIDATION_ERROR', 'Request validation failed', 400, details),
  invalidCredentials: () =>
    new ArgusError('INVALID_CREDENTIALS', 'Invalid email or password', 401),
  invalidToken: () =>
    new ArgusError('INVALID_TOKEN', 'Access token is invalid or expired', 401),
  invalidRefreshToken: () =>
    new ArgusError('INVALID_REFRESH_TOKEN', 'Refresh token is invalid, expired, or revoked', 401),
  refreshTokenReuse: () =>
    new ArgusError('REFRESH_TOKEN_REUSE_DETECTED', 'Refresh token reuse detected. All sessions revoked.', 401),
  sessionExpired: () =>
    new ArgusError('SESSION_EXPIRED', 'Session has been revoked', 401),
  mfaRequired: () =>
    new ArgusError('MFA_REQUIRED', 'Multi-factor authentication is required', 403),
  invalidMfaCode: () =>
    new ArgusError('INVALID_MFA_CODE', 'Verification code is incorrect', 400),
  invalidMfaToken: () =>
    new ArgusError('INVALID_MFA_TOKEN', 'MFA challenge token is invalid or expired', 401),
  mfaAlreadyEnabled: () =>
    new ArgusError('MFA_ALREADY_ENABLED', 'MFA is already active', 409),
  mfaNotEnabled: () =>
    new ArgusError('MFA_NOT_ENABLED', 'MFA is not enabled on this account', 400),
  emailNotVerified: () =>
    new ArgusError('EMAIL_NOT_VERIFIED', 'Email verification required', 403),
  forbidden: () =>
    new ArgusError('FORBIDDEN', 'Insufficient permissions', 403),
  notFound: (resource: string) =>
    new ArgusError('NOT_FOUND', `${resource} not found`, 404),
  emailExists: () =>
    new ArgusError('EMAIL_ALREADY_EXISTS', 'Email is already registered', 409),
  weakPassword: (reasons: string[], _suggestions?: string[]) =>
    new ArgusError('WEAK_PASSWORD', `Password does not meet strength requirements: ${reasons.join(', ')}`, 422),
  breachedPassword: () =>
    new ArgusError('BREACHED_PASSWORD', 'Password found in data breach database', 422),
  passwordRecentlyUsed: () =>
    new ArgusError('PASSWORD_RECENTLY_USED', 'Password was recently used and cannot be reused', 422),
  accountLocked: (until: Date) =>
    new ArgusError('ACCOUNT_LOCKED', `Account locked until ${until.toISOString()}`, 423),
  rateLimitExceeded: (retryAfter: number) =>
    new ArgusError('RATE_LIMIT_EXCEEDED', `Too many requests. Retry after ${retryAfter}s`, 429),
  oauthFailed: (message: string) =>
    new ArgusError('OAUTH_FAILED', message, 401),
  providerNotConfigured: (provider: string) =>
    new ArgusError('PROVIDER_NOT_CONFIGURED', `OAuth provider '${provider}' is not configured`, 400),
  providerAlreadyLinked: () =>
    new ArgusError('PROVIDER_ALREADY_LINKED', 'This provider is already linked', 409),
  cannotUnlinkOnlyAuth: () =>
    new ArgusError('CANNOT_UNLINK_ONLY_AUTH', 'Cannot unlink only authentication method', 400),
  internal: (message?: string) =>
    new ArgusError('INTERNAL_SERVER_ERROR', message ?? 'An unexpected error occurred', 500),
};
