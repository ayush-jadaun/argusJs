import type { DbAdapter } from '../interfaces/db-adapter.js';
import type { CacheAdapter } from '../interfaces/cache-adapter.js';
import type { PasswordHasher } from '../interfaces/password-hasher.js';
import type { TokenProvider } from '../interfaces/token-provider.js';
import type { MFAProvider } from '../interfaces/mfa-provider.js';
import type { OAuthProviderAdapter } from '../interfaces/oauth-provider.js';
import type { EmailProvider } from '../interfaces/email-provider.js';
import type { RateLimiter } from '../interfaces/rate-limiter.js';
import type { PasswordPolicy } from '../interfaces/password-policy.js';
import type { SecurityEngine } from '../interfaces/security-engine.js';
import type { User, Session } from './entities.js';

export interface ArgusConfig {
  db: DbAdapter;
  cache: CacheAdapter;
  hasher: PasswordHasher;
  token: TokenProvider;

  issuer?: string;
  audience?: string[];

  mfa?: Record<string, MFAProvider>;
  mfaEncryptionKey?: string;
  oauth?: Record<string, OAuthProviderAdapter>;
  email?: EmailProvider;
  rateLimiter?: RateLimiter;
  passwordPolicy?: PasswordPolicy[];
  security?: SecurityEngine;

  password?: {
    minLength?: number;
    maxLength?: number;
    historyCount?: number;
  };

  session?: {
    maxPerUser?: number;
    absoluteTimeout?: number;
    inactivityTimeout?: number;
    bindToIP?: boolean;
    bindToDevice?: boolean;
    rotateRefreshTokens?: boolean;   // default true — rotate on every refresh (secure). Set false for Keycloak-style reuse (faster).
    cacheRefreshTokens?: boolean;    // default false — when true, cache refresh token lookups in Redis (faster, but reuse detection has a TTL delay window).
    refreshTokenCacheTTL?: number;   // seconds, default 30 — only used when cacheRefreshTokens is true. Shorter = more secure, longer = faster.
    bindToTLSFingerprint?: boolean;  // bind session to client TLS certificate fingerprint (mTLS)
  };

  passkey?: {
    rpId?: string;
    rpName?: string;
  };

  lockout?: {
    maxAttempts?: number;
    duration?: number;
    captchaThreshold?: number;
  };

  emailVerification?: {
    required?: boolean;
    tokenTTL?: number;
  };

  audit?: {
    enabled?: boolean;
    retentionDays?: number;
  };

  hooks?: {
    beforeRegister?: (input: { email: string; displayName: string }) => Promise<void>;
    afterRegister?: (user: User) => Promise<void>;
    beforeLogin?: (input: { email: string }) => Promise<void>;
    afterLogin?: (user: User, session: Session) => Promise<void>;
    onPasswordChange?: (user: User) => Promise<void>;
    onAccountLock?: (user: User) => Promise<void>;
    onSuspiciousActivity?: (user: User, event: Record<string, unknown>) => Promise<void>;
  };
}
