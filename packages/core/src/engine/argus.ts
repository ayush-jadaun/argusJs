import type { ArgusConfig } from '../types/config.js';
import type { User, Session, RefreshToken, AuditAction, AuditLogEntry, Organization, OrgMember, OrgInvite, OrgSettings, ApiKey, Role, Webhook } from '../types/entities.js';
import type { AuthResponse, UserResponse, MFAChallengeResponse, MFASetupData, AccessTokenClaims, OAuthTokens } from '../types/responses.js';
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
import { Errors } from '../types/errors.js';
import { ArgusEventEmitter } from './event-emitter.js';
import { generateToken, hashToken, generateUUID, encryptAES256GCM, decryptAES256GCM } from '../utils/crypto.js';
import { AuthorizationEngine } from './authorization.js';
import { WebhookDispatcher } from './webhook-dispatcher.js';
import { randomBytes, createHash } from 'node:crypto';


export interface RegisterInput {
  email: string;
  password: string;
  displayName: string;
  ipAddress: string;
  userAgent: string;
}

export interface LoginContext {
  ipAddress: string;
  userAgent: string;
  deviceFingerprint?: string;
}

export class Argus {
  private readonly db: DbAdapter;
  private readonly cache: CacheAdapter;
  private readonly hasher: PasswordHasher;
  private readonly token: TokenProvider;
  private readonly email?: EmailProvider;
  private readonly rateLimiter?: RateLimiter;
  private readonly passwordPolicy?: PasswordPolicy[];
  private readonly security?: SecurityEngine;
  private readonly config: ArgusConfig;
  private readonly emitter: ArgusEventEmitter;
  private readonly authorizationEngine: AuthorizationEngine;
  private readonly webhookDispatcher: WebhookDispatcher;
  private readonly mfaEncryptionKey: string;
  private readonly issuer: string;
  private readonly audience: string[];

  // Audit log batching
  private auditBuffer: AuditLogEntry[] = [];
  private auditFlushTimer: ReturnType<typeof setInterval> | null = null;
  private auditFlushInterval = 1000; // flush every 1 second
  private auditBatchSize = 50;       // or when buffer reaches 50 entries

  public readonly mfa: MFANamespace;
  public readonly oauth: OAuthNamespace;
  public readonly orgs: OrgNamespace;
  public readonly roles: RoleNamespace;
  public readonly apiKeys: ApiKeyNamespace;
  public readonly webhooks: WebhookNamespace;

  constructor(config: ArgusConfig) {
    this.db = config.db;
    this.cache = config.cache;
    this.hasher = config.hasher;
    this.token = config.token;
    this.email = config.email;
    this.rateLimiter = config.rateLimiter;
    this.passwordPolicy = config.passwordPolicy;
    this.security = config.security;
    this.config = config;
    this.issuer = config.issuer ?? 'argus';
    this.audience = config.audience ?? ['argus'];
    this.emitter = new ArgusEventEmitter();
    this.authorizationEngine = new AuthorizationEngine(this.db);
    this.webhookDispatcher = new WebhookDispatcher(this.db, this.emitter);

    // MFA encryption key
    if (config.mfaEncryptionKey) {
      this.mfaEncryptionKey = config.mfaEncryptionKey;
    } else {
      this.mfaEncryptionKey = randomBytes(32).toString('hex');
    }

    // Initialize namespaces
    this.mfa = this.createMFANamespace();
    this.oauth = this.createOAuthNamespace();
    this.orgs = this.createOrgNamespace();
    this.roles = this.createRoleNamespace();
    this.apiKeys = this.createApiKeyNamespace();
    this.webhooks = this.createWebhookNamespace();
  }

  async init(): Promise<void> {
    await this.db.init();
    await this.cache.init();
    await this.token.init();
    if (this.email?.init) await this.email.init();
    if (this.rateLimiter?.init) await this.rateLimiter.init();
    if (this.security) await this.security.init();
    if (this.passwordPolicy) {
      for (const policy of this.passwordPolicy) {
        if (policy.init) await policy.init();
      }
    }
    // Initialize OAuth providers
    if (this.config.oauth) {
      for (const provider of Object.values(this.config.oauth)) {
        if (provider.init) await provider.init();
      }
    }
    this.webhookDispatcher.init();
    this.startAuditFlusher();
  }

  async shutdown(): Promise<void> {
    // Stop audit flusher and drain remaining entries
    if (this.auditFlushTimer) {
      clearInterval(this.auditFlushTimer);
      this.auditFlushTimer = null;
    }
    await this.flushAuditLog();

    await this.db.shutdown();
    await this.cache.shutdown();
    if (this.token.shutdown) await this.token.shutdown();
    if (this.email?.shutdown) await this.email.shutdown();
    if (this.rateLimiter?.shutdown) await this.rateLimiter.shutdown();
    if (this.security) await this.security.shutdown();
  }

  on(event: string, handler: (data: unknown) => void | Promise<void>): void {
    this.emitter.on(event, handler);
  }

  // ─── Register Pipeline ──────────────────────────────────────────────

  async register(input: RegisterInput): Promise<AuthResponse> {
    // 1. Execute beforeRegister hook
    if (this.config.hooks?.beforeRegister) {
      await this.config.hooks.beforeRegister({ email: input.email, displayName: input.displayName });
    }

    // Normalize email
    const email = input.email.trim().toLowerCase();

    // 2. Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw Errors.validation([{ field: 'email', message: 'Invalid email format', code: 'invalid_format' }]);
    }

    // 3. Check password length and content
    const minLength = this.config.password?.minLength ?? 8;
    const maxLength = this.config.password?.maxLength ?? 128;
    if (input.password.trim().length === 0) {
      throw Errors.weakPassword([`Password must not be empty or whitespace-only`]);
    }
    if (input.password.length < minLength) {
      throw Errors.weakPassword([`Password must be at least ${minLength} characters`]);
    }
    if (input.password.length > maxLength) {
      throw Errors.weakPassword([`Password must be at most ${maxLength} characters`]);
    }

    // 4. Run password policies
    if (this.passwordPolicy) {
      for (const policy of this.passwordPolicy) {
        const result = await policy.validate(input.password, { email, displayName: input.displayName });
        if (!result.valid) {
          throw Errors.weakPassword(result.reasons, result.suggestions);
        }
      }
    }

    // 5. Check if email exists
    const existingUser = await this.db.findUserByEmail(email);
    if (existingUser) {
      throw Errors.emailExists();
    }

    // 6. Hash password
    const passwordHash = await this.hasher.hash(input.password);

    // 7. Create user in DB
    const user = await this.db.createUser({
      email,
      passwordHash,
      displayName: input.displayName,
      roles: ['user'],
      emailVerified: false,
    });

    // 8. Generate verification token
    const verificationToken = generateToken(32);
    const verificationTokenHash = hashToken(verificationToken);
    const tokenTTL = this.config.emailVerification?.tokenTTL ?? 86400;

    // 9. Store hashed verification token
    await this.db.createEmailVerificationToken({
      userId: user.id,
      tokenHash: verificationTokenHash,
      expiresAt: new Date(Date.now() + tokenTTL * 1000),
    });

    // 10. Send verification email
    if (this.email) {
      await this.email.sendVerificationEmail(user.email, verificationToken, user);
    }

    // 11. Generate access token
    const sessionTimeout = this.config.session?.absoluteTimeout ?? 2592000;
    const session = await this.db.createSession({
      userId: user.id,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      expiresAt: new Date(Date.now() + sessionTimeout * 1000),
    });

    // Cache session and user for fast refresh lookups
    this.cacheSession(session).catch(() => {});
    this.cacheUser(user).catch(() => {});

    const accessTokenClaims: AccessTokenClaims = {
      iss: this.issuer,
      sub: user.id,
      aud: this.audience,
      exp: Math.floor(Date.now() / 1000) + 900,
      iat: Math.floor(Date.now() / 1000),
      jti: generateUUID(),
      email: user.email,
      emailVerified: user.emailVerified,
      roles: user.roles,
      permissions: user.permissions,
      sessionId: session.id,
    };
    const accessToken = await this.token.signAccessToken(accessTokenClaims);

    // 12. Generate refresh token
    const refreshTokenRaw = generateToken(48);
    const refreshTokenHash = hashToken(refreshTokenRaw);
    const family = generateUUID();
    await this.db.createRefreshToken({
      userId: user.id,
      sessionId: session.id,
      tokenHash: refreshTokenHash,
      family,
      generation: 0,
      expiresAt: new Date(Date.now() + sessionTimeout * 1000),
    });

    // 13. Session already created above (step 11)

    // 14. Write audit log
    if (this.config.audit?.enabled) {
      this.writeAudit('USER_REGISTERED', user.id, input.ipAddress, input.userAgent, {});
    }

    // 15. Emit event
    await this.emitter.emit('user.registered', {
      userId: user.id,
      email: user.email,
      timestamp: new Date(),
    });

    // 16. Execute afterRegister hook
    if (this.config.hooks?.afterRegister) {
      await this.config.hooks.afterRegister(user);
    }

    // 17. Flush any buffered audit entries before returning
    await this.flushAuditLog();

    // 18. Return AuthResponse
    return this.buildAuthResponse(user, accessToken, refreshTokenRaw, 900);
  }

  // ─── Login Pipeline ─────────────────────────────────────────────────

  async login(email: string, password: string, context: LoginContext): Promise<AuthResponse | MFAChallengeResponse> {
    // 1. Execute beforeLogin hook
    if (this.config.hooks?.beforeLogin) {
      await this.config.hooks.beforeLogin({ email });
    }

    // Normalize email
    const normalizedEmail = email.trim().toLowerCase();

    // 2. Find user by email
    const user = await this.db.findUserByEmail(normalizedEmail);
    if (!user) {
      throw Errors.invalidCredentials();
    }

    // 3. Check if account is locked
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw Errors.accountLocked(user.lockedUntil);
    }

    // 4. Verify password
    const passwordValid = user.passwordHash
      ? await this.hasher.verify(password, user.passwordHash)
      : false;

    if (!passwordValid) {
      // 4a. Increment failedLoginAttempts
      const newFailedAttempts = user.failedLoginAttempts + 1;
      const maxAttempts = this.config.lockout?.maxAttempts ?? 5;
      const lockoutDuration = this.config.lockout?.duration ?? 1800;

      const updateFields: Partial<User> = {
        failedLoginAttempts: newFailedAttempts,
      };

      // 4b. Lock account if max attempts reached
      if (newFailedAttempts >= maxAttempts) {
        const lockedUntil = new Date(Date.now() + lockoutDuration * 1000);
        updateFields.lockedUntil = lockedUntil;

        // Write audit ACCOUNT_LOCKED
        if (this.config.audit?.enabled) {
          this.writeAudit('ACCOUNT_LOCKED', user.id, context.ipAddress, context.userAgent, {
            failedAttempts: newFailedAttempts,
          });
        }

        // Emit user.locked
        await this.emitter.emit('user.locked', {
          userId: user.id,
          lockedUntil,
          timestamp: new Date(),
        });
      }

      await this.db.updateUser(user.id, updateFields);
      this.invalidateUserCache(user.id).catch(() => {});

      // 4c. Write audit LOGIN_FAILED
      if (this.config.audit?.enabled) {
        this.writeAudit('LOGIN_FAILED', user.id, context.ipAddress, context.userAgent, {
          failedAttempts: newFailedAttempts,
        });
      }

      // 4d. Emit login_failed
      await this.emitter.emit('user.login_failed', {
        userId: user.id,
        ipAddress: context.ipAddress,
        timestamp: new Date(),
      });

      // 4e. Flush audit buffer and throw
      await this.flushAuditLog();
      throw Errors.invalidCredentials();
    }

    // 5. Reset failedLoginAttempts
    await this.db.updateUser(user.id, {
      failedLoginAttempts: 0,
      lockedUntil: null,
    });
    this.invalidateUserCache(user.id).catch(() => {});

    // 6. If MFA enabled, return MFA challenge
    if (user.mfaEnabled) {
      const mfaToken = await this.token.signMFAToken(user.id);
      return {
        mfaRequired: true,
        mfaToken,
        mfaMethods: user.mfaMethods,
        expiresIn: 300,
      };
    }

    // 7. Create session first, then enforce limit (avoids race condition under concurrency)
    const sessionTimeout = this.config.session?.absoluteTimeout ?? 2592000;
    const session = await this.db.createSession({
      userId: user.id,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      deviceFingerprint: context.deviceFingerprint,
      expiresAt: new Date(Date.now() + sessionTimeout * 1000),
    });

    // Cache session for fast refresh lookups
    this.cacheSession(session).catch(() => {});

    // 9. Generate access + refresh tokens
    const accessTokenClaims: AccessTokenClaims = {
      iss: this.issuer,
      sub: user.id,
      aud: this.audience,
      exp: Math.floor(Date.now() / 1000) + 900,
      iat: Math.floor(Date.now() / 1000),
      jti: generateUUID(),
      email: user.email,
      emailVerified: user.emailVerified,
      roles: user.roles,
      permissions: user.permissions,
      sessionId: session.id,
    };
    const accessToken = await this.token.signAccessToken(accessTokenClaims);

    const refreshTokenRaw = generateToken(48);
    const refreshTokenHash = hashToken(refreshTokenRaw);
    const family = generateUUID();
    await this.db.createRefreshToken({
      userId: user.id,
      sessionId: session.id,
      tokenHash: refreshTokenHash,
      family,
      generation: 0,
      expiresAt: new Date(Date.now() + sessionTimeout * 1000),
    });

    // 8. Enforce session limit AFTER creating session (create-then-trim is race-safe)
    const maxPerUser = this.config.session?.maxPerUser ?? 5;
    const activeSessions = await this.db.getActiveSessions(user.id);
    if (activeSessions.length > maxPerUser) {
      // Sort by createdAt ASC (oldest first), keep the newest maxPerUser sessions
      activeSessions.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
      const toRevoke = activeSessions.slice(0, activeSessions.length - maxPerUser);
      for (const s of toRevoke) {
        await this.db.revokeSession(s.id, 'session_limit_exceeded');
        this.invalidateSessionCache(s.id).catch(() => {});
      }
    }

    // 10. Update user
    await this.db.updateUser(user.id, {
      lastLoginAt: new Date(),
      lastLoginIp: context.ipAddress,
      failedLoginAttempts: 0,
    });
    this.invalidateUserCache(user.id).catch(() => {});

    // 11. Write audit
    if (this.config.audit?.enabled) {
      this.writeAudit('LOGIN_SUCCESS', user.id, context.ipAddress, context.userAgent, {});
    }

    // 12. Emit events
    await this.emitter.emit('user.login', {
      userId: user.id,
      sessionId: session.id,
      ipAddress: context.ipAddress,
      timestamp: new Date(),
    });
    await this.emitter.emit('session.created', {
      userId: user.id,
      sessionId: session.id,
      timestamp: new Date(),
    });

    // 13. Execute afterLogin hook
    if (this.config.hooks?.afterLogin) {
      await this.config.hooks.afterLogin(user, session);
    }

    // 14. Flush any buffered audit entries before returning
    await this.flushAuditLog();

    // 15. Return AuthResponse
    return this.buildAuthResponse(user, accessToken, refreshTokenRaw, 900);
  }

  // ─── Logout Pipeline ────────────────────────────────────────────────

  async logout(userId: string, sessionId: string, options?: { allDevices?: boolean }): Promise<void> {
    if (options?.allDevices) {
      // 1. Revoke all sessions and tokens
      await this.db.revokeAllSessions(userId, 'logout');
      await this.db.revokeAllUserTokens(userId, 'logout');

      // Invalidate user cache (sessions are invalidated by clearing all)
      this.invalidateUserCache(userId).catch(() => {});

      // Write audit
      if (this.config.audit?.enabled) {
        this.writeAudit('LOGOUT_ALL_SESSIONS', userId, null, null, {});
      }
    } else {
      // 2. Revoke single session
      await this.db.revokeSession(sessionId, 'logout');
      this.invalidateSessionCache(sessionId).catch(() => {});

      // Write audit
      if (this.config.audit?.enabled) {
        this.writeAudit('LOGOUT', userId, null, null, { sessionId });
      }
    }

    // 3. Flush audit buffer
    await this.flushAuditLog();

    // 4. Emit event
    await this.emitter.emit('user.logout', {
      userId,
      sessionId,
      allDevices: options?.allDevices ?? false,
      timestamp: new Date(),
    });
  }

  // ─── Refresh Token Pipeline ─────────────────────────────────────────

  async refresh(refreshTokenValue: string): Promise<AuthResponse> {
    const shouldRotate = this.config.session?.rotateRefreshTokens ?? true;

    // 1. Hash the provided refresh token
    const tokenHash = hashToken(refreshTokenValue);

    // 2. Look up refresh token — cache first if enabled, then DB
    const shouldCacheTokens = this.config.session?.cacheRefreshTokens ?? false;
    const tokenCacheTTL = this.config.session?.refreshTokenCacheTTL ?? 30;
    let token: RefreshToken | null = null;

    if (shouldCacheTokens) {
      try {
        const cached = await this.cache.get(`rtoken:${tokenHash}`);
        if (cached) {
          const parsed = JSON.parse(cached);
          parsed.expiresAt = new Date(parsed.expiresAt);
          parsed.createdAt = new Date(parsed.createdAt);
          if (parsed.revokedAt) parsed.revokedAt = new Date(parsed.revokedAt);
          token = parsed;
        }
      } catch {}
    }
    if (!token) {
      token = await this.db.findRefreshTokenByHash(tokenHash);
      // Populate cache for next time
      if (token && shouldCacheTokens) {
        this.cache.set(`rtoken:${tokenHash}`, JSON.stringify(token), tokenCacheTTL).catch(() => {});
      }
    }

    // 3. If not found → throw
    if (!token) {
      throw Errors.invalidRefreshToken();
    }

    // 4. If revoked → TOKEN REUSE DETECTED (only meaningful when rotation is on)
    if (token.revoked) {
      await this.db.revokeTokenFamily(token.family, 'reuse_detected');
      await this.db.revokeAllSessions(token.userId, 'security_alert');
      if (this.config.audit?.enabled) {
        this.writeAudit('TOKEN_REUSE_DETECTED', token.userId, null, null, {
          family: token.family,
          generation: token.generation,
        });
      }
      await this.emitter.emit('token.reuse_detected', {
        userId: token.userId,
        family: token.family,
        timestamp: new Date(),
      });
      await this.emitter.emit('security.suspicious_activity', {
        userId: token.userId,
        type: 'token_reuse',
        timestamp: new Date(),
      });
      await this.flushAuditLog();
      throw Errors.refreshTokenReuse();
    }

    // 5. If expired → throw
    if (token.expiresAt < new Date()) {
      throw Errors.invalidRefreshToken();
    }

    // 6. Get session (cache first, then DB), verify not revoked
    let session = await this.getCachedSession(token.sessionId);
    if (!session) {
      session = await this.db.getSession(token.sessionId);
      if (session && !session.revoked) {
        this.cacheSession(session).catch(() => {});
      }
    }
    if (!session || session.revoked) {
      throw Errors.sessionExpired();
    }

    // 7. Token rotation (when enabled)
    let returnRefreshToken = refreshTokenValue; // default: return same token (no rotation)

    if (shouldRotate) {
      // Invalidate cached token so replays hit DB (which has revoked=true)
      if (shouldCacheTokens) {
        this.cache.del(`rtoken:${tokenHash}`).catch(() => {});
      }
      // Atomically revoke old token — only the first concurrent caller wins
      const didRevoke = await this.db.revokeRefreshTokenIfActive(token.id, 'rotated');
      if (!didRevoke) {
        // Another concurrent refresh already consumed this token — treat as reuse
        await this.db.revokeTokenFamily(token.family, 'reuse_detected');
        await this.db.revokeAllSessions(token.userId, 'security_alert');
        if (this.config.audit?.enabled) {
          this.writeAudit('TOKEN_REUSE_DETECTED', token.userId, null, null, {
            family: token.family,
            generation: token.generation,
          });
        }
        await this.emitter.emit('token.reuse_detected', {
          userId: token.userId,
          family: token.family,
          timestamp: new Date(),
        });
        await this.emitter.emit('security.suspicious_activity', {
          userId: token.userId,
          type: 'token_reuse',
          timestamp: new Date(),
        });
        await this.flushAuditLog();
        throw Errors.refreshTokenReuse();
      }

      // Generate new refresh token
      const newRefreshTokenRaw = generateToken(48);
      const newRefreshTokenHash = hashToken(newRefreshTokenRaw);
      const sessionTimeout = this.config.session?.absoluteTimeout ?? 2592000;
      await this.db.createRefreshToken({
        userId: token.userId,
        sessionId: token.sessionId,
        tokenHash: newRefreshTokenHash,
        family: token.family,
        generation: token.generation + 1,
        expiresAt: new Date(Date.now() + sessionTimeout * 1000),
      });
      returnRefreshToken = newRefreshTokenRaw;
    }

    // 8. Get user (cache first, then DB)
    let user = await this.getCachedUser(token.userId);
    if (!user) {
      user = await this.db.findUserById(token.userId);
      if (user) {
        this.cacheUser(user).catch(() => {});
      }
    }
    if (!user) {
      throw Errors.invalidRefreshToken();
    }

    // 9. Sign new access token
    const accessTokenClaims: AccessTokenClaims = {
      iss: this.issuer,
      sub: user.id,
      aud: this.audience,
      exp: Math.floor(Date.now() / 1000) + 900,
      iat: Math.floor(Date.now() / 1000),
      jti: generateUUID(),
      email: user.email,
      emailVerified: user.emailVerified,
      roles: user.roles,
      permissions: user.permissions,
      sessionId: session.id,
    };
    const accessToken = await this.token.signAccessToken(accessTokenClaims);

    // 10. Write audit
    if (this.config.audit?.enabled) {
      this.writeAudit('TOKEN_REFRESHED', user.id, null, null, {
        sessionId: session.id,
      });
    }

    // 11. Emit event
    await this.emitter.emit('token.refreshed', {
      userId: user.id,
      sessionId: session.id,
      timestamp: new Date(),
    });

    // 12. Flush any buffered audit entries before returning
    await this.flushAuditLog();

    // 13. Return AuthResponse
    return this.buildAuthResponse(user, accessToken, returnRefreshToken, 900);
  }

  // ─── Forgot Password Pipeline ─────────────────────────────────────

  async forgotPassword(email: string, ipAddress: string, userAgent?: string): Promise<void> {
    // Normalize email
    const normalizedEmail = email.trim().toLowerCase();

    // Find user by email — if not found, return silently (prevent enumeration)
    const user = await this.db.findUserByEmail(normalizedEmail);
    if (!user) {
      return;
    }

    // Invalidate all existing reset tokens for user
    await this.db.invalidateUserResetTokens(user.id);

    // Generate reset token
    const resetToken = generateToken(32);
    const resetTokenHash = hashToken(resetToken);

    // Store in DB with 1 hour expiry
    await this.db.createPasswordResetToken({
      userId: user.id,
      tokenHash: resetTokenHash,
      requestedFromIp: ipAddress,
      requestedFromUa: userAgent,
      expiresAt: new Date(Date.now() + 3600 * 1000), // 1 hour
    });

    // Send password reset email if email provider configured
    if (this.email) {
      await this.email.sendPasswordResetEmail(user.email, resetToken, user);
    }

    // Write audit
    if (this.config.audit?.enabled) {
      this.writeAudit('PASSWORD_RESET_REQUESTED', user.id, ipAddress, userAgent ?? null, {});
    }
    await this.flushAuditLog();
  }

  // ─── Reset Password Pipeline ──────────────────────────────────────

  async resetPassword(tokenValue: string, newPassword: string, ipAddress: string): Promise<void> {
    // 1. Hash token, look up
    const tokenHash = hashToken(tokenValue);
    const resetToken = await this.db.findPasswordResetByHash(tokenHash);

    // 2. If not found, expired, or already used → throw
    if (!resetToken || resetToken.used || resetToken.expiresAt < new Date()) {
      throw Errors.invalidToken();
    }

    // 3. Validate new password (min/max length)
    const minLength = this.config.password?.minLength ?? 8;
    const maxLength = this.config.password?.maxLength ?? 128;
    if (newPassword.length < minLength) {
      throw Errors.weakPassword([`Password must be at least ${minLength} characters`]);
    }
    if (newPassword.length > maxLength) {
      throw Errors.weakPassword([`Password must be at most ${maxLength} characters`]);
    }

    // 4. Run password policies if configured
    if (this.passwordPolicy) {
      const user = await this.db.findUserById(resetToken.userId);
      for (const policy of this.passwordPolicy) {
        const result = await policy.validate(newPassword, { email: user?.email ?? '', displayName: user?.displayName ?? '' });
        if (!result.valid) {
          throw Errors.weakPassword(result.reasons, result.suggestions);
        }
      }
    }

    // 5. Check password history
    const historyCount = this.config.password?.historyCount ?? 0;
    if (historyCount > 0) {
      const history = await this.db.getPasswordHistory(resetToken.userId, historyCount);
      for (const oldHash of history) {
        const matches = await this.hasher.verify(newPassword, oldHash);
        if (matches) {
          throw Errors.passwordRecentlyUsed();
        }
      }
    }

    // 6. Hash new password
    const newPasswordHash = await this.hasher.hash(newPassword);

    // Get the user to access old passwordHash
    const user = await this.db.findUserById(resetToken.userId);
    if (!user) {
      throw Errors.invalidToken();
    }

    // 8. Add old passwordHash to history
    if (user.passwordHash) {
      await this.db.addPasswordHistory(user.id, user.passwordHash);
    }

    // 7. Update user's passwordHash
    await this.db.updateUser(user.id, { passwordHash: newPasswordHash });
    this.invalidateUserCache(user.id).catch(() => {});

    // 9. Mark reset token as used
    await this.db.markResetTokenUsed(resetToken.id);

    // 10. Revoke ALL sessions for user
    await this.db.revokeAllSessions(user.id, 'password_change');

    // 11. Revoke ALL refresh tokens for user
    await this.db.revokeAllUserTokens(user.id, 'password_change');

    // 12. Send security alert email if email provider configured
    if (this.email) {
      await this.email.sendSecurityAlertEmail(user.email, {
        type: 'password_reset',
        description: 'Your password has been reset',
        ipAddress,
        timestamp: new Date(),
      }, user);
    }

    // 13. Write audit
    if (this.config.audit?.enabled) {
      this.writeAudit('PASSWORD_RESET_COMPLETED', user.id, ipAddress, null, {});
    }
    await this.flushAuditLog();

    // 14. Emit event
    await this.emitter.emit('user.password_changed', {
      userId: user.id,
      timestamp: new Date(),
    });
  }

  // ─── Verify Email Pipeline ────────────────────────────────────────

  async verifyEmail(tokenValue: string): Promise<void> {
    // 1. Hash token, look up
    const tokenHash = hashToken(tokenValue);
    const verificationToken = await this.db.findVerificationByHash(tokenHash);

    // 2. If not found, expired, or used → throw
    if (!verificationToken || verificationToken.used || verificationToken.expiresAt < new Date()) {
      throw Errors.invalidToken();
    }

    // 3. Mark token as used
    await this.db.markVerificationUsed(verificationToken.id);

    // 4. Update user: emailVerified = true, emailVerifiedAt = now
    await this.db.updateUser(verificationToken.userId, {
      emailVerified: true,
      emailVerifiedAt: new Date(),
    });
    this.invalidateUserCache(verificationToken.userId).catch(() => {});

    // 5. Write audit
    if (this.config.audit?.enabled) {
      this.writeAudit('EMAIL_VERIFIED', verificationToken.userId, null, null, {});
    }
    await this.flushAuditLog();

    // 6. Emit event
    await this.emitter.emit('user.email_verified', {
      userId: verificationToken.userId,
      timestamp: new Date(),
    });
  }

  // ─── Resend Verification Pipeline ─────────────────────────────────

  async resendVerification(userId: string): Promise<void> {
    // 1. Get user by id
    const user = await this.db.findUserById(userId);
    if (!user) {
      throw Errors.notFound('User');
    }

    // 2. If already verified, return (no-op)
    if (user.emailVerified) {
      return;
    }

    // 3. Generate new verification token
    const verificationToken = generateToken(32);
    const verificationTokenHash = hashToken(verificationToken);
    const tokenTTL = this.config.emailVerification?.tokenTTL ?? 86400;

    // 4. Store hashed in DB
    await this.db.createEmailVerificationToken({
      userId: user.id,
      tokenHash: verificationTokenHash,
      expiresAt: new Date(Date.now() + tokenTTL * 1000),
    });

    // 5. Send verification email
    if (this.email) {
      await this.email.sendVerificationEmail(user.email, verificationToken, user);
    }

    // 6. Write audit
    if (this.config.audit?.enabled) {
      this.writeAudit('EMAIL_VERIFICATION_SENT', user.id, null, null, {});
    }
    await this.flushAuditLog();
  }

  // ─── Token Verification ────────────────────────────────────────────

  async verifyToken(token: string): Promise<AccessTokenClaims> {
    return this.token.verifyAccessToken(token);
  }

  // ─── Helpers ────────────────────────────────────────────────────────

  private buildAuthResponse(user: User, accessToken: string, refreshToken: string, expiresIn: number): AuthResponse {
    const userResponse: UserResponse = {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl,
      emailVerified: user.emailVerified,
      mfaEnabled: user.mfaEnabled,
      mfaMethods: user.mfaMethods,
      roles: user.roles,
      orgId: user.orgId,
      orgRole: user.orgRole,
      metadata: user.metadata,
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.updatedAt.toISOString(),
    };

    return {
      user: userResponse,
      accessToken,
      refreshToken,
      expiresIn,
      tokenType: 'Bearer',
    };
  }

  // ─── Session & User Cache ─────────────────────────────────────────

  private async cacheSession(session: Session): Promise<void> {
    try {
      await this.cache.set(
        `session:${session.id}`,
        JSON.stringify(session),
        this.config.session?.absoluteTimeout ?? 2592000
      );
    } catch {}  // cache miss is not fatal
  }

  private async getCachedSession(id: string): Promise<Session | null> {
    try {
      const cached = await this.cache.get(`session:${id}`);
      if (cached) {
        const session = JSON.parse(cached);
        // Restore Date objects
        session.lastActivityAt = new Date(session.lastActivityAt);
        session.expiresAt = new Date(session.expiresAt);
        session.createdAt = new Date(session.createdAt);
        if (session.revokedAt) session.revokedAt = new Date(session.revokedAt);
        return session;
      }
    } catch {}
    return null;
  }

  private async invalidateSessionCache(id: string): Promise<void> {
    try { await this.cache.del(`session:${id}`); } catch {}
  }

  private async cacheUser(user: User): Promise<void> {
    try {
      await this.cache.set(`user:${user.id}`, JSON.stringify(user), 300); // 5 min TTL
    } catch {}
  }

  private async getCachedUser(id: string): Promise<User | null> {
    try {
      const cached = await this.cache.get(`user:${id}`);
      if (cached) {
        const user = JSON.parse(cached);
        // Restore Date objects
        user.createdAt = new Date(user.createdAt);
        user.updatedAt = new Date(user.updatedAt);
        if (user.lockedUntil) user.lockedUntil = new Date(user.lockedUntil);
        if (user.lastLoginAt) user.lastLoginAt = new Date(user.lastLoginAt);
        if (user.emailVerifiedAt) user.emailVerifiedAt = new Date(user.emailVerifiedAt);
        if (user.deletedAt) user.deletedAt = new Date(user.deletedAt);
        return user;
      }
    } catch {}
    return null;
  }

  private async invalidateUserCache(id: string): Promise<void> {
    try { await this.cache.del(`user:${id}`); } catch {}
  }

  // ─── Audit Log Batching ──────────────────────────────────────────

  private startAuditFlusher(): void {
    this.auditFlushTimer = setInterval(() => this.flushAuditLog(), this.auditFlushInterval);
    this.auditFlushTimer.unref(); // don't keep process alive
  }

  private async flushAuditLog(): Promise<void> {
    if (this.auditBuffer.length === 0) return;
    const batch = this.auditBuffer.splice(0);
    try {
      // Write all entries — could be optimized with a bulk insert method
      await Promise.all(batch.map(entry => this.db.writeAuditLog(entry)));
    } catch (err) {
      // On failure, push back to buffer (with size limit to prevent memory leak)
      if (this.auditBuffer.length < 10000) {
        this.auditBuffer.unshift(...batch);
      }
    }
  }

  private writeAudit(
    action: AuditAction,
    userId: string | null,
    ipAddress: string | null,
    userAgent: string | null,
    metadata: Record<string, unknown>,
  ): void {
    // Non-blocking — push to buffer, flush async
    this.auditBuffer.push({
      id: generateUUID(),
      userId,
      action,
      ipAddress,
      userAgent,
      metadata,
      orgId: null,
      createdAt: new Date(),
    });
    // Flush immediately if buffer is full
    if (this.auditBuffer.length >= this.auditBatchSize) {
      this.flushAuditLog().catch(() => {});
    }
  }

  // ─── Authorization ──────────────────────────────────────────────────

  async authorize(userId: string, action: string, context?: Record<string, unknown>): Promise<boolean> {
    return this.authorizationEngine.authorize(userId, action, context);
  }

  // ─── MFA Namespace ──────────────────────────────────────────────────

  private getMFAProvider(method: string): MFAProvider {
    const provider = this.config.mfa?.[method];
    if (!provider) {
      throw Errors.providerNotConfigured(method);
    }
    return provider;
  }

  private createMFANamespace(): MFANamespace {
    return {
      setup: async (userId: string, method: string): Promise<MFASetupData> => {
        // 1. Get user, check MFA not already enabled
        const user = await this.db.findUserById(userId);
        if (!user) throw Errors.notFound('User');
        if (user.mfaEnabled) throw Errors.mfaAlreadyEnabled();

        // 2. Get MFA provider
        const provider = this.getMFAProvider(method);

        // 3. Generate secret
        const setupData = await provider.generateSecret(user);

        // 4. Encrypt the secret with AES-256-GCM
        const encryptedSecret = encryptAES256GCM(setupData.secret, this.mfaEncryptionKey);

        // 5. Store encrypted secret + backup codes temporarily in cache (10 min TTL)
        const cachePayload = JSON.stringify({
          encryptedSecret,
          backupCodes: setupData.backupCodes,
          method,
        });
        await this.cache.set(`mfa:setup:${userId}`, cachePayload, 600);

        // 6. Return MFASetupData
        return setupData;
      },

      verifySetup: async (userId: string, method: string, code: string): Promise<void> => {
        // 1. Get the temp secret from cache
        const cached = await this.cache.get(`mfa:setup:${userId}`);
        if (!cached) throw Errors.invalidMfaCode();

        const { encryptedSecret, backupCodes } = JSON.parse(cached) as {
          encryptedSecret: string;
          backupCodes: string[];
          method: string;
        };

        // 2. Decrypt the secret
        const secret = decryptAES256GCM(encryptedSecret, this.mfaEncryptionKey);

        // 3. Verify code with provider
        const provider = this.getMFAProvider(method);
        const valid = await provider.verifyCode(secret, code);
        if (!valid) throw Errors.invalidMfaCode();

        // 4. Save to DB (encrypted), set user.mfaEnabled=true
        const encryptedBackupCodes = backupCodes.map(
          (bc: string) => encryptAES256GCM(bc, this.mfaEncryptionKey),
        );
        await this.db.saveMFASecret({
          userId,
          method,
          encryptedSecret,
          encryptedBackupCodes,
          backupCodesUsed: backupCodes.map(() => false),
        });
        await this.db.updateUser(userId, {
          mfaEnabled: true,
          mfaMethods: [method],
        });
        this.invalidateUserCache(userId).catch(() => {});

        // Clean up cache
        await this.cache.del(`mfa:setup:${userId}`);

        // 5. Write audit + emit
        if (this.config.audit?.enabled) {
          this.writeAudit('MFA_ENABLED', userId, null, null, { method });
        }
        await this.flushAuditLog();
        await this.emitter.emit('mfa.enabled', {
          userId,
          method,
          timestamp: new Date(),
        });
      },

      verifyLogin: async (mfaToken: string, code: string, method: string, context: LoginContext): Promise<AuthResponse> => {
        // 1. Verify MFA token to get userId
        let userId: string;
        try {
          const result = await this.token.verifyMFAToken(mfaToken);
          userId = result.userId;
        } catch {
          throw Errors.invalidMfaToken();
        }

        // 2. Get user + MFA secret from DB
        const user = await this.db.findUserById(userId);
        if (!user) throw Errors.notFound('User');

        const mfaSecret = await this.db.getMFASecret(userId);
        if (!mfaSecret) throw Errors.mfaNotEnabled();

        // 3. Decrypt secret
        const secret = decryptAES256GCM(mfaSecret.encryptedSecret, this.mfaEncryptionKey);

        // 4. Check if code is a backup code
        let isBackupCode = false;
        for (let i = 0; i < mfaSecret.encryptedBackupCodes.length; i++) {
          if (mfaSecret.backupCodesUsed[i]) continue;
          const decryptedBackup = decryptAES256GCM(mfaSecret.encryptedBackupCodes[i], this.mfaEncryptionKey);
          if (decryptedBackup === code) {
            isBackupCode = true;
            await this.db.markBackupCodeUsed(userId, i);

            if (this.config.audit?.enabled) {
              this.writeAudit('BACKUP_CODE_USED', userId, context.ipAddress, context.userAgent, {
                codeIndex: i,
              });
            }
            break;
          }
        }

        // 5. If not a backup code, verify with provider
        if (!isBackupCode) {
          const provider = this.getMFAProvider(method);
          const valid = await provider.verifyCode(secret, code);
          if (!valid) {
            // Write audit MFA_CHALLENGE_FAILED
            if (this.config.audit?.enabled) {
              this.writeAudit('MFA_CHALLENGE_FAILED', userId, context.ipAddress, context.userAgent, { method });
            }
            await this.emitter.emit('mfa.challenge_failed', {
              userId,
              method,
              timestamp: new Date(),
            });
            await this.flushAuditLog();
            throw Errors.invalidMfaCode();
          }
        }

        // 6. Create session, generate tokens, return AuthResponse
        const sessionTimeout = this.config.session?.absoluteTimeout ?? 2592000;
        const session = await this.db.createSession({
          userId: user.id,
          ipAddress: context.ipAddress,
          userAgent: context.userAgent,
          deviceFingerprint: context.deviceFingerprint,
          expiresAt: new Date(Date.now() + sessionTimeout * 1000),
        });

        // Cache session for fast refresh lookups
        this.cacheSession(session).catch(() => {});

        const accessTokenClaims: AccessTokenClaims = {
          iss: this.issuer,
          sub: user.id,
          aud: this.audience,
          exp: Math.floor(Date.now() / 1000) + 900,
          iat: Math.floor(Date.now() / 1000),
          jti: generateUUID(),
          email: user.email,
          emailVerified: user.emailVerified,
          roles: user.roles,
          permissions: user.permissions,
          sessionId: session.id,
        };
        const accessToken = await this.token.signAccessToken(accessTokenClaims);

        const refreshTokenRaw = generateToken(48);
        const refreshTokenHash = hashToken(refreshTokenRaw);
        const family = generateUUID();
        await this.db.createRefreshToken({
          userId: user.id,
          sessionId: session.id,
          tokenHash: refreshTokenHash,
          family,
          generation: 0,
          expiresAt: new Date(Date.now() + sessionTimeout * 1000),
        });

        // Update user last login
        await this.db.updateUser(user.id, {
          lastLoginAt: new Date(),
          lastLoginIp: context.ipAddress,
          failedLoginAttempts: 0,
        });
        this.invalidateUserCache(user.id).catch(() => {});

        // Write audit
        if (this.config.audit?.enabled) {
          this.writeAudit('MFA_CHALLENGE_PASSED', userId, context.ipAddress, context.userAgent, { method });
        }
        await this.flushAuditLog();

        // Emit events
        await this.emitter.emit('user.login', {
          userId: user.id,
          sessionId: session.id,
          ipAddress: context.ipAddress,
          method: 'mfa',
          timestamp: new Date(),
        });

        return this.buildAuthResponse(user, accessToken, refreshTokenRaw, 900);
      },

      disable: async (userId: string, code: string): Promise<void> => {
        // 1. Get user + MFA secret
        const user = await this.db.findUserById(userId);
        if (!user) throw Errors.notFound('User');
        if (!user.mfaEnabled) throw Errors.mfaNotEnabled();

        const mfaSecret = await this.db.getMFASecret(userId);
        if (!mfaSecret) throw Errors.mfaNotEnabled();

        // 2. Decrypt + verify code
        const secret = decryptAES256GCM(mfaSecret.encryptedSecret, this.mfaEncryptionKey);
        const provider = this.getMFAProvider(mfaSecret.method);
        const valid = await provider.verifyCode(secret, code);
        if (!valid) throw Errors.invalidMfaCode();

        // 3. Delete MFA secret from DB
        await this.db.deleteMFASecret(userId);

        // 4. Update user
        await this.db.updateUser(userId, {
          mfaEnabled: false,
          mfaMethods: [],
        });
        this.invalidateUserCache(userId).catch(() => {});

        // 5. Write audit + emit
        if (this.config.audit?.enabled) {
          this.writeAudit('MFA_DISABLED', userId, null, null, { method: mfaSecret.method });
        }
        await this.flushAuditLog();
        await this.emitter.emit('mfa.disabled', {
          userId,
          method: mfaSecret.method,
          timestamp: new Date(),
        });
      },

      regenerateBackupCodes: async (userId: string, code: string): Promise<string[]> => {
        // 1. Get user + MFA secret
        const user = await this.db.findUserById(userId);
        if (!user) throw Errors.notFound('User');
        if (!user.mfaEnabled) throw Errors.mfaNotEnabled();

        const mfaSecret = await this.db.getMFASecret(userId);
        if (!mfaSecret) throw Errors.mfaNotEnabled();

        // 2. Verify current code first (security)
        const secret = decryptAES256GCM(mfaSecret.encryptedSecret, this.mfaEncryptionKey);
        const provider = this.getMFAProvider(mfaSecret.method);
        const valid = await provider.verifyCode(secret, code);
        if (!valid) throw Errors.invalidMfaCode();

        // 3. Generate new backup codes via provider
        const newCodes = provider.generateBackupCodes
          ? provider.generateBackupCodes()
          : ['XXXX-XXXX', 'YYYY-YYYY', 'ZZZZ-ZZZZ'];

        // 4. Encrypt and update in DB
        const encryptedBackupCodes = newCodes.map(
          (bc: string) => encryptAES256GCM(bc, this.mfaEncryptionKey),
        );
        await this.db.saveMFASecret({
          userId,
          method: mfaSecret.method,
          encryptedSecret: mfaSecret.encryptedSecret,
          encryptedBackupCodes,
          backupCodesUsed: newCodes.map(() => false),
        });

        // 5. Return new codes
        return newCodes;
      },
    };
  }

  // ─── OAuth Namespace ─────────────────────────────────────────────────

  private getOAuthProvider(providerName: string): OAuthProviderAdapter {
    const provider = this.config.oauth?.[providerName];
    if (!provider) {
      throw Errors.providerNotConfigured(providerName);
    }
    return provider;
  }

  private generatePKCE(): { codeVerifier: string; codeChallenge: string } {
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    return { codeVerifier, codeChallenge };
  }

  private createOAuthNamespace(): OAuthNamespace {
    return {
      getAuthorizationUrl: async (providerName: string, redirectUri: string) => {
        const provider = this.getOAuthProvider(providerName);

        // Generate state and PKCE
        const state = generateToken(32);
        const { codeVerifier, codeChallenge } = this.generatePKCE();

        // Store state + verifier in cache with 5 min TTL
        await this.cache.set(`oauth:state:${state}`, JSON.stringify({
          provider: providerName,
          codeVerifier,
          redirectUri,
        }), 300);

        const url = provider.getAuthorizationUrl(state, redirectUri, codeChallenge);

        return { url, state };
      },

      handleCallback: async (providerName: string, code: string, state: string, context: LoginContext) => {
        const provider = this.getOAuthProvider(providerName);

        // 1. Validate state from cache
        const stateData = await this.cache.get(`oauth:state:${state}`);
        if (!stateData) {
          throw Errors.oauthFailed('Invalid or expired OAuth state');
        }

        const { codeVerifier, redirectUri } = JSON.parse(stateData) as {
          provider: string;
          codeVerifier: string;
          redirectUri: string;
        };

        // Delete state to prevent replay
        await this.cache.del(`oauth:state:${state}`);

        // 2. Exchange code for tokens via provider
        let tokens: OAuthTokens;
        try {
          tokens = await provider.exchangeCode(code, redirectUri, codeVerifier);
        } catch (err) {
          throw Errors.oauthFailed(`Token exchange failed: ${(err as Error).message}`);
        }

        // 3. Get user profile from provider
        const profile = await provider.getUserProfile(tokens);

        // 4. Check if OAuth link exists
        const existingLink = await this.db.findOAuthProvider(providerName, profile.id);

        let user: User;

        if (existingLink) {
          // Existing link: find the linked user
          const linkedUser = await this.db.findUserById(existingLink.userId);
          if (!linkedUser) {
            throw Errors.oauthFailed('Linked user account not found');
          }
          user = linkedUser;

          // Update OAuth link with latest tokens
          await this.db.linkOAuthProvider({
            userId: user.id,
            provider: providerName,
            providerUserId: profile.id,
            email: profile.email,
            displayName: profile.displayName,
            avatarUrl: profile.avatarUrl,
            rawProfile: profile.raw,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            tokenExpiresAt: tokens.expiresIn ? new Date(Date.now() + tokens.expiresIn * 1000) : undefined,
          });
        } else {
          // No existing link: check if email matches an existing user
          const existingUser = profile.email ? await this.db.findUserByEmail(profile.email.toLowerCase()) : null;

          if (existingUser) {
            user = existingUser;
          } else {
            // Create new user
            user = await this.db.createUser({
              email: profile.email?.toLowerCase() ?? '',
              passwordHash: null,
              displayName: profile.displayName,
              avatarUrl: profile.avatarUrl,
              emailVerified: !!profile.email,
              roles: ['user'],
            });
          }

          // Link OAuth provider
          await this.db.linkOAuthProvider({
            userId: user.id,
            provider: providerName,
            providerUserId: profile.id,
            email: profile.email,
            displayName: profile.displayName,
            avatarUrl: profile.avatarUrl,
            rawProfile: profile.raw,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            tokenExpiresAt: tokens.expiresIn ? new Date(Date.now() + tokens.expiresIn * 1000) : undefined,
          });

          // Write audit for new link
          if (this.config.audit?.enabled) {
            this.writeAudit('OAUTH_LINKED', user.id, context.ipAddress, context.userAgent, {
              provider: providerName,
              providerUserId: profile.id,
            });
          }

          await this.emitter.emit('oauth.linked', {
            userId: user.id,
            provider: providerName,
            timestamp: new Date(),
          });
        }

        // 5. Generate tokens and create session
        const sessionTimeout = this.config.session?.absoluteTimeout ?? 2592000;
        const session = await this.db.createSession({
          userId: user.id,
          ipAddress: context.ipAddress,
          userAgent: context.userAgent,
          deviceFingerprint: context.deviceFingerprint,
          expiresAt: new Date(Date.now() + sessionTimeout * 1000),
        });

        // Cache session for fast refresh lookups
        this.cacheSession(session).catch(() => {});

        const accessTokenClaims: AccessTokenClaims = {
          iss: this.issuer,
          sub: user.id,
          aud: this.audience,
          exp: Math.floor(Date.now() / 1000) + 900,
          iat: Math.floor(Date.now() / 1000),
          jti: generateUUID(),
          email: user.email,
          emailVerified: user.emailVerified,
          roles: user.roles,
          permissions: user.permissions,
          sessionId: session.id,
        };
        const accessToken = await this.token.signAccessToken(accessTokenClaims);

        const refreshTokenRaw = generateToken(48);
        const refreshTokenHash = hashToken(refreshTokenRaw);
        const family = generateUUID();
        await this.db.createRefreshToken({
          userId: user.id,
          sessionId: session.id,
          tokenHash: refreshTokenHash,
          family,
          generation: 0,
          expiresAt: new Date(Date.now() + sessionTimeout * 1000),
        });

        // Update user last login
        await this.db.updateUser(user.id, {
          lastLoginAt: new Date(),
          lastLoginIp: context.ipAddress,
        });
        this.invalidateUserCache(user.id).catch(() => {});

        // Write audit
        if (this.config.audit?.enabled) {
          this.writeAudit('LOGIN_SUCCESS', user.id, context.ipAddress, context.userAgent, {
            method: 'oauth',
            provider: providerName,
          });
        }
        await this.flushAuditLog();

        // Emit events
        await this.emitter.emit('user.login', {
          userId: user.id,
          sessionId: session.id,
          ipAddress: context.ipAddress,
          method: 'oauth',
          provider: providerName,
          timestamp: new Date(),
        });
        await this.emitter.emit('session.created', {
          userId: user.id,
          sessionId: session.id,
          timestamp: new Date(),
        });

        return this.buildAuthResponse(user, accessToken, refreshTokenRaw, 900);
      },

      link: async (userId: string, providerName: string, code: string, redirectUri: string) => {
        const provider = this.getOAuthProvider(providerName);

        // Exchange code for tokens
        const tokens = await provider.exchangeCode(code, redirectUri);

        // Get profile
        const profile = await provider.getUserProfile(tokens);

        // Check if this provider is already linked to another user
        const existingLink = await this.db.findOAuthProvider(providerName, profile.id);
        if (existingLink && existingLink.userId !== userId) {
          throw Errors.providerAlreadyLinked();
        }

        // Check if this user already has this provider linked
        const userProviders = await this.db.getUserOAuthProviders(userId);
        const alreadyLinked = userProviders.find(p => p.provider === providerName);
        if (alreadyLinked) {
          throw Errors.providerAlreadyLinked();
        }

        // Link
        await this.db.linkOAuthProvider({
          userId,
          provider: providerName,
          providerUserId: profile.id,
          email: profile.email,
          displayName: profile.displayName,
          avatarUrl: profile.avatarUrl,
          rawProfile: profile.raw,
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          tokenExpiresAt: tokens.expiresIn ? new Date(Date.now() + tokens.expiresIn * 1000) : undefined,
        });

        if (this.config.audit?.enabled) {
          this.writeAudit('OAUTH_LINKED', userId, null, null, {
            provider: providerName,
            providerUserId: profile.id,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('oauth.linked', {
          userId,
          provider: providerName,
          timestamp: new Date(),
        });
      },

      unlink: async (userId: string, providerName: string) => {
        // Check the user has another auth method
        const user = await this.db.findUserById(userId);
        if (!user) {
          throw Errors.notFound('User');
        }

        const providers = await this.db.getUserOAuthProviders(userId);
        const hasPassword = !!user.passwordHash;
        const otherProviders = providers.filter(p => p.provider !== providerName);

        if (!hasPassword && otherProviders.length === 0) {
          throw Errors.cannotUnlinkOnlyAuth();
        }

        await this.db.unlinkOAuthProvider(userId, providerName);

        if (this.config.audit?.enabled) {
          this.writeAudit('OAUTH_UNLINKED', userId, null, null, {
            provider: providerName,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('oauth.unlinked', {
          userId,
          provider: providerName,
          timestamp: new Date(),
        });
      },
    };
  }

  // ─── Organizations Namespace ────────────────────────────────────────

  private createOrgNamespace(): OrgNamespace {
    return {
      create: async (input: { name: string; slug: string; ownerId: string; plan?: string; settings?: Partial<OrgSettings> }) => {
        const org = await this.db.createOrganization(input);

        // Add owner as a member
        await this.db.addOrgMember({
          userId: input.ownerId,
          orgId: org.id,
          role: 'owner',
          permissions: [],
        });

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', input.ownerId, null, null, {
            subAction: 'org.created',
            orgId: org.id,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('org.created', {
          type: 'org.created',
          orgId: org.id,
          ownerId: input.ownerId,
          timestamp: new Date(),
        });

        return org;
      },

      get: async (id: string) => {
        const org = await this.db.getOrganization(id);
        if (!org) throw Errors.notFound('Organization');
        return org;
      },

      update: async (id: string, updates: Partial<Organization>) => {
        const org = await this.db.getOrganization(id);
        if (!org) throw Errors.notFound('Organization');

        const updated = await this.db.updateOrganization(id, updates);

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', null, null, null, {
            subAction: 'org.updated',
            orgId: id,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('org.updated', {
          type: 'org.updated',
          orgId: id,
          timestamp: new Date(),
        });

        return updated;
      },

      delete: async (id: string) => {
        await this.db.deleteOrganization(id);

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', null, null, null, {
            subAction: 'org.deleted',
            orgId: id,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('org.deleted', {
          type: 'org.deleted',
          orgId: id,
          timestamp: new Date(),
        });
      },

      addMember: async (input: { userId: string; orgId: string; role: 'owner' | 'admin' | 'member' | 'viewer' }) => {
        const member = await this.db.addOrgMember({
          userId: input.userId,
          orgId: input.orgId,
          role: input.role,
          permissions: [],
        });

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', input.userId, null, null, {
            subAction: 'org.member_added',
            orgId: input.orgId,
            role: input.role,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('org.member_added', {
          type: 'org.member_added',
          orgId: input.orgId,
          userId: input.userId,
          role: input.role,
          timestamp: new Date(),
        });

        return member;
      },

      removeMember: async (orgId: string, userId: string) => {
        await this.db.removeOrgMember(orgId, userId);

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', userId, null, null, {
            subAction: 'org.member_removed',
            orgId,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('org.member_removed', {
          type: 'org.member_removed',
          orgId,
          userId,
          timestamp: new Date(),
        });
      },

      updateMember: async (orgId: string, userId: string, updates: Partial<OrgMember>) => {
        const member = await this.db.updateOrgMember(orgId, userId, updates);

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', userId, null, null, {
            subAction: 'org.member_updated',
            orgId,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('org.member_updated', {
          type: 'org.member_updated',
          orgId,
          userId,
          timestamp: new Date(),
        });

        return member;
      },

      listMembers: async (orgId: string) => {
        return this.db.listOrgMembers(orgId);
      },

      createInvite: async (input: { orgId: string; email: string; role: string; invitedBy: string }) => {
        const token = generateToken(32);
        const invite = await this.db.createOrgInvite({
          orgId: input.orgId,
          email: input.email,
          role: input.role,
          invitedBy: input.invitedBy,
          token,
          expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000), // 7 days
        });

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', input.invitedBy, null, null, {
            subAction: 'org.invite_created',
            orgId: input.orgId,
            email: input.email,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('org.invite_created', {
          type: 'org.invite_created',
          orgId: input.orgId,
          email: input.email,
          timestamp: new Date(),
        });

        return invite;
      },

      acceptInvite: async (token: string) => {
        const invite = await this.db.findOrgInviteByToken(token);
        if (!invite) throw Errors.invalidToken();
        if (invite.acceptedAt) throw Errors.invalidToken();
        if (invite.expiresAt < new Date()) throw Errors.invalidToken();

        await this.db.acceptOrgInvite(invite.id);

        // Find user by email and add as member
        const user = await this.db.findUserByEmail(invite.email);
        if (user) {
          await this.db.addOrgMember({
            userId: user.id,
            orgId: invite.orgId,
            role: invite.role as 'owner' | 'admin' | 'member' | 'viewer',
            permissions: [],
          });
        }

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', user?.id ?? null, null, null, {
            subAction: 'org.invite_accepted',
            orgId: invite.orgId,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('org.invite_accepted', {
          type: 'org.invite_accepted',
          orgId: invite.orgId,
          email: invite.email,
          timestamp: new Date(),
        });
      },

      listInvites: async (orgId: string) => {
        return this.db.listPendingInvites(orgId);
      },

      updateSettings: async (orgId: string, settings: Partial<OrgSettings>) => {
        const org = await this.db.getOrganization(orgId);
        if (!org) throw Errors.notFound('Organization');

        const updatedSettings: OrgSettings = { ...org.settings, ...settings };
        const updated = await this.db.updateOrganization(orgId, { settings: updatedSettings });

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', null, null, null, {
            subAction: 'org.settings_updated',
            orgId,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('org.settings_updated', {
          type: 'org.settings_updated',
          orgId,
          timestamp: new Date(),
        });

        return updated;
      },
    };
  }

  // ─── Roles Namespace ───────────────────────────────────────────────

  private createRoleNamespace(): RoleNamespace {
    return {
      create: async (role: Role) => {
        const created = await this.db.createRole(role);

        if (this.config.audit?.enabled) {
          this.writeAudit('ROLE_CHANGED', null, null, null, {
            subAction: 'role.created',
            roleName: role.name,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('role.created', {
          type: 'role.created',
          roleName: role.name,
          timestamp: new Date(),
        });

        return created;
      },

      get: async (name: string) => {
        const role = await this.db.getRole(name);
        if (!role) throw Errors.notFound('Role');
        return role;
      },

      list: async () => {
        return this.db.listRoles();
      },

      update: async (name: string, updates: Partial<Role>) => {
        const updated = await this.db.updateRole(name, updates);

        if (this.config.audit?.enabled) {
          this.writeAudit('ROLE_CHANGED', null, null, null, {
            subAction: 'role.updated',
            roleName: name,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('role.updated', {
          type: 'role.updated',
          roleName: name,
          timestamp: new Date(),
        });

        return updated;
      },

      delete: async (name: string) => {
        await this.db.deleteRole(name);

        if (this.config.audit?.enabled) {
          this.writeAudit('ROLE_CHANGED', null, null, null, {
            subAction: 'role.deleted',
            roleName: name,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('role.deleted', {
          type: 'role.deleted',
          roleName: name,
          timestamp: new Date(),
        });
      },
    };
  }

  // ─── API Keys Namespace ────────────────────────────────────────────

  private createApiKeyNamespace(): ApiKeyNamespace {
    return {
      create: async (userId: string, input: { name: string; permissions: string[]; orgId?: string; expiresAt?: Date; ipAllowlist?: string[] }) => {
        const rawKey = `argus_pk_${generateToken(36)}`;
        const keyHash = hashToken(rawKey);
        const keyPrefix = rawKey.slice(0, 16);

        const apiKey = await this.db.createApiKey({
          name: input.name,
          keyPrefix,
          keyHash,
          userId,
          orgId: input.orgId,
          permissions: input.permissions,
          ipAllowlist: input.ipAllowlist,
          expiresAt: input.expiresAt,
        });

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', userId, null, null, {
            subAction: 'apikey.created',
            keyId: apiKey.id,
            name: input.name,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('apikey.created', {
          type: 'apikey.created',
          userId,
          keyId: apiKey.id,
          timestamp: new Date(),
        });

        return { apiKey, rawKey };
      },

      list: async (userId: string) => {
        return this.db.listApiKeys(userId);
      },

      revoke: async (id: string) => {
        await this.db.revokeApiKey(id);

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', null, null, null, {
            subAction: 'apikey.revoked',
            keyId: id,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('apikey.revoked', {
          type: 'apikey.revoked',
          keyId: id,
          timestamp: new Date(),
        });
      },

      validate: async (rawKey: string) => {
        const keyHash = hashToken(rawKey);
        const apiKey = await this.db.findApiKeyByHash(keyHash);

        if (!apiKey) return null;
        if (apiKey.revokedAt) return null;
        if (apiKey.expiresAt && apiKey.expiresAt < new Date()) return null;

        const user = await this.db.findUserById(apiKey.userId);
        if (!user) return null;

        // Update last used timestamp
        await this.db.updateApiKeyLastUsed(apiKey.id);

        return { apiKey, user };
      },
    };
  }

  // ─── Webhooks Namespace ────────────────────────────────────────────

  private createWebhookNamespace(): WebhookNamespace {
    return {
      create: async (input: { url: string; events: string[]; orgId?: string }) => {
        const secret = generateToken(32);

        const webhook = await this.db.createWebhook({
          url: input.url,
          events: input.events,
          secret,
          orgId: input.orgId,
        });

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', null, null, null, {
            subAction: 'webhook.created',
            webhookId: webhook.id,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('webhook.created', {
          type: 'webhook.created',
          webhookId: webhook.id,
          timestamp: new Date(),
        });

        return webhook;
      },

      list: async (orgId?: string) => {
        return this.db.listWebhooks(orgId);
      },

      update: async (id: string, updates: Partial<Webhook>) => {
        const updated = await this.db.updateWebhook(id, updates);

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', null, null, null, {
            subAction: 'webhook.updated',
            webhookId: id,
          });
        }
        await this.flushAuditLog();

        return updated;
      },

      delete: async (id: string) => {
        await this.db.deleteWebhook(id);

        if (this.config.audit?.enabled) {
          this.writeAudit('ADMIN_ACTION', null, null, null, {
            subAction: 'webhook.deleted',
            webhookId: id,
          });
        }
        await this.flushAuditLog();

        await this.emitter.emit('webhook.deleted', {
          type: 'webhook.deleted',
          webhookId: id,
          timestamp: new Date(),
        });
      },

      test: async (id: string) => {
        const webhooks = await this.db.listWebhooks();
        const webhook = webhooks.find(w => w.id === id);
        if (!webhook) throw Errors.notFound('Webhook');

        await this.emitter.emit('webhook.test', {
          type: 'webhook.test',
          webhookId: id,
          timestamp: new Date(),
        });
      },
    };
  }
}

// ─── Namespace Types ──────────────────────────────────────────────────

export interface MFANamespace {
  setup(userId: string, method: string): Promise<MFASetupData>;
  verifySetup(userId: string, method: string, code: string): Promise<void>;
  verifyLogin(mfaToken: string, code: string, method: string, context: LoginContext): Promise<AuthResponse>;
  disable(userId: string, code: string): Promise<void>;
  regenerateBackupCodes(userId: string, code: string): Promise<string[]>;
}

export interface OAuthNamespace {
  getAuthorizationUrl(providerName: string, redirectUri: string): Promise<{ url: string; state: string }>;
  handleCallback(providerName: string, code: string, state: string, context: LoginContext): Promise<AuthResponse>;
  link(userId: string, providerName: string, code: string, redirectUri: string): Promise<void>;
  unlink(userId: string, providerName: string): Promise<void>;
}

export interface OrgNamespace {
  create(input: { name: string; slug: string; ownerId: string; plan?: string; settings?: Partial<OrgSettings> }): Promise<Organization>;
  get(id: string): Promise<Organization>;
  update(id: string, updates: Partial<Organization>): Promise<Organization>;
  delete(id: string): Promise<void>;
  addMember(input: { userId: string; orgId: string; role: 'owner' | 'admin' | 'member' | 'viewer' }): Promise<OrgMember>;
  removeMember(orgId: string, userId: string): Promise<void>;
  updateMember(orgId: string, userId: string, updates: Partial<OrgMember>): Promise<OrgMember>;
  listMembers(orgId: string): Promise<OrgMember[]>;
  createInvite(input: { orgId: string; email: string; role: string; invitedBy: string }): Promise<OrgInvite>;
  acceptInvite(token: string): Promise<void>;
  listInvites(orgId: string): Promise<OrgInvite[]>;
  updateSettings(orgId: string, settings: Partial<OrgSettings>): Promise<Organization>;
}

export interface RoleNamespace {
  create(role: Role): Promise<Role>;
  get(name: string): Promise<Role>;
  list(): Promise<Role[]>;
  update(name: string, updates: Partial<Role>): Promise<Role>;
  delete(name: string): Promise<void>;
}

export interface ApiKeyNamespace {
  create(userId: string, input: { name: string; permissions: string[]; orgId?: string; expiresAt?: Date; ipAllowlist?: string[] }): Promise<{ apiKey: ApiKey; rawKey: string }>;
  list(userId: string): Promise<ApiKey[]>;
  revoke(id: string): Promise<void>;
  validate(rawKey: string): Promise<{ apiKey: ApiKey; user: User } | null>;
}

export interface WebhookNamespace {
  create(input: { url: string; events: string[]; orgId?: string }): Promise<Webhook>;
  list(orgId?: string): Promise<Webhook[]>;
  update(id: string, updates: Partial<Webhook>): Promise<Webhook>;
  delete(id: string): Promise<void>;
  test(id: string): Promise<void>;
}
