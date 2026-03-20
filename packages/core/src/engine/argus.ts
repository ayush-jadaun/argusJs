import type { ArgusConfig } from '../types/config.js';
import type { User, Session, AuditAction } from '../types/entities.js';
import type { AuthResponse, UserResponse, MFAChallengeResponse, AccessTokenClaims } from '../types/responses.js';
import type { DbAdapter } from '../interfaces/db-adapter.js';
import type { CacheAdapter } from '../interfaces/cache-adapter.js';
import type { PasswordHasher } from '../interfaces/password-hasher.js';
import type { TokenProvider } from '../interfaces/token-provider.js';
import type { EmailProvider } from '../interfaces/email-provider.js';
import type { RateLimiter } from '../interfaces/rate-limiter.js';
import type { PasswordPolicy } from '../interfaces/password-policy.js';
import type { SecurityEngine } from '../interfaces/security-engine.js';
import { Errors } from '../types/errors.js';
import { ArgusEventEmitter } from './event-emitter.js';
import { generateToken, hashToken, generateUUID } from '../utils/crypto.js';

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
    this.emitter = new ArgusEventEmitter();
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
  }

  async shutdown(): Promise<void> {
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
    const email = input.email.toLowerCase();

    // 2. Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw Errors.validation([{ field: 'email', message: 'Invalid email format', code: 'invalid_format' }]);
    }

    // 3. Check password length
    const minLength = this.config.password?.minLength ?? 8;
    const maxLength = this.config.password?.maxLength ?? 128;
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

    const accessTokenClaims: AccessTokenClaims = {
      iss: 'argus',
      sub: user.id,
      aud: ['argus'],
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
      await this.writeAudit('USER_REGISTERED', user.id, input.ipAddress, input.userAgent, {});
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

    // 17. Return AuthResponse
    return this.buildAuthResponse(user, accessToken, refreshTokenRaw, 900);
  }

  // ─── Login Pipeline ─────────────────────────────────────────────────

  async login(email: string, password: string, context: LoginContext): Promise<AuthResponse | MFAChallengeResponse> {
    // 1. Execute beforeLogin hook
    if (this.config.hooks?.beforeLogin) {
      await this.config.hooks.beforeLogin({ email });
    }

    // Normalize email
    const normalizedEmail = email.toLowerCase();

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
          await this.writeAudit('ACCOUNT_LOCKED', user.id, context.ipAddress, context.userAgent, {
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

      // 4c. Write audit LOGIN_FAILED
      if (this.config.audit?.enabled) {
        await this.writeAudit('LOGIN_FAILED', user.id, context.ipAddress, context.userAgent, {
          failedAttempts: newFailedAttempts,
        });
      }

      // 4d. Emit login_failed
      await this.emitter.emit('user.login_failed', {
        userId: user.id,
        ipAddress: context.ipAddress,
        timestamp: new Date(),
      });

      // 4e. Throw
      throw Errors.invalidCredentials();
    }

    // 5. Reset failedLoginAttempts
    await this.db.updateUser(user.id, {
      failedLoginAttempts: 0,
      lockedUntil: null,
    });

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

    // 7. Enforce session limit
    const maxPerUser = this.config.session?.maxPerUser ?? 5;
    const activeSessionCount = await this.db.countActiveSessions(user.id);
    if (activeSessionCount >= maxPerUser) {
      const activeSessions = await this.db.getActiveSessions(user.id);
      // Sort by createdAt ASC (oldest first)
      activeSessions.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
      // Revoke oldest sessions until we're under the limit
      const toRevoke = activeSessions.slice(0, activeSessionCount - maxPerUser + 1);
      for (const session of toRevoke) {
        await this.db.revokeSession(session.id, 'session_limit_exceeded');
      }
    }

    // 8. Create session
    const sessionTimeout = this.config.session?.absoluteTimeout ?? 2592000;
    const session = await this.db.createSession({
      userId: user.id,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      deviceFingerprint: context.deviceFingerprint,
      expiresAt: new Date(Date.now() + sessionTimeout * 1000),
    });

    // 9. Generate access + refresh tokens
    const accessTokenClaims: AccessTokenClaims = {
      iss: 'argus',
      sub: user.id,
      aud: ['argus'],
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

    // 10. Update user
    await this.db.updateUser(user.id, {
      lastLoginAt: new Date(),
      lastLoginIp: context.ipAddress,
      failedLoginAttempts: 0,
    });

    // 11. Write audit
    if (this.config.audit?.enabled) {
      await this.writeAudit('LOGIN_SUCCESS', user.id, context.ipAddress, context.userAgent, {});
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

    // 14. Return AuthResponse
    return this.buildAuthResponse(user, accessToken, refreshTokenRaw, 900);
  }

  // ─── Logout Pipeline ────────────────────────────────────────────────

  async logout(userId: string, sessionId: string, options?: { allDevices?: boolean }): Promise<void> {
    if (options?.allDevices) {
      // 1. Revoke all sessions and tokens
      await this.db.revokeAllSessions(userId, 'logout');
      await this.db.revokeAllUserTokens(userId, 'logout');

      // Write audit
      if (this.config.audit?.enabled) {
        await this.writeAudit('LOGOUT_ALL_SESSIONS', userId, null, null, {});
      }
    } else {
      // 2. Revoke single session
      await this.db.revokeSession(sessionId, 'logout');

      // Write audit
      if (this.config.audit?.enabled) {
        await this.writeAudit('LOGOUT', userId, null, null, { sessionId });
      }
    }

    // 3. Emit event
    await this.emitter.emit('user.logout', {
      userId,
      sessionId,
      allDevices: options?.allDevices ?? false,
      timestamp: new Date(),
    });
  }

  // ─── Refresh Token Pipeline ─────────────────────────────────────────

  async refresh(refreshTokenValue: string): Promise<AuthResponse> {
    // 1. Hash the provided refresh token
    const tokenHash = hashToken(refreshTokenValue);

    // 2. Look up in DB by hash
    const token = await this.db.findRefreshTokenByHash(tokenHash);

    // 3. If not found → throw
    if (!token) {
      throw Errors.invalidRefreshToken();
    }

    // 4. If revoked → TOKEN REUSE DETECTED
    if (token.revoked) {
      // a. Revoke entire token family
      await this.db.revokeTokenFamily(token.family, 'reuse_detected');
      // b. Revoke all sessions for user
      await this.db.revokeAllSessions(token.userId, 'security_alert');
      // c. Write audit
      if (this.config.audit?.enabled) {
        await this.writeAudit('TOKEN_REUSE_DETECTED', token.userId, null, null, {
          family: token.family,
          generation: token.generation,
        });
      }
      // d. Emit events
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
      // e. Throw
      throw Errors.refreshTokenReuse();
    }

    // 5. If expired → throw
    if (token.expiresAt < new Date()) {
      throw Errors.invalidRefreshToken();
    }

    // 6. Get session, verify not revoked
    const session = await this.db.getSession(token.sessionId);
    if (!session || session.revoked) {
      throw Errors.sessionExpired();
    }

    // 7. Revoke old refresh token
    await this.db.revokeRefreshToken(token.id, 'rotated');

    // 8. Generate new refresh token value, hash it
    const newRefreshTokenRaw = generateToken(48);
    const newRefreshTokenHash = hashToken(newRefreshTokenRaw);

    // 9. Create new refresh token in DB (same family, generation + 1)
    const sessionTimeout = this.config.session?.absoluteTimeout ?? 2592000;
    await this.db.createRefreshToken({
      userId: token.userId,
      sessionId: token.sessionId,
      tokenHash: newRefreshTokenHash,
      family: token.family,
      generation: token.generation + 1,
      expiresAt: new Date(Date.now() + sessionTimeout * 1000),
    });

    // 10. Get user from DB
    const user = await this.db.findUserById(token.userId);
    if (!user) {
      throw Errors.invalidRefreshToken();
    }

    // 11. Sign new access token
    const accessTokenClaims: AccessTokenClaims = {
      iss: 'argus',
      sub: user.id,
      aud: ['argus'],
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

    // 12. Write audit
    if (this.config.audit?.enabled) {
      await this.writeAudit('TOKEN_REFRESHED', user.id, null, null, {
        sessionId: session.id,
      });
    }

    // 13. Emit event
    await this.emitter.emit('token.refreshed', {
      userId: user.id,
      sessionId: session.id,
      timestamp: new Date(),
    });

    // 14. Return AuthResponse
    return this.buildAuthResponse(user, accessToken, newRefreshTokenRaw, 900);
  }

  // ─── Forgot Password Pipeline ─────────────────────────────────────

  async forgotPassword(email: string, ipAddress: string, userAgent?: string): Promise<void> {
    // Normalize email
    const normalizedEmail = email.toLowerCase();

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
      await this.writeAudit('PASSWORD_RESET_REQUESTED', user.id, ipAddress, userAgent ?? null, {});
    }
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
      await this.writeAudit('PASSWORD_RESET_COMPLETED', user.id, ipAddress, null, {});
    }

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

    // 5. Write audit
    if (this.config.audit?.enabled) {
      await this.writeAudit('EMAIL_VERIFIED', verificationToken.userId, null, null, {});
    }

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
      await this.writeAudit('EMAIL_VERIFICATION_SENT', user.id, null, null, {});
    }
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

  private async writeAudit(
    action: AuditAction,
    userId: string | null,
    ipAddress: string | null,
    userAgent: string | null,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    await this.db.writeAuditLog({
      id: generateUUID(),
      userId,
      action,
      ipAddress,
      userAgent,
      metadata,
      orgId: null,
      createdAt: new Date(),
    });
  }
}
