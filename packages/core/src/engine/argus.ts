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
