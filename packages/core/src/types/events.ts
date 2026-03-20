export interface ArgusEvent {
  type: ArgusEventType;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  timestamp: Date;
  data?: Record<string, unknown>;
}

export type ArgusEventType =
  | 'user.registered'
  | 'user.login'
  | 'user.login_failed'
  | 'user.logout'
  | 'user.locked'
  | 'user.unlocked'
  | 'user.deleted'
  | 'user.email_verified'
  | 'user.password_changed'
  | 'user.password_reset_requested'
  | 'user.password_reset_completed'
  | 'session.created'
  | 'session.revoked'
  | 'session.expired'
  | 'token.refreshed'
  | 'token.reuse_detected'
  | 'mfa.enabled'
  | 'mfa.disabled'
  | 'mfa.challenge_passed'
  | 'mfa.challenge_failed'
  | 'mfa.backup_code_used'
  | 'oauth.linked'
  | 'oauth.unlinked'
  | 'security.suspicious_activity'
  | 'security.brute_force_detected'
  | 'admin.role_changed'
  | 'admin.permission_changed';
