import type { PasswordPolicyResult } from '../types/responses.js';

export interface PasswordPolicy {
  name: string;
  init?(): Promise<void>;
  validate(password: string, context?: { email?: string; displayName?: string }): Promise<PasswordPolicyResult>;
}
