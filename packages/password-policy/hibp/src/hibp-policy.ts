import { createHash } from 'node:crypto';
import type { PasswordPolicy, PasswordPolicyResult } from '@argus/core';

export class HIBPPolicy implements PasswordPolicy {
  name = 'hibp';

  async validate(password: string): Promise<PasswordPolicyResult> {
    try {
      const sha1 = createHash('sha1').update(password).digest('hex').toUpperCase();
      const prefix = sha1.slice(0, 5);
      const suffix = sha1.slice(5);

      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      if (!response.ok) {
        // If API is down, don't block the user
        return { valid: true, reasons: [] };
      }

      const text = await response.text();
      const found = text.split('\n').some(line => line.split(':')[0] === suffix);

      if (found) {
        return {
          valid: false,
          reasons: ['breached'],
          suggestions: ['This password has been found in a data breach. Choose a different password.'],
        };
      }
      return { valid: true, reasons: [] };
    } catch {
      // Network error — don't block
      return { valid: true, reasons: [] };
    }
  }
}
