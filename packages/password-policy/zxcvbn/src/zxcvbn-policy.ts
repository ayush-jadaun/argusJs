import zxcvbn from 'zxcvbn';
import type { PasswordPolicy, PasswordPolicyResult } from '@argusjs/core';

export interface ZxcvbnConfig {
  minScore?: number; // 0-4, default 3
}

export class ZxcvbnPolicy implements PasswordPolicy {
  name = 'zxcvbn';
  private minScore: number;

  constructor(config: ZxcvbnConfig = {}) {
    this.minScore = config.minScore ?? 3;
  }

  async validate(
    password: string,
    context?: { email?: string; displayName?: string },
  ): Promise<PasswordPolicyResult> {
    const userInputs: string[] = [];
    if (context?.email) {
      userInputs.push(context.email);
      // Also add the local part of the email
      const localPart = context.email.split('@')[0];
      if (localPart) {
        userInputs.push(localPart);
      }
    }
    if (context?.displayName) {
      userInputs.push(context.displayName);
    }

    const result = zxcvbn(password, userInputs);

    const reasons: string[] = [];
    if (result.feedback.warning) {
      reasons.push(result.feedback.warning);
    }

    const suggestions = result.feedback.suggestions.length > 0
      ? result.feedback.suggestions
      : undefined;

    return {
      valid: result.score >= this.minScore,
      score: result.score,
      reasons,
      suggestions,
    };
  }
}
