import { describe, it, expect } from 'vitest';
import { ZxcvbnPolicy } from '../src/zxcvbn-policy.js';

describe('ZxcvbnPolicy', () => {
  const policy = new ZxcvbnPolicy({ minScore: 3 });

  it('should have name zxcvbn', () => { expect(policy.name).toBe('zxcvbn'); });

  it('should reject weak passwords', async () => {
    const r = await policy.validate('password');
    expect(r.valid).toBe(false);
    expect(r.score).toBeLessThan(3);
  });

  it('should accept strong passwords', async () => {
    const r = await policy.validate('correct-horse-battery-staple-2024!');
    expect(r.valid).toBe(true);
    expect(r.score).toBeGreaterThanOrEqual(3);
  });

  it('should return suggestions for weak passwords', async () => {
    const r = await policy.validate('abc123');
    expect(r.reasons.length + (r.suggestions?.length ?? 0)).toBeGreaterThan(0);
  });

  it('should penalize passwords containing email', async () => {
    const r = await policy.validate('alice2024', { email: 'alice@example.com' });
    expect(r.score).toBeLessThanOrEqual(2);
  });

  it('should respect custom minScore', async () => {
    const lenient = new ZxcvbnPolicy({ minScore: 1 });
    const r = await lenient.validate('test1234');
    // score 1 or higher should pass with minScore 1
    expect(r.valid).toBe(r.score! >= 1);
  });
});
