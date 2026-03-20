import { describe, it, expect, vi } from 'vitest';
import { HIBPPolicy } from '../src/hibp-policy.js';

describe('HIBPPolicy', () => {
  const policy = new HIBPPolicy();

  it('should have name hibp', () => { expect(policy.name).toBe('hibp'); });

  it('should detect known breached password "password"', async () => {
    const r = await policy.validate('password');
    expect(r.valid).toBe(false);
    expect(r.reasons).toContain('breached');
  });

  it('should accept a likely unique password', async () => {
    const unique = `xK9$mZ2!qW4@pL7_${Date.now()}_${Math.random()}`;
    const r = await policy.validate(unique);
    expect(r.valid).toBe(true);
  });

  it('should not block when API fails', async () => {
    // Mock fetch to simulate failure
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('network error'));
    const r = await policy.validate('anything');
    expect(r.valid).toBe(true);
    globalThis.fetch = originalFetch;
  });

  it('should return suggestions for breached passwords', async () => {
    const r = await policy.validate('123456');
    if (!r.valid) {
      expect(r.suggestions).toBeDefined();
      expect(r.suggestions!.length).toBeGreaterThan(0);
    }
  });
});
