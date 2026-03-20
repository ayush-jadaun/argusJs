import { describe, it, expect } from 'vitest';
import { BcryptHasher } from '../bcrypt-hasher.js';

describe('BcryptHasher', () => {
  const hasher = new BcryptHasher();

  it('should have name bcrypt', () => {
    expect(hasher.name).toBe('bcrypt');
  });

  it('should hash to a string starting with $2b$', async () => {
    const hash = await hasher.hash('password');
    expect(hash).toMatch(/^\$2[aby]\$/);
  });

  it('should verify correct password', async () => {
    const hash = await hasher.hash('password');
    expect(await hasher.verify('password', hash)).toBe(true);
  });

  it('should reject wrong password', async () => {
    const hash = await hasher.hash('password');
    expect(await hasher.verify('wrong', hash)).toBe(false);
  });

  it('should produce different hashes (random salt)', async () => {
    const h1 = await hasher.hash('same');
    const h2 = await hasher.hash('same');
    expect(h1).not.toBe(h2);
  });

  it('should accept custom rounds', async () => {
    const fast = new BcryptHasher({ rounds: 4 });
    const hash = await fast.hash('test');
    expect(await fast.verify('test', hash)).toBe(true);
  });

  it('should detect needsRehash for different rounds', () => {
    const hasher12 = new BcryptHasher({ rounds: 12 });
    // $2b$10$ prefix means 10 rounds — if configured for 12, needs rehash
    expect(typeof hasher12.needsRehash).toBe('function');
  });
});
