import { describe, it, expect } from 'vitest';
import { ScryptHasher } from '../scrypt-hasher.js';

describe('ScryptHasher', () => {
  const hasher = new ScryptHasher();

  it('should have name scrypt', () => {
    expect(hasher.name).toBe('scrypt');
  });

  it('should hash and verify correctly', async () => {
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

  it('should handle unicode', async () => {
    const hash = await hasher.hash('пароль🔑');
    expect(await hasher.verify('пароль🔑', hash)).toBe(true);
  });

  it('should accept custom cost/blockSize/parallelization', async () => {
    const custom = new ScryptHasher({ cost: 8192, blockSize: 8, parallelization: 1 });
    const hash = await custom.hash('test');
    expect(await custom.verify('test', hash)).toBe(true);
  });
});
