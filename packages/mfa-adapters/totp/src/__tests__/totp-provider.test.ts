import { describe, it, expect } from 'vitest';
import { TOTPProvider } from '../totp-provider.js';
import { authenticator } from 'otplib';

describe('TOTPProvider', () => {
  const provider = new TOTPProvider({ appName: 'TestApp' });

  it('should have name totp', () => {
    expect(provider.name).toBe('totp');
  });

  it('should generate a secret with base32 format', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'A' } as any;
    const setup = await provider.generateSecret(user);
    expect(setup.secret).toMatch(/^[A-Z2-7]+=*$/);
    expect(setup.secret.length).toBeGreaterThanOrEqual(16);
  });

  it('should generate qrCodeUrl with otpauth format', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'A' } as any;
    const setup = await provider.generateSecret(user);
    expect(setup.qrCodeUrl).toMatch(/^otpauth:\/\/totp\//);
    expect(setup.qrCodeUrl).toContain('TestApp');
    expect(setup.qrCodeUrl).toContain('a@b.com');
  });

  it('should generate 10 backup codes in XXXX-XXXX format', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'A' } as any;
    const setup = await provider.generateSecret(user);
    expect(setup.backupCodes).toHaveLength(10);
    setup.backupCodes.forEach(code => {
      expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    });
  });

  it('should verify a valid TOTP code', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'A' } as any;
    const setup = await provider.generateSecret(user);
    const validCode = authenticator.generate(setup.secret);
    expect(await provider.verifyCode(setup.secret, validCode)).toBe(true);
  });

  it('should reject an invalid code', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'A' } as any;
    const setup = await provider.generateSecret(user);
    expect(await provider.verifyCode(setup.secret, '000000')).toBe(false);
  });

  it('should return expiresIn', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'A' } as any;
    const setup = await provider.generateSecret(user);
    expect(setup.expiresIn).toBe(600);
  });

  it('should generate unique backup codes', () => {
    const codes = provider.generateBackupCodes!();
    const unique = new Set(codes);
    expect(unique.size).toBe(codes.length);
  });
});
