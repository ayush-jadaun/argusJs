import { describe, it, expect } from 'vitest';
import { WebAuthnProvider } from '../webauthn-provider.js';

describe('WebAuthnProvider', () => {
  const provider = new WebAuthnProvider({ rpName: 'TestApp', rpId: 'localhost', origin: 'http://localhost:3000' });

  it('should have name webauthn', () => { expect(provider.name).toBe('webauthn'); });

  it('should generate registration options', async () => {
    const user = { id: 'u1', email: 'a@b.com', displayName: 'Alice' } as any;
    const setup = await provider.generateSecret(user);
    expect(setup.secret).toBeDefined();
    const options = JSON.parse(setup.secret);
    expect(options.rp).toBeDefined();
    expect(options.rp.name).toBe('TestApp');
  });

  it('should generate backup codes', () => {
    const codes = provider.generateBackupCodes!();
    expect(codes).toHaveLength(10);
    codes.forEach(code => expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/));
  });

  it('should reject invalid verification data', async () => {
    expect(await provider.verifyCode('bad', 'bad')).toBe(false);
  });
});
