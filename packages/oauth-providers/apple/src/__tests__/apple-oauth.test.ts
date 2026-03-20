import { describe, it, expect, vi, afterEach } from 'vitest';
import { AppleOAuth } from '../apple-oauth.js';

describe('AppleOAuth', () => {
  const provider = new AppleOAuth({
    clientId: 'com.example.app',
    teamId: 'TEAM123',
    keyId: 'KEY456',
    privateKey: 'fake-private-key',
  });
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('should have name apple', () => {
    expect(provider.name).toBe('apple');
  });

  it('should generate authorization URL', () => {
    const url = provider.getAuthorizationUrl('state123', 'http://localhost:3000/callback');
    expect(url).toContain('appleid.apple.com/auth/authorize');
    expect(url).toContain('client_id=com.example.app');
    expect(url).toContain('state=state123');
    expect(url).toContain('response_mode=form_post');
    expect(url).toContain('response_type=code');
    expect(url).toContain('scope=');
  });

  it('should include PKCE in auth URL when provided', () => {
    const url = provider.getAuthorizationUrl('state', 'http://localhost/cb', 'challenge123');
    expect(url).toContain('code_challenge=challenge123');
    expect(url).toContain('code_challenge_method=S256');
  });

  it('should not include PKCE params when no challenge provided', () => {
    const url = provider.getAuthorizationUrl('state', 'http://localhost/cb');
    expect(url).not.toContain('code_challenge');
    expect(url).not.toContain('code_challenge_method');
  });

  it('should exchange code for tokens', async () => {
    // Mock the fetch for token exchange - the generateClientSecret will fail
    // with a fake key, so we mock the entire exchange
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'apple_at',
        refresh_token: 'apple_rt',
        id_token: 'header.eyJzdWIiOiIxMjMiLCJlbWFpbCI6ImFAYXBwbGUuY29tIn0.signature',
        expires_in: 3600,
        token_type: 'Bearer',
      }),
    });

    // We need to mock the private method, so instead test via prototype
    const mockProvider = new AppleOAuth({
      clientId: 'com.example.app',
      teamId: 'TEAM123',
      keyId: 'KEY456',
      privateKey: 'fake-private-key',
    });

    // Override the private generateClientSecret method
    (mockProvider as any).generateClientSecret = vi.fn().mockResolvedValue('mock-client-secret');

    const tokens = await mockProvider.exchangeCode('code123', 'http://localhost/cb');
    expect(tokens.accessToken).toBe('apple_at');
    expect(tokens.refreshToken).toBe('apple_rt');
    expect(tokens.idToken).toContain('.');
    expect(tokens.expiresIn).toBe(3600);
    expect(tokens.tokenType).toBe('Bearer');
  });

  it('should throw on failed token exchange', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      text: () => Promise.resolve('invalid_client'),
    });

    const mockProvider = new AppleOAuth({
      clientId: 'com.example.app',
      teamId: 'TEAM123',
      keyId: 'KEY456',
      privateKey: 'fake',
    });
    (mockProvider as any).generateClientSecret = vi.fn().mockResolvedValue('mock-secret');

    await expect(mockProvider.exchangeCode('bad', 'http://localhost/cb'))
      .rejects.toThrow('Apple token exchange failed');
  });

  it('should get user profile from id_token', async () => {
    const payload = Buffer.from(JSON.stringify({
      sub: 'apple-user-123',
      email: 'user@icloud.com',
    })).toString('base64url');

    const idToken = `header.${payload}.signature`;

    const profile = await provider.getUserProfile({
      accessToken: 'at',
      idToken,
      expiresIn: 3600,
      tokenType: 'Bearer',
    });

    expect(profile.id).toBe('apple-user-123');
    expect(profile.email).toBe('user@icloud.com');
    expect(profile.raw).toBeDefined();
  });

  it('should throw when id_token is missing', async () => {
    await expect(provider.getUserProfile({
      accessToken: 'at',
      expiresIn: 3600,
      tokenType: 'Bearer',
    })).rejects.toThrow('Apple OAuth requires an id_token');
  });

  it('should include default scopes', () => {
    const url = provider.getAuthorizationUrl('state', 'http://localhost/cb');
    expect(url).toContain('name');
    expect(url).toContain('email');
  });
});
