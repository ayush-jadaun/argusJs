import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { GoogleOAuth } from '../google-oauth.js';

describe('GoogleOAuth', () => {
  const provider = new GoogleOAuth({ clientId: 'test-id', clientSecret: 'test-secret' });
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('should have name google', () => {
    expect(provider.name).toBe('google');
  });

  it('should generate authorization URL', () => {
    const url = provider.getAuthorizationUrl('state123', 'http://localhost:3000/callback');
    expect(url).toContain('accounts.google.com');
    expect(url).toContain('client_id=test-id');
    expect(url).toContain('state=state123');
    expect(url).toContain('scope=');
    expect(url).toContain('response_type=code');
    expect(url).toContain('redirect_uri=');
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
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'at',
        refresh_token: 'rt',
        id_token: 'idt',
        expires_in: 3600,
        token_type: 'Bearer',
        scope: 'openid email profile',
      }),
    });

    const tokens = await provider.exchangeCode('code123', 'http://localhost/cb');
    expect(tokens.accessToken).toBe('at');
    expect(tokens.refreshToken).toBe('rt');
    expect(tokens.idToken).toBe('idt');
    expect(tokens.expiresIn).toBe(3600);
    expect(tokens.tokenType).toBe('Bearer');
  });

  it('should pass code verifier when exchanging code', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'at',
        expires_in: 3600,
        token_type: 'Bearer',
      }),
    });

    await provider.exchangeCode('code123', 'http://localhost/cb', 'verifier123');

    const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = call[1].body as string;
    expect(body).toContain('code_verifier=verifier123');
  });

  it('should throw on failed token exchange', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      text: () => Promise.resolve('invalid_grant'),
    });

    await expect(provider.exchangeCode('bad', 'http://localhost/cb'))
      .rejects.toThrow('Google token exchange failed');
  });

  it('should get user profile', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        id: '123',
        email: 'a@gmail.com',
        name: 'Alice',
        picture: 'http://photo.jpg',
      }),
    });

    const profile = await provider.getUserProfile({ accessToken: 'at', expiresIn: 3600, tokenType: 'Bearer' });
    expect(profile.id).toBe('123');
    expect(profile.email).toBe('a@gmail.com');
    expect(profile.displayName).toBe('Alice');
    expect(profile.avatarUrl).toBe('http://photo.jpg');
    expect(profile.raw).toBeDefined();
  });

  it('should throw on failed profile fetch', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      text: () => Promise.resolve('Unauthorized'),
    });

    await expect(provider.getUserProfile({ accessToken: 'bad', expiresIn: 3600, tokenType: 'Bearer' }))
      .rejects.toThrow('Google userinfo request failed');
  });

  it('should include default scopes in auth URL', () => {
    const url = provider.getAuthorizationUrl('state', 'http://localhost/cb');
    expect(url).toContain('openid');
    expect(url).toContain('email');
    expect(url).toContain('profile');
  });
});
