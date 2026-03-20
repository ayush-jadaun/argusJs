import { describe, it, expect, vi, afterEach } from 'vitest';
import { MicrosoftOAuth } from '../microsoft-oauth.js';

describe('MicrosoftOAuth', () => {
  const provider = new MicrosoftOAuth({ clientId: 'ms-id', clientSecret: 'ms-secret' });
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('should have name microsoft', () => {
    expect(provider.name).toBe('microsoft');
  });

  it('should generate authorization URL with common tenant', () => {
    const url = provider.getAuthorizationUrl('state123', 'http://localhost:3000/callback');
    expect(url).toContain('login.microsoftonline.com/common/oauth2/v2.0/authorize');
    expect(url).toContain('client_id=ms-id');
    expect(url).toContain('state=state123');
    expect(url).toContain('response_type=code');
    expect(url).toContain('scope=');
  });

  it('should use custom tenant when configured', () => {
    const customProvider = new MicrosoftOAuth({
      clientId: 'ms-id',
      clientSecret: 'ms-secret',
      tenant: 'my-tenant-id',
    });
    const url = customProvider.getAuthorizationUrl('state', 'http://localhost/cb');
    expect(url).toContain('login.microsoftonline.com/my-tenant-id/oauth2/v2.0/authorize');
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
        access_token: 'ms_at',
        refresh_token: 'ms_rt',
        id_token: 'ms_idt',
        expires_in: 3600,
        token_type: 'Bearer',
        scope: 'openid email profile',
      }),
    });

    const tokens = await provider.exchangeCode('code123', 'http://localhost/cb');
    expect(tokens.accessToken).toBe('ms_at');
    expect(tokens.refreshToken).toBe('ms_rt');
    expect(tokens.expiresIn).toBe(3600);
    expect(tokens.tokenType).toBe('Bearer');
  });

  it('should pass code verifier when exchanging code', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'ms_at',
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
      .rejects.toThrow('Microsoft token exchange failed');
  });

  it('should get user profile', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        id: 'ms-user-123',
        mail: 'alice@outlook.com',
        displayName: 'Alice Smith',
        userPrincipalName: 'alice@outlook.com',
      }),
    });

    const profile = await provider.getUserProfile({ accessToken: 'at', expiresIn: 3600, tokenType: 'Bearer' });
    expect(profile.id).toBe('ms-user-123');
    expect(profile.email).toBe('alice@outlook.com');
    expect(profile.displayName).toBe('Alice Smith');
    expect(profile.raw).toBeDefined();
  });

  it('should fall back to userPrincipalName if mail is null', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        id: 'ms-user-456',
        mail: null,
        displayName: 'Bob',
        userPrincipalName: 'bob@contoso.onmicrosoft.com',
      }),
    });

    const profile = await provider.getUserProfile({ accessToken: 'at', expiresIn: 3600, tokenType: 'Bearer' });
    expect(profile.email).toBe('bob@contoso.onmicrosoft.com');
  });

  it('should throw on failed profile fetch', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      text: () => Promise.resolve('Unauthorized'),
    });

    await expect(provider.getUserProfile({ accessToken: 'bad', expiresIn: 3600, tokenType: 'Bearer' }))
      .rejects.toThrow('Microsoft user profile request failed');
  });

  it('should include default scopes in auth URL', () => {
    const url = provider.getAuthorizationUrl('state', 'http://localhost/cb');
    expect(url).toContain('openid');
    expect(url).toContain('email');
    expect(url).toContain('profile');
  });
});
