import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { CustomOAuth } from '../custom-oauth.js';

describe('CustomOAuth', () => {
  const originalFetch = globalThis.fetch;

  const discoveryDoc = {
    issuer: 'https://idp.example.com',
    authorization_endpoint: 'https://idp.example.com/authorize',
    token_endpoint: 'https://idp.example.com/token',
    userinfo_endpoint: 'https://idp.example.com/userinfo',
    jwks_uri: 'https://idp.example.com/.well-known/jwks.json',
  };

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function createProvider(name?: string) {
    return new CustomOAuth({
      name: name ?? 'myidp',
      discoveryUrl: 'https://idp.example.com',
      clientId: 'custom-id',
      clientSecret: 'custom-secret',
    });
  }

  async function initProvider(provider: CustomOAuth) {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(discoveryDoc),
    });
    await provider.init();
  }

  it('should have configurable name', () => {
    const provider = createProvider('keycloak');
    expect(provider.name).toBe('keycloak');
  });

  it('should default to name custom', () => {
    const provider = new CustomOAuth({
      discoveryUrl: 'https://idp.example.com',
      clientId: 'id',
      clientSecret: 'secret',
    });
    expect(provider.name).toBe('custom');
  });

  it('should fetch discovery document on init', async () => {
    const provider = createProvider();
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(discoveryDoc),
    });

    await provider.init();

    const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[0]).toContain('.well-known/openid-configuration');
  });

  it('should throw if init fails', async () => {
    const provider = createProvider();
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      text: () => Promise.resolve('Not Found'),
    });

    await expect(provider.init()).rejects.toThrow('OIDC discovery failed');
  });

  it('should throw if used before init', () => {
    const provider = createProvider();
    expect(() => provider.getAuthorizationUrl('state', 'http://localhost/cb'))
      .toThrow('init() must be called');
  });

  it('should generate authorization URL after init', async () => {
    const provider = createProvider();
    await initProvider(provider);

    const url = provider.getAuthorizationUrl('state123', 'http://localhost/cb');
    expect(url).toContain('idp.example.com/authorize');
    expect(url).toContain('client_id=custom-id');
    expect(url).toContain('state=state123');
    expect(url).toContain('response_type=code');
  });

  it('should include PKCE in auth URL when provided', async () => {
    const provider = createProvider();
    await initProvider(provider);

    const url = provider.getAuthorizationUrl('state', 'http://localhost/cb', 'challenge123');
    expect(url).toContain('code_challenge=challenge123');
    expect(url).toContain('code_challenge_method=S256');
  });

  it('should not include PKCE params when no challenge provided', async () => {
    const provider = createProvider();
    await initProvider(provider);

    const url = provider.getAuthorizationUrl('state', 'http://localhost/cb');
    expect(url).not.toContain('code_challenge');
    expect(url).not.toContain('code_challenge_method');
  });

  it('should exchange code for tokens', async () => {
    const provider = createProvider();
    await initProvider(provider);

    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'custom_at',
        refresh_token: 'custom_rt',
        id_token: 'custom_idt',
        expires_in: 3600,
        token_type: 'Bearer',
      }),
    });

    const tokens = await provider.exchangeCode('code123', 'http://localhost/cb');
    expect(tokens.accessToken).toBe('custom_at');
    expect(tokens.refreshToken).toBe('custom_rt');
    expect(tokens.expiresIn).toBe(3600);
  });

  it('should pass code verifier when exchanging code', async () => {
    const provider = createProvider();
    await initProvider(provider);

    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'at',
        expires_in: 3600,
        token_type: 'Bearer',
      }),
    });

    await provider.exchangeCode('code', 'http://localhost/cb', 'verifier123');

    const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = call[1].body as string;
    expect(body).toContain('code_verifier=verifier123');
  });

  it('should throw on failed token exchange', async () => {
    const provider = createProvider();
    await initProvider(provider);

    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      text: () => Promise.resolve('invalid_grant'),
    });

    await expect(provider.exchangeCode('bad', 'http://localhost/cb'))
      .rejects.toThrow('token exchange failed');
  });

  it('should get user profile from userinfo endpoint', async () => {
    const provider = createProvider();
    await initProvider(provider);

    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        sub: 'user-123',
        email: 'user@example.com',
        name: 'Custom User',
        picture: 'http://photo.jpg',
      }),
    });

    const profile = await provider.getUserProfile({ accessToken: 'at', expiresIn: 3600, tokenType: 'Bearer' });
    expect(profile.id).toBe('user-123');
    expect(profile.email).toBe('user@example.com');
    expect(profile.displayName).toBe('Custom User');
    expect(profile.avatarUrl).toBe('http://photo.jpg');
    expect(profile.raw).toBeDefined();
  });

  it('should fall back to preferred_username when name is missing', async () => {
    const provider = createProvider();
    await initProvider(provider);

    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        sub: 'user-456',
        email: 'user@example.com',
        preferred_username: 'jdoe',
      }),
    });

    const profile = await provider.getUserProfile({ accessToken: 'at', expiresIn: 3600, tokenType: 'Bearer' });
    expect(profile.displayName).toBe('jdoe');
  });

  it('should throw on failed profile fetch', async () => {
    const provider = createProvider();
    await initProvider(provider);

    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      text: () => Promise.resolve('Unauthorized'),
    });

    await expect(provider.getUserProfile({ accessToken: 'bad', expiresIn: 3600, tokenType: 'Bearer' }))
      .rejects.toThrow('userinfo request failed');
  });
});
