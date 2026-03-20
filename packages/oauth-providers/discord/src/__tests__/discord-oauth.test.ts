import { describe, it, expect, vi, afterEach } from 'vitest';
import { DiscordOAuth } from '../discord-oauth.js';

describe('DiscordOAuth', () => {
  const provider = new DiscordOAuth({ clientId: 'dc-id', clientSecret: 'dc-secret' });
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('should have name discord', () => {
    expect(provider.name).toBe('discord');
  });

  it('should generate authorization URL', () => {
    const url = provider.getAuthorizationUrl('state123', 'http://localhost:3000/callback');
    expect(url).toContain('discord.com/oauth2/authorize');
    expect(url).toContain('client_id=dc-id');
    expect(url).toContain('state=state123');
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
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'dc_at',
        refresh_token: 'dc_rt',
        expires_in: 604800,
        token_type: 'Bearer',
        scope: 'identify email',
      }),
    });

    const tokens = await provider.exchangeCode('code123', 'http://localhost/cb');
    expect(tokens.accessToken).toBe('dc_at');
    expect(tokens.refreshToken).toBe('dc_rt');
    expect(tokens.expiresIn).toBe(604800);
    expect(tokens.tokenType).toBe('Bearer');
  });

  it('should pass code verifier when exchanging code', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'dc_at',
        expires_in: 604800,
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
      .rejects.toThrow('Discord token exchange failed');
  });

  it('should get user profile', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        id: '123456789',
        username: 'alice',
        global_name: 'Alice Smith',
        email: 'alice@example.com',
        avatar: 'abc123',
      }),
    });

    const profile = await provider.getUserProfile({ accessToken: 'at', expiresIn: 3600, tokenType: 'Bearer' });
    expect(profile.id).toBe('123456789');
    expect(profile.email).toBe('alice@example.com');
    expect(profile.displayName).toBe('Alice Smith');
    expect(profile.avatarUrl).toBe('https://cdn.discordapp.com/avatars/123456789/abc123.png');
    expect(profile.raw).toBeDefined();
  });

  it('should fall back to username when global_name is null', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        id: '987',
        username: 'bob',
        global_name: null,
        email: 'bob@example.com',
        avatar: null,
      }),
    });

    const profile = await provider.getUserProfile({ accessToken: 'at', expiresIn: 3600, tokenType: 'Bearer' });
    expect(profile.displayName).toBe('bob');
    expect(profile.avatarUrl).toBeUndefined();
  });

  it('should throw on failed profile fetch', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      text: () => Promise.resolve('Unauthorized'),
    });

    await expect(provider.getUserProfile({ accessToken: 'bad', expiresIn: 3600, tokenType: 'Bearer' }))
      .rejects.toThrow('Discord user profile request failed');
  });

  it('should include default scopes in auth URL', () => {
    const url = provider.getAuthorizationUrl('state', 'http://localhost/cb');
    expect(url).toContain('identify');
    expect(url).toContain('email');
  });
});
