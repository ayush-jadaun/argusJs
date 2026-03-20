import { describe, it, expect, vi, afterEach } from 'vitest';
import { GitHubOAuth } from '../github-oauth.js';

describe('GitHubOAuth', () => {
  const provider = new GitHubOAuth({ clientId: 'gh-id', clientSecret: 'gh-secret' });
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('should have name github', () => {
    expect(provider.name).toBe('github');
  });

  it('should generate authorization URL', () => {
    const url = provider.getAuthorizationUrl('state123', 'http://localhost:3000/callback');
    expect(url).toContain('github.com/login/oauth/authorize');
    expect(url).toContain('client_id=gh-id');
    expect(url).toContain('state=state123');
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
        access_token: 'gho_abc',
        token_type: 'bearer',
        scope: 'user:email',
      }),
    });

    const tokens = await provider.exchangeCode('code123', 'http://localhost/cb');
    expect(tokens.accessToken).toBe('gho_abc');
    expect(tokens.tokenType).toBe('bearer');
  });

  it('should pass code verifier when exchanging code', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        access_token: 'gho_abc',
        token_type: 'bearer',
      }),
    });

    await provider.exchangeCode('code123', 'http://localhost/cb', 'verifier123');

    const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(call[1].body as string);
    expect(body.code_verifier).toBe('verifier123');
  });

  it('should throw on error response from token exchange', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        error: 'bad_verification_code',
        error_description: 'The code passed is incorrect',
      }),
    });

    await expect(provider.exchangeCode('bad', 'http://localhost/cb'))
      .rejects.toThrow('GitHub token exchange failed');
  });

  it('should throw on HTTP error from token exchange', async () => {
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      text: () => Promise.resolve('server error'),
    });

    await expect(provider.exchangeCode('bad', 'http://localhost/cb'))
      .rejects.toThrow('GitHub token exchange failed');
  });

  it('should get user profile with primary email', async () => {
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          id: 456,
          login: 'alice',
          name: 'Alice Smith',
          avatar_url: 'http://avatar.jpg',
          email: null,
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([
          { email: 'alice@work.com', primary: false, verified: true },
          { email: 'alice@gmail.com', primary: true, verified: true },
        ]),
      });

    const profile = await provider.getUserProfile({ accessToken: 'at', expiresIn: 0, tokenType: 'bearer' });
    expect(profile.id).toBe('456');
    expect(profile.email).toBe('alice@gmail.com');
    expect(profile.displayName).toBe('Alice Smith');
    expect(profile.avatarUrl).toBe('http://avatar.jpg');
  });

  it('should fall back to login for display name', async () => {
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          id: 789,
          login: 'bob',
          name: null,
          email: 'bob@example.com',
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([]),
      });

    const profile = await provider.getUserProfile({ accessToken: 'at', expiresIn: 0, tokenType: 'bearer' });
    expect(profile.displayName).toBe('bob');
  });

  it('should throw on failed profile fetch', async () => {
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce({
        ok: false,
        text: () => Promise.resolve('Unauthorized'),
      });

    await expect(provider.getUserProfile({ accessToken: 'bad', expiresIn: 0, tokenType: 'bearer' }))
      .rejects.toThrow('GitHub user request failed');
  });
});
