import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ArgusClient } from '../argus-client.js';

// Mock global fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('ArgusClient', () => {
  let client: ArgusClient;

  beforeEach(() => {
    mockFetch.mockReset();
    client = new ArgusClient({ baseUrl: 'http://localhost:3100' });
  });

  it('should register and store tokens', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 201,
      json: async () => ({ user: { id: '1', email: 'a@b.com' }, accessToken: 'at', refreshToken: 'rt', expiresIn: 900, tokenType: 'Bearer' }),
    });
    const res = await client.register({ email: 'a@b.com', password: 'pass', displayName: 'A' });
    expect(res.accessToken).toBe('at');
    expect(client.isAuthenticated()).toBe(true);
    expect(client.getAccessToken()).toBe('at');
  });

  it('should login and detect MFA challenge', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      json: async () => ({ mfaRequired: true, mfaToken: 'mfa-tok', mfaMethods: ['totp'], expiresIn: 300 }),
    });
    const res = await client.login('a@b.com', 'pass');
    expect((res as any).mfaRequired).toBe(true);
    expect(client.isAuthenticated()).toBe(false); // no token stored yet
  });

  it('should deduplicate concurrent refresh calls', async () => {
    // First register to store tokens
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 201,
      json: async () => ({ user: { id: '1' }, accessToken: 'at1', refreshToken: 'rt1', expiresIn: 900, tokenType: 'Bearer' }),
    });
    await client.register({ email: 'a@b.com', password: 'pass', displayName: 'A' });

    // Now mock refresh endpoint
    let callCount = 0;
    mockFetch.mockImplementation(async () => {
      callCount++;
      await new Promise(r => setTimeout(r, 50)); // simulate delay
      return {
        ok: true, status: 200,
        json: async () => ({ user: { id: '1' }, accessToken: 'at2', refreshToken: 'rt2', expiresIn: 900, tokenType: 'Bearer' }),
      };
    });

    // Fire 5 concurrent refreshes
    const promises = Array.from({ length: 5 }, () => client.refresh());
    await Promise.all(promises);

    // Only ONE actual HTTP call should have been made (deduplication)
    expect(callCount).toBe(1);
  });

  it('should clear tokens on logout', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 201,
      json: async () => ({ user: { id: '1' }, accessToken: 'at', refreshToken: 'rt', expiresIn: 900, tokenType: 'Bearer' }),
    });
    await client.register({ email: 'a@b.com', password: 'pass', displayName: 'A' });
    expect(client.isAuthenticated()).toBe(true);

    mockFetch.mockResolvedValueOnce({ ok: true, status: 204, json: async () => {} });
    await client.logout();
    expect(client.isAuthenticated()).toBe(false);
  });

  it('should throw on unauthenticated protected call', async () => {
    await expect(client.getProfile()).rejects.toThrow('Not authenticated');
  });

  it('should handle API errors', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false, status: 401,
      json: async () => ({ error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password', statusCode: 401 } }),
    });
    await expect(client.login('a@b.com', 'wrong')).rejects.toThrow('Invalid email or password');
  });

  it('should call onAuthError callback', async () => {
    const onAuthError = vi.fn();
    const c = new ArgusClient({ baseUrl: 'http://localhost:3100', onAuthError });
    mockFetch.mockResolvedValueOnce({
      ok: false, status: 401,
      json: async () => ({ error: { code: 'INVALID_CREDENTIALS', message: 'Bad', statusCode: 401 } }),
    });
    await c.login('a@b.com', 'wrong').catch(() => {});
    expect(onAuthError).toHaveBeenCalledTimes(1);
  });

  it('should send forgot-password without auth', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({}) });
    await client.forgotPassword('a@b.com');
    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:3100/v1/auth/forgot-password',
      expect.objectContaining({ method: 'POST' }),
    );
  });
});
