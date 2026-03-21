import type {
  AuthResponse, UserResponse, MFAChallengeResponse, SessionResponse,
  MFASetupData, ErrorResponse,
} from '@argus/core';

export interface ArgusClientConfig {
  baseUrl: string;
  onTokenRefresh?: (tokens: { accessToken: string; refreshToken: string }) => void;
  onAuthError?: (error: ErrorResponse) => void;
  storage?: TokenStorage;
}

export interface TokenStorage {
  getAccessToken(): string | null;
  setAccessToken(token: string): void;
  getRefreshToken(): string | null;
  setRefreshToken(token: string): void;
  clear(): void;
}

// Default in-memory storage
class MemoryTokenStorage implements TokenStorage {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  getAccessToken() { return this.accessToken; }
  setAccessToken(token: string) { this.accessToken = token; }
  getRefreshToken() { return this.refreshToken; }
  setRefreshToken(token: string) { this.refreshToken = token; }
  clear() { this.accessToken = null; this.refreshToken = null; }
}

export class ArgusClient {
  private config: ArgusClientConfig;
  private storage: TokenStorage;
  private refreshPromise: Promise<AuthResponse> | null = null; // deduplication

  constructor(config: ArgusClientConfig) {
    this.config = config;
    this.storage = config.storage ?? new MemoryTokenStorage();
  }

  // ========== Auth ==========

  async register(input: { email: string; password: string; displayName: string }): Promise<AuthResponse> {
    const res = await this.post<AuthResponse>('/v1/auth/register', input);
    this.storeTokens(res);
    return res;
  }

  async login(email: string, password: string): Promise<AuthResponse | MFAChallengeResponse> {
    const res = await this.post<AuthResponse | MFAChallengeResponse>('/v1/auth/login', { email, password });
    if ('accessToken' in res) {
      this.storeTokens(res);
    }
    return res;
  }

  async verifyMFA(input: { mfaToken: string; code: string; method: string }): Promise<AuthResponse> {
    const res = await this.post<AuthResponse>('/v1/auth/mfa/verify', input);
    this.storeTokens(res);
    return res;
  }

  async logout(allDevices = false): Promise<void> {
    await this.postAuth<void>('/v1/auth/logout', { allDevices });
    this.storage.clear();
  }

  async refresh(): Promise<AuthResponse> {
    // Deduplicate concurrent refresh calls
    if (this.refreshPromise) return this.refreshPromise;

    const refreshToken = this.storage.getRefreshToken();
    if (!refreshToken) throw new Error('No refresh token available');

    this.refreshPromise = this.post<AuthResponse>('/v1/auth/refresh', { refreshToken })
      .then(res => {
        this.storeTokens(res);
        this.config.onTokenRefresh?.(res);
        return res;
      })
      .finally(() => { this.refreshPromise = null; });

    return this.refreshPromise;
  }

  // ========== Password ==========

  async forgotPassword(email: string): Promise<void> {
    await this.post('/v1/auth/forgot-password', { email });
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    await this.post('/v1/auth/reset-password', { token, newPassword });
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.postAuth('/v1/auth/change-password', { currentPassword, newPassword });
  }

  // ========== Email Verification ==========

  async verifyEmail(token: string): Promise<void> {
    await this.post('/v1/auth/verify-email', { token });
  }

  async resendVerification(): Promise<void> {
    await this.postAuth('/v1/auth/resend-verification', {});
  }

  // ========== MFA ==========

  async setupMFA(method: string): Promise<MFASetupData> {
    return this.postAuth<MFASetupData>('/v1/auth/mfa/setup', { method });
  }

  async verifyMFASetup(method: string, code: string): Promise<void> {
    await this.postAuth('/v1/auth/mfa/verify-setup', { method, code });
  }

  async disableMFA(code: string): Promise<void> {
    await this.postAuth('/v1/auth/mfa/disable', { code });
  }

  async regenerateBackupCodes(code: string): Promise<{ backupCodes: string[] }> {
    return this.getAuth<{ backupCodes: string[] }>('/v1/auth/mfa/backup-codes');
  }

  // ========== Profile ==========

  async getProfile(): Promise<UserResponse> {
    return this.getAuth<UserResponse>('/v1/auth/me');
  }

  async updateProfile(updates: Partial<{ displayName: string; avatarUrl: string }>): Promise<UserResponse> {
    return this.patchAuth<UserResponse>('/v1/auth/me', updates);
  }

  async deleteAccount(): Promise<void> {
    await this.deleteAuth('/v1/auth/me');
    this.storage.clear();
  }

  async exportData(): Promise<Record<string, unknown>> {
    return this.getAuth('/v1/auth/me/export');
  }

  // ========== Sessions ==========

  async getSessions(): Promise<SessionResponse[]> {
    return this.getAuth<SessionResponse[]>('/v1/auth/sessions');
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.deleteAuth(`/v1/auth/sessions/${sessionId}`);
  }

  // ========== API Keys ==========

  async createApiKey(input: { name: string; permissions: string[] }): Promise<{ key: string; id: string }> {
    return this.postAuth('/v1/auth/api-keys', input);
  }

  async listApiKeys(): Promise<any[]> {
    return this.getAuth('/v1/auth/api-keys');
  }

  async revokeApiKey(id: string): Promise<void> {
    await this.deleteAuth(`/v1/auth/api-keys/${id}`);
  }

  // ========== Helpers ==========

  getAccessToken(): string | null {
    return this.storage.getAccessToken();
  }

  isAuthenticated(): boolean {
    return this.storage.getAccessToken() !== null;
  }

  private storeTokens(res: AuthResponse) {
    this.storage.setAccessToken(res.accessToken);
    this.storage.setRefreshToken(res.refreshToken);
  }

  private async request<T>(method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
    const url = `${this.config.baseUrl}${path}`;
    const opts: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
    };
    if (body !== undefined) {
      opts.body = JSON.stringify(body);
    }

    const res = await fetch(url, opts);

    if (!res.ok) {
      const errorBody = await res.json().catch(() => ({}));
      const error = errorBody as ErrorResponse;
      this.config.onAuthError?.(error);
      throw new Error(error?.error?.message || `HTTP ${res.status}`);
    }

    if (res.status === 204) return undefined as T;
    return res.json() as Promise<T>;
  }

  private post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  private async postAuth<T>(path: string, body: unknown): Promise<T> {
    const token = this.storage.getAccessToken();
    if (!token) throw new Error('Not authenticated');
    try {
      return await this.request<T>('POST', path, body, { Authorization: `Bearer ${token}` });
    } catch (e: any) {
      if (e.message?.includes('401') || e.message?.includes('expired')) {
        await this.refresh();
        const newToken = this.storage.getAccessToken()!;
        return this.request<T>('POST', path, body, { Authorization: `Bearer ${newToken}` });
      }
      throw e;
    }
  }

  private async getAuth<T>(path: string): Promise<T> {
    const token = this.storage.getAccessToken();
    if (!token) throw new Error('Not authenticated');
    try {
      return await this.request<T>('GET', path, undefined, { Authorization: `Bearer ${token}` });
    } catch (e: any) {
      if (e.message?.includes('401') || e.message?.includes('expired')) {
        await this.refresh();
        const newToken = this.storage.getAccessToken()!;
        return this.request<T>('GET', path, undefined, { Authorization: `Bearer ${newToken}` });
      }
      throw e;
    }
  }

  private async patchAuth<T>(path: string, body: unknown): Promise<T> {
    const token = this.storage.getAccessToken();
    if (!token) throw new Error('Not authenticated');
    return this.request<T>('PATCH', path, body, { Authorization: `Bearer ${token}` });
  }

  private async deleteAuth(path: string): Promise<void> {
    const token = this.storage.getAccessToken();
    if (!token) throw new Error('Not authenticated');
    await this.request<void>('DELETE', path, undefined, { Authorization: `Bearer ${token}` });
  }
}
