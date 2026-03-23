const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3100';

async function apiRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = typeof window !== 'undefined' ? localStorage.getItem('argus_admin_token') : null;
  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error?.error?.message || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  // Auth
  login: (email: string, password: string) =>
    apiRequest<any>('/v1/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),

  // Users
  getUsers: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return apiRequest<any>(`/v1/admin/users${qs}`);
  },
  getUser: (id: string) => apiRequest<any>(`/v1/admin/users/${id}`),
  updateUser: (id: string, data: any) =>
    apiRequest<any>(`/v1/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteUser: (id: string) =>
    apiRequest<void>(`/v1/admin/users/${id}`, { method: 'DELETE' }),
  unlockUser: (id: string) =>
    apiRequest<void>(`/v1/admin/users/${id}/unlock`, { method: 'POST' }),

  // Sessions
  getSessions: () => apiRequest<any>('/v1/admin/sessions'),
  revokeSession: (id: string) =>
    apiRequest<void>(`/v1/admin/sessions/${id}`, { method: 'DELETE' }),

  // Audit
  getAuditLog: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return apiRequest<any>(`/v1/admin/audit-log${qs}`);
  },

  // Stats
  getStats: () => apiRequest<any>('/v1/admin/stats'),

  // Webhooks
  getWebhooks: () => apiRequest<any>('/v1/admin/webhooks'),
  createWebhook: (data: { url: string; events: string[] }) =>
    apiRequest<any>('/v1/admin/webhooks', { method: 'POST', body: JSON.stringify(data) }),
  updateWebhook: (id: string, data: any) =>
    apiRequest<any>(`/v1/admin/webhooks/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteWebhook: (id: string) =>
    apiRequest<void>(`/v1/admin/webhooks/${id}`, { method: 'DELETE' }),
  testWebhook: (id: string) =>
    apiRequest<any>(`/v1/admin/webhooks/${id}/test`, { method: 'POST' }),

  // Health
  getHealth: () => apiRequest<any>('/v1/health'),
};
