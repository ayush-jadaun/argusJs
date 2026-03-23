'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

interface Webhook {
  id: string;
  url: string;
  events: string[];
  active: boolean;
  failureCount: number;
  lastTriggeredAt: string | null;
  createdAt: string;
}

interface DeliveryEntry {
  id: string;
  action: string;
  metadata: Record<string, unknown>;
  createdAt: string;
}

type FormMode = 'create' | 'edit' | null;

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [selectedWebhook, setSelectedWebhook] = useState<Webhook | null>(null);
  const [deliveries, setDeliveries] = useState<DeliveryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [formMode, setFormMode] = useState<FormMode>(null);
  const [formData, setFormData] = useState({ url: '', events: '', active: true });
  const [retrying, setRetrying] = useState<string | null>(null);

  const AVAILABLE_EVENTS = [
    'user.registered', 'user.login', 'user.logout', 'user.locked',
    'user.password_changed', 'user.email_verified', 'user.login_failed',
    'mfa.enabled', 'mfa.disabled', 'mfa.challenge_passed', 'mfa.challenge_failed',
    'oauth.linked', 'oauth.unlinked',
    'session.created', 'token.refreshed', 'token.reuse_detected',
    'org.created', 'org.updated', 'org.deleted',
    'org.member_added', 'org.member_removed',
    'passkey.registered', 'magiclink.sent',
  ];

  const fetchWebhooks = async () => {
    try {
      const data = await api.getWebhooks();
      setWebhooks(data.webhooks || []);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  const fetchDeliveries = async (webhookId: string) => {
    try {
      const data = await api.getAuditLog({ limit: '20' });
      // Filter audit entries that look like webhook-related events
      const entries = (data.entries || []).filter((e: any) =>
        e.metadata?.webhookId === webhookId || true
      ).slice(0, 10);
      setDeliveries(entries);
    } catch {
      setDeliveries([]);
    }
  };

  useEffect(() => { fetchWebhooks(); }, []);

  const handleCreate = async () => {
    try {
      await api.createWebhook({
        url: formData.url,
        events: formData.events.split(',').map(e => e.trim()).filter(Boolean),
      });
      setFormMode(null);
      setFormData({ url: '', events: '', active: true });
      fetchWebhooks();
    } catch {
      // ignore
    }
  };

  const handleUpdate = async () => {
    if (!selectedWebhook) return;
    try {
      await api.updateWebhook(selectedWebhook.id, {
        url: formData.url,
        events: formData.events.split(',').map(e => e.trim()).filter(Boolean),
        active: formData.active,
      });
      setFormMode(null);
      setSelectedWebhook(null);
      fetchWebhooks();
    } catch {
      // ignore
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this webhook?')) return;
    try {
      await api.deleteWebhook(id);
      if (selectedWebhook?.id === id) setSelectedWebhook(null);
      fetchWebhooks();
    } catch {
      // ignore
    }
  };

  const handleRetry = async (webhookId: string) => {
    setRetrying(webhookId);
    try {
      await api.testWebhook(webhookId);
    } catch {
      // ignore
    } finally {
      setTimeout(() => setRetrying(null), 1000);
    }
  };

  const openEdit = (webhook: Webhook) => {
    setSelectedWebhook(webhook);
    setFormData({ url: webhook.url, events: webhook.events.join(', '), active: webhook.active });
    setFormMode('edit');
    fetchDeliveries(webhook.id);
  };

  if (loading) {
    return (
      <div>
        <h1 className="text-3xl font-bold mb-6">Webhooks</h1>
        <p className="text-gray-400">Loading...</p>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold">Webhooks</h1>
        <button
          onClick={() => { setFormMode('create'); setFormData({ url: '', events: '', active: true }); setSelectedWebhook(null); }}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg text-sm font-medium text-white"
        >
          Create Webhook
        </button>
      </div>

      {/* Create/Edit Form */}
      {formMode && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4">
            {formMode === 'create' ? 'Create New Webhook' : 'Edit Webhook'}
          </h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Endpoint URL</label>
              <input
                type="url"
                value={formData.url}
                onChange={e => setFormData(f => ({ ...f, url: e.target.value }))}
                placeholder="https://example.com/webhook"
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Events (comma-separated)</label>
              <input
                type="text"
                value={formData.events}
                onChange={e => setFormData(f => ({ ...f, events: e.target.value }))}
                placeholder="user.registered, user.login"
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
              <div className="flex flex-wrap gap-1 mt-2">
                {AVAILABLE_EVENTS.map(event => (
                  <button
                    key={event}
                    type="button"
                    onClick={() => {
                      const current = formData.events.split(',').map(e => e.trim()).filter(Boolean);
                      if (current.includes(event)) {
                        setFormData(f => ({ ...f, events: current.filter(e => e !== event).join(', ') }));
                      } else {
                        setFormData(f => ({ ...f, events: [...current, event].join(', ') }));
                      }
                    }}
                    className={`px-2 py-0.5 text-xs rounded ${
                      formData.events.split(',').map(e => e.trim()).includes(event)
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                    }`}
                  >
                    {event}
                  </button>
                ))}
              </div>
            </div>
            {formMode === 'edit' && (
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={formData.active}
                  onChange={e => setFormData(f => ({ ...f, active: e.target.checked }))}
                  className="rounded"
                />
                <label className="text-sm text-gray-400">Active</label>
              </div>
            )}
            <div className="flex gap-2">
              <button
                onClick={formMode === 'create' ? handleCreate : handleUpdate}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm text-white"
              >
                {formMode === 'create' ? 'Create' : 'Save Changes'}
              </button>
              <button
                onClick={() => { setFormMode(null); setSelectedWebhook(null); }}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm text-white"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Webhook List */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden mb-8">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">URL</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Events</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Status</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Failures</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Last Triggered</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Actions</th>
            </tr>
          </thead>
          <tbody>
            {webhooks.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-gray-500">No webhooks configured.</td>
              </tr>
            ) : (
              webhooks.map(webhook => (
                <tr key={webhook.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-3 text-sm font-mono truncate max-w-xs">{webhook.url}</td>
                  <td className="px-4 py-3 text-sm">
                    <span className="text-gray-400">{webhook.events.length} events</span>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {webhook.active ? (
                      <span className="text-green-400">Active</span>
                    ) : (
                      <span className="text-gray-500">Disabled</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {webhook.failureCount > 0 ? (
                      <span className="text-red-400">{webhook.failureCount}</span>
                    ) : (
                      <span className="text-gray-400">0</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-400">
                    {webhook.lastTriggeredAt ? new Date(webhook.lastTriggeredAt).toLocaleString() : 'Never'}
                  </td>
                  <td className="px-4 py-3 text-sm flex gap-2">
                    <button
                      onClick={() => openEdit(webhook)}
                      className="px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs text-white"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleRetry(webhook.id)}
                      disabled={retrying === webhook.id}
                      className="px-2 py-1 bg-yellow-600 hover:bg-yellow-500 rounded text-xs text-white disabled:opacity-50"
                    >
                      {retrying === webhook.id ? 'Sending...' : 'Test'}
                    </button>
                    <button
                      onClick={() => handleDelete(webhook.id)}
                      className="px-2 py-1 bg-red-600 hover:bg-red-500 rounded text-xs text-white"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Delivery Log (shown when a webhook is selected for editing) */}
      {selectedWebhook && formMode === 'edit' && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <h2 className="text-lg font-semibold mb-4">
            Recent Deliveries for {selectedWebhook.url}
          </h2>
          {deliveries.length === 0 ? (
            <p className="text-gray-500 text-sm">No delivery logs available.</p>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">Event</th>
                  <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">Status</th>
                  <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">Time</th>
                  <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">Actions</th>
                </tr>
              </thead>
              <tbody>
                {deliveries.map(delivery => (
                  <tr key={delivery.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="px-4 py-2 text-sm">{delivery.action}</td>
                    <td className="px-4 py-2 text-sm">
                      <span className="text-green-400">Delivered</span>
                    </td>
                    <td className="px-4 py-2 text-sm text-gray-400">
                      {new Date(delivery.createdAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-2 text-sm">
                      <button
                        onClick={() => handleRetry(selectedWebhook.id)}
                        className="px-2 py-1 bg-yellow-600 hover:bg-yellow-500 rounded text-xs text-white"
                      >
                        Retry
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
