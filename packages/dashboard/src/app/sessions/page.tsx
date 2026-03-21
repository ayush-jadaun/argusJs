'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

export default function SessionsPage() {
  const [sessions, setSessions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchSessions = () => {
    setLoading(true);
    api.getSessions()
      .then(data => setSessions(data.sessions || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchSessions(); }, []);

  const handleRevoke = async (id: string) => {
    try {
      await api.revokeSession(id);
      fetchSessions();
    } catch {
      // ignore
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold">Sessions</h1>
        <button
          onClick={fetchSessions}
          className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700 transition-colors"
        >
          Refresh
        </button>
      </div>

      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">User</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">IP Address</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">User Agent</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Created</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Expires</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-gray-500">Loading...</td>
              </tr>
            ) : sessions.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-gray-500">No active sessions</td>
              </tr>
            ) : (
              sessions.map(session => (
                <tr key={session.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-3 text-sm">{session.userId}</td>
                  <td className="px-4 py-3 text-sm font-mono">{session.ipAddress || '-'}</td>
                  <td className="px-4 py-3 text-sm max-w-xs truncate">{session.userAgent || '-'}</td>
                  <td className="px-4 py-3 text-sm">{session.createdAt ? new Date(session.createdAt).toLocaleString() : '-'}</td>
                  <td className="px-4 py-3 text-sm">{session.expiresAt ? new Date(session.expiresAt).toLocaleString() : '-'}</td>
                  <td className="px-4 py-3 text-sm">
                    <button
                      onClick={() => handleRevoke(session.id)}
                      className="text-red-400 hover:text-red-300"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
