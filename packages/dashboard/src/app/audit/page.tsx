'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

export default function AuditLogPage() {
  const [entries, setEntries] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [filterAction, setFilterAction] = useState('');
  const [filterUserId, setFilterUserId] = useState('');

  useEffect(() => {
    const params: Record<string, string> = {
      limit: '30',
      offset: String(page * 30),
    };
    if (filterAction) params.action = filterAction;
    if (filterUserId) params.userId = filterUserId;

    api.getAuditLog(params)
      .then(data => {
        setEntries(data.entries || []);
        setTotal(data.total || 0);
      })
      .catch(() => {});
  }, [page, filterAction, filterUserId]);

  return (
    <div>
      <h1 className="text-3xl font-bold mb-6">Audit Log</h1>

      <div className="flex gap-4 mb-6">
        <input
          type="text"
          placeholder="Filter by action..."
          value={filterAction}
          onChange={(e) => { setFilterAction(e.target.value); setPage(0); }}
          className="px-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        <input
          type="text"
          placeholder="Filter by user ID..."
          value={filterUserId}
          onChange={(e) => { setFilterUserId(e.target.value); setPage(0); }}
          className="px-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
      </div>

      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Timestamp</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Action</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">User ID</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">IP Address</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Details</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500">No audit log entries</td>
              </tr>
            ) : (
              entries.map((entry, i) => (
                <tr key={entry.id || i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-3 text-sm font-mono">
                    {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '-'}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <span className="px-2 py-1 bg-gray-800 rounded text-xs font-mono">{entry.action}</span>
                  </td>
                  <td className="px-4 py-3 text-sm font-mono">{entry.userId || '-'}</td>
                  <td className="px-4 py-3 text-sm font-mono">{entry.ipAddress || '-'}</td>
                  <td className="px-4 py-3 text-sm max-w-xs truncate text-gray-400">
                    {entry.details ? JSON.stringify(entry.details) : '-'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex gap-4 mt-4">
        <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
          className="px-4 py-2 bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-50">
          Previous
        </button>
        <span className="py-2 text-gray-400">
          Page {page + 1} of {Math.ceil(total / 30) || 1} ({total} entries)
        </span>
        <button onClick={() => setPage(p => p + 1)} disabled={(page + 1) * 30 >= total}
          className="px-4 py-2 bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-50">
          Next
        </button>
      </div>
    </div>
  );
}
