'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

export default function UsersPage() {
  const [users, setUsers] = useState<any[]>([]);
  const [search, setSearch] = useState('');
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);

  useEffect(() => {
    api.getUsers({ search, limit: '20', offset: String(page * 20) })
      .then(data => {
        setUsers(data.users || []);
        setTotal(data.total || 0);
      })
      .catch(() => {});
  }, [search, page]);

  return (
    <div>
      <h1 className="text-3xl font-bold mb-6">Users</h1>

      <input
        type="text"
        placeholder="Search by email or name..."
        value={search}
        onChange={(e) => { setSearch(e.target.value); setPage(0); }}
        className="w-full max-w-md mb-6 px-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
      />

      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Email</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Name</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Verified</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">MFA</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Roles</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Status</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-400">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="px-4 py-3 text-sm">{user.email}</td>
                <td className="px-4 py-3 text-sm">{user.displayName}</td>
                <td className="px-4 py-3 text-sm">{user.emailVerified ? '\u2713' : '\u2717'}</td>
                <td className="px-4 py-3 text-sm">{user.mfaEnabled ? '\u2713' : '\u2014'}</td>
                <td className="px-4 py-3 text-sm">{user.roles?.join(', ')}</td>
                <td className="px-4 py-3 text-sm">
                  {user.lockedUntil && new Date(user.lockedUntil) > new Date() ? (
                    <span className="text-red-400">Locked</span>
                  ) : (
                    <span className="text-green-400">Active</span>
                  )}
                </td>
                <td className="px-4 py-3 text-sm">
                  <a href={`/users/${user.id}`} className="text-blue-400 hover:text-blue-300">View</a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex gap-4 mt-4">
        <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
          className="px-4 py-2 bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-50">
          Previous
        </button>
        <span className="py-2 text-gray-400">
          Page {page + 1} of {Math.ceil(total / 20) || 1} ({total} users)
        </span>
        <button onClick={() => setPage(p => p + 1)} disabled={(page + 1) * 20 >= total}
          className="px-4 py-2 bg-gray-800 rounded hover:bg-gray-700 disabled:opacity-50">
          Next
        </button>
      </div>
    </div>
  );
}
