'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

interface LockedUser {
  id: string;
  email: string;
  displayName: string;
  lockedUntil: string;
  failedLoginAttempts: number;
}

interface SecurityStats {
  totalUsers: number;
  activeSessions: number;
  lockedAccounts: number;
  mfaAdoptionRate: number;
}

interface AuditEntry {
  id: string;
  userId: string | null;
  action: string;
  ipAddress: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export default function SecurityPage() {
  const [stats, setStats] = useState<SecurityStats | null>(null);
  const [lockedUsers, setLockedUsers] = useState<LockedUser[]>([]);
  const [recentBlocked, setRecentBlocked] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [statsData, usersData, auditData] = await Promise.all([
        api.getStats().catch(() => ({ stats: null })),
        api.getUsers({ locked: 'true', limit: '50' }).catch(() => ({ users: [] })),
        api.getAuditLog({ action: 'LOGIN_FAILED', limit: '20' }).catch(() => ({ entries: [] })),
      ]);

      if (statsData.stats) setStats(statsData.stats);
      setLockedUsers(
        (usersData.users || []).filter((u: any) => u.lockedUntil && new Date(u.lockedUntil) > new Date())
      );
      setRecentBlocked(auditData.entries || []);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const handleUnlock = async (userId: string) => {
    try {
      await api.unlockUser(userId);
      setLockedUsers(prev => prev.filter(u => u.id !== userId));
      fetchData();
    } catch {
      // ignore
    }
  };

  // Aggregate blocked IPs from audit data
  const ipCounts: Record<string, number> = {};
  for (const entry of recentBlocked) {
    if (entry.ipAddress) {
      ipCounts[entry.ipAddress] = (ipCounts[entry.ipAddress] || 0) + 1;
    }
  }
  const topIPs = Object.entries(ipCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10);

  // Group blocked requests by hour for the chart
  const hourCounts: Record<string, number> = {};
  for (const entry of recentBlocked) {
    const hour = entry.createdAt?.slice(0, 13) ?? 'unknown';
    hourCounts[hour] = (hourCounts[hour] || 0) + 1;
  }
  const chartData = Object.entries(hourCounts)
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(-12);

  if (loading) {
    return (
      <div>
        <h1 className="text-3xl font-bold mb-6">Security</h1>
        <p className="text-gray-400">Loading...</p>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-3xl font-bold mb-6">Security</h1>

      {/* Security Engine Status */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <div className="text-sm text-gray-400 mb-1">Total Users</div>
          <div className="text-2xl font-bold">{stats?.totalUsers ?? 0}</div>
        </div>
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <div className="text-sm text-gray-400 mb-1">Active Sessions</div>
          <div className="text-2xl font-bold">{stats?.activeSessions ?? 0}</div>
        </div>
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <div className="text-sm text-gray-400 mb-1">Locked Accounts</div>
          <div className="text-2xl font-bold text-red-400">{stats?.lockedAccounts ?? lockedUsers.length}</div>
        </div>
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
          <div className="text-sm text-gray-400 mb-1">MFA Adoption</div>
          <div className="text-2xl font-bold text-green-400">{stats?.mfaAdoptionRate ?? 0}%</div>
        </div>
      </div>

      {/* Blocked Requests Over Time (simple bar chart) */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4">Failed Login Attempts Over Time</h2>
        {chartData.length === 0 ? (
          <p className="text-gray-500 text-sm">No failed login data available.</p>
        ) : (
          <div className="flex items-end gap-2 h-32">
            {chartData.map(([hour, count]) => {
              const maxCount = Math.max(...chartData.map(([, c]) => c));
              const height = maxCount > 0 ? (count / maxCount) * 100 : 0;
              return (
                <div key={hour} className="flex flex-col items-center flex-1">
                  <div className="text-xs text-gray-400 mb-1">{count}</div>
                  <div
                    className="w-full bg-red-500/60 rounded-t"
                    style={{ height: `${height}%`, minHeight: count > 0 ? '4px' : '0' }}
                  />
                  <div className="text-xs text-gray-600 mt-1 truncate w-full text-center">
                    {hour.slice(11) || hour.slice(5, 10)}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Top Rate-Limited IPs */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4">Top Blocked IPs</h2>
        {topIPs.length === 0 ? (
          <p className="text-gray-500 text-sm">No blocked IPs recorded.</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">IP Address</th>
                <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">Failed Attempts</th>
                <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">Risk</th>
              </tr>
            </thead>
            <tbody>
              {topIPs.map(([ip, count]) => (
                <tr key={ip} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-2 text-sm font-mono">{ip}</td>
                  <td className="px-4 py-2 text-sm">{count}</td>
                  <td className="px-4 py-2 text-sm">
                    {count >= 10 ? (
                      <span className="text-red-400 font-medium">High</span>
                    ) : count >= 5 ? (
                      <span className="text-yellow-400 font-medium">Medium</span>
                    ) : (
                      <span className="text-green-400">Low</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Locked Accounts */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <h2 className="text-xl font-semibold mb-4">Locked Accounts</h2>
        {lockedUsers.length === 0 ? (
          <p className="text-gray-500 text-sm">No locked accounts.</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">Email</th>
                <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">Name</th>
                <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">Failed Attempts</th>
                <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">Locked Until</th>
                <th className="text-left px-4 py-2 text-sm font-medium text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody>
              {lockedUsers.map(user => (
                <tr key={user.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-2 text-sm">{user.email}</td>
                  <td className="px-4 py-2 text-sm">{user.displayName}</td>
                  <td className="px-4 py-2 text-sm">{user.failedLoginAttempts}</td>
                  <td className="px-4 py-2 text-sm text-red-400">
                    {new Date(user.lockedUntil).toLocaleString()}
                  </td>
                  <td className="px-4 py-2 text-sm">
                    <button
                      onClick={() => handleUnlock(user.id)}
                      className="px-3 py-1 bg-blue-600 hover:bg-blue-500 rounded text-sm text-white"
                    >
                      Unlock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
