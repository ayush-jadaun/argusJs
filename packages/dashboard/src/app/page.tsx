'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

interface Stats {
  totalUsers: number;
  activeUsers: number;
  totalSessions: number;
  activeSessions: number;
  mfaAdoptionRate: number;
  lockedAccounts: number;
}

export default function OverviewPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [health, setHealth] = useState<any>(null);

  useEffect(() => {
    api.getStats().then(setStats).catch(() => {});
    api.getHealth().then(setHealth).catch(() => {});
  }, []);

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8">Dashboard Overview</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        <StatCard title="Total Users" value={stats?.totalUsers ?? '-'} />
        <StatCard title="Active Sessions" value={stats?.activeSessions ?? '-'} />
        <StatCard title="MFA Adoption" value={stats?.mfaAdoptionRate ? `${(stats.mfaAdoptionRate * 100).toFixed(1)}%` : '-'} />
        <StatCard title="Locked Accounts" value={stats?.lockedAccounts ?? '-'} alert={stats?.lockedAccounts ? stats.lockedAccounts > 0 : false} />
        <StatCard title="Server Status" value={health?.status === 'ok' ? 'Healthy' : 'Unknown'} />
        <StatCard title="Active Users (24h)" value={stats?.activeUsers ?? '-'} />
      </div>
    </div>
  );
}

function StatCard({ title, value, alert }: { title: string; value: string | number; alert?: boolean }) {
  return (
    <div className={`rounded-xl p-6 ${alert ? 'bg-red-900/30 border border-red-800' : 'bg-gray-900 border border-gray-800'}`}>
      <p className="text-sm text-gray-400 mb-1">{title}</p>
      <p className="text-2xl font-bold">{value}</p>
    </div>
  );
}
