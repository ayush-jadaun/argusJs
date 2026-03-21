import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'ArgusJS Dashboard',
  description: 'Enterprise Authentication Platform Admin Dashboard',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-gray-950 text-gray-100 min-h-screen">
        <div className="flex min-h-screen">
          <Sidebar />
          <main className="flex-1 p-8 overflow-auto">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}

function Sidebar() {
  const links = [
    { href: '/', label: 'Overview', icon: '\u{1F4CA}' },
    { href: '/users', label: 'Users', icon: '\u{1F465}' },
    { href: '/sessions', label: 'Sessions', icon: '\u{1F510}' },
    { href: '/audit', label: 'Audit Log', icon: '\u{1F4CB}' },
    { href: '/orgs', label: 'Organizations', icon: '\u{1F3E2}' },
    { href: '/roles', label: 'Roles', icon: '\u{1F6E1}\uFE0F' },
    { href: '/security', label: 'Security', icon: '\u26A0\uFE0F' },
    { href: '/webhooks', label: 'Webhooks', icon: '\u{1F517}' },
    { href: '/settings', label: 'Settings', icon: '\u2699\uFE0F' },
  ];

  return (
    <aside className="w-64 bg-gray-900 border-r border-gray-800 p-4">
      <div className="text-xl font-bold text-white mb-8 px-2">
        ArgusJS
      </div>
      <nav className="space-y-1">
        {links.map(link => (
          <a
            key={link.href}
            href={link.href}
            className="flex items-center gap-3 px-3 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
          >
            <span>{link.icon}</span>
            <span>{link.label}</span>
          </a>
        ))}
      </nav>
    </aside>
  );
}
