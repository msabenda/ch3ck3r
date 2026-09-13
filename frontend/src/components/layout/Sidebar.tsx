'use client';

import { useAuth } from '@/context/AuthContext';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  Search,
  Bug,
  FolderKanban,
  FileText,
  Settings,
  LogOut,
  Shield,
  Menu,
  X,
  Bell,
  GitBranch,
  Upload,
  Plug,
} from 'lucide-react';
import Link from 'next/link';
import { useState } from 'react';
import { classNames } from '@/utils/helpers';
import ThemeToggle from './ThemeToggle';

const navItems = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/projects', label: 'Projects', icon: FolderKanban },
  { href: '/repositories', label: 'Repositories', icon: GitBranch },
  { href: '/scans', label: 'Scans', icon: Search },
  { href: '/findings', label: 'Findings', icon: Bug },
  { href: '/reports', label: 'Reports', icon: FileText },
  { href: '/import', label: 'Import Spec', icon: Upload },
  { href: '/integrations', label: 'Integrations', icon: Plug },
  { href: '/alerts', label: 'Alerts', icon: Bell },
  { href: '/settings', label: 'Settings', icon: Settings },
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={classNames(
        'fixed top-0 left-0 h-full transition-all duration-200 z-30 flex flex-col',
        collapsed ? 'w-16' : 'w-64'
      )}
      style={{
        backgroundColor: 'var(--bg-raised)',
        borderRight: '1px solid var(--bg-border)',
      }}
    >
      {/* Logo */}
      <div
        className="flex items-center justify-between h-16 px-4"
        style={{ borderBottom: '1px solid var(--bg-border)' }}
      >
        <Link href="/dashboard" className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-cyber-600 flex items-center justify-center flex-shrink-0">
            <Shield size={18} className="text-white" />
          </div>
          {!collapsed && (
            <span
              className="text-lg font-bold tracking-tight"
              style={{ color: 'var(--text-primary)' }}
            >
              Ch3ck3r
            </span>
          )}
        </Link>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="p-1.5 rounded-lg hover:opacity-70 transition-colors"
          style={{ color: 'var(--text-muted)' }}
        >
          {collapsed ? <Menu size={18} /> : <X size={18} />}
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const active = pathname?.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              style={{
                backgroundColor: active ? 'var(--cyber-active-bg)' : 'transparent',
                color: active ? 'var(--cyber-400)' : 'var(--text-secondary)',
                border: `1px solid ${active ? 'var(--cyber-active-border)' : 'transparent'}`,
              }}
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-150 hover:opacity-80"
            >
              <item.icon size={20} className="flex-shrink-0" />
              {!collapsed && (
                <span className="text-sm font-medium truncate">{item.label}</span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Theme Toggle */}
      {!collapsed && (
        <div className="px-4 pb-2">
          <div
            className="flex items-center justify-between px-3 py-2 rounded-lg"
            style={{ color: 'var(--text-muted)' }}
          >
            <span className="text-sm">Theme</span>
            <ThemeToggle />
          </div>
        </div>
      )}

      {/* User */}
      <div style={{ borderTop: '1px solid var(--bg-border)' }} className="p-4">
        {!collapsed && user && (
          <div className="mb-3 px-1">
            <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
              {user.full_name}
            </p>
            <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>{user.email}</p>
          </div>
        )}
        <button
          onClick={logout}
          className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg transition-all border border-transparent hover:border-red-500/20 hover:bg-red-500/10"
          style={{ color: 'var(--text-muted)' }}
        >
          <LogOut size={20} />
          {!collapsed && <span className="text-sm">Logout</span>}
        </button>
      </div>
    </aside>
  );
}
