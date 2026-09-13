'use client';

import { useState, useEffect } from 'react';
import AppLayout from '@/components/layout/AppLayout';
import {
  Settings, User, Shield, Bell, GitBranch, Mail, Lock,
  Globe, Moon, Sun, Loader2, CheckCircle2, AlertTriangle,
  Save, Key,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { classNames } from '@/utils/helpers';
import ThemeToggle from '@/components/layout/ThemeToggle';
import type { User as UserType } from '@/types';

export default function SettingsPage() {
  const { user: authUser } = useAuth();
  const [activeTab, setActiveTab] = useState('account');
  const [darkMode, setDarkMode] = useState(true);
  const [gitHubToken, setGitHubToken] = useState('');
  const [saved, setSaved] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const stored = localStorage.getItem('ch3ck3r_theme');
    setDarkMode(stored ? stored === 'dark' : true);
    const savedToken = localStorage.getItem('ch3ck3r_github_token');
    if (savedToken) setGitHubToken(savedToken);
  }, []);

  const saveGitHubToken = () => {
    localStorage.setItem('ch3ck3r_github_token', gitHubToken);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const tabs = [
    { id: 'account', label: 'Account', icon: User },
    { id: 'appearance', label: 'Appearance', icon: Sun },
    { id: 'github', label: 'GitHub', icon: GitBranch },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'security', label: 'Security', icon: Shield },
  ];

  if (!mounted) {
    return (
      <AppLayout>
        <div className="flex items-center justify-center h-64">
          <Loader2 size={32} className="text-cyber-500 animate-spin" />
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="space-y-6 animate-fade-in">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-white">Settings</h1>
          <p className="text-gray-400 mt-1">Manage your account, preferences, and integrations</p>
        </div>

        <div className="flex gap-6">
          {/* Tab Navigation */}
          <div className="w-48 flex-shrink-0 space-y-1">
            {tabs.map((tab) => {
              const active = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={classNames(
                    'w-full flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm transition-all',
                    active
                      ? 'bg-cyber-600/20 text-cyber-400 border border-cyber-600/30'
                      : 'text-gray-400 hover:text-white hover:bg-surface-overlay border border-transparent'
                  )}
                >
                  <tab.icon size={16} />
                  {tab.label}
                </button>
              );
            })}
          </div>

          {/* Content */}
          <div className="flex-1 max-w-2xl">
            {/* Account */}
            {activeTab === 'account' && (
              <div className="bg-surface-raised border border-surface-border rounded-xl p-6 space-y-6">
                <h2 className="text-lg font-semibold text-white">Account Settings</h2>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Full Name</label>
                    <input
                      type="text"
                      value={authUser?.full_name || ''}
                      readOnly
                      className="w-full bg-surface-overlay border border-surface-border rounded-lg py-2.5 px-3 text-sm text-white cursor-not-allowed opacity-70"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Email</label>
                    <input
                      type="email"
                      value={authUser?.email || ''}
                      readOnly
                      className="w-full bg-surface-overlay border border-surface-border rounded-lg py-2.5 px-3 text-sm text-white cursor-not-allowed opacity-70"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Role</label>
                    <input
                      type="text"
                      value={authUser?.role || ''}
                      readOnly
                      className="w-full bg-surface-overlay border border-surface-border rounded-lg py-2.5 px-3 text-sm text-white cursor-not-allowed opacity-70 capitalize"
                    />
                  </div>
                </div>
                <div className="pt-4 border-t border-surface-border">
                  <p className="text-xs text-gray-600">
                    Account management features are read-only in this version.
                    Full profile editing coming soon.
                  </p>
                </div>
              </div>
            )}

            {/* Appearance */}
            {activeTab === 'appearance' && (
              <div className="bg-surface-raised border border-surface-border rounded-xl p-6 space-y-6">
                <h2 className="text-lg font-semibold text-white">Appearance</h2>
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-4 rounded-lg bg-surface-overlay">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-cyber-600/10">
                        {darkMode ? <Moon size={16} className="text-cyber-400" /> : <Sun size={16} className="text-cyber-400" />}
                      </div>
                      <div>
                        <p className="text-sm text-white font-medium">Theme Mode</p>
                        <p className="text-xs text-gray-500">{darkMode ? 'Dark mode is active' : 'Light mode is active'}</p>
                      </div>
                    </div>
                    <ThemeToggle />
                  </div>
                  <div className="p-4 rounded-lg bg-surface-overlay">
                    <p className="text-sm text-white font-medium mb-2">Color Scheme</p>
                    <div className="flex gap-2">
                      {[
                        { name: 'Blue', colors: ['#2563eb', '#1d4ed8', '#60a5fa'] },
                      ].map((scheme) => (
                        <div key={scheme.name} className="flex items-center gap-2 p-2 rounded-lg bg-cyber-600/10 border border-cyber-600/30">
                          <div className="flex gap-0.5">
                            {scheme.colors.map((c, i) => (
                              <div key={i} className="w-3 h-3 rounded-sm" style={{ backgroundColor: c }} />
                            ))}
                          </div>
                          <span className="text-xs text-cyber-400">{scheme.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* GitHub */}
            {activeTab === 'github' && (
              <div className="bg-surface-raised border border-surface-border rounded-xl p-6 space-y-6">
                <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                  <GitBranch size={16} className="text-cyber-400" />
                  GitHub Integration
                </h2>
                <div>
                  <label className="block text-sm text-gray-400 mb-1.5">
                    Personal Access Token
                  </label>
                  <div className="relative">
                    <Key size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                    <input
                      type="password"
                      value={gitHubToken}
                      onChange={(e) => setGitHubToken(e.target.value)}
                      placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                      className="w-full bg-surface-overlay border border-surface-border rounded-lg py-2.5 pl-10 pr-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyber-600 transition-colors"
                    />
                  </div>
                  <p className="text-xs text-gray-600 mt-1">
                    Token is stored locally and never sent to our servers. Requires <code className="text-gray-500">repo</code> or <code className="text-gray-500">public_repo</code> scope.
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={saveGitHubToken}
                    className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyber-600 text-white text-sm hover:bg-cyber-500 transition-colors"
                  >
                    <Save size={14} />
                    Save Token
                  </button>
                  {saved && (
                    <span className="flex items-center gap-1 text-sm text-green-400 animate-fade-in">
                      <CheckCircle2 size={14} />
                      Saved
                    </span>
                  )}
                </div>

                <div className="pt-4 border-t border-surface-border">
                  <h3 className="text-sm font-medium text-white mb-3">Recommended Scopes</h3>
                  <div className="space-y-2">
                    {[
                      { scope: 'repo', description: 'Full control of private repositories' },
                      { scope: 'public_repo', description: 'Access public repositories only' },
                      { scope: 'read:org', description: 'Read organization membership' },
                    ].map((s) => (
                      <div key={s.scope} className="flex items-center gap-2 text-sm">
                        <code className="text-xs bg-surface-overlay px-2 py-1 rounded text-cyber-400 font-mono">{s.scope}</code>
                        <span className="text-gray-500">{s.description}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Notifications */}
            {activeTab === 'notifications' && (
              <div className="bg-surface-raised border border-surface-border rounded-xl p-6 space-y-6">
                <h2 className="text-lg font-semibold text-white">Notification Preferences</h2>
                <p className="text-sm text-gray-500">
                  Configure alert channels in the <a href="/alerts" className="text-cyber-400 hover:text-cyber-300">Alerts</a> section.
                  Notification preferences coming in a future update.
                </p>
              </div>
            )}

            {/* Security */}
            {activeTab === 'security' && (
              <div className="bg-surface-raised border border-surface-border rounded-xl p-6 space-y-6">
                <h2 className="text-lg font-semibold text-white">Security Settings</h2>
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-4 rounded-lg bg-surface-overlay">
                    <div>
                      <p className="text-sm text-white font-medium">JWT Sessions</p>
                      <p className="text-xs text-gray-500">Active session expires after token refresh</p>
                    </div>
                    <span className="text-xs text-green-400 bg-green-500/10 px-2 py-1 rounded-full">Active</span>
                  </div>
                  <div className="flex items-center justify-between p-4 rounded-lg bg-surface-overlay">
                    <div>
                      <p className="text-sm text-white font-medium">Rate Limiting</p>
                      <p className="text-xs text-gray-500">API rate limiting enabled (fail-open if Redis down)</p>
                    </div>
                    <span className="text-xs text-cyber-400 bg-cyber-500/10 px-2 py-1 rounded-full">Enabled</span>
                  </div>
                  <div className="flex items-center justify-between p-4 rounded-lg bg-surface-overlay">
                    <div>
                      <p className="text-sm text-white font-medium">Webhook Signing</p>
                      <p className="text-xs text-gray-500">HMAC-SHA256 signature on outbound webhooks</p>
                    </div>
                    <span className="text-xs text-cyber-400 bg-cyber-500/10 px-2 py-1 rounded-full">Enabled</span>
                  </div>
                </div>

                <div className="pt-4 border-t border-surface-border">
                  <p className="text-xs text-gray-600">
                    Ch3ck3r follows OWASP security best practices. Passwords are hashed with bcrypt,
                    tokens use JWT with RS256, and all API responses include security headers.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
