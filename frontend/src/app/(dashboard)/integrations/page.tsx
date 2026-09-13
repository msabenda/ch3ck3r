'use client';

import { useState, useEffect } from 'react';
import AppLayout from '@/components/layout/AppLayout';
import {
  Loader2, CheckCircle2, AlertTriangle, Plug, Plus,
  X, ExternalLink, Trash2,
  Zap, Globe,
} from 'lucide-react';

/* ── Platform SVG Icons ──────────────────────────────── */
const PLATFORM_ICONS: Record<string, string> = {
  postman: `<svg viewBox="0 0 24 24" fill="#FF6C37" xmlns="http://www.w3.org/2000/svg"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm4.243 7.757a6 6 0 1 1-8.486 8.486 6 6 0 0 1 8.486-8.486z" opacity="0.2"/><path d="M12 6a6 6 0 1 0 0 12 6 6 0 0 0 0-12zm1.5 8.5L12 13l-1.5 1.5L12 16l1.5-1.5z"/></svg>`,
  azure: `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="3" y="3" width="18" height="18" rx="2" fill="#0078D4"/><path d="M7 17l3-10h1.5L9 17H7zm5 0l3-10h1.5L14 17h-2z" fill="white"/></svg>`,
  mulesoft: `<svg viewBox="0 0 24 24" fill="#00A3E0" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="9" fill="#00A3E0" opacity="0.2"/><path d="M7 10l5-4 5 4-2 2-3-2.5L9 12l-2-2z" fill="#00A3E0"/><path d="M7 14l5 4 5-4-2-2-3 2.5L9 12l-2 2z" fill="#00A3E0"/></svg>`,
  apigee: `<svg viewBox="0 0 24 24" fill="#4285F4" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="9" fill="#4285F4" opacity="0.2"/><path d="M12 5l3 3-3 3-3-3 3-3zm0 8l3 3-3 3-3-3 3-3z" fill="#4285F4"/></svg>`,
  swaggerhub: `<svg viewBox="0 0 24 24" fill="#85EA2D" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L2 7v10l10 5 10-5V7l-10-5zm0 3l6 3-6 3-6-3 6-3z" opacity="0.2"/><path d="M12 13l6-3v4l-6 3-6-3v-4l6 3z" fill="#85EA2D"/></svg>`,
  kong: `<svg viewBox="0 0 24 24" fill="#00313F" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="9" fill="#00313F" opacity="0.2"/><path d="M9 8l3-3 3 3-2 2h-2l-2-2zm0 8l3 3 3-3-2-2h-2l-2 2z" fill="#00313F"/><circle cx="12" cy="12" r="2" fill="#00313F"/></svg>`,
  boomi: `<svg viewBox="0 0 24 24" fill="#0072CE" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="9" fill="#0072CE" opacity="0.2"/><path d="M12 6a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM8 14a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm8 0a2 2 0 1 0 0 4 2 2 0 0 0 0-4z" fill="#0072CE"/></svg>`,
  jira: `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M11.99 2L5.09 7.98 3 10.07l9 9 9-9-9-9z" fill="#0052CC" opacity="0.5"/><path d="M12 19.07l3.91-3.91-3.91-3.9-3.91 3.9L12 19.07z" fill="#0052CC"/></svg>`,
  azure_devops: `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="3" y="5" width="17" height="14" rx="2" fill="#0078D4"/><path d="M9 11l3-2 3 2v3l-3 2-3-2v-3z" fill="white"/></svg>`,
  slack: `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6 15a2 2 0 0 1-2-2 2 2 0 0 1 2-2h2v2a2 2 0 0 1-2 2zm2-6H6a2 2 0 0 1 0-4h2a2 2 0 0 1 0 4zm3 3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h2a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-2zm3 3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h2a2 2 0 0 1 0 4h-2zm-3 3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h2a2 2 0 0 1 0 4h-2zM9 9v2" stroke="#4A154B" stroke-width="1.5" fill="none"/></svg>`,
  ms_teams: `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="9" cy="9" r="5" fill="#6264A7"/><path d="M16 12c-1.5 0-3 1-3 3v3h6v-3c0-2-1.5-3-3-3z" fill="#6264A7"/><circle cx="16" cy="8" r="3" fill="#6264A7"/></svg>`,
  jenkins: `<svg viewBox="0 0 24 24" fill="#D24939" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="9" fill="#D24939" opacity="0.2"/><path d="M8 9h1v1H8V9zm2 0h1v1h-1V9zm2 0h1v1h-1V9zm-4 3h1v1H8v-1zm2 0h1v1h-1v-1zm2 0h1v1h-1v-1zm-4 3h4v1H8v-1z" fill="#D24939"/><path d="M12 5c-3 0-5.5 2-5.5 5v2c0 1 .5 2 1.5 2.5V17h8v-2.5c1-.5 1.5-1.5 1.5-2.5v-2c0-3-2.5-5-5.5-5z" stroke="#D24939" stroke-width="1" fill="none"/></svg>`,
  github_actions: `<svg viewBox="0 0 24 24" fill="#181717" xmlns="http://www.w3.org/2000/svg"><path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm0 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16z" opacity="0.2"/><path d="M12 6c-2.5 0-4.5 1.8-4.5 4.2 0 1.9 1.2 3.5 3 4.1.2 0 .3-.1.3-.3v-.7c-1.2.2-1.5-.4-1.6-.8-.1-.2-.3-.5-.5-.6-.2-.1-.3-.1-.1-.3.3-.1.5 0 .7.3.2.4.6.5 1 .4.1-.2.2-.4.4-.5-1.2-.2-2.4-.6-2.4-2.7 0-.6.2-1.1.6-1.5-.1-.1-.3-.7.1-1.4 0 0 .5-.1 1.5.5.9-.3 1.8-.3 2.7 0 1-.6 1.5-.5 1.5-.5.4.7.2 1.3.1 1.4.4.4.6 1 .6 1.5 0 2.1-1.3 2.5-2.5 2.7.2.2.4.5.4 1v1.5c0 .2.1.3.3.3 1.8-.6 3-2.2 3-4.1C16.5 7.8 14.5 6 12 6z" fill="#181717"/></svg>`,
  gitlab: `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M4.5 21.5L2 13l4.5-8 2 8h9l2-8 4.5 8-2.5 8.5-6.5 2-6.5-2z" fill="#FC6D26" opacity="0.9"/><path d="M12 23.5l2.5-8.5h-5L12 23.5z" fill="#E24329"/></svg>`,
};

function PlatformIcon({ icon, color, platformId }: { icon: string; color: string; platformId: string }) {
  const svg = PLATFORM_ICONS[platformId];
  if (svg) {
    return (
      <div
        className="w-10 h-10 rounded-lg flex items-center justify-center"
        style={{ backgroundColor: color + '18' }}
        dangerouslySetInnerHTML={{ __html: svg.replace('<svg ', '<svg width="22" height="22" ') }}
      />
    );
  }
  return (
    <div
      className="w-10 h-10 rounded-lg flex items-center justify-center text-lg"
      style={{ backgroundColor: color + '15' }}
    >
      {icon}
    </div>
  );
}
import { api } from '@/lib/api';
import { classNames } from '@/utils/helpers';

interface PlatformDef {
  id: string;
  name: string;
  description: string;
  icon: string;
  color: string;
  fields: string[];
  doc_url: string;
}

interface ConfiguredIntegration {
  key: string;
  platform: string;
  name: string;
  config: Record<string, string>;
  enabled: boolean;
}

interface ConfigModalProps {
  platform: PlatformDef;
  onClose: () => void;
  onDone: () => void;
}

function ConfigModal({ platform, onClose, onDone }: ConfigModalProps) {
  const [config, setConfig] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState<{ status: string; detail: string } | null>(null);
  const [name, setName] = useState(platform.name);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api('/integrations/configure', {
        method: 'POST',
        body: JSON.stringify({
          platform: platform.id,
          name,
          config,
          enabled: true,
        }),
      });
      onDone();
      onClose();
    } catch (err) {
      console.error(err);
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    try {
      const resp = await api(`/integrations/test/${platform.id}`, {
        method: 'POST',
        body: JSON.stringify({
          platform: platform.id,
          name,
          config,
        }),
      });
      setTestResult(resp as unknown as { status: string; detail: string });
    } catch (err) {
      setTestResult({ status: 'error', detail: String(err) });
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div
        className="rounded-xl w-full max-w-md mx-4 animate-slide-up"
        style={{
          backgroundColor: 'var(--bg-raised)',
          border: '1px solid var(--bg-border)',
        }}
      >
        <div
          className="flex items-center justify-between p-5"
          style={{ borderBottom: '1px solid var(--bg-border)' }}
        >
          <div className="flex items-center gap-3">
            <span className="text-xl">{platform.icon}</span>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
              Configure {platform.name}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg hover:opacity-70"
            style={{ color: 'var(--text-muted)' }}
          >
            <X size={18} />
          </button>
        </div>

        <div className="p-5 space-y-4">
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {platform.description}
          </p>

          <div>
            <label
              className="block text-sm mb-1"
              style={{ color: 'var(--text-secondary)' }}
            >
              Connection Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-lg py-2.5 px-3 text-sm focus:outline-none focus:border-cyber-600 transition-colors"
              style={{
                backgroundColor: 'var(--bg-overlay)',
                border: '1px solid var(--bg-border)',
                color: 'var(--text-primary)',
              }}
            />
          </div>

          {platform.fields.map((field) => (
            <div key={field}>
              <label
                className="block text-sm mb-1 capitalize"
                style={{ color: 'var(--text-secondary)' }}
              >
                {field.replace(/_/g, ' ')}
              </label>
              <input
                type={field.includes('token') || field.includes('secret') || field.includes('password') ? 'password' : 'text'}
                value={config[field] || ''}
                onChange={(e) => setConfig({ ...config, [field]: e.target.value })}
                placeholder={`Enter ${field.replace(/_/g, ' ')}`}
                className="w-full rounded-lg py-2.5 px-3 text-sm focus:outline-none focus:border-cyber-600 transition-colors"
                style={{
                  backgroundColor: 'var(--bg-overlay)',
                  border: '1px solid var(--bg-border)',
                  color: 'var(--text-primary)',
                }}
              />
            </div>
          ))}

          {platform.doc_url && (
            <a
              href={platform.doc_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-xs text-cyber-400 hover:text-cyber-300"
            >
              <ExternalLink size={10} />
              View integration docs
            </a>
          )}

          {testResult && (
            <div
              className={classNames(
                'flex items-start gap-2 p-3 rounded-lg border',
                testResult.status === 'ok'
                  ? 'bg-green-500/10 border-green-500/20 text-green-400'
                  : 'bg-red-500/10 border-red-500/20 text-red-400'
              )}
            >
              {testResult.status === 'ok' ? (
                <CheckCircle2 size={14} className="mt-0.5 flex-shrink-0" />
              ) : (
                <AlertTriangle size={14} className="mt-0.5 flex-shrink-0" />
              )}
              <p className="text-sm">{testResult.detail}</p>
            </div>
          )}

          <div className="flex gap-2 justify-end pt-2">
            <button
              onClick={handleTest}
              className="px-4 py-2 rounded-lg text-sm transition-colors"
              style={{
                border: '1px solid var(--bg-border)',
                color: 'var(--text-secondary)',
                backgroundColor: 'transparent',
              }}
            >
              <Zap size={14} className="inline mr-1.5" />
              Test Connection
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-4 py-2 rounded-lg bg-cyber-600 text-white text-sm hover:bg-cyber-500 disabled:opacity-50 transition-colors flex items-center gap-2"
            >
              {saving ? <Loader2 size={14} className="animate-spin" /> : null}
              Save Configuration
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function IntegrationsPage() {
  const [platforms, setPlatforms] = useState<PlatformDef[]>([]);
  const [configured, setConfigured] = useState<ConfiguredIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [configuring, setConfiguring] = useState<PlatformDef | null>(null);

  const loadData = async () => {
    try {
      const [plats, confs] = await Promise.all([
        api('/integrations/platforms'),
        api('/integrations/configured'),
      ]);
      setPlatforms((plats as unknown as { platforms: PlatformDef[] }).platforms || []);
      setConfigured(
        (confs as unknown as { integrations: ConfiguredIntegration[] }).integrations || []
      );
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadData(); }, []);

  const removeIntegration = async (key: string) => {
    try {
      await api(`/integrations/configured/${encodeURIComponent(key)}`, {
        method: 'DELETE',
      });
      loadData();
    } catch (err) {
      console.error(err);
    }
  };

  if (loading) {
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
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-[var(--text-primary)]">
              Integrations
            </h1>
            <p className="text-[var(--text-secondary)] mt-1">
              Connect Ch3ck3r with your API platform, CI/CD pipeline, and monitoring tools
            </p>
          </div>
          <span className="text-sm text-[var(--text-muted)]">
            {configured.length} connected
          </span>
        </div>

        {/* Configured Integrations */}
        {configured.length > 0 && (
          <div>
            <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-2">
              <CheckCircle2 size={14} className="text-green-400" />
              Active Connections
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {configured.map((ci) => {
                const plat = platforms.find((p) => p.id === ci.platform);
                return (
                  <div
                    key={ci.key}
                    className="bg-[var(--bg-raised)] border border-[var(--bg-border)] rounded-xl p-4"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">{plat?.icon || '🔌'}</span>
                        <div>
                          <p className="text-sm font-medium text-[var(--text-primary)]">
                            {ci.name}
                          </p>
                          <p className="text-xs text-[var(--text-muted)]">
                            {plat?.name || ci.platform}
                          </p>
                        </div>
                      </div>
                      <span className="text-xs text-green-400 bg-green-500/10 px-2 py-0.5 rounded-full">
                        Active
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-3 pt-3 border-t border-[var(--bg-border)]">
                      <button
                        onClick={() => removeIntegration(ci.key)}
                        className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1"
                      >
                        <Trash2 size={12} />
                        Remove
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* All Platforms */}
        <div>
          <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-2">
            <Plug size={14} className="text-cyber-400" />
            Available Platforms ({platforms.length})
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {platforms.map((platform) => {
              const isConfigured = configured.some(
                (c) => c.platform === platform.id
              );
              return (
                <div
                  key={platform.id}
                  className={classNames(
                    'bg-[var(--bg-raised)] border rounded-xl p-4 transition-all hover:border-cyber-600/30',
                    isConfigured
                      ? 'border-green-500/30'
                      : 'border-[var(--bg-border)]'
                  )}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <PlatformIcon
                        icon={platform.icon}
                        color={platform.color}
                        platformId={platform.id}
                      />
                      <div>
                        <p className="text-sm font-medium text-[var(--text-primary)]">
                          {platform.name}
                        </p>
                        {isConfigured && (
                          <span className="text-xs text-green-400">Connected</span>
                        )}
                      </div>
                    </div>
                    <button
                      onClick={() => setConfiguring(platform)}
                      className={classNames(
                        'p-1.5 rounded-lg transition-colors',
                        isConfigured
                          ? 'text-green-400 hover:bg-green-500/10'
                          : 'text-cyber-400 hover:bg-cyber-600/10'
                      )}
                    >
                      <Plus size={16} />
                    </button>
                  </div>
                  <p className="text-xs text-[var(--text-muted)] mt-2">
                    {platform.description}
                  </p>
                  <div className="flex items-center gap-2 mt-3 text-xs text-[var(--text-muted)]">
                    <Globe size={10} />
                    <span>{platform.fields.length} fields</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {configuring && (
        <ConfigModal
          platform={configuring}
          onClose={() => setConfiguring(null)}
          onDone={loadData}
        />
      )}
    </AppLayout>
  );
}
