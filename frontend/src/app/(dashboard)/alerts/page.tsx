'use client';

import { useState, useEffect } from 'react';
import AppLayout from '@/components/layout/AppLayout';
import {
  Bell, Plus, Loader2, Trash2, Edit2,
  AlertTriangle, CheckCircle2, Activity,
  Server, Mail, MessageSquare, Globe,
} from 'lucide-react';
import { classNames } from '@/utils/helpers';

interface AlertRule {
  id: string;
  name: string;
  channel: string;
  severity: string[];
  enabled: boolean;
  webhook_url?: string;
  created_at: string;
}

const defaultRules: AlertRule[] = [
  { id: '1', name: 'Critical Findings', channel: 'slack', severity: ['critical'], enabled: true, created_at: new Date().toISOString() },
  { id: '2', name: 'High & Critical Alerts', channel: 'discord', severity: ['critical', 'high'], enabled: true, created_at: new Date().toISOString() },
  { id: '3', name: 'Scan Failures', channel: 'email', severity: ['critical'], enabled: false, created_at: new Date().toISOString() },
];

const channelIcons: Record<string, React.ElementType> = {
  slack: MessageSquare,
  discord: MessageSquare,
  email: Mail,
  webhook: Globe,
};

const channelColors: Record<string, string> = {
  slack: 'text-purple-400 bg-purple-500/10',
  discord: 'text-indigo-400 bg-indigo-500/10',
  email: 'text-blue-400 bg-blue-500/10',
  webhook: 'text-cyber-400 bg-cyber-600/10',
};

export default function AlertsPage() {
  const [rules, setRules] = useState<AlertRule[]>(defaultRules);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Load from localStorage for demo
    const stored = localStorage.getItem('ch3ck3r_alert_rules');
    if (stored) {
      try { setRules(JSON.parse(stored)); } catch {}
    }
  }, []);

  const saveRules = (updated: AlertRule[]) => {
    setRules(updated);
    localStorage.setItem('ch3ck3r_alert_rules', JSON.stringify(updated));
  };

  const toggleRule = (id: string) => {
    saveRules(rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const deleteRule = (id: string) => {
    saveRules(rules.filter(r => r.id !== id));
  };

  const addDemoRule = () => {
    const newRule: AlertRule = {
      id: Date.now().toString(),
      name: `Alert Rule ${rules.length + 1}`,
      channel: 'webhook',
      severity: ['critical', 'high'],
      enabled: true,
      webhook_url: 'https://hooks.example.com/ch3ck3r',
      created_at: new Date().toISOString(),
    };
    saveRules([...rules, newRule]);
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
            <h1 className="text-2xl font-bold text-white">Alert Rules</h1>
            <p className="text-gray-400 mt-1">
              Configure multi-channel alerting for security findings
            </p>
          </div>
          <button
            onClick={addDemoRule}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyber-600 text-white text-sm hover:bg-cyber-500 transition-colors"
          >
            <Plus size={16} />
            New Rule
          </button>
        </div>

        {/* Channels Overview */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { name: 'Slack', icon: MessageSquare, color: 'bg-purple-500/10 text-purple-400', desc: 'Channel messages' },
            { name: 'Discord', icon: MessageSquare, color: 'bg-indigo-500/10 text-indigo-400', desc: 'Webhook integration' },
            { name: 'Email', icon: Mail, color: 'bg-blue-500/10 text-blue-400', desc: 'SMTP notifications' },
            { name: 'Webhook', icon: Globe, color: 'bg-cyber-500/10 text-cyber-400', desc: 'Custom HTTP endpoint' },
          ].map((ch) => (
            <div key={ch.name} className="bg-surface-raised border border-surface-border rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <div className={classNames('p-1.5 rounded-lg', ch.color)}>
                  <ch.icon size={14} />
                </div>
                <span className="text-sm text-white font-medium">{ch.name}</span>
              </div>
              <p className="text-xs text-gray-500">{ch.desc}</p>
              <p className="text-xs text-cyber-400 mt-1">
                {rules.filter(r => r.channel === ch.name.toLowerCase()).length} rules
              </p>
            </div>
          ))}
        </div>

        {/* Rules List */}
        {rules.length === 0 ? (
          <div className="bg-surface-raised border border-surface-border rounded-xl p-12 text-center">
            <Bell size={32} className="mx-auto text-gray-600 mb-3" />
            <p className="text-white font-medium">No Alert Rules</p>
            <p className="text-sm text-gray-500 mt-1">Create rules to receive alerts for critical findings</p>
          </div>
        ) : (
          <div className="space-y-2">
            {rules.map((rule) => {
              const Icon = channelIcons[rule.channel] || Globe;
              const iconColor = channelColors[rule.channel] || 'text-gray-400 bg-gray-500/10';

              return (
                <div
                  key={rule.id}
                  className={classNames(
                    'bg-surface-raised border rounded-xl p-5 transition-all',
                    rule.enabled ? 'border-surface-border' : 'border-surface-border opacity-60'
                  )}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={classNames('p-2 rounded-lg', iconColor)}>
                        <Icon size={18} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <p className="text-white font-medium">{rule.name}</p>
                          <span className={classNames(
                            'text-xs px-2 py-0.5 rounded-full capitalize',
                            rule.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                          )}>
                            {rule.enabled ? 'Active' : 'Disabled'}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-xs text-gray-500 capitalize">{rule.channel}</span>
                          <span className="text-xs text-gray-600">·</span>
                          <div className="flex gap-1">
                            {rule.severity.map(s => (
                              <span key={s} className={classNames(
                                'text-xs px-1.5 py-0.5 rounded',
                                s === 'critical' ? 'bg-red-500/20 text-red-400' :
                                s === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                s === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                'bg-gray-500/20 text-gray-400'
                              )}>
                                {s}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => toggleRule(rule.id)}
                        className={classNames(
                          'px-3 py-1.5 rounded-lg text-xs font-medium transition-colors',
                          rule.enabled
                            ? 'bg-red-500/10 text-red-400 hover:bg-red-500/20'
                            : 'bg-green-500/10 text-green-400 hover:bg-green-500/20'
                        )}
                      >
                        {rule.enabled ? 'Disable' : 'Enable'}
                      </button>
                      <button
                        onClick={() => deleteRule(rule.id)}
                        className="p-1.5 rounded-lg text-gray-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AppLayout>
  );
}
