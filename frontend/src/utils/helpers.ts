// ─── Utility Helpers ────────────────────────────────────────────

import { severityOrder, type SeverityBreakdown } from '@/types';

export function formatDate(date: string | null): string {
  if (!date) return '-';
  const d = new Date(date);
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatDateFull(date: string): string {
  const d = new Date(date);
  return d.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function truncate(str: string, len: number): string {
  if (str.length <= len) return str;
  return str.slice(0, len) + '...';
}

export function severityBadgeClass(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  };
  return colors[severity] || colors.info;
}

export function statusBadgeClass(status: string): string {
  const colors: Record<string, string> = {
    completed: 'bg-green-500/20 text-green-400 border-green-500/30',
    running: 'bg-blue-500/20 text-blue-400 border-blue-500/30 animate-pulse',
    pending: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    failed: 'bg-red-500/20 text-red-400 border-red-500/30',
    cancelled: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  };
  return colors[status] || colors.pending;
}

export function categoryBadgeClass(category: string): string {
  const colors: Record<string, string> = {
    authentication: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    authorization: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
    cors: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
    rate_limiting: 'bg-pink-500/20 text-pink-400 border-pink-500/30',
    sensitive_data: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
    injection: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    misconfiguration: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    security_misconfiguration: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    deprecated: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    'improper_assets': 'bg-slate-500/20 text-slate-400 border-slate-500/30',
  };
  return colors[category] || 'bg-gray-500/20 text-gray-400 border-gray-500/30';
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#6b7280',
  };
  return colors[severity] || colors.info;
}

export function sortedSeverities(
  breakdown: SeverityBreakdown | Record<string, number>
): Array<{ key: string; count: number }> {
  return Object.entries(breakdown)
    .sort((a, b) => (severityOrder[a[0]] ?? 99) - (severityOrder[b[0]] ?? 99))
    .map(([key, count]) => ({ key: key.charAt(0).toUpperCase() + key.slice(1), count }));
}

export function getRiskColor(score: number | null): string {
  if (score === null) return 'text-gray-400';
  if (score >= 8) return 'text-red-400';
  if (score >= 5) return 'text-orange-400';
  if (score >= 3) return 'text-yellow-400';
  return 'text-cyber-400';
}

export function getRiskLabel(score: number | null): string {
  if (score === null) return 'N/A';
  if (score >= 8) return 'Critical';
  if (score >= 5) return 'High';
  if (score >= 3) return 'Medium';
  if (score >= 1) return 'Low';
  return 'Info';
}

export function classNames(...classes: (string | boolean | undefined | null)[]): string {
  return classes.filter(Boolean).join(' ');
}
