'use client';

import { useState, useEffect, useCallback } from 'react';
import AppLayout from '@/components/layout/AppLayout';
import {
  Shield, Search, Bug, AlertTriangle, TrendingUp, Activity,
  ArrowUp, ArrowDown, GitBranch, Play, FileText, FolderKanban,
  CheckCircle2, XCircle, Clock, Zap, BarChart3,
  ChevronRight, Loader2, TrendingUp as LineChartIcon,
} from 'lucide-react';
import { scansApi, projectsApi, findingsApi } from '@/lib/api';
import { formatDate, getRiskColor, severityBadgeClass, getSeverityColor, classNames } from '@/utils/helpers';
import { severityColors, severityOrder, type Finding } from '@/types';
import type { Scan, Project } from '@/types';
import Link from 'next/link';

// ─── Recharts Lazy Imports ─────────────────────────────────────
// eslint-disable-next-line @typescript-eslint/no-explicit-any
import dynamic from 'next/dynamic';
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const loadRC = (name: string): any => dynamic<any>(() => import('recharts').then(m => ({ default: (m as any)[name] })), { ssr: false });

const ReChartsPieChart = loadRC('PieChart');
const ReChartsPie = loadRC('Pie');
const ReChartsCell = loadRC('Cell');
const ReChartsResponsiveContainer = loadRC('ResponsiveContainer');
const ReChartsLineChart = loadRC('LineChart');
const ReChartsLine = loadRC('Line');
const ReChartsXAxis = loadRC('XAxis');
const ReChartsYAxis = loadRC('YAxis');
const ReChartsCartesianGrid = loadRC('CartesianGrid');
const ReChartsTooltip = loadRC('Tooltip');

interface ScanStats {
  total_scans: number;
  total_findings: number;
  avg_risk_score: number;
}

interface SIEMEvent {
  id: string;
  timestamp: string;
  severity: string;
  message: string;
  type: 'finding' | 'scan' | 'severity' | 'deploy';
}

const severityChartColors = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

function findSeverity(findings: Finding[], sev: string): number {
  return findings.filter(f => f.severity === sev).length;
}

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [recentFindings, setRecentFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [siemEvents, setSiemEvents] = useState<SIEMEvent[]>([]);
  const [stats, setStats] = useState<ScanStats>({ total_scans: 0, total_findings: 0, avg_risk_score: 0 });
  const [connectedRepos, setConnectedRepos] = useState(0);

  const loadData = useCallback(async () => {
    try {
      const [scansData, projectsData, findingsData, allFindingsData] = await Promise.all([
        scansApi.list({ limit: '10' }),
        projectsApi.list(),
        findingsApi.list({ limit: '10', sort: 'created_at', order: 'desc' }),
        findingsApi.list({ limit: '100', sort: 'created_at', order: 'desc' }),
      ]);

      const scansList = scansData || [];
      const projectsList = projectsData || [];
      const findingsRecent = allFindingsData || [];

      setScans(scansList);
      setProjects(projectsList);
      setRecentFindings(findingsData || []);
      setAllFindings(findingsRecent);

      // Count repos
      const repos = projectsList.filter((p: Project) => p.repository_url);
      setConnectedRepos(repos.length);

      // Calculate stats
      const severityBreakdown = {
        critical: findSeverity(findingsRecent, 'critical'),
        high: findSeverity(findingsRecent, 'high'),
        medium: findSeverity(findingsRecent, 'medium'),
        low: findSeverity(findingsRecent, 'low'),
        info: findSeverity(findingsRecent, 'info'),
      };
      const totalFindings = Object.values(severityBreakdown).reduce((a, b) => a + b, 0);
      const completedScans = scansList.filter((s: Scan) => s.status === 'completed');
      const avgScore = completedScans.length > 0
        ? completedScans.reduce((a, s) => a + (s.risk_score || 0), 0) / completedScans.length
        : 0;

      setStats({
        total_scans: scansList.length,
        total_findings: totalFindings,
        avg_risk_score: Math.round(avgScore * 10) / 10,
      });

      // Build SIEM events
      const events: SIEMEvent[] = [];
      const criticalF = findingsRecent.filter((f: Finding) => f.severity === 'critical');
      const highF = findingsRecent.filter((f: Finding) => f.severity === 'high');

      // Critical findings become top-priority SIEM events
      criticalF.slice(0, 5).forEach((f: Finding) => {
        events.push({
          id: `siem-${f.id}`,
          timestamp: f.created_at || new Date().toISOString(),
          severity: 'critical',
          message: `Critical finding detected: ${f.title}${f.endpoint ? ` on ${f.endpoint}` : ''}`,
          type: 'finding',
        });
      });

      // High findings
      highF.slice(0, 5).forEach((f: Finding) => {
        events.push({
          id: `siem-high-${f.id}`,
          timestamp: f.created_at || new Date().toISOString(),
          severity: 'high',
          message: `High severity finding: ${f.title} (${f.category})`,
          type: 'finding',
        });
      });

      // Scan completions
      completedScans.slice(0, 5).forEach((s: Scan) => {
        events.push({
          id: `siem-scan-${s.id}`,
          timestamp: s.completed_at || s.created_at,
          severity: s.risk_score && s.risk_score >= 7 ? 'high' : 'info',
          message: `Scan completed: ${s.scan_type.toUpperCase()} scan on ${s.target}`,
          type: 'scan',
        });
      });

      events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      setSiemEvents(events.slice(0, 20));
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const totalBySeverity = {
    critical: findSeverity(allFindings, 'critical'),
    high: findSeverity(allFindings, 'high'),
    medium: findSeverity(allFindings, 'medium'),
    low: findSeverity(allFindings, 'low'),
    info: findSeverity(allFindings, 'info'),
  };

  const pieData = Object.entries(totalBySeverity)
    .filter(([, count]) => count > 0)
    .map(([name, value]) => ({ name, value }));

  // Build risk trend for line chart
  const completedScansSorted = [...scans]
    .filter(s => s.status === 'completed' && s.risk_score !== null)
    .slice(-10);
  const trendData = completedScansSorted.map((s, i) => ({
    index: i + 1,
    risk: s.risk_score,
    label: s.scan_type.toUpperCase(),
  }));

  // DevSecOps pipeline health
  const completedCount = scans.filter(s => s.status === 'completed').length;
  const failedCount = scans.filter(s => s.status === 'failed').length;
  const runningCount = scans.filter(s => s.status === 'running' || s.status === 'pending').length;
  const totalCount = scans.length;
  const passRate = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;

  // Severity SIEM indicator
  const criticalCount = totalBySeverity.critical;
  const highCount = totalBySeverity.high;

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
        <div id="tour-welcome" className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
            <p className="text-gray-400 mt-1">API security posture overview with DevSecOps insights</p>
          </div>
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-2 text-sm">
              <span className={classNames(
                'inline-block w-2 h-2 rounded-full',
                criticalCount > 0 ? 'bg-red-500 animate-pulse' : 'bg-gray-600'
              )} />
              <span className={criticalCount > 0 ? 'text-red-400 font-medium' : 'text-gray-500'}>
                {criticalCount > 0 ? `${criticalCount} Critical` : 'No critical'}
              </span>
            </span>
            <div className="h-6 w-px bg-surface-border" />
            <span className="text-sm text-cyber-400 font-mono">
              v0.1.0
            </span>
          </div>
        </div>

        {/* Stats Row */}
        <div id="tour-dashboard" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-surface-raised border border-surface-border rounded-xl p-5 hover:border-cyber-600/30 transition-colors">
            <div className="flex items-center justify-between mb-3">
              <p className="text-sm text-gray-500">Total Scans</p>
              <div className="p-2 rounded-lg bg-cyber-600/10">
                <Search size={16} className="text-cyber-400" />
              </div>
            </div>
            <p className="text-3xl font-bold text-white">{stats.total_scans}</p>
            <div className="flex items-center gap-1 mt-1">
              <span className={classNames(
                'text-xs',
                passRate >= 80 ? 'text-green-400' : 'text-yellow-400'
              )}>
                {passRate}% pass rate
              </span>
            </div>
          </div>

          <div className={classNames(
            'bg-surface-raised border rounded-xl p-5 transition-colors',
            criticalCount > 0 ? 'border-red-500/30' : 'border-surface-border'
          )}>
            <div className="flex items-center justify-between mb-3">
              <p className="text-sm text-gray-500">
                {criticalCount > 0 ? 'Critical Findings' : 'Total Findings'}
              </p>
              <div className={classNames(
                'p-2 rounded-lg',
                criticalCount > 0 ? 'bg-red-500/10' : 'bg-cyber-600/10'
              )}>
                <Bug size={16} className={criticalCount > 0 ? 'text-red-400' : 'text-cyber-400'} />
              </div>
            </div>
            <p className={classNames(
              'text-3xl font-bold',
              criticalCount > 0 ? 'text-red-400' : 'text-white'
            )}>
              {criticalCount > 0 ? criticalCount : stats.total_findings}
            </p>
            <div className="flex items-center gap-1 mt-1">
              <span className="text-xs text-gray-500">
                {criticalCount > 0 ? `+${highCount} high severity` : 'No critical issues'}
              </span>
            </div>
          </div>

          <div className="bg-surface-raised border border-surface-border rounded-xl p-5 hover:border-cyber-600/30 transition-colors">
            <div className="flex items-center justify-between mb-3">
              <p className="text-sm text-gray-500">GitHub Repos</p>
              <div className="p-2 rounded-lg bg-cyber-600/10">
                <GitBranch size={16} className="text-cyber-400" />
              </div>
            </div>
            <p className="text-3xl font-bold text-white">{connectedRepos}</p>
            <div className="flex items-center gap-1 mt-1">
              <Link href="/repositories" className="text-xs text-cyber-400 hover:text-cyber-300">
                Manage repos →
              </Link>
            </div>
          </div>

          <div className="bg-surface-raised border border-surface-border rounded-xl p-5 hover:border-cyber-600/30 transition-colors">
            <div className="flex items-center justify-between mb-3">
              <p className="text-sm text-gray-500">Avg Risk Score</p>
              <div className="p-2 rounded-lg bg-cyber-600/10">
                <AlertTriangle size={16} className="text-cyber-400" />
              </div>
            </div>
            <p className={classNames('text-3xl font-bold', getRiskColor(stats.avg_risk_score))}>
              {stats.avg_risk_score.toFixed(1)}
            </p>
            <div className="flex items-center gap-1 mt-1">
              <span className="text-xs text-gray-500">/ 10.0</span>
            </div>
          </div>
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Severity Donut */}
          <div className="bg-surface-raised border border-surface-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Severity Breakdown</h2>
              <BarChart3 size={18} className="text-gray-500" />
            </div>
            {pieData.length > 0 ? (
              <div className="flex items-center justify-center">
                <ReChartsResponsiveContainer width="100%" height={220}>
                  <ReChartsPieChart>
                    <ReChartsPie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={90}
                      dataKey="value"
                      nameKey="name"
                      paddingAngle={2}
                    >
                      {pieData.map((entry) => (
                        <ReChartsCell key={entry.name} fill={severityChartColors[entry.name as keyof typeof severityChartColors] || '#6b7280'} />
                      ))}
                    </ReChartsPie>
                    <ReChartsTooltip
                      contentStyle={{
                        backgroundColor: '#1e1e1e',
                        border: '1px solid #2a2a2a',
                        borderRadius: '8px',
                        color: '#fff',
                      }}
                      formatter={(value: number, name: string) => [value, name.charAt(0).toUpperCase() + name.slice(1)]}
                    />
                  </ReChartsPieChart>
                </ReChartsResponsiveContainer>
                <div className="space-y-2 ml-4">
                  {Object.entries(totalBySeverity).map(([sev, count]) => (
                    <div key={sev} className="flex items-center gap-2">
                      <span className="w-3 h-3 rounded-sm" style={{ backgroundColor: severityChartColors[sev as keyof typeof severityChartColors] }} />
                      <span className="text-sm text-gray-400 capitalize w-16">{sev}</span>
                      <span className="text-sm text-white font-mono">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="flex items-center justify-center h-[220px] text-gray-600">
                <p>No findings data available</p>
              </div>
            )}
          </div>

          {/* Risk Trend Line Chart */}
          <div className="bg-surface-raised border border-surface-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Scan Risk Trend</h2>
              <LineChartIcon size={18} className="text-gray-500" />
            </div>
            {trendData.length > 1 ? (
              <ReChartsResponsiveContainer width="100%" height={220}>
                <ReChartsLineChart data={trendData}>
                  <ReChartsCartesianGrid strokeDasharray="3 3" stroke="#2a2a2a" />
                  <ReChartsXAxis dataKey="label" tick={{ fill: '#6b7280', fontSize: 11 }} />
                  <ReChartsYAxis domain={[0, 10]} tick={{ fill: '#6b7280', fontSize: 11 }} />
                  <ReChartsTooltip
                    contentStyle={{
                      backgroundColor: '#1e1e1e',
                      border: '1px solid #2a2a2a',
                      borderRadius: '8px',
                      color: '#fff',
                    }}
                  />
                  <ReChartsLine
                    type="monotone"
                    dataKey="risk"
                    stroke="#3b82f6"
                    strokeWidth={2}
                    dot={{ fill: '#3b82f6', strokeWidth: 2, r: 4 }}
                    activeDot={{ r: 6, fill: '#3b82f6' }}
                  />
                </ReChartsLineChart>
              </ReChartsResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-[220px] text-gray-600">
                <p>Run more scans to see risk trend</p>
              </div>
            )}
          </div>
        </div>

        {/* DevSecOps Pipeline Status */}
        <div className="bg-surface-raised border border-surface-border rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">DevSecOps Pipeline Status</h2>
            <Activity size={18} className="text-gray-500" />
          </div>

          {/* Pipeline Steps */}
          <div className="flex items-center justify-between mb-6 px-4">
            {[
              { label: 'Code', icon: GitBranch, status: 'pass' },
              { label: 'Build', icon: CheckCircle2, status: 'pass' },
              { label: 'Test', icon: Bug, status: 'pass' },
              { label: 'Security Scan', icon: Shield, status: runningCount > 0 ? 'running' : completedCount > 0 ? 'pass' : 'pending' },
              { label: 'Deploy', icon: TrendingUp, status: passRate >= 80 ? 'pass' : 'warning' },
            ].map((step, i) => (
              <div key={step.label} className="flex items-center">
                <div className="flex flex-col items-center gap-1.5">
                  <div className={classNames(
                    'w-10 h-10 rounded-full flex items-center justify-center border-2 transition-all',
                    step.status === 'pass' ? 'bg-green-500/20 border-green-500 text-green-400' :
                    step.status === 'running' ? 'bg-cyber-500/20 border-cyber-500 text-cyber-400 animate-pulse' :
                    step.status === 'warning' ? 'bg-yellow-500/20 border-yellow-500 text-yellow-400' :
                    'bg-surface-overlay border-surface-border text-gray-600'
                  )}>
                    <step.icon size={18} />
                  </div>
                  <span className={classNames(
                    'text-xs',
                    step.status === 'pass' ? 'text-green-400' :
                    step.status === 'running' ? 'text-cyber-400' :
                    step.status === 'warning' ? 'text-yellow-400' :
                    'text-gray-600'
                  )}>
                    {step.label}
                  </span>
                </div>
                {i < 4 && (
                  <div className={classNames(
                    'w-12 h-0.5 mx-2 mt-[-1.5rem]',
                    step.status === 'pass' ? 'bg-green-500/50' :
                    step.status === 'running' ? 'bg-cyber-500/50' :
                    'bg-surface-border'
                  )} />
                )}
              </div>
            ))}
          </div>

          {/* Pipeline Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-4 pt-4 border-t border-surface-border">
            <div className="text-center">
              <p className="text-xs text-gray-500 mb-1">Pass Rate</p>
              <p className={classNames('text-lg font-bold', passRate >= 80 ? 'text-green-400' : 'text-yellow-400')}>
                {passRate}%
              </p>
            </div>
            <div className="text-center">
              <p className="text-xs text-gray-500 mb-1">Total Scans</p>
              <p className="text-lg font-bold text-white">{totalCount}</p>
            </div>
            <div className="text-center">
              <p className="text-xs text-gray-500 mb-1">Failed</p>
              <p className={classNames('text-lg font-bold', failedCount > 0 ? 'text-red-400' : 'text-green-400')}>
                {failedCount}
              </p>
            </div>
            <div className="text-center">
              <p className="text-xs text-gray-500 mb-1">Scan Coverage</p>
              <p className="text-lg font-bold text-cyber-400">
                {totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0}%
              </p>
            </div>
          </div>
        </div>

        {/* SIEM Activity Feed + Recent Scans */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* SIEM Feed */}
          <div className="bg-surface-raised border border-surface-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                <Activity size={16} className="text-cyber-400" />
                SIEM Activity Feed
              </h2>
              <span className="text-xs text-gray-500">
                {siemEvents.length} events
              </span>
            </div>
            <div className="space-y-1 max-h-[320px] overflow-y-auto">
              {siemEvents.length > 0 ? siemEvents.slice(0, 12).map((event) => (
                <div key={event.id} className="flex items-start gap-3 p-2.5 rounded-lg hover:bg-surface-overlay transition-colors">
                  <div className={classNames(
                    'w-2 h-2 rounded-full mt-1.5 flex-shrink-0',
                    event.severity === 'critical' ? 'bg-red-500' :
                    event.severity === 'high' ? 'bg-orange-500' :
                    'bg-cyber-400'
                  )} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-gray-300">{event.message}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-xs text-gray-600">{formatDate(event.timestamp)}</span>
                      <span className={classNames(
                        'text-xs px-1.5 py-0.5 rounded capitalize',
                        event.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                        event.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        'bg-gray-500/20 text-gray-400'
                      )}>
                        {event.severity}
                      </span>
                    </div>
                  </div>
                </div>
              )) : (
                <div className="text-center py-8 text-gray-600">
                  <Activity size={24} className="mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No security events yet</p>
                  <p className="text-xs mt-1">Run a scan to populate the feed</p>
                </div>
              )}
            </div>
            <Link
              href="/findings"
              className="flex items-center justify-center gap-1 mt-3 w-full py-2 rounded-lg text-sm text-cyber-400 hover:bg-cyber-600/10 transition-colors"
            >
              View all findings
              <ChevronRight size={14} />
            </Link>
          </div>

          {/* Recent Scans */}
          <div className="bg-surface-raised border border-surface-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Recent Scans</h2>
              <Link href="/scans" className="text-sm text-cyber-400 hover:text-cyber-300">
                View all →
              </Link>
            </div>
            <div className="space-y-2">
              {scans.slice(0, 7).map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="flex items-center justify-between p-3 rounded-lg hover:bg-surface-overlay transition-colors"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="text-sm text-white truncate">{scan.target}</p>
                      {scan.risk_score !== null && (
                        <span className={classNames('text-xs font-mono', getRiskColor(scan.risk_score))}>
                          {scan.risk_score.toFixed(1)}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 mt-0.5">
                      {scan.scan_type.toUpperCase()} · {formatDate(scan.created_at)}
                      {scan.critical_count > 0 && ` · ${scan.critical_count} critical`}
                    </p>
                  </div>
                  <span className={classNames(
                    'text-xs px-2 py-1 rounded-full border capitalize',
                    scan.status === 'completed' ? 'bg-green-500/20 text-green-400 border-green-500/30' :
                    scan.status === 'running' ? 'bg-cyber-500/20 text-cyber-400 border-cyber-500/30 animate-pulse' :
                    scan.status === 'failed' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                    'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                  )}>
                    {scan.status}
                  </span>
                </Link>
              ))}
              {scans.length === 0 && (
                <div className="text-center py-8 text-gray-600">
                  <Search size={24} className="mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No scans yet</p>
                  <p className="text-xs mt-1">Create your first scan to get started</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="bg-surface-raised border border-surface-border rounded-xl p-5">
          <h2 className="text-lg font-semibold text-white mb-4">Quick Actions</h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <Link
              href="/projects"
              className="flex flex-col items-center gap-2 p-4 rounded-xl bg-cyber-600/10 border border-cyber-600/20 hover:bg-cyber-600/20 hover:border-cyber-600/30 transition-all group"
            >
              <div className="p-2 rounded-lg bg-cyber-600/20 group-hover:bg-cyber-600/30 transition-colors">
                <Play size={20} className="text-cyber-400" />
              </div>
              <span className="text-sm text-cyber-400 font-medium">New Scan</span>
            </Link>
            <Link
              href="/repositories"
              className="flex flex-col items-center gap-2 p-4 rounded-xl bg-cyber-600/10 border border-cyber-600/20 hover:bg-cyber-600/20 hover:border-cyber-600/30 transition-all group"
            >
              <div className="p-2 rounded-lg bg-cyber-600/20 group-hover:bg-cyber-600/30 transition-colors">
                <GitBranch size={20} className="text-cyber-400" />
              </div>
              <span className="text-sm text-cyber-400 font-medium">Connect Repo</span>
            </Link>
            <Link
              href="/reports"
              className="flex flex-col items-center gap-2 p-4 rounded-xl bg-cyber-600/10 border border-cyber-600/20 hover:bg-cyber-600/20 hover:border-cyber-600/30 transition-all group"
            >
              <div className="p-2 rounded-lg bg-cyber-600/20 group-hover:bg-cyber-600/30 transition-colors">
                <FileText size={20} className="text-cyber-400" />
              </div>
              <span className="text-sm text-cyber-400 font-medium">Generate Report</span>
            </Link>
            <Link
              href="/projects"
              className="flex flex-col items-center gap-2 p-4 rounded-xl bg-cyber-600/10 border border-cyber-600/20 hover:bg-cyber-600/20 hover:border-cyber-600/30 transition-all group"
            >
              <div className="p-2 rounded-lg bg-cyber-600/20 group-hover:bg-cyber-600/30 transition-colors">
                <FolderKanban size={20} className="text-cyber-400" />
              </div>
              <span className="text-sm text-cyber-400 font-medium">View Projects</span>
            </Link>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
