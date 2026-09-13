'use client';

import { useState, useEffect, useCallback } from 'react';
import AppLayout from '@/components/layout/AppLayout';
import {
  Bug, Filter, Loader2, ChevronDown, ChevronRight,
  AlertTriangle, ExternalLink, Lightbulb, Activity,
  RefreshCw, Search,
} from 'lucide-react';
import { findingsApi } from '@/lib/api';
import {
  formatDate, classNames, severityBadgeClass, categoryBadgeClass,
} from '@/utils/helpers';
import type { Finding } from '@/types';

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [searchFilter, setSearchFilter] = useState('');
  const [falsePositiveOnly, setFalsePositiveOnly] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await findingsApi.list({ limit: '500', sort: 'created_at', order: 'desc' });
      setFindings(data || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const categories = [...new Set(findings.map(f => f.category))].sort();
  const toggleFinding = (id: string) => {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpanded(next);
  };

  const filteredFindings = findings.filter(f => {
    if (severityFilter && f.severity !== severityFilter) return false;
    if (categoryFilter && f.category !== categoryFilter) return false;
    if (falsePositiveOnly && !f.false_positive) return false;
    if (searchFilter) {
      const q = searchFilter.toLowerCase();
      return f.title.toLowerCase().includes(q) ||
        (f.description?.toLowerCase().includes(q)) ||
        (f.endpoint?.toLowerCase().includes(q)) ||
        (f.cve_id?.toLowerCase().includes(q));
    }
    return true;
  });

  const severityCounts = {
    critical: filteredFindings.filter(f => f.severity === 'critical').length,
    high: filteredFindings.filter(f => f.severity === 'high').length,
    medium: filteredFindings.filter(f => f.severity === 'medium').length,
    low: filteredFindings.filter(f => f.severity === 'low').length,
    info: filteredFindings.filter(f => f.severity === 'info').length,
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
            <h1 id="tour-findings" className="text-2xl font-bold text-white">Findings</h1>
            <p className="text-gray-400 mt-1">
              All detected vulnerabilities organized by severity
            </p>
          </div>
          <button onClick={load} className="p-2 rounded-lg border border-surface-border text-gray-400 hover:text-white transition-colors">
            <RefreshCw size={16} />
          </button>
        </div>

        {/* Severity Counts */}
        <div className="grid grid-cols-5 gap-3">
          {[
            { key: 'critical', count: severityCounts.critical, color: 'bg-red-500', textColor: 'text-red-400' },
            { key: 'high', count: severityCounts.high, color: 'bg-orange-500', textColor: 'text-orange-400' },
            { key: 'medium', count: severityCounts.medium, color: 'bg-yellow-500', textColor: 'text-yellow-400' },
            { key: 'low', count: severityCounts.low, color: 'bg-blue-500', textColor: 'text-blue-400' },
            { key: 'info', count: severityCounts.info, color: 'bg-gray-500', textColor: 'text-gray-400' },
          ].map(s => (
            <button
              key={s.key}
              onClick={() => setSeverityFilter(severityFilter === s.key ? '' : s.key)}
              className={classNames(
                'bg-surface-raised border rounded-xl p-4 text-center transition-all hover:border-cyber-600/30',
                severityFilter === s.key ? `border-${s.key === 'critical' ? 'red' : s.key === 'high' ? 'orange' : s.key === 'medium' ? 'yellow' : s.key === 'low' ? 'blue' : 'gray'}-500/40` : 'border-surface-border'
              )}
            >
              <p className={classNames('text-2xl font-bold', s.textColor)}>{s.count}</p>
              <p className="text-xs text-gray-500 mt-1 capitalize">{s.key}</p>
            </button>
          ))}
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 max-w-xs">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Search findings..."
              className="w-full bg-surface-raised border border-surface-border rounded-lg py-2 pl-9 pr-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyber-600 transition-colors"
            />
          </div>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-surface-raised border border-surface-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyber-600"
          >
            <option value="">All Categories</option>
            {categories.map(c => <option key={c} value={c}>{c.replace(/_/g, ' ')}</option>)}
          </select>
          <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
            <input
              type="checkbox"
              checked={falsePositiveOnly}
              onChange={(e) => setFalsePositiveOnly(e.target.checked)}
              className="rounded border-surface-border bg-surface-overlay text-cyber-600 focus:ring-cyber-600"
            />
            False Positives
          </label>
        </div>

        {/* Findings List */}
        {filteredFindings.length === 0 ? (
          <div className="bg-surface-raised border border-surface-border rounded-xl p-12 text-center">
            <Search size={32} className="mx-auto text-gray-600 mb-3" />
            <p className="text-white font-medium">No Findings</p>
            <p className="text-sm text-gray-500 mt-1">
              {severityFilter || categoryFilter ? 'No matches for the selected filters' : 'No findings detected yet. Run a scan to find vulnerabilities.'}
            </p>
          </div>
        ) : (
          <div className="space-y-1">
            {filteredFindings.map((finding) => {
              const isExpanded = expanded.has(finding.id);
              return (
                <div
                  key={finding.id}
                  className="bg-surface-raised border border-surface-border rounded-lg overflow-hidden hover:border-cyber-600/20 transition-colors"
                >
                  <button
                    onClick={() => toggleFinding(finding.id)}
                    className="w-full flex items-center justify-between p-4 text-left bg-surface-overlay hover:bg-surface-overlay/80 transition-colors"
                  >
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <span className={severityBadgeClass(finding.severity)}>
                        {finding.severity.toUpperCase()}
                      </span>
                      <div className="min-w-0">
                        <p className="text-sm text-white font-medium truncate">{finding.title}</p>
                        <p className="text-xs text-gray-500 mt-0.5">
                          {formatDate(finding.created_at)}
                          {finding.endpoint && <> · <code className="text-gray-600">{finding.endpoint}</code></>}
                          {finding.owasp_category && <> · OWASP: {finding.owasp_category}</>}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 ml-4 flex-shrink-0">
                      {finding.false_positive && (
                        <span className="text-xs text-yellow-400 bg-yellow-500/10 px-1.5 py-0.5 rounded">FP</span>
                      )}
                      <span className={categoryBadgeClass(finding.category)}>
                        {finding.category.replace(/_/g, ' ')}
                      </span>
                      {isExpanded ? <ChevronDown size={14} className="text-gray-500" /> : <ChevronRight size={14} className="text-gray-500" />}
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="p-4 border-t border-surface-border space-y-3 animate-fade-in">
                      {finding.description && (
                        <div>
                          <p className="text-xs text-gray-500 mb-1">Description</p>
                          <p className="text-sm text-gray-300">{finding.description}</p>
                        </div>
                      )}
                      {finding.evidence && (
                        <div>
                          <p className="text-xs text-gray-500 mb-1">Evidence</p>
                          <pre className="text-xs text-gray-400 bg-surface p-3 rounded-lg overflow-x-auto max-h-48 overflow-y-auto font-mono">
                            {JSON.stringify(finding.evidence, null, 2)}
                          </pre>
                        </div>
                      )}
                      {finding.remediation && (
                        <div className="flex items-start gap-2 p-3 rounded-lg bg-cyber-600/5 border border-cyber-600/20">
                          <Lightbulb size={14} className="text-cyber-400 mt-0.5 flex-shrink-0" />
                          <div>
                            <p className="text-xs text-cyber-400 font-medium mb-1">Remediation</p>
                            <p className="text-sm text-gray-300">{finding.remediation}</p>
                          </div>
                        </div>
                      )}
                      <div className="flex flex-wrap items-center gap-3 text-xs text-gray-600">
                        {finding.cve_id && (
                          <a href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${finding.cve_id}`} target="_blank" rel="noopener noreferrer"
                            className="flex items-center gap-1 text-cyber-400 hover:text-cyber-300">
                            {finding.cve_id} <ExternalLink size={10} />
                          </a>
                        )}
                        {finding.cwe_id && <span>CWE-{finding.cwe_id}</span>}
                        <span>Category: {finding.category}</span>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AppLayout>
  );
}
