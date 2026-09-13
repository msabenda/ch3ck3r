'use client';

import { useState, useEffect } from 'react';
import AppLayout from '@/components/layout/AppLayout';
import {
  GitBranch, Plus, Loader2, CheckCircle2, XCircle, ExternalLink,
  Shield, Clock, AlertTriangle, Trash2, Search, FileText,
  Lock, Globe, ChevronRight, Link as LinkIcon, X,
} from 'lucide-react';
import { api, projectsApi } from '@/lib/api';
import { formatDate, classNames } from '@/utils/helpers';
import type { Project } from '@/types';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

interface ConnectModalProps {
  open: boolean;
  onClose: () => void;
  onConnected: () => void;
}

function ConnectModal({ open, onClose, onConnected }: ConnectModalProps) {
  const [url, setUrl] = useState('');
  const [token, setToken] = useState('');
  const [branch, setBranch] = useState('main');
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState('');
  const [repoInfo, setRepoInfo] = useState<Record<string, unknown> | null>(null);

  const handleConnect = async () => {
    setError('');
    setConnecting(true);

    try {
      // Verify via GitHub API
      const resp = await api('/github/connect', { method: 'POST', body: JSON.stringify({
        repository_url: url,
        token,
        branch,
      }) });

      const data = resp as unknown as Record<string, unknown>;
      setRepoInfo(data);

      // Now create the project in Ch3ck3r
      await projectsApi.create({
        name: data.full_name as string || url.split('/').pop()?.replace('.git', '') || 'repo',
        description: (data.description as string) || `GitHub repository: ${url}`,
        repository_url: url,
      });

      onConnected();
      onClose();
      setUrl('');
      setToken('');
      setBranch('main');
      setRepoInfo(null);
    } catch (err: unknown) {
      const e = err as { response?: { data?: { detail?: string } } };
      setError(e?.response?.data?.detail || 'Failed to connect repository');
    } finally {
      setConnecting(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-surface-raised border border-surface-border rounded-xl w-full max-w-lg mx-4 animate-slide-up">
        <div className="flex items-center justify-between p-5 border-b border-surface-border">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyber-600/10">
              <GitBranch size={18} className="text-cyber-400" />
            </div>
            <h2 className="text-lg font-semibold text-white">Connect GitHub Repository</h2>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-surface-overlay text-gray-400">
            <X size={18} />
          </button>
        </div>

        {repoInfo ? (
          <div className="p-5 space-y-4">
            <div className="flex items-center gap-3 p-3 rounded-lg bg-green-500/10 border border-green-500/20">
              <CheckCircle2 size={20} className="text-green-400 flex-shrink-0" />
              <div>
                <p className="text-sm text-white font-medium">
                  {(repoInfo.full_name as string) || 'Repository'} verified
                </p>
                <p className="text-xs text-gray-500 mt-0.5">
                  {repoInfo.private ? 'Private repo' : 'Public repo'} · Language: {repoInfo.language as string || 'N/A'} · {repoInfo.stars as number} stars
                </p>
              </div>
            </div>
            {!connecting && (
              <div className="flex gap-2 justify-end">
                <button
                  onClick={() => setRepoInfo(null)}
                  className="px-4 py-2 rounded-lg border border-surface-border text-sm text-gray-400 hover:text-white transition-colors"
                >
                  Back
                </button>
                <button
                  onClick={handleConnect}
                  className="px-4 py-2 rounded-lg bg-cyber-600 text-white text-sm hover:bg-cyber-500 transition-colors"
                >
                  Create Project & Connect
                </button>
              </div>
            )}
            {connecting && (
              <div className="flex items-center justify-center py-4">
                <Loader2 size={20} className="text-cyber-400 animate-spin" />
                <span className="ml-2 text-sm text-gray-400">Creating project...</span>
              </div>
            )}
          </div>
        ) : (
          <form onSubmit={(e) => { e.preventDefault(); handleConnect(); }} className="p-5 space-y-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1.5">Repository URL</label>
              <div className="relative">
                <LinkIcon size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://github.com/owner/repository"
                  className="w-full bg-surface-overlay border border-surface-border rounded-lg py-2.5 pl-10 pr-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyber-600 focus:ring-1 focus:ring-cyber-600/30 transition-colors"
                  required
                />
              </div>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1.5">Personal Access Token</label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                <input
                  type="password"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                  className="w-full bg-surface-overlay border border-surface-border rounded-lg py-2.5 pl-10 pr-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyber-600 focus:ring-1 focus:ring-cyber-600/30 transition-colors"
                  required
                />
              </div>
              <p className="text-xs text-gray-600 mt-1">
                Token needs `repo` scope for private repos or `public_repo` for public
              </p>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1.5">Branch</label>
              <input
                type="text"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                className="w-full bg-surface-overlay border border-surface-border rounded-lg py-2.5 px-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyber-600 focus:ring-1 focus:ring-cyber-600/30 transition-colors"
              />
            </div>

            {error && (
              <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                <AlertTriangle size={16} className="text-red-400 mt-0.5 flex-shrink-0" />
                <p className="text-sm text-red-400">{error}</p>
              </div>
            )}

            <div className="flex gap-2 justify-end pt-2">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 rounded-lg border border-surface-border text-sm text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={connecting || !url || !token}
                className="px-4 py-2 rounded-lg bg-cyber-600 text-white text-sm hover:bg-cyber-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
              >
                {connecting ? <Loader2 size={14} className="animate-spin" /> : null}
                {connecting ? 'Verifying...' : 'Verify & Connect'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

export default function RepositoriesPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [showConnect, setShowConnect] = useState(false);
  const router = useRouter();

  const loadProjects = async () => {
    try {
      const data = await projectsApi.list();
      setProjects(data || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadProjects(); }, []);

  const repos = projects;

  const runScan = async (projectId: string) => {
    try {
      const resp = await fetch('/api/v1/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${localStorage.getItem('ch3ck3r_token')}` },
        body: JSON.stringify({ project_id: projectId, scan_type: 'semgrep', target: 'repository' }),
      });
      const data = await resp.json();
      router.push(`/scans/${data.id}`);
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
            <h1 id="tour-repos" className="text-2xl font-bold text-white">GitHub Repositories</h1>
            <p className="text-gray-400 mt-1">
              Connect repositories for automated API security scanning
            </p>
          </div>
          <button
            onClick={() => setShowConnect(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyber-600 text-white text-sm hover:bg-cyber-500 transition-colors"
          >
            <Plus size={16} />
            Connect Repository
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bg-surface-raised border border-surface-border rounded-xl p-4">
            <p className="text-sm text-gray-500">Total Connected</p>
            <p className="text-2xl font-bold text-white mt-1">{repos.length}</p>
          </div>
          {/* Rest are visual */}
          <div className="bg-surface-raised border border-surface-border rounded-xl p-4">
            <p className="text-sm text-gray-500">Scanned</p>
            <p className="text-2xl font-bold text-cyber-400 mt-1">
              {repos.filter((r) => r.updated_at !== r.created_at).length}
            </p>
          </div>
          <div className="bg-surface-raised border border-surface-border rounded-xl p-4">
            <p className="text-sm text-gray-500">Awaiting Scan</p>
            <p className="text-2xl font-bold text-yellow-400 mt-1">
              {repos.filter((r) => r.updated_at === r.created_at).length}
            </p>
          </div>
        </div>

        {/* Repo List */}
        {repos.length === 0 ? (
          <div className="bg-surface-raised border border-surface-border rounded-xl p-12">
            <div className="flex flex-col items-center text-center">
              <div className="p-4 rounded-full bg-cyber-600/10 mb-4">
                <GitBranch size={32} className="text-cyber-400" />
              </div>
              <h3 className="text-lg font-medium text-white mb-2">No Repositories Connected</h3>
              <p className="text-sm text-gray-500 max-w-md mb-6">
                Connect your GitHub repositories to automatically scan for API vulnerabilities,
                SAST issues, and OWASP API Top 10 security risks.
              </p>
              <button
                onClick={() => setShowConnect(true)}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyber-600 text-white text-sm hover:bg-cyber-500 transition-colors"
              >
                <Plus size={16} />
                Connect Your First Repository
              </button>
            </div>
          </div>
        ) : (
          <div className="grid gap-4">
            {repos.map((repo) => (
              <div
                key={repo.id}
                className="bg-surface-raised border border-surface-border rounded-xl p-5 hover:border-cyber-600/20 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-3">
                    <div className="p-2 rounded-lg bg-cyber-600/10">
                      <GitBranch size={18} className="text-cyber-400" />
                    </div>
                    <div>
                      <Link href={`/projects/${repo.id}`} className="text-white font-medium hover:text-cyber-400 transition-colors">
                        {repo.name}
                      </Link>
                      {repo.repository_url && (
                        <a
                          href={repo.repository_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-xs text-gray-500 hover:text-cyber-400 mt-0.5"
                        >
                          <ExternalLink size={12} />
                          {repo.repository_url}
                        </a>
                      )}
                      {repo.description && (
                        <p className="text-xs text-gray-500 mt-1 max-w-lg">{repo.description}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-600">
                      Connected {formatDate(repo.created_at)}
                    </span>
                    <button
                      onClick={() => runScan(repo.id)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-600/10 text-cyber-400 text-xs hover:bg-cyber-600/20 border border-cyber-600/20 hover:border-cyber-600/30 transition-all"
                    >
                      <Shield size={12} />
                      Scan Now
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* OWASP API Top 10 Coverage */}
        <div className="bg-surface-raised border border-surface-border rounded-xl p-5">
          <h2 className="text-lg font-semibold text-white mb-4">OWASP API Top 10 Coverage</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {[
              { num: 'API1', title: 'Broken Object Level Auth', severity: 'critical' },
              { num: 'API2', title: 'Broken Authentication', severity: 'critical' },
              { num: 'API3', title: 'Broken Object Property Level', severity: 'high' },
              { num: 'API4', title: 'Unrestricted Resource Consumption', severity: 'medium' },
              { num: 'API5', title: 'Broken Function Level Auth', severity: 'critical' },
              { num: 'API6', title: 'Unrestricted Access to Sensitive', severity: 'high' },
              { num: 'API7', title: 'Server Side Request Forgery', severity: 'critical' },
              { num: 'API8', title: 'Security Misconfiguration', severity: 'medium' },
              { num: 'API9', title: 'Improper Inventory Management', severity: 'low' },
              { num: 'API10', title: 'Unsafe Consumption of APIs', severity: 'high' },
            ].map((item) => (
              <div
                key={item.num}
                className={classNames(
                  'p-3 rounded-lg border',
                  item.severity === 'critical' ? 'bg-red-500/5 border-red-500/20' :
                  item.severity === 'high' ? 'bg-orange-500/5 border-orange-500/20' :
                  item.severity === 'medium' ? 'bg-yellow-500/5 border-yellow-500/20' :
                  'bg-blue-500/5 border-blue-500/20'
                )}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className={classNames(
                    'text-xs font-mono font-bold',
                    item.severity === 'critical' ? 'text-red-400' :
                    item.severity === 'high' ? 'text-orange-400' :
                    item.severity === 'medium' ? 'text-yellow-400' :
                    'text-blue-400'
                  )}>
                    {item.num}
                  </span>
                  <CheckCircle2 size={14} className="text-green-400" />
                </div>
                <p className="text-xs text-gray-400">{item.title}</p>
              </div>
            ))}
          </div>
          <p className="text-xs text-gray-600 mt-3">
            ✓ All OWASP API Top 10 categories covered by Ch3ck3r scanner plugins
          </p>
        </div>
      </div>

      <ConnectModal
        open={showConnect}
        onClose={() => setShowConnect(false)}
        onConnected={loadProjects}
      />
    </AppLayout>
  );
}
