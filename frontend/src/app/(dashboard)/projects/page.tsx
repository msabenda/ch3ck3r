'use client';

import { useState, useEffect, useCallback } from 'react';
import AppLayout from '@/components/layout/AppLayout';
import {
  Search, Plus, Filter, Loader2, ChevronRight,
  AlertTriangle, CheckCircle2, RefreshCw,
} from 'lucide-react';
import { projectsApi, scansApi } from '@/lib/api';
import { formatDate, classNames } from '@/utils/helpers';
import type { Project, Scan } from '@/types';
import Link from 'next/link';

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const [p, s] = await Promise.all([
        projectsApi.list(),
        scansApi.list({ limit: '100' }),
      ]);
      setProjects(p || []);
      setScans(s || []);
    } catch (err) {
      setError('Failed to load projects');
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const getProjectScans = (projectId: string) => scans.filter(s => s.project_id === projectId);
  const getLatestScan = (projectId: string) => {
    const projectScans = getProjectScans(projectId)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return projectScans[0] || null;
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
            <h1 className="text-2xl font-bold text-white">Projects</h1>
            <p className="text-gray-400 mt-1">Manage your API scanning projects and repositories</p>
          </div>
          <Link
            href="/repositories"
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyber-600 text-white text-sm hover:bg-cyber-500 transition-colors"
          >
            <Plus size={16} />
            New Project
          </Link>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          <div className="bg-surface-raised border border-surface-border rounded-xl p-4">
            <p className="text-sm text-gray-500">Total</p>
            <p className="text-2xl font-bold text-white mt-1">{projects.length}</p>
          </div>
          <div className="bg-surface-raised border border-surface-border rounded-xl p-4">
            <p className="text-sm text-gray-500">GitHub Connected</p>
            <p className="text-2xl font-bold text-cyber-400 mt-1">
              {projects.filter(p => p.repository_url).length}
            </p>
          </div>
          <div className="bg-surface-raised border border-surface-border rounded-xl p-4">
            <p className="text-sm text-gray-500">Scans Run</p>
            <p className="text-2xl font-bold text-white mt-1">{scans.length}</p>
          </div>
          <div className="bg-surface-raised border border-surface-border rounded-xl p-4">
            <p className="text-sm text-gray-500">Avg Risk Score</p>
            <p className="text-2xl font-bold text-cyber-400 mt-1">
              {scans.length > 0
                ? (scans.reduce((a, s) => a + (s.risk_score || 0), 0) / scans.filter(s => s.risk_score).length || 0).toFixed(1)
                : 'N/A'}
            </p>
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
            <AlertTriangle size={16} className="text-red-400" />
            <p className="text-sm text-red-400">{error}</p>
            <button onClick={load} className="ml-auto text-red-400 hover:text-red-300">
              <RefreshCw size={14} />
            </button>
          </div>
        )}

        {/* Projects Grid */}
        {projects.length === 0 ? (
          <div className="bg-surface-raised border border-surface-border rounded-xl p-12 text-center">
            <Search size={32} className="mx-auto text-gray-600 mb-3" />
            <h3 className="text-lg text-white font-medium mb-2">No Projects</h3>
            <p className="text-sm text-gray-500">
              Create a project by connecting a GitHub repository or running a scan.
            </p>
          </div>
        ) : (
          <div className="grid gap-3">
            {projects.map((project) => {
              const latest = getLatestScan(project.id);
              const projectScans = getProjectScans(project.id);
              const completedScans = projectScans.filter(s => s.status === 'completed');
              const totalFinds = completedScans.reduce((a, s) => a + (s.total_findings || 0), 0);

              return (
                <div
                  key={project.id}
                  className="bg-surface-raised border border-surface-border rounded-xl p-5 hover:border-cyber-600/20 transition-all"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <h3 className="text-white font-medium">{project.name}</h3>
                        {project.repository_url && (
                          <span className="text-xs text-cyber-400 bg-cyber-600/10 px-2 py-0.5 rounded-full">
                            GitHub
                          </span>
                        )}
                      </div>
                      {project.description && (
                        <p className="text-sm text-gray-500 mt-1">{project.description}</p>
                      )}
                      {project.repository_url && (
                        <p className="text-xs text-gray-600 font-mono mt-1 truncate">
                          {project.repository_url}
                        </p>
                      )}
                      <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
                        <span>{projectScans.length} scan{projectScans.length !== 1 ? 's' : ''}</span>
                        <span>{totalFinds} finding{totalFinds !== 1 ? 's' : ''}</span>
                        <span>Created {formatDate(project.created_at)}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 ml-4">
                      {latest && (
                        <span className={classNames(
                          'text-xs font-mono font-bold',
                          latest.risk_score !== null && latest.risk_score >= 7 ? 'text-red-400' :
                          latest.risk_score !== null && latest.risk_score >= 4 ? 'text-orange-400' :
                          'text-green-400'
                        )}>
                          Score: {latest.risk_score?.toFixed(1) || 'N/A'}
                        </span>
                      )}
                      <Link
                        href={`/scans?project=${project.id}`}
                        className="text-xs text-cyber-400 hover:text-cyber-300"
                      >
                        View scans <ChevronRight size={12} className="inline" />
                      </Link>
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
