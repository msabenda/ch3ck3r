'use client';

import { useState, useRef } from 'react';
import AppLayout from '@/components/layout/AppLayout';
import {
  Upload, FileJson, FileText, CheckCircle2, AlertTriangle,
  Loader2, Search, ExternalLink, ChevronRight, UploadCloud,
  Code, File, List, Activity, ArrowRight, X,
} from 'lucide-react';
import { api } from '@/lib/api';
import { classNames, formatDate } from '@/utils/helpers';
import Link from 'next/link';

interface DetectionResult {
  filename: string;
  size_bytes: number;
  format: string | null;
  endpoints: string[];
  spec_info: Record<string, unknown>;
}

interface ParseResult {
  status: string;
  source: string;
  endpoint_count: number;
  base_url: string;
  endpoints: Array<{
    method: string;
    path: string;
    url: string;
    summary: string;
    parameters: unknown[];
  }>;
}

const formatIcons: Record<string, React.ElementType> = {
  'openapi-3.x': FileJson,
  'openapi-3.x-yaml': FileJson,
  'swagger-2.x': FileJson,
  'swagger-2.x-yaml': FileJson,
  'postman-collection-v2': Code,
  'har': Activity,
  'api-blueprint': FileText,
  'raml': FileText,
};

const formatColors: Record<string, string> = {
  'openapi-3.x': 'text-green-400 bg-green-500/10',
  'openapi-3.x-yaml': 'text-green-400 bg-green-500/10',
  'swagger-2.x': 'text-blue-400 bg-blue-500/10',
  'swagger-2.x-yaml': 'text-blue-400 bg-blue-500/10',
  'postman-collection-v2': 'text-orange-400 bg-orange-500/10',
  'har': 'text-purple-400 bg-purple-500/10',
  'api-blueprint': 'text-cyan-400 bg-cyan-500/10',
  'raml': 'text-rose-400 bg-rose-500/10',
};

const methodColors: Record<string, string> = {
  GET: 'bg-green-500/20 text-green-400',
  POST: 'bg-blue-500/20 text-blue-400',
  PUT: 'bg-orange-500/20 text-orange-400',
  PATCH: 'bg-cyan-500/20 text-cyan-400',
  DELETE: 'bg-red-500/20 text-red-400',
  HEAD: 'bg-gray-500/20 text-gray-400',
  OPTIONS: 'bg-purple-500/20 text-purple-400',
};

export default function ImportPage() {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [loading, setLoading] = useState(false);
  const [detected, setDetected] = useState<DetectionResult | null>(null);
  const [parsed, setParsed] = useState<ParseResult | null>(null);
  const [error, setError] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const handleFile = async (file: File) => {
    setSelectedFile(file);
    setLoading(true);
    setError('');
    setDetected(null);
    setParsed(null);

    // First detect format
    const formData = new FormData();
    formData.append('file', file);

    try {
      const detectResp = await fetch(
        `/api/v1/imports/detect`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${localStorage.getItem('ch3ck3r_access_token')}`,
          },
          body: formData,
        }
      );

      if (!detectResp.ok) {
        const errData = await detectResp.json().catch(() => ({}));
        throw new Error(
          (errData as Record<string, unknown>).detail as string ||
            'Failed to detect format'
        );
      }

      const detectData: DetectionResult = await detectResp.json();
      setDetected(detectData);

      // Then parse
      const parseForm = new FormData();
      parseForm.append('file', file);

      const parseResp = await fetch(
        `/api/v1/imports/parse`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${localStorage.getItem('ch3ck3r_access_token')}`,
          },
          body: parseForm,
        }
      );

      if (!parseResp.ok) {
        const errData = await parseResp.json().catch(() => ({}));
        throw new Error(
          (errData as Record<string, unknown>).detail as string ||
            'Failed to parse specification'
        );
      }

      const parseData: ParseResult = await parseResp.json();
      setParsed(parseData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFile(files[0]);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFile(files[0]);
    }
  };

  const reset = () => {
    setSelectedFile(null);
    setDetected(null);
    setParsed(null);
    setError('');
  };

  return (
    <AppLayout>
      <div className="space-y-6 animate-fade-in">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">
            Import API Specification
          </h1>
          <p className="text-[var(--text-secondary)] mt-1">
            Upload OpenAPI/Swagger specs, Postman collections, or HAR files
            for automated API security scanning
          </p>
        </div>

        {/* Drop Zone */}
        <div
          id="tour-import"
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={classNames(
            'border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all',
            dragOver
              ? 'border-cyber-400 bg-cyber-600/5'
              : 'border-[var(--bg-border)] hover:border-cyber-600/40',
            loading ? 'pointer-events-none opacity-60' : '',
            'bg-[var(--bg-raised)]'
          )}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,.yaml,.yml,.har,.apib,.raml"
            onChange={handleFileSelect}
            className="hidden"
          />

          {loading ? (
            <div className="flex flex-col items-center gap-3">
              <Loader2 size={36} className="text-cyber-400 animate-spin" />
              <p className="text-base text-[var(--text-secondary)]">
                Analyzing specification...
              </p>
              <p className="text-sm text-[var(--text-muted)]">
                Auto-detecting format and extracting endpoints
              </p>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-3">
              <div className="p-4 rounded-full bg-cyber-600/10">
                <UploadCloud size={36} className="text-cyber-400" />
              </div>
              <p className="text-base text-[var(--text-primary)] font-medium">
                Drop your API specification file here
              </p>
              <p className="text-sm text-[var(--text-muted)]">
                or click to browse · Supports OpenAPI, Swagger, Postman, HAR, API Blueprint, RAML
              </p>
              <div className="flex flex-wrap gap-2 mt-2">
                {['OpenAPI JSON/YAML', 'Swagger', 'Postman', 'HAR', 'API Blueprint', 'RAML'].map(
                  (fmt) => (
                    <span
                      key={fmt}
                      className="text-xs px-2.5 py-1 rounded-full bg-cyber-600/10 text-cyber-400 border border-cyber-600/20"
                    >
                      {fmt}
                    </span>
                  )
                )}
              </div>
            </div>
          )}
        </div>

        {error && (
          <div className="flex items-start gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20">
            <AlertTriangle size={16} className="text-red-400 mt-0.5 flex-shrink-0" />
            <div className="flex-1">
              <p className="text-sm font-medium text-red-400">Import Failed</p>
              <p className="text-sm text-[var(--text-secondary)] mt-1">{error}</p>
            </div>
            <button onClick={reset} className="text-red-400 hover:text-red-300 text-sm">
              Try Again
            </button>
          </div>
        )}

        {/* Detection Results */}
        {detected && parsed && (
          <div className="space-y-4">
            {/* File Info */}
            <div className="bg-[var(--bg-raised)] border border-[var(--bg-border)] rounded-xl p-5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div
                    className={classNames(
                      'p-2 rounded-lg',
                      formatColors[detected.format || ''] || 'bg-gray-500/10 text-gray-400'
                    )}
                  >
                    {detected.format && (() => {
                      const Icon = formatIcons[detected.format] || File;
                      return <Icon size={18} />;
                    })()}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-[var(--text-primary)]">
                      {selectedFile?.name}
                    </p>
                    <p className="text-xs text-[var(--text-muted)] mt-0.5">
                      {detected.format || 'Unknown format'} ·{' '}
                      {(detected.size_bytes / 1024).toFixed(1)} KB ·{' '}
                      {parsed.endpoint_count} endpoints detected
                    </p>
                  </div>
                </div>
                <button
                  onClick={reset}
                  className="text-sm text-cyber-400 hover:text-cyber-300"
                >
                  Import another
                </button>
              </div>
            </div>

            {/* Spec Info */}
            {Object.keys(detected.spec_info).length > 0 && (
              <div className="bg-[var(--bg-raised)] border border-[var(--bg-border)] rounded-xl p-5">
                <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">
                  Specification Details
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {Object.entries(detected.spec_info).map(([key, value]) => (
                    <div key={key} className="p-3 rounded-lg bg-[var(--bg-overlay)]">
                      <p className="text-xs text-[var(--text-muted)] capitalize">
                        {key.replace(/_/g, ' ')}
                      </p>
                      <p className="text-sm text-[var(--text-primary)] font-medium mt-0.5 truncate">
                        {String(value)}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Endpoints Table */}
            {parsed.endpoints && parsed.endpoints.length > 0 && (
              <div className="bg-[var(--bg-raised)] border border-[var(--bg-border)] rounded-xl overflow-hidden">
                <div className="p-4 border-b border-[var(--bg-border)]">
                  <h3 className="text-sm font-semibold text-[var(--text-primary)]">
                    Detected Endpoints
                  </h3>
                  <p className="text-xs text-[var(--text-muted)] mt-0.5">
                    {parsed.endpoint_count} endpoints found
                    {parsed.base_url && (
                      <>
                        {' · '}Base URL:{' '}
                        <code className="text-cyber-400">{parsed.base_url}</code>
                      </>
                    )}
                  </p>
                </div>
                <div className="max-h-80 overflow-y-auto">
                  {parsed.endpoints.slice(0, 50).map((ep, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-3 px-4 py-2.5 border-b border-[var(--bg-border)] last:border-0 hover:bg-[var(--bg-overlay)] transition-colors"
                    >
                      <span
                        className={classNames(
                          'text-xs px-2 py-0.5 rounded font-mono font-medium',
                          methodColors[ep.method] || 'bg-gray-500/20 text-gray-400'
                        )}
                      >
                        {ep.method}
                      </span>
                      <code className="text-xs text-[var(--text-secondary)] truncate font-mono flex-1">
                        {ep.url || ep.path}
                      </code>
                      {ep.summary && (
                        <span className="text-xs text-[var(--text-muted)] hidden sm:block truncate max-w-[200px]">
                          {ep.summary}
                        </span>
                      )}
                    </div>
                  ))}
                  {parsed.endpoints.length > 50 && (
                    <div className="px-4 py-3 text-center text-xs text-[var(--text-muted)]">
                      Showing 50 of {parsed.endpoints.length} endpoints
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center gap-3 justify-end">
              <button
                onClick={reset}
                className="px-4 py-2.5 rounded-lg border border-[var(--bg-border)] text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
              >
                Cancel
              </button>
              <Link
                href={
                  parsed.base_url
                    ? `/scans?target=${encodeURIComponent(parsed.base_url)}`
                    : '/scans'
                }
                className="flex items-center gap-1.5 px-4 py-2.5 rounded-lg bg-cyber-600 text-white text-sm hover:bg-cyber-500 transition-colors"
              >
                <Search size={14} />
                Scan Imported APIs
                <ArrowRight size={14} />
              </Link>
            </div>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
