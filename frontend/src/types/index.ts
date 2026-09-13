// ─── API Types ─────────────────────────────────────────────────

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: 'admin' | 'scanner' | 'viewer';
  is_active: boolean;
  created_at: string;
}

export interface Project {
  id: string;
  name: string;
  description: string | null;
  repository_url: string | null;
  user_id: string;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  project_id: string;
  user_id: string;
  scan_type: 'openapi' | 'zap' | 'nuclei' | 'semgrep' | 'full';
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  risk_score: number | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  description: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  owasp_category: string | null;
  endpoint: string | null;
  evidence: Record<string, unknown> | null;
  remediation: string | null;
  cve_id: string | null;
  cwe_id: number | null;
  false_positive: boolean;
  created_at: string;
}

export interface Report {
  id: string;
  scan_id: string;
  project_id: string;
  format: string;
  summary: Record<string, unknown> | null;
  file_path: string | null;
  created_at: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface ScanStats {
  total_scans: number;
  total_findings: number;
  avg_risk_score: number;
}

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Repository {
  id: string;
  name: string;
  url: string;
  owner: string;
  branch: string;
  private: boolean;
  last_scan_at: string | null;
  finding_count: number;
  status: 'connected' | 'scanning' | 'error';
}

export interface ReportDetail {
  scan_id: string;
  scan_type: string;
  target: string;
  risk_score: number | null;
  total_findings: number;
  severity_breakdown: SeverityBreakdown;
  findings: FindingDetail[];
  categories: Record<string, CategorySummary>;
  generated_at: string;
  recommendations: Recommendation[];
  author: string;
  tool: string;
  disclaimer: string;
}

export interface FindingDetail {
  id: string;
  title: string;
  severity: string;
  category: string;
  owasp_category: string | null;
  endpoint: string | null;
  description: string | null;
  evidence: Record<string, unknown> | null;
  remediation: string | null;
  cve_id: string | null;
  cwe_id: number | null;
}

export interface CategorySummary {
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Recommendation {
  priority: number;
  title: string;
  description: string;
}

export interface ChainInfo {
  name: string;
  description: string;
  scanners: string[];
}

export interface DiffResult {
  new_findings: Finding[];
  fixed_findings: Finding[];
  recurring_findings: Finding[];
  severity_changes: Finding[];
  risk_score_delta: number;
}

// ─── Severity Utilities ────────────────────────────────────────

export const severityColors: Record<string, string> = {
  critical: 'bg-red-600 text-red-50 border-red-500',
  high: 'bg-orange-600 text-orange-50 border-orange-500',
  medium: 'bg-yellow-600 text-yellow-50 border-yellow-500',
  low: 'bg-blue-600 text-blue-50 border-blue-500',
  info: 'bg-gray-600 text-gray-100 border-gray-500',
};

export const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};
