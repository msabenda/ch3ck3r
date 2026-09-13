// ─── API Client ─────────────────────────────────────────────────

// In the browser, use relative URLs so Next.js rewrites proxy requests.
// On the server (SSR), use the absolute API_BASE.
const API_BASE = typeof window !== 'undefined'
  ? ''
  : (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000');

interface FetchOptions extends RequestInit {
  skipAuth?: boolean;
}

function getTokens(): { access: string | null; refresh: string | null } {
  if (typeof window === 'undefined') return { access: null, refresh: null };
  try {
    return {
      access: localStorage.getItem('ch3ck3r_access_token'),
      refresh: localStorage.getItem('ch3ck3r_refresh_token'),
    };
  } catch { return { access: null, refresh: null }; }
}

function setTokens(access: string, refresh: string) {
  localStorage.setItem('ch3ck3r_access_token', access);
  localStorage.setItem('ch3ck3r_refresh_token', refresh);
}

export function clearTokens() {
  localStorage.removeItem('ch3ck3r_access_token');
  localStorage.removeItem('ch3ck3r_refresh_token');
}

export function isAuthenticated(): boolean {
  const { access } = getTokens();
  return !!access;
}

async function refreshToken(): Promise<boolean> {
  const { refresh } = getTokens();
  if (!refresh) return false;
  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refresh }),
    });
    if (!res.ok) {
      clearTokens();
      return false;
    }
    const data = await res.json();
    setTokens(data.access_token, data.refresh_token);
    return true;
  } catch {
    clearTokens();
    return false;
  }
}

export async function api<T>(
  path: string,
  options: FetchOptions = {}
): Promise<T> {
  const { skipAuth, ...fetchOptions } = options;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(fetchOptions.headers as Record<string, string>),
  };

  if (!skipAuth) {
    const { access } = getTokens();
    if (access) {
      headers['Authorization'] = `Bearer ${access}`;
    }
  }

  const res = await fetch(`${API_BASE}/api/v1${path}`, {
    ...fetchOptions,
    headers,
  });

  if (res.status === 401 && !skipAuth) {
    const refreshed = await refreshToken();
    if (refreshed) {
      return api<T>(path, options);
    }
    // If refresh fails, redirect to login
    if (typeof window !== 'undefined') {
      window.location.href = '/login';
    }
    throw new Error('Session expired');
  }

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(error.detail || `Request failed: ${res.status}`);
  }

  if (res.status === 204) return {} as T;
  return res.json();
}

// ─── Auth API ───────────────────────────────────────────────────

export async function login(email: string, password: string) {
  const data = await api<{ access_token: string; refresh_token: string }>(
    '/auth/login',
    {
      method: 'POST',
      body: JSON.stringify({ email, password }),
      skipAuth: true,
    }
  );
  setTokens(data.access_token, data.refresh_token);
  return data;
}

export async function register(
  email: string,
  password: string,
  full_name: string
) {
  return api('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password, full_name }),
    skipAuth: true,
  });
}

// ─── Resource APIs ──────────────────────────────────────────────

export const projectsApi = {
  list: () => api<any[]>('/projects'),
  create: (data: { name: string; description?: string; repository_url?: string }) =>
    api<any>('/projects', { method: 'POST', body: JSON.stringify(data) }),
  get: (id: string) => api<any>(`/projects/${id}`),
  update: (id: string, data: any) =>
    api<any>(`/projects/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  delete: (id: string) =>
    api<void>(`/projects/${id}`, { method: 'DELETE' }),
};

export const scansApi = {
  list: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return api<any[]>(`/scans${qs}`);
  },
  create: (data: { project_id: string; scan_type: string; target: string }) =>
    api<any>('/scans', { method: 'POST', body: JSON.stringify(data) }),
  get: (id: string) => api<any>(`/scans/${id}`),
  execute: (id: string) =>
    api<any>(`/scans/${id}/execute`, { method: 'POST' }),
  stats: () => api<any>('/scans/stats/overview'),
};

export const findingsApi = {
  list: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return api<any[]>(`/findings${qs}`);
  },
  update: (id: string, data: { false_positive?: boolean }) =>
    api<any>(`/findings/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
};

export const reportsApi = {
  list: (scanId: string) => api<any[]>(`/reports/${scanId}`),
  generate: (scanId: string, format: string = 'json') =>
    api<any>(`/reports/${scanId}/generate`, {
      method: 'POST',
      body: JSON.stringify({ report_format: format }),
    }),
};
