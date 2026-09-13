'use client';

import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { User } from '@/types';
import { api, clearTokens, login as apiLogin } from '@/lib/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  isAdmin: boolean;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  loading: true,
  login: async () => {},
  logout: () => {},
  isAdmin: false,
});

function safeGetItem(key: string): string | null {
  if (typeof window === 'undefined') return null;
  try { return localStorage.getItem(key); } catch { return null; }
}

function safeSetItem(key: string, value: string) {
  if (typeof window === 'undefined') return;
  try { localStorage.setItem(key, value); } catch { /* noop */ }
}

function safeRemoveItem(key: string) {
  if (typeof window === 'undefined') return;
  try { localStorage.removeItem(key); } catch { /* noop */ }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState<string | null>(null);

  // Hydrate token from localStorage on mount only (safe from SSR)
  useEffect(() => {
    const t = safeGetItem('ch3ck3r_access_token');
    if (t) setToken(t);
  }, []);

  const fetchUser = useCallback(async () => {
    try {
      const t = safeGetItem('ch3ck3r_access_token');
      if (!t) {
        setLoading(false);
        return;
      }
      const u = await api<User>('/auth/me');
      setUser(u);
    } catch {
      clearTokens();
      setToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  const login = async (email: string, password: string) => {
    const tokens = await apiLogin(email, password);
    if (!tokens) throw new Error('Login failed');
    safeSetItem('ch3ck3r_access_token', tokens.access_token);
    setToken(tokens.access_token);
    await fetchUser();
  };

  const logout = () => {
    clearTokens();
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        login,
        logout,
        isAdmin: user?.role === 'admin',
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
