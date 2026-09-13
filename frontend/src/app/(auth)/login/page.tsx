'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/context/AuthContext';
import { useRouter } from 'next/navigation';
import {
  Shield, Mail, Lock, User, Loader2, Eye, EyeOff,
  AlertTriangle, Github,
} from 'lucide-react';
import { classNames } from '@/utils/helpers';

export default function LoginPage() {
  const { user, loading: authLoading, login: authLogin } = useAuth();
  const router = useRouter();

  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!authLoading && user) {
      router.push('/dashboard');
    }
  }, [user, authLoading, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (mode === 'register') {
        await authRegister();
        setMode('login');
        setPassword('');
        setError('Registration successful! Please log in.');
      } else {
        await authLogin(email, password);
        router.push('/dashboard');
      }
    } catch (err: unknown) {
      const msg = (err as Error).message || 'An error occurred';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const authRegister = async () => {
    const res = await fetch(
      '/api/v1/auth/register',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, full_name: fullName }),
      }
    );
    if (!res.ok) {
      const data = await res.json().catch(() => ({ detail: 'Registration failed' }));
      throw new Error(data.detail || 'Registration failed');
    }
  };

  if (authLoading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <Loader2 size={32} className="text-cyber-500 animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-cyber-600 mb-4">
            <Shield size={32} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">Ch3ck3r</h1>
          <p className="text-gray-500 mt-1">Intelligent API Security Scanner</p>
        </div>

        {/* Card */}
        <div className="bg-surface-raised border border-surface-border rounded-2xl p-8 shadow-2xl">
          {/* Tabs */}
          <div className="flex mb-6 bg-surface-overlay rounded-lg p-1">
            {(['login', 'register'] as const).map((m) => (
              <button
                key={m}
                onClick={() => { setMode(m); setError(''); }}
                className={classNames(
                  'flex-1 py-2 text-sm font-medium rounded-md transition-all',
                  mode === m
                    ? 'bg-cyber-600 text-white shadow-sm'
                    : 'text-gray-500 hover:text-gray-300'
                )}
              >
                {m === 'login' ? 'Sign In' : 'Register'}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'register' && (
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">Full Name</label>
                <div className="relative">
                  <User size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="John Doe"
                    className="w-full bg-surface-overlay border border-surface-border rounded-lg py-2.5 pl-10 pr-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyber-600 focus:ring-1 focus:ring-cyber-600/30 transition-colors"
                    required={mode === 'register'}
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-sm text-gray-400 mb-1.5">Email</label>
              <div className="relative">
                <Mail size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  className="w-full bg-surface-overlay border border-surface-border rounded-lg py-2.5 pl-10 pr-3 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyber-600 focus:ring-1 focus:ring-cyber-600/30 transition-colors"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-1.5">Password</label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-surface-overlay border border-surface-border rounded-lg py-2.5 pl-10 pr-10 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyber-600 focus:ring-1 focus:ring-cyber-600/30 transition-colors"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                >
                  {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {error && (
              <div className={classNames(
                'flex items-start gap-2 p-3 rounded-lg border',
                error.includes('successful')
                  ? 'bg-green-500/10 border-green-500/20 text-green-400'
                  : 'bg-red-500/10 border-red-500/20 text-red-400'
              )}>
                <AlertTriangle size={14} className="mt-0.5 flex-shrink-0" />
                <p className="text-sm">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-cyber-600 text-white text-sm font-medium hover:bg-cyber-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
            >
              {loading && <Loader2 size={14} className="animate-spin" />}
              {loading ? 'Please wait...' : mode === 'login' ? 'Sign In' : 'Create Account'}
            </button>
          </form>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-gray-700 mt-6">
          <strong>Ch3ck3r</strong> — Intelligent API Security Scanner
          <br />
          Author: <span className="text-gray-600">Msambili Ndaga</span> — @remnant01
        </p>
      </div>
    </div>
  );
}
