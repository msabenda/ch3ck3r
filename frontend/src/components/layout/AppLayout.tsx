'use client';

import Sidebar from '@/components/layout/Sidebar';
import { useAuth } from '@/context/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { Shield, Loader2 } from 'lucide-react';
import OnboardingTour from '@/components/onboarding/OnboardingTour';

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) {
      router.push('/login');
    }
  }, [user, loading, router]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-surface dark:bg-surface" style={{ backgroundColor: 'var(--bg-primary)' }}>
        <div className="flex items-center gap-3">
          <Loader2 size={24} className="text-cyber-500 animate-spin" />
          <span className="text-gray-400">Loading...</span>
        </div>
      </div>
    );
  }

  if (!user) return null;

  return (
    <div className="flex min-h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <Sidebar />
      <main data-layout-main className="flex-1 ml-64 p-6 lg:p-8">
        <OnboardingTour />
        {children}
      </main>
    </div>
  );
}
