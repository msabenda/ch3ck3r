'use client';

import { useState, useEffect, useCallback } from 'react';
import { Shield, ChevronRight, ChevronLeft, X, Zap } from 'lucide-react';
import { classNames } from '@/utils/helpers';

interface TourStep {
  title: string;
  description: string;
  targetId: string;
  position: 'bottom' | 'top' | 'left' | 'right';
  icon?: React.ReactNode;
}

const steps: TourStep[] = [
  {
    title: 'Welcome to Ch3ck3r!',
    description:
      'Your intelligent API security scanner. This quick tour will show you how to get started securing your APIs with professional-grade scanning, AI-powered analysis, and DevSecOps integration.',
    targetId: 'tour-welcome',
    position: 'bottom',
    icon: <Shield size={24} className="text-cyber-400" />,
  },
  {
    title: 'Security Dashboard',
    description:
      'Your command center. View real-time security posture, severity breakdowns, SIEM activity feed, DevSecOps pipeline status, and risk trends across all your API scans.',
    targetId: 'tour-dashboard',
    position: 'bottom',
  },
  {
    title: 'Connect Repositories',
    description:
      'Securely connect your GitHub repositories using personal access tokens. Ch3ck3r will automatically discover API endpoints and scan for OWASP API Top 10 vulnerabilities.',
    targetId: 'tour-repos',
    position: 'bottom',
  },
  {
    title: 'Import API Specs',
    description:
      'Drag and drop OpenAPI/Swagger specs, Postman collections, or HAR files. Ch3ck3r auto-detects the format and extracts all endpoints for immediate scanning.',
    targetId: 'tour-import',
    position: 'right',
  },
  {
    title: 'Run Security Scans',
    description:
      'Launch scans against your APIs using multiple scanners — OpenAPI analysis, OWASP ZAP, Nuclei, and Semgrep. Use scan chains for multi-scanner orchestration.',
    targetId: 'tour-scans',
    position: 'bottom',
  },
  {
    title: 'Review & Remediate',
    description:
      'Findings are enriched with AI-prioritized severity, CWE/CVE references, OWASP categorization, and smart remediation recommendations. Generate professional bug bounty reports.',
    targetId: 'tour-findings',
    position: 'top',
    icon: <Zap size={20} className="text-yellow-400" />,
  },
];

export default function OnboardingTour() {
  const [active, setActive] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);
  const [targetRect, setTargetRect] = useState<DOMRect | null>(null);

  useEffect(() => {
    const done = localStorage.getItem('ch3ck3r_tour_done');
    if (!done) {
      // Delay to let page render
      const t = setTimeout(() => setActive(true), 800);
      return () => clearTimeout(t);
    }
  }, []);

  const updatePosition = useCallback(() => {
    const step = steps[stepIndex];
    if (!step) return;
    const el = document.getElementById(step.targetId);
    if (el) {
      setTargetRect(el.getBoundingClientRect());
    }
  }, [stepIndex]);

  useEffect(() => {
    if (active) updatePosition();
    window.addEventListener('resize', updatePosition);
    return () => window.removeEventListener('resize', updatePosition);
  }, [active, updatePosition]);

  const dismiss = () => {
    setActive(false);
    localStorage.setItem('ch3ck3r_tour_done', 'true');
  };

  const next = () => {
    if (stepIndex < steps.length - 1) {
      setStepIndex(stepIndex + 1);
    } else {
      dismiss();
    }
  };

  const prev = () => {
    if (stepIndex > 0) setStepIndex(stepIndex - 1);
  };

  if (!active) return null;

  const step = steps[stepIndex];
  const isLast = stepIndex === steps.length - 1;

  const getPopoverStyle = (): React.CSSProperties => {
    if (!targetRect) return { top: '40%', left: '50%', transform: 'translate(-50%, -50%)' };

    const gap = 12;
    const popoverWidth = 340;
    const popoverHeight = 200;

    let top = 0, left = 0, transform = '';

    switch (step.position) {
      case 'bottom':
        top = targetRect.bottom + gap + window.scrollY;
        left = targetRect.left + targetRect.width / 2 - popoverWidth / 2;
        break;
      case 'top':
        top = targetRect.top - popoverHeight - gap + window.scrollY;
        left = targetRect.left + targetRect.width / 2 - popoverWidth / 2;
        break;
      case 'left':
        top = targetRect.top + targetRect.height / 2 - popoverHeight / 2 + window.scrollY;
        left = targetRect.left - popoverWidth - gap;
        break;
      case 'right':
        top = targetRect.top + targetRect.height / 2 - popoverHeight / 2 + window.scrollY;
        left = targetRect.right + gap;
        break;
    }

    // Clamp to viewport
    left = Math.max(16, Math.min(left, window.innerWidth - popoverWidth - 16));
    top = Math.max(80, Math.min(top, window.innerHeight - popoverHeight - 16));

    return { position: 'fixed', top, left, width: popoverWidth, zIndex: 9999 };
  };

  return (
    <>
      {/* Overlay */}
      <div
        className="fixed inset-0 bg-black/50 z-[9997]"
        onClick={dismiss}
      />

      {/* Highlight ring around target */}
      {targetRect && (
        <div
          className="fixed z-[9998] border-2 border-cyber-400 rounded-xl animate-pulse pointer-events-none"
          style={{
            top: targetRect.top - 4 + window.scrollY,
            left: targetRect.left - 4,
            width: targetRect.width + 8,
            height: targetRect.height + 8,
          }}
        />
      )}

      {/* Popover */}
      <div
        className="bg-[#1e1e1e] border border-[#2a2a2a] rounded-2xl shadow-2xl animate-slide-up overflow-hidden"
        style={getPopoverStyle()}
      >
        <div className="p-5">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyber-600/20 flex items-center justify-center">
                {step.icon || <Shield size={20} className="text-cyber-400" />}
              </div>
              <h3 className="text-lg font-semibold text-white">{step.title}</h3>
            </div>
            <button onClick={dismiss} className="text-gray-500 hover:text-white p-1">
              <X size={16} />
            </button>
          </div>

          <p className="text-sm text-gray-400 leading-relaxed mb-5">
            {step.description}
          </p>

          {/* Progress dots */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              {steps.map((_, i) => (
                <div
                  key={i}
                  className={classNames(
                    'w-2 h-2 rounded-full transition-all',
                    i === stepIndex
                      ? 'bg-cyber-400 w-4'
                      : i < stepIndex
                      ? 'bg-cyber-600'
                      : 'bg-gray-600'
                  )}
                />
              ))}
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={dismiss}
                className="text-xs text-gray-500 hover:text-gray-300 px-3 py-1.5"
              >
                Skip
              </button>
              <div className="flex gap-1.5">
                {stepIndex > 0 && (
                  <button
                    onClick={prev}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-gray-600 text-xs text-gray-300 hover:bg-gray-700 transition-colors"
                  >
                    <ChevronLeft size={12} />
                    Back
                  </button>
                )}
                <button
                  onClick={next}
                  className="flex items-center gap-1 px-4 py-1.5 rounded-lg bg-cyber-600 text-xs text-white hover:bg-cyber-500 transition-colors"
                >
                  {isLast ? 'Done' : 'Next'}
                  {!isLast && <ChevronRight size={12} />}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
