# 📋 Changelog — Ch3ck3r Rebrand & Enterprise v2.0

## Changes Made (2026-05-28)

### 🎨 Complete Rebrand
- Color scheme: Green → Blue/White/Black (cyber-* palette)
- Dark/Light mode: Full dual-theme support via Tailwind class strategy
- Theme toggle: ThemeToggle.tsx component with Sun/Moon icons, persisted to localStorage
- Root layout: Inline theme script prevents FOUC, respects prefers-color-scheme
- CSS variables: Light + dark themes with smooth transitions

### 📊 Professional DevSecOps/SIEM Dashboard
- Stats row: Total scans, critical findings, GitHub repos, avg risk score
- Severity donut chart: Recharts PieChart with colored segments
- Risk trend line chart: Last 10 scans with gradient-fill line
- DevSecOps pipeline: 5-step visualization (Code → Build → Test → Scan → Deploy) with status indicators
- Pipeline metrics: Pass rate, total scans, failures, scan coverage
- SIEM Activity Feed: Real-time event log with severity badges, timestamps
- Quick Actions: New Scan, Connect Repo, Generate Report, View Projects

### 🔗 GitHub Repository Integration
- Repositories page: Full UI for managing connected GitHub repos
- Connect modal: URL + PAT + branch, verifies via GitHub API before creating project
- Backend: github.py — validates token access to repo via GitHub API
- OWASP API Top 10 Coverage: Visual grid showing all 10 categories with detection status

### 📑 Professional Bug Bounty Reports
- Report detail page: reports/[id]/page.tsx — beautiful, printable
- Author credit: Msambili Ndaga — @remnant01
- Disclaimer: Explicit author liability disclaimer on every report
- Executive Summary: Risk score with color, total findings, severity bar chart
- Detailed findings: Expandable per-finding with evidence (collapsible JSON), remediation
- Prioritized recommendations: Top 8 recommendations extracted from findings
- Print/Download: HTML, PDF, JSON export buttons

### 🎯 OWASP API Security Top 10
- Visual coverage grid on Repositories page
- All 10 categories: API1–API10
- Finding categories mapped to OWASP classifications
- Severity-inherited color coding per category

### 🔵 All Pages Updated
- Login: Blue brand, clean auth form
- Sidebar: Blue nav highlights, Repositories link, Theme toggle at bottom
- Scans: Blue theme, scan chains, status/project filters
- Scan Detail: Live progress, severity chart, expandable findings with OWASP/CVE/CWE
- Findings: Full filtering (severity, category, search, false positives), expandable cards
- Projects: GitHub indicator, scan overview, risk scores
- Reports: List with links to detailed bug-bounty reports
- Alerts: Multi-channel alert rules (Slack, Discord, Email, Webhook)
- Settings: 5-tab layout — Account, Appearance (with theme toggle), GitHub (token management), Notifications, Security

### 🛡️ TypeScript + Backend
- Zero TypeScript errors — npx tsc --noEmit passes clean
- Backend modules valid — github.py router wired into API v1 router
- recharts dynamic imports: All via wrapper to avoid type conflicts

### 📁 New Files
- src/components/layout/ThemeToggle.tsx
- src/app/(dashboard)/repositories/page.tsx
- src/app/(dashboard)/reports/[id]/page.tsx
- backend/app/api/v1/github.py
- CHANGELOG.md
