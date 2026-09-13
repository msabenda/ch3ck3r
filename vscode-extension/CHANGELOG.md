# Changelog

## [1.2.0] - 2026-08-23

### Security
- Removed shell-interpolated external-tool probing; Semgrep checks now use bounded `execFile` with `shell: false` and require Workspace Trust.
- Moved backend tokens from plaintext settings to VS Code SecretStorage.
- Enforced HTTPS for remote backends, loopback-only HTTP, redirect rejection, cancellation, timeouts, and request/response limits.
- Made security explanation webviews scriptless with a restrictive CSP and context-escaped finding data.
- Redacted secret material before finding persistence and report serialization.
- Added canonical workspace containment, symlink rejection, and scan resource limits.
- Restricted automatic remediation to reviewed deterministic rules, with preview and post-edit rescan.

### Fixed
- Restored extension activation by correcting the findings-provider import and invalid diagnostics registration.
- Enabled `patterns.all`, including cross-language secret rules.
- Enabled dedicated OpenAPI rules for YAML and JSON.
- Replaced stale per-file findings and added stable SHA-256 fingerprints.
- Removed duplicate Dockerfile analysis.
- Corrected SARIF `security-severity` metadata and safe artifact URI handling.
- Escaped HTML/Markdown report content.

### Added
- 23 assertion-based security and activation tests.
- CI workflow for tests, coverage, audit, package inspection, SBOM, dependency review, and CodeQL.
- Dependabot configuration, threat model, baseline audit, implementation plan, and security policy.
- Reproducible package allowlist and source secret gates.

### Changed
- Reframed authorization/business-logic findings and Ruby/Rust support as heuristic/experimental.
- Updated documentation to distinguish local SAST from explicit backend DAST operations.
- Added machine-scoped backend/tool configuration and bounded workspace settings.

## [1.1.0] - 2026-06-06

### Added
- 🧠 **SmartRemediator** — intelligent contextual fix & recommendation engine
  - Line-precise highlighting (highlights the exact offending expression, not whole line)
  - Language-aware secure code templates (Python, JS, TS, Go, Java, Ruby, Rust)
  - "Why this is dangerous" explanations with real attack scenarios
  - Severity badges with actionable labels (CRITICAL → Immediate action required)
  - Contextual fix code that adapts to the specific vulnerability
- 📖 **Rich Security Explanation Panel** — dedicated webview with:
  - Danger explanation with real-world attack descriptions
  - Before/After code comparison (bad vs. secure)
  - CWE/OWASP reference links
  - One-click "Apply Fix" and "Dismiss" buttons
- 🛠️ **Enhanced Code Actions:**
  - "Apply fix: {vulnerability name}" — replaces the exact problematic expression
  - "Why is this dangerous?" — opens the explanation panel
  - "View CWE-### details" — opens MITRE CWE page
  - Proactive security hints for code patterns (even without full scan)
- 🔍 **Precise Hover Hints** — hover over flagged code and see:
  - Severity badge + vulnerability name
  - Danger explanation (one-liner)
  - OWASP/CWE references
  - Fix code snippet
  - Quick action links (Apply Fix, Dismiss, Learn More)
- ➕ **New vulnerability categories:**
  - IDOR detection (no ownership check)
  - Prototype pollution detection
  - Verbose error handling (stack trace exposure)
  - Unversioned API endpoints
  - GraphQL introspection abuse
  - Missing CSP/X-Frame-Options headers
  - Terraform hardcoded secrets
  - Kubernetes privileged containers
  - Docker root user + apt cleanup + ENV secrets
- 🌐 **TypeScript module** — 7 TS-specific rules (auth, SSRF, SQLi, command inj, path traversal, IDOR, sensitive exposure)
- 🧪 **Performance test suite** — `test/runner.js` with detection rate tracking across 8 vulnerable apps

### Changed
- **DiagnosticProvider** — now uses SmartRemediator for precise range highlighting
- **HoverProvider** — uses SmartRemediator for rich Markdown-based hover content
- **CodeActionProvider** — proactive detection of hardcoded secrets, SSL bypass, CORS wildcards
- **Rules engine** — 73 total rules across 17 modules with 37 CWE references
- **extension.js** — `remediateFinding` now uses SmartRemediator for language-aware fix code

### Fixed
- TypeScript detection gap: 1→10 findings (100%) with new TS-specific rules
- Rust detection gap: 0→5 findings (56%) with Rust `format!()` SQL injection + `Command::new` patterns
- `analyzeApiSpec()` and `analyzeConfig()` — removed calls to non-existent methods (`_specRelevantCategories`, `_analyzeApiSpecStatic`, `_analyzeConfigStatic`)
- Module exports — stable destructure pattern for `{ SecurityRules }`

## [1.0.0] - 2025-06-22

### Added
- Initial release of Ch3ck3r SAST VS Code Extension
- Inline diagnostics for API security issues
- API Security Explorer tree view in activity bar
- Scan Summary view
- Automatic scanning on file save/open
- Built-in security rules covering all 10 OWASP API Top 2023 categories
- Multi-language support (Python, JavaScript, TypeScript, Go, Java, Ruby, Rust)
- OpenAPI/Swagger specification analysis
- Hover provider for security hints
- Code actions with quick fixes
- Backend integration for Ch3ck3r server
- Report generation (SARIF, JSON, Markdown, HTML)
- Status bar integration
- Exclusion patterns for files/directories
- Configuration via VS Code settings
- Context menu commands (editor, explorer)
- Keyboard shortcuts (Ctrl+Shift+C/Cmd+Shift+C)
- First-run welcome message
