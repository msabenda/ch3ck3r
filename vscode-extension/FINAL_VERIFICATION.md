# Ch3ck3r SAST 1.2.0 verification report

Date: 2026-08-23
Scope: VS Code extension hardening release

## Result

**Hardened evaluation release passed local release gates.** It is materially safer and more reliable than the baseline, but it is not represented as complete SAST coverage or protection from every attack.

## Implemented controls

- Activation blockers fixed and activation smoke-tested.
- Shell interpolation removed from external-tool probing.
- Workspace Trust required for external tools and backend operations.
- Bounded asynchronous file discovery/reads, cancellation, canonical containment, and symlink rejection.
- All-language and OpenAPI rule dispatch corrected; duplicate Dockerfile dispatch removed.
- Stable content-based fingerprints and per-file finding replacement.
- Credential match/snippet/evidence redaction.
- Workspace-local minimal finding persistence and expiration-compatible suppression records.
- Backend URL/TLS validation, manual redirect rejection, timeout/cancellation, bounded payloads, safe JSON handling, and redacted errors.
- SecretStorage token persistence plus an explicit deletion command.
- Scriptless CSP-restricted explanation webview with escaped fields.
- HTML/Markdown/SARIF/JSON report redaction and context encoding.
- Deterministic-only reviewed automatic edits with post-edit rescan.
- Locked development dependency, audit, package allowlist, secret gate, CycloneDX SBOM, CI, Dependabot, dependency review, and CodeQL workflow.
- Accurate capability/privacy/limitations documentation, threat model, migration notes, security policy, and release checklist.

## Verification evidence

- JavaScript syntax: **43 files passed**.
- Assertion tests: **23 passed, 0 failed**.
- Coverage run: **71.12% line coverage overall**.
  - scanner engine: 88.19%
  - backend client: 83.39%
  - findings store: 87.68%
  - report generator: 97.39%
- Legacy fixture runner: **129 findings across 8 files**, exit 0; retained as a demo, not an accuracy benchmark.
- Dependency audit: **0 vulnerabilities** at final successful audit.
- VSIX: `ch3ck3r-sast-1.2.0.vsix`, **42 files, approximately 90 KB**.
- VSIX sensitive-file/package allowlist: passed.
- Packaged runtime SHA-256 matched source for extension entry point, scanner engine, backend client, and report generator.
- CycloneDX SBOM 1.5: generated and parsed successfully.
- GitHub workflow and Dependabot YAML: parsed successfully.
- Git status: only the previously untracked extension directory plus newly added extension CI/Dependabot files; unrelated tracked source remains unchanged.

## Known limitations / deferred work

These requested capabilities are intentionally not claimed as complete in 1.2.0:

- Full AST-based and interprocedural data-flow analysis.
- A complete Semgrep execution pipeline and trusted pinned rule-pack lifecycle; 1.2.0 only performs safe availability probing.
- Changed-lines-only filtering and a reviewed project-file suppression UI/format.
- Per-rule precision/recall benchmarking at production scale.
- Equal test depth for Ruby, Rust, Terraform, Kubernetes, and cloud configuration checks.
- Full VS Code Electron-host integration suite; activation currently has a controlled API-stub smoke test.
- Immutable-SHA pinning of all GitHub Actions; Dependabot is configured to maintain action references.
- Marketplace signing/publishing and live backend/DAST testing were not performed because those are external actions requiring maintainer approval and authorized targets.

## Release recommendation

Use 1.2.0 as a **hardened evaluation/beta release**. Before labeling it generally available, add the real VS Code Electron integration suite, production rule-quality benchmarks, and a bounded Semgrep scan implementation. Publish only after explicit maintainer review and approval.
