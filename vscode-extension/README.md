# Ch3ck3r SAST for VS Code

Developer-first static security checks for API and web application code, with an emphasis on OWASP API Security risks.

Ch3ck3r combines fast local pattern rules with editor diagnostics and optional Ch3ck3r backend requests. It is a security review aid—not proof that an application is secure.

## Current capabilities

- Local, offline scanning of the current file or workspace
- Automatic, debounced scan on save
- Problems-panel diagnostics and a severity-grouped findings explorer
- YAML/JSON OpenAPI and Swagger checks
- Stable content-based finding fingerprints
- Secret-value redaction before persistence and reporting
- SARIF 2.1.0, JSON, Markdown, and HTML reports
- Workspace Trust enforcement for external tools and backend operations
- Optional HTTPS backend connection with tokens stored in VS Code SecretStorage
- Bounded asynchronous file discovery, symlink rejection, cancellation, and resource limits
- Guidance for all findings and a small allowlist of previewed deterministic edits

## Capability matrix

| Area | Status | Notes |
|---|---|---|
| JavaScript / TypeScript | Supported, heuristic | Priority ecosystem; pattern and limited context checks |
| Python | Supported, heuristic | Priority ecosystem |
| Go | Supported, heuristic | Priority ecosystem |
| Java | Supported, heuristic | Priority ecosystem |
| Ruby / Rust | Experimental | Uneven rule and test depth |
| YAML / JSON OpenAPI | Supported | Structural/pattern misconfiguration checks, not full schema validation |
| Dockerfile / Terraform / cloud config | Experimental | Hardening indicators and common misconfiguration checks |
| Semgrep | Availability probe only | No automatic download or remote rule execution; full bounded scan integration is planned |
| Whole-program data flow | Not supported | Current checks cannot prove exploitability or authorization correctness |
| Automatic remediation | Limited | Only deterministic allowlisted edits; review and application tests remain mandatory |
| Backend DAST/Nuclei/ZAP | Optional backend action | Not part of local SAST and never starts automatically |

## Install locally

```bash
cd vscode-extension
npm ci --ignore-scripts
npm test
npm run package:vsix
code --install-extension ch3ck3r-sast-1.2.0.vsix
```

Inspect the VSIX before installation:

```bash
npm run security:gates
```

## Commands

- `Ch3ck3r: Scan Current File`
- `Ch3ck3r: Scan Workspace Folder`
- `Ch3ck3r: Scan OpenAPI/Swagger Spec`
- `Ch3ck3r: Show Scan Report`
- `Ch3ck3r: Connect to Ch3ck3r Backend`
- `Ch3ck3r: Delete Stored Backend Token`
- `Ch3ck3r: Run Full Security Scan (Backend)`
- `Ch3ck3r: Clear All Findings`
- `Ch3ck3r: Toggle Inline Diagnostics`

The editor shortcut for current-file scanning is `Ctrl+Shift+C` (`Cmd+Shift+C` on macOS).

## Important settings

- `ch3ck3r.enabled`: enable local scanning
- `ch3ck3r.severityThreshold`: minimum displayed severity
- `ch3ck3r.autoScanOnSave`: scan changed files after save
- `ch3ck3r.autoScanOnOpen`: scan files when opened
- `ch3ck3r.autoScanOnStart`: optional workspace scan; disabled by default
- `ch3ck3r.scanDebounceMs`: automatic-scan debounce
- `ch3ck3r.excludePatterns`: ignored files and directories
- `ch3ck3r.maxFileSizeKB`: per-file read limit
- `ch3ck3r.maxWorkspaceFiles`: workspace file-count limit
- `ch3ck3r.maxScanConcurrency`: bounded analysis concurrency
- `ch3ck3r.backendUrl`: HTTPS backend URL; loopback HTTP is allowed for development
- `ch3ck3r.semgrepPath`: machine-scoped executable name or absolute path
- `ch3ck3r.reportFormat`: `sarif`, `json`, `markdown`, or `html`

Backend tokens are not ordinary settings. They are stored through VS Code SecretStorage.

## Security and privacy model

### Local scanning

Built-in rules run locally and perform no network requests. The extension does not collect telemetry by default.

### Backend communication

Backend actions require a trusted workspace and an explicit developer command. Remote URLs must use HTTPS; HTTP is accepted only for loopback hosts. Requests reject redirects and enforce time, request-size, and response-size limits. A confirmation displays the scan target before it is sent.

Local source code is not implicitly uploaded by normal local scans. A target entered for a backend scan is sent to the configured backend.

### Malicious repositories

Repository content, filenames, symlinks, workspace settings, scanner output, and finding text are treated as untrusted. External tools are disabled in untrusted workspaces. Discovery does not follow symlinks and enforces canonical workspace containment. Webview/report fields are escaped and sensitive matches are redacted.

See `SECURITY.md` and `THREAT_MODEL.md` for reporting and design details.

## Findings, confidence, and limitations

Most built-in findings are heuristic. Authorization, business logic, missing controls, and taint-like matches may require substantial context that a local pattern engine cannot observe.

A finding means “review this location,” not “this vulnerability is confirmed.” Ch3ck3r can produce false positives and false negatives. Developers should:

1. Review the complete code path.
2. Confirm attacker control and effective sanitization/authorization.
3. Add a regression test before changing behavior.
4. Review every generated edit.
5. Run application tests and a second security tool where risk is high.

## Development verification

```bash
npm ci --ignore-scripts
npm run check
npm run test:coverage
npm audit --audit-level=high
npm run security:gates
npm run package:vsix
npm run security:gates
```

The legacy fixture runner is retained as a demonstration via `npm run test:legacy`; it is not a release-quality accuracy benchmark.

## Suppressions

The internal store supports stable fingerprint records and expiration-compatible suppression metadata. A reviewed project-file suppression format with required justification is planned; broad source-comment suppressions are intentionally not advertised yet.

## Responsible disclosure

Report extension vulnerabilities privately as described in `SECURITY.md`. Never include real credentials or private source in a report.

## License

MIT
