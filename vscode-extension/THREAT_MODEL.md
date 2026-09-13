# Ch3ck3r SAST Threat Model

## Scope and security objectives

Ch3ck3r runs inside the VS Code extension host and processes adversary-controlled repositories. Its primary security objectives are:

1. Opening or scanning a repository must not execute repository-controlled commands.
2. Source code and findings must not leave the machine without explicit informed action.
3. Credentials must not be stored in plaintext settings, logs, reports, or cross-workspace state.
4. Malformed or oversized input must not freeze or crash VS Code.
5. Rendered findings must remain inert data, not executable HTML/Markdown/script.
6. Findings and fixes must be attributable, reproducible, bounded, and honest about confidence.

## Trust boundaries

- **Untrusted workspace:** filenames, paths, symlinks, source, configuration, `.vscode/settings.json`, generated code, reports, and repository metadata.
- **VS Code extension host:** trusted execution environment that must not synchronously process unbounded input.
- **External tools:** Semgrep executable and local rule packs; trusted only after path validation, Workspace Trust, and explicit invocation.
- **Ch3ck3r backend:** remote trust boundary; URL, TLS, authentication, responses, redirects, and payload size require validation.
- **Webviews/browser reports:** separate rendering boundary; all findings are attacker-controlled data.
- **Persistent storage:** SecretStorage for tokens; workspace-scoped state for minimal redacted metadata.
- **CI/package supply chain:** npm registry, GitHub Actions, VSIX contents, dependencies, and release artifacts.

## Assets

- Developer source code and repository metadata
- Backend bearer tokens and API credentials found in source
- Developer workstation and VS Code privileges
- Integrity of findings, suppressions, reports, and automatic edits
- Backend projects, scans, and organization data
- Extension update and release channel

## Threat actors

- Author of a malicious or compromised repository
- Malicious/compromised backend or network intermediary
- Compromised external scanner/rule pack
- Dependency or build-pipeline attacker
- Local low-privilege process reading insecure settings/artifacts
- Accidental misuse caused by misleading confidence or unsafe fixes

## Primary threats and controls

### T-01 Command execution through configuration

Attack: workspace sets an executable path containing shell metacharacters or unsafe flags.

Controls:
- Never use a shell.
- Use `execFile`/`spawn` with an argument array and `shell: false`.
- Resolve and validate executable paths.
- Require Workspace Trust before any external process.
- Enforce timeout, output limit, cancellation, and process cleanup.
- Never auto-download or execute rules.

### T-02 Path traversal and symlink escape

Attack: recursive scan follows links or reaches files outside the chosen workspace.

Controls:
- Use canonical real paths and confirm containment in a canonical workspace root.
- Do not follow symbolic links.
- Limit depth/file count/file size.
- Skip devices, sockets, binaries, archives, dependencies, and generated content.

### T-03 Resource exhaustion

Attack: huge files, deep trees, pathological regex input, excessive findings, or hanging tools/backend.

Controls:
- Asynchronous filesystem operations.
- File-count, file-size, depth, output-size, finding-count, and concurrency limits.
- Cancellation tokens and hard deadlines.
- Regex review and adversarial performance tests.
- Incremental content-hash cache.

### T-04 Credential disclosure

Attack: discovered secret persists in global state, logs, clipboard, report, backend payload, or error text.

Controls:
- Redact secret matches/snippets at finding creation and serialization.
- Store backend tokens only in `ExtensionContext.secrets`.
- Keep findings workspace-scoped and minimal.
- Never log source, tokens, authorization headers, or raw backend errors.
- Require explicit consent before sending source-derived data.

### T-05 Backend interception, SSRF, and malicious responses

Attack: insecure URL sends bearer token over HTTP; redirects exfiltrate it; large/malformed response hangs/crashes extension.

Controls:
- HTTPS by default; permit HTTP only for loopback development.
- Reject credentials in URLs and unsupported protocols.
- Disable redirects by default.
- Enforce timeout, cancellation, and response-size limits.
- Validate response content type and expected structure.
- Bound error text; treat it as untrusted.

### T-06 Webview/report injection

Attack: source text becomes HTML/script/Markdown links in an explanation or exported report.

Controls:
- Escape every untrusted field for its output context.
- Prefer scriptless webviews.
- Apply restrictive CSP and restricted `localResourceRoots`.
- Validate all messages if messaging is introduced.
- Neutralize Markdown control characters and unsafe link schemes.

### T-07 Unsafe remediation

Attack: a heuristic finding applies incorrect code, changes behavior, or hides an unresolved issue.

Controls:
- Automatic edits only for deterministic context-safe rules.
- Preview and explicit confirmation.
- Never dismiss automatically.
- Rescan after edits.
- Provide guidance rather than edits for uncertain cases.
- Positive, negative, and regression tests per automated fix.

### T-08 Finding integrity and suppression abuse

Attack: unstable IDs cause collision, stale findings remain, or broad suppressions conceal new vulnerabilities.

Controls:
- Stable fingerprint from rule, canonical workspace-relative path, normalized location, and content hash.
- Replace findings per scanned file.
- Suppressions require rule/fingerprint, justification, and optional expiration.
- Expired/content-changed suppressions fail closed and become visible.

### T-09 Supply-chain compromise

Attack: dependency, action, package contents, or bundled binary is compromised.

Controls:
- Minimal pinned dependencies and lockfile.
- Dependency review, CodeQL, secret scanning, audit, SBOM, and reproducible package inspection.
- Pin CI actions to immutable commits where practical.
- No bundled executable or remote rule download by default.
- VSIX allowlist and sensitive-file rejection.

## Privacy model

- Built-in local scanning performs no network activity.
- Telemetry is disabled and absent by default.
- Backend operations are explicit user commands.
- Source upload is disabled unless a future flow presents and records informed consent.
- Network behavior and payload schemas are documented.

## Residual risks

- Heuristic SAST can produce false positives and false negatives.
- Intra-procedural analysis cannot prove whole-program authorization or exploitability.
- A trusted external scanner executes with developer privileges and remains a supply-chain risk.
- VS Code and operating-system security are outside the extension boundary.
- Secure quick fixes cannot replace human review and tests.

## Security acceptance gates

- Malicious workspace configuration cannot invoke a shell.
- Untrusted workspaces cannot run external tools or backend operations.
- Injected finding fields remain inert in webviews and exports.
- Tokens use SecretStorage and are never present in package/config logs.
- Scans and network/tool operations are bounded and cancellable.
- Regression tests cover command injection, traversal, injection rendering, redaction, malformed responses, and resource limits.
