# Ch3ck3r SAST Baseline Audit

Date: 2026-08-23
Scope: `vscode-extension/` before production-hardening changes

## Validation performed

- Inspected extension lifecycle, scanner/rules, providers, backend client, reports, tests, packaging metadata, README, and CHANGELOG.
- Parsed every JavaScript source and test file with `node --check` successfully.
- Ran the existing local runner: 128 findings against approximately 86 marker comments, exit status 0.
- Inspected the VSIX file list with `vsce ls` and `unzip -l`.
- Ran a filename-only and count-only secret preflight; no private keys, AWS access keys, or GitHub-token-shaped values were found. Generic assignment-like examples exist in scanner/remediation fixtures and must not be treated as production credentials.
- `npm audit` could not run because the extension had no lockfile or declared dependencies.
- Repository status before extension changes: the entire `vscode-extension/` directory was untracked. Temporary frontend build and Python cache artifacts created during validation were restored/removed; status returned to only `?? vscode-extension/`.

## Critical findings

### C-01: Extension and shipped VSIX cannot activate

- `src/extension.js:9` imports `./providers/findingsProvider`, which does not exist.
- The available implementation is `src/ui/resultsTree.js`.
- `src/extension.js:50-53` calls `vscode.languages.registerDiagnosticProvider`, which is not a VS Code API. The diagnostic provider already owns a `DiagnosticCollection`.

Impact: the extension fails before developers can use it.

### C-02: Workspace-controlled shell-command injection

- `semgrepPath` is configurable in `package.json`.
- It is checked automatically during activation.
- `src/scanner/engine.js` interpolates it into `execSync(`${p} --version`)`.

Impact: a malicious repository can place shell metacharacters in workspace settings and gain command execution when opened. The activation failure currently masks this path but does not reduce its severity.

## High findings

### H-01: Entire rule families never execute

The dispatcher evaluates only `rule.patterns[language]`. Rules using `patterns.all`, including important secret rules, are skipped.

### H-02: OpenAPI scanning is effectively nonfunctional

The engine sends `yaml`/`json`, while dedicated spec rules use incompatible dispatch metadata/language keys. Local checks produced no OpenAPI findings.

### H-03: Sensitive matched source is persisted globally

Findings retain matches/snippets/evidence and are saved to extension-wide `globalState`, potentially preserving detected credentials across workspaces.

### H-04: Automatic remediation is unreliable and unsafe

Unknown rule IDs can dereference a missing default template; multiple rule/template IDs disagree; applied edits are immediately dismissed without validation or rescan.

### H-05: Source-controlled HTML reaches a script-enabled webview

The explanation webview enables scripts, has no CSP, and interpolates finding fields without escaping.

## Medium findings

### M-01: Automatic save/open scanning crashes during exclusion matching

The minimatch utility is imported as an object and called as if it directly exported `match`.

### M-02: Findings become stale, collide, and remain suppressed

Finding IDs omit content hashes/columns, rescans append instead of replacing per-file results, and suppressions do not expire when code changes.

### M-03: Backend token uses plaintext VS Code settings

The token is stored globally as ordinary configuration rather than `SecretStorage`. Plain HTTP is accepted and documented.

### M-04: Backend requests are unbounded

Requests have no timeout, cancellation, response-size limit, or redirect policy.

### M-05: Report encoding is unsafe and SARIF metadata is malformed

HTML interpolates finding data without escaping. Markdown is injection-prone. SARIF misspells `security-severity` as `securitySeeverity`.

### M-06: Workspace scans are synchronous and insufficiently bounded

Recursive discovery and file reads use synchronous APIs on the extension host. Manual scans do not enforce the configured maximum file size or file-count bounds.

### M-07: Existing tests provide false assurance

The runner has no assertions, caps its computed rate at 100%, and exits successfully regardless of missed/extra findings. It claims fixture coverage that is absent.

## Low findings

- False-positive action and store filtering use incompatible state.
- Dockerfiles are analyzed twice.
- Package/report/activation version is 1.0.0 while CHANGELOG leads with 1.1.0.
- `owaspCategories` is declared but unused; `autoScanOnStart` and welcome-state keys are consumed without complete declarations.

## Documentation claim comparison

| Claim | Baseline result |
|---|---|
| Extension activates and scans in VS Code | False: activation blockers exist |
| Automatic scan on save/open | False: exclusion matcher call fails |
| OpenAPI/Swagger analysis | False: dispatch produces no dedicated findings |
| One-click smart remediation | Partially implemented but unsafe/unreliable |
| Semgrep integration | Only unsafe availability probing; no actual Semgrep scan pipeline |
| SARIF/JSON/Markdown/HTML reports | Serializers exist; HTML/Markdown unsafe and SARIF metadata has an error |
| Seven-language support | Pattern modules exist, but quality is heuristic and uneven |
| OWASP API Top 10 coverage | Rule labels exist; semantic coverage and accuracy are not established |
| No external dependencies required | True for built-in rules |
| Developer-reliable test coverage | False: current runner has no assertions |

## Architecture strengths

- Modular scanner structure with 73 rules across 16 modules and broad CWE labeling.
- Separation between engine, providers, store, remediator, backend client, and reports.
- Central severity filtering and cancellation check during workspace iteration.
- Four report formats already exist.
- `.vscodeignore` excludes tests and packaged VSIX artifacts.

## Prioritized remediation order

1. Restore extension activation.
2. Remove shell execution and enforce Workspace Trust around external/backend operations.
3. Escape all rendered output and add webview CSP.
4. Move tokens to `SecretStorage`; harden backend URL and request handling.
5. Correct all-language and OpenAPI rule dispatch.
6. Replace stale findings per file; introduce stable content-based fingerprints and redaction.
7. Bound, cancel, and move filesystem work off synchronous extension-host paths.
8. Disable unsafe automatic fixes; permit only deterministic previewed changes followed by rescan.
9. Replace the demonstration runner with assertion-based security/regression tests.
10. Add packaging inspection, CI, supply-chain checks, and accurate documentation.

## Baseline verdict

The codebase is a promising prototype with a real modular rule set, but version 1.0.0 is not currently safe or reliable for developer use. Productionization must begin with activation and extension self-security—not additional detection claims.
