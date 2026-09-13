# How the Ch3ck3r VS Code extension works

This document explains the runtime flow of Ch3ck3r SAST 1.2.0. The extension is a developer security aid: findings require review and do not prove that code is exploitable or secure.

## 1. Activation

VS Code loads `src/extension.js` after startup, when a supported language is opened, or when a Ch3ck3r command is invoked.

During activation the extension:

1. Creates the scanner engine, findings store, diagnostics collection, tree views, hover/code-action providers, and status bar.
2. Registers scan, report, backend, exclusion, and remediation commands.
3. Loads minimal workspace-local finding state.
4. Registers save/open listeners when automatic scanning is enabled.
5. Checks optional external tools only when the workspace is trusted.

An untrusted workspace can still use bounded built-in local analysis, but external tools and backend operations are blocked.

## 2. Scan entry points

A scan begins through one of these paths:

- **Current file:** command, editor context menu, shortcut, open event, or save event.
- **Workspace:** explicit workspace-folder command or optional startup scan.
- **OpenAPI:** explicit command for a YAML or JSON API specification.
- **Backend scan:** explicit command after connection and consent; this is separate from local SAST.

Automatic scans are debounced so repeated saves do not launch unbounded concurrent work. Cancellation tokens stop stale or user-cancelled scans.

## 3. Safe file discovery

`src/scanner/engine.js` treats repository paths as untrusted.

Before reading a file, it:

- resolves and checks canonical workspace containment;
- rejects symbolic links;
- applies configured exclusion globs;
- enforces maximum depth, directory count, file count, and file size;
- limits concurrent reads and analysis;
- checks cancellation during discovery and scanning.

Binary, unsupported, oversized, excluded, or out-of-workspace files are skipped.

## 4. Rule selection and analysis

The engine determines the file language from its extension/name and loads:

- language-specific rules;
- cross-language rules from `patterns.all`;
- specialized OpenAPI YAML/JSON rules when applicable;
- specialized container or configuration rules for supported file types.

Rules currently use bounded pattern and limited contextual checks. JavaScript, TypeScript, Python, Go, and Java are the priority ecosystems. Ruby, Rust, infrastructure, and cloud checks have less test depth.

The engine does not currently provide full AST-based, interprocedural, or whole-program data-flow analysis. Authorization and business-logic findings are therefore review signals rather than proof of a vulnerability.

## 5. Finding normalization

For each match, the scanner creates a normalized finding containing fields such as:

- rule ID and title;
- severity, CWE, and OWASP mapping;
- file URI, line, column, and range;
- explanation and remediation guidance;
- a stable SHA-256 fingerprint derived from rule, location, and relevant content.

Credential-shaped matches, snippets, and evidence are redacted before persistence or reporting. The engine enforces a maximum finding count to avoid memory/UI exhaustion.

## 6. Persistence and stale-result handling

`src/utils/findingsStore.js` stores minimal redacted records in VS Code `workspaceState`.

After a file is rescanned, findings for that file are replaced rather than appended. This removes fixed/stale findings while leaving results from other files intact. Stable fingerprints allow reviewed false-positive or suppression state to survive harmless ID changes; expiration-compatible records prevent accidental permanent suppression.

## 7. Editor presentation

Findings are rendered through several VS Code APIs:

- **Problems panel:** `DiagnosticProvider` publishes bounded ranges and severities.
- **Security explorer:** `ResultsTreeProvider` groups findings for navigation.
- **Hover:** displays concise explanation and references.
- **Code actions:** offers guidance and eligible remediation actions.
- **Status bar and summary:** show scan progress and finding totals.

Finding text is treated as untrusted. The explanation webview is scriptless, uses a restrictive Content Security Policy, and context-escapes displayed values.

## 8. Remediation safety

`src/intel/smartRemediator.js` can generate explanations for many findings, but source modification is intentionally narrower.

Only deterministic allowlisted fixes may edit code. Before an edit, Ch3ck3r:

1. validates the active document and exact range;
2. shows a preview/confirmation;
3. applies only the reviewed replacement;
4. saves and rescans the file.

Heuristic recommendations remain guidance-only. A finding is not automatically dismissed merely because an edit was attempted.

## 9. Backend connection

Backend operations are opt-in and require Workspace Trust.

`src/utils/backendClient.js` enforces:

- HTTPS for remote hosts, with HTTP allowed only for loopback development;
- no credentials, query string, or fragment in the backend URL;
- no redirect following;
- request and response size limits;
- timeout and caller cancellation;
- bounded JSON parsing and redacted error messages.

Tokens are stored in VS Code SecretStorage, never ordinary workspace/user settings. `Ch3ck3r: Delete Stored Backend Token` removes the saved credential. Connecting tests the endpoint before saving a replacement token or URL.

A backend target is shown for explicit confirmation before a full backend scan. Built-in local scanning does not make network requests.

## 10. Reports

`src/utils/reportGenerator.js` exports SARIF 2.1.0, JSON, Markdown, or HTML.

Before serialization it:

- redacts credential-shaped content;
- safely converts unexpected values;
- escapes HTML;
- neutralizes Markdown structure and links;
- creates safe SARIF artifact URIs;
- emits standard SARIF `security-severity` metadata.

Generated reports can still contain filenames, rule names, and security observations, so treat them as sensitive development artifacts.

## 11. Packaging and verification

The release workflow runs:

```bash
npm ci --ignore-scripts
npm run check
npm run test:coverage
npm audit --audit-level=high
npm run security:gates
npm run package:vsix
npm run security:gates
npm run sbom
```

The second security-gate run inspects VSIX contents and rejects tests, scripts, dependency folders, environment files, databases, keys, and other unexpected artifacts. CI also runs dependency review and CodeQL and produces a CycloneDX SBOM.

## Main source map

- `src/extension.js` — lifecycle, commands, events, trust gates, UI orchestration
- `src/scanner/engine.js` — safe discovery, dispatch, analysis, normalization
- `src/scanner/rules/` — built-in rule definitions
- `src/utils/findingsStore.js` — redacted workspace persistence and state
- `src/utils/backendClient.js` — bounded backend transport
- `src/utils/reportGenerator.js` — safe report serialization
- `src/intel/smartRemediator.js` — explanations and limited remediation
- `src/providers/` and `src/ui/` — diagnostics, hover, actions, explorer, summary, status

For security assumptions and limitations, also read `THREAT_MODEL.md`, `SECURITY.md`, and `FINAL_VERIFICATION.md`.
