# Migration notes: 1.1.x to 1.2.0

## Backend token storage

`ch3ck3r.backendToken` is no longer an ordinary VS Code setting. Reconnect once with `Ch3ck3r: Connect to Ch3ck3r Backend`; the token is stored in VS Code SecretStorage. Remove any old plaintext token from user/workspace settings and rotate it if those settings were shared.

Use `Ch3ck3r: Delete Stored Backend Token` to remove the credential.

## Backend URL policy

Remote backends now require HTTPS. Plain HTTP remains available only for loopback development (`localhost`, `127.0.0.0/8`, or `::1`). URLs containing credentials, query strings, or fragments are rejected. Redirects are not followed.

## Workspace Trust

External-tool probing and backend actions are disabled in untrusted workspaces. Built-in local checks remain available with bounded file access.

## Finding identity and persistence

Findings now use content-based fingerprints and workspace-local state. Existing global findings and suppression records are read for migration where possible, but rescanning is recommended. Fixed findings are replaced per file instead of remaining stale.

## Remediation behavior

Heuristic fixes are now guidance-only. Only a small deterministic allowlist can edit source, and those edits require preview confirmation followed by a rescan. Findings are no longer automatically dismissed after an edit.

## Reports

Reports redact credential-shaped content and escape untrusted HTML/Markdown. SARIF now uses the standard `security-severity` property and safer artifact URIs. Downstream tooling should regenerate old reports.

## Semgrep

The extension safely probes a configured Semgrep executable only in trusted workspaces. A full Semgrep execution pipeline is not advertised in 1.2.0; no rules are downloaded or executed automatically.
