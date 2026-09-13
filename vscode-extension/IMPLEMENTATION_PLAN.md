# Ch3ck3r SAST Productionization Plan

## Release policy

Work proceeds in security-risk order. A feature is documented as supported only after an assertion-based test and a packaging check prove it. Heuristic rules are never described as proof of exploitability.

## P0 — Release blockers

- Restore extension activation and test activation with a VS Code API stub/integration host.
- Replace shell-interpolated Semgrep checks with bounded `execFile`/`spawn`, `shell: false`.
- Respect Workspace Trust for external tools and backend communication.
- Make all webviews scriptless or CSP-restricted and context-escape all finding fields.
- Store backend tokens in SecretStorage and remove plaintext token configuration.

Exit gate: malicious workspace settings and finding strings cannot execute code.

## P1 — Correctness and confidentiality

- Execute `patterns.all` and dedicated OpenAPI rules.
- Redact secret values at finding creation, persistence, logs, clipboard, and reports.
- Persist minimal findings in workspace state.
- Replace findings per file and introduce stable content-based fingerprints.
- Validate backend URLs and bound redirects, time, response size, and errors.
- Correct SARIF 2.1.0 properties and encode HTML/Markdown safely.
- Disable heuristic automatic edits; preview deterministic fixes and rescan afterward.

Exit gate: regression tests prove rule dispatch, redaction, report safety, and stale-finding removal.

## P2 — Performance and developer workflow

- Asynchronous bounded discovery and reads.
- No symlink following; canonical workspace containment.
- File-size, file-count, concurrency, finding-count, depth, timeout, and output limits.
- Incremental content-hash cache and scan-on-save debounce.
- Cancellation through local, external-tool, and backend paths.
- Suppressions with rule/fingerprint, justification, and expiration.
- Confidence classification and rule enable/disable filters.

Exit gate: large/malformed/pathological fixtures remain responsive and cancellable.

## P3 — Analysis quality

- Establish language priority: JavaScript/TypeScript, Python, Go, Java.
- Add parsers incrementally where they materially reduce false positives.
- Add basic intra-procedural source/sanitizer/sink tracking.
- Keep Ruby/Rust checks explicitly experimental until equivalent test depth exists.
- Add a trusted, pinned local Semgrep rule-pack interface; never auto-download rules.
- Track per-rule positive, negative, precision-proxy, and performance fixtures.

Exit gate: each promoted rule has metadata, positive/negative tests, and a documented confidence class.

## P4 — Supply chain and release

- Lock dependencies and keep runtime dependency count minimal.
- CI: syntax, tests, coverage, audit, secret scan, CodeQL, dependency review, package allowlist, SARIF validation, SBOM.
- Reject sensitive or unexpected files in VSIX.
- Maintain SECURITY.md, threat model, privacy/network documentation, capability matrix, release checklist, and migration notes.

Exit gate: clean reproducible package, inspected file list, passing CI-equivalent local checks, reviewed diff.

## Deferred architecture decisions

- Full TypeScript migration is intentionally incremental; security fixes must not wait for a rewrite.
- Whole-program interprocedural data flow is outside the first hardened release.
- Backend source upload remains disabled until an explicit consent and minimization design is reviewed.
- Telemetry remains absent by default.
