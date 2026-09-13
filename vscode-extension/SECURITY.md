# Security Policy

## Supported versions

Ch3ck3r SAST is undergoing security hardening. Until a hardened release is published, install local VSIX builds only for evaluation and inspect their contents first.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the repository maintainer rather than opening a public issue. Include:

- affected version and platform;
- reproduction steps or a minimal repository;
- security impact;
- whether source code, credentials, or command execution are involved;
- suggested mitigation, if known.

Do not include real credentials or private source code. Use synthetic fixtures and redact sensitive data.

The maintainer should acknowledge receipt, reproduce safely, assign severity, prepare a regression test, and coordinate disclosure after a fix is available.

## Security guarantees and limitations

- Built-in scanning is local and does not require network access.
- Ch3ck3r does not claim to detect every vulnerability.
- Findings may be false positives or false negatives and require developer review.
- Authorization/business-logic findings are generally heuristic unless explicitly marked otherwise.
- Automatic remediation is limited to reviewed deterministic transformations; other findings provide guidance only.
- External tools execute with the developer's privileges and must be independently trusted.

## Safe use

- Keep VS Code Workspace Trust enabled.
- Do not run external scanners in untrusted repositories.
- Use HTTPS for remote Ch3ck3r backends; HTTP is allowed only for loopback development.
- Never paste real secrets into bug reports or test fixtures.
- Review every proposed edit and resulting diff.
- Run application tests after remediation.

## Data and network behavior

- Local built-in scans process files on the developer machine.
- Telemetry is not collected by default.
- Backend operations occur only after an explicit command.
- Backend tokens are stored through VS Code SecretStorage.
- Source upload is not an implicit part of local scanning.

See `THREAT_MODEL.md` for trust boundaries and controls.
