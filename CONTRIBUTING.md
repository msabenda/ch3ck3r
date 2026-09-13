# Contributing to Ch3ck3r

Thanks for improving open-source API security tooling.

## Before You Start

- Use an issue for substantial features or rule-design changes.
- Keep pull requests focused and explain security trade-offs.
- Never commit credentials, customer data, proprietary source, generated builds, databases, or VSIX files.
- Use only authorized, local, or intentionally vulnerable targets for testing.

## Extension Development

```bash
cd vscode-extension
npm ci --ignore-scripts
npm run check
npm run test:coverage
npm audit --audit-level=high
npm run security:gates
npm run package:vsix
npm run security:gates
```

### Adding or Changing a Rule

Every rule should include:

- a stable identifier and severity;
- supported languages and an OWASP/CWE mapping where applicable;
- a precise explanation and defensive remediation;
- positive and negative fixtures;
- tests for secret redaction when evidence might contain credentials;
- documentation when support or limitations change.

Prefer syntax-aware checks where practical. Pattern rules must be narrowly scoped and described as heuristic; avoid claiming exploitability that the extension cannot prove.

## Commit Style

Use concise Conventional Commit subjects:

- `feat(rules): detect unsafe outbound URL construction`
- `fix(reports): escape SARIF artifact locations`
- `test(scanner): cover symlinked workspace files`
- `docs: explain offline scanning guarantees`

## Pull Requests

Describe the problem, approach, security impact, validation evidence, and known limitations. UI changes should include screenshots. Changes affecting packaged files must include `npm run package:check` output.

Report platform vulnerabilities privately according to [`SECURITY.md`](SECURITY.md), not through a public issue.
