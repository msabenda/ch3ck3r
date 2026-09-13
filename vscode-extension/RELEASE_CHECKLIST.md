# Ch3ck3r SAST release checklist

## Source and metadata

- [ ] Version matches package, activation log, reports, README, and CHANGELOG.
- [ ] Capability matrix reflects tested behavior and known limitations.
- [ ] No unsupported “complete,” “all vulnerabilities,” or exploitability claims.
- [ ] Git diff reviewed; unrelated files unchanged.

## Security

- [ ] Workspace-controlled values never reach a shell.
- [ ] External tools and backend actions require Workspace Trust.
- [ ] Backend token is present only in SecretStorage.
- [ ] Remote backend requires HTTPS; loopback HTTP exception tested.
- [ ] Redirect, timeout, cancellation, request-size, and response-size behavior tested.
- [ ] Finding fields are escaped in webviews, HTML, Markdown, and SARIF.
- [ ] Secret values are redacted before persistence, clipboard, and reports.
- [ ] Symlink, traversal, oversized-file, and file-count limits tested.
- [ ] Automatic edits are deterministic, previewed, and followed by rescan.

## Quality gates

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

- [ ] Assertion tests pass.
- [ ] Coverage reviewed, especially extension lifecycle and security-critical utilities.
- [ ] Dependency audit has no high/critical vulnerability.
- [ ] CycloneDX SBOM parses successfully.
- [ ] VSIX contains only allowlisted runtime/documentation files.
- [ ] Packaged extension activation is smoke-tested.
- [ ] SARIF output is validated by a downstream consumer/schema validator.

## Release operations

- [ ] Sign/publish only after explicit maintainer approval.
- [ ] Preserve release SHA and checksum.
- [ ] Attach VSIX, SBOM, changelog, and verification report.
- [ ] Do not publish test credentials, `.env` files, databases, logs, or raw findings.
- [ ] Monitor private security-reporting channel after release.
