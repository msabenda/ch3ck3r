# Security Policy

## Scope

Please report vulnerabilities in the Ch3ck3r VS Code extension, backend, dashboard, packaging, update process, or documentation examples. Scanner findings against another project are not vulnerabilities in Ch3ck3r.

Supported security fixes target the latest commit on `main` and the latest Marketplace release.

## Private Reporting

Use GitHub private vulnerability reporting for this repository. If it is unavailable, contact the maintainer through the address listed on the GitHub profile.

Include the affected version or commit, reproduction steps, impact, and a minimal proof of concept. Do not include real credentials, private source code, or personal data.

## Safe Harbor

Good-faith research is welcomed when it:

- avoids privacy violations, persistence, social engineering, and service disruption;
- accesses only data needed to demonstrate the issue;
- does not test third-party targets without explicit authorization;
- allows reasonable time for remediation before disclosure.

## Scanner Safety

Local SAST performs static analysis and should not execute repository code. Optional backend scanners may send network traffic to a configured target. Use active scanning only against systems you own or are authorized to assess.

See [`vscode-extension/THREAT_MODEL.md`](vscode-extension/THREAT_MODEL.md) for extension trust boundaries and mitigations.
