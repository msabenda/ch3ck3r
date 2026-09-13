/**
 * Container / Docker security rules
 */
module.exports = {
    rules: [
        {
            id: 'container-root-user',
            name: 'Container Running as Root',
            severity: 'high',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 250,
            description: 'Dockerfile/container does not switch to non-root user. Root inside container = host root if breakout.',
            remediation: 'Add USER directive: USER 1000:1000 or USER appuser',
            category: 'container',
            patterns: {
                dockerfile: [
                    { pattern: /^FROM\s+\S+/gm, contextCheck: (content) =>
                        !/^USER\s\d+/m.test(content) && !/^USER\s+[a-z]/m.test(content)
                    },
                ],
            }
        },
        {
            id: 'container-env-secrets',
            name: 'Secrets Passed via Docker ENV (Layer Leak)',
            severity: 'medium',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 798,
            description: 'Secrets set as ENV in Dockerfile — stored in Docker image layers, visible via history.',
            remediation: 'Use build args with ARG, Docker secrets (Swarm), or --secret flag with BuildKit.',
            category: 'container',
            patterns: {
                dockerfile: [
                    { pattern: /^ENV\s+(?:API_KEY|SECRET|PASSWORD|TOKEN|ACCESS_KEY)/gmi },
                ],
            }
        },
        {
            id: 'container-latest-tag',
            name: 'Container Image Using Latest Tag',
            severity: 'low',
            owasp: 'API9:2023 — Improper Assets Management',
            cwe: 1104,
            description: 'FROM image uses :latest tag — unpredictable updates can break builds or introduce vulnerabilities.',
            remediation: 'Pin to specific version: node:20.12.0-alpine3.19 instead of node:latest',
            category: 'container',
            patterns: {
                dockerfile: [
                    { pattern: /FROM\s+\S+:latest/gmi },
                    { pattern: /FROM\s+\S+(?<!:\d+\.\d+\.\d+)(?<!:\d+)($|\s)/gm },
                ],
            }
        },
        {
            id: 'container-apt-no-cleanup',
            name: 'apt-get Without Cleanup (Cache Layers)',
            severity: 'low',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 1104,
            description: 'apt-get install without && rm -rf /var/lib/apt/lists/* after — layer bloat includes caches.',
            remediation: 'Add: && rm -rf /var/lib/apt/lists/* to same RUN layer.',
            category: 'container',
            patterns: {
                dockerfile: [
                    { pattern: /apt-get\s+install.*&&\s*\n\s*\w/gm, contextCheck: (content, m) =>
                        !/rm\s+-rf\s+\/var\/lib\/apt/.test(content)
                    },
                ],
            }
        },
        {
            id: 'container-add-vs-copy',
            name: 'Using ADD Instead of COPY',
            severity: 'low',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 829,
            description: 'ADD has extra features (URL expansion, tar auto-extraction) that can be dangerous.',
            remediation: 'Use COPY for local files. Only use ADD when explicitly needing auto-extraction.',
            category: 'container',
            patterns: {
                dockerfile: [
                    { pattern: /^ADD\s+/gm, contextCheck: (content, m) =>
                        content.slice(m.index, m.index + 150).includes('COPY') === false
                    },
                ],
            }
        },
        {
            id: 'exposed-port-no-whitelist',
            name: 'Exposed Port Without Access Restriction Comments',
            severity: 'low',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 1104,
            description: 'Port exposed in container without documentation of intended access restrictions.',
            remediation: 'Add comments documenting which ports are public vs internal. Consider multi-stage builds.',
            category: 'container',
            patterns: {
                dockerfile: [
                    { pattern: /EXPOSE\s+\d+/gm },
                ],
            }
        },
    ]
};
