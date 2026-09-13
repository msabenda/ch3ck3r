/**
 * Secrets, tokens, credentials detection
 */
module.exports = {
    rules: [
        {
            id: 'exposed-git-token',
            name: 'Git / OAuth Token in Code',
            severity: 'critical',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 798,
            description: 'Git personal access token, OAuth token, or AWS secret key found in code.',
            remediation: 'Remove token immediately and rotate. Use env variables or secret manager.',
            category: 'secrets',
            patterns: {
                all: [
                    { pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/gm },
                    { pattern: /(?:xox[abpr]|xapp|xoxe)-[A-Za-z0-9]{24,}/gm },
                    { pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/gm },
                    { pattern: /sk-[A-Za-z0-9]{20,}/gm },
                    { pattern: /pk-[A-Za-z0-9]{20,}/gm },
                    { pattern: /(?:ghp_|github_pat_)[A-Za-z0-9_]{36,}/gm },
                    { pattern: /(?:access_token|accessToken)\s*[:=]\s*['"`][A-Za-z0-9_-]{20,}['"`]/gm },
                ],
            }
        },
        {
            id: 'exposed-aws-credentials',
            name: 'AWS Access Key / Secret Key Exposed',
            severity: 'critical',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 798,
            description: 'AWS IAM credentials hardcoded — anyone with access to repo can escalate cloud privileges.',
            remediation: 'Use AWS IAM roles (ECS, EC2, Lambda) or environment variables. Remove and rotate keys.',
            category: 'secrets',
            patterns: {
                all: [
                    { pattern: /(?:AWS_ACCESS_KEY_ID|aws_access_key_id|AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[:=]\s*['"](?!env|\.env|os\.environ|process\.env\b)[^'"]+/gm },
                ],
            }
        },
        {
            id: 'exposed-password',
            name: 'Password Literal in Code',
            severity: 'critical',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 798,
            description: 'Password found as a string literal — can be leaked via version control.',
            remediation: 'Never hardcode passwords. Use environment variables or a secrets manager.',
            category: 'secrets',
            patterns: {
                python: [
                    { pattern: /password\s*[=:]\s*['"][^'"]+['"]/gmi, contextCheck: (content) =>
                        !/environ|getenv|config/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /password\s*[:=]\s*['"`][^'"`]+['"`]/gmi, contextCheck: (content) =>
                        !/process\.env|config|\.env/.test(content)
                    },
                ],
                typescript: [
                    { pattern: /password\s*[:=]\s*['"`][^'"`]+['"`]/gmi, contextCheck: (content) =>
                        !/process\.env/.test(content)
                    },
                ],
                go: [
                    { pattern: /password\s*[:=]\s*["'`][^"'`$]+["'`]/gmi },
                ],
                java: [
                    { pattern: /password\s*=\s*["'][^"'$]+["']/gmi, contextCheck: (content) =>
                        !/System\.getenv|Environment\.getEnv/.test(content)
                    },
                ],
            }
        },
        {
            id: 'private-key-exposed',
            name: 'Private / SSH Key Content in Code',
            severity: 'critical',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 798,
            description: 'Private key (RSA, ED25519, EC) embedded in source code — immediate compromise risk.',
            remediation: 'Remove key immediately. Rotate. Store in secrets manager or volume-mounted at deploy time.',
            category: 'secrets',
            patterns: {
                all: [
                    { pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gm },
                    { pattern: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/gm },
                    { pattern: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----/gm },
                ],
            }
        },
        {
            id: 'jwt-token-hardcoded',
            name: 'Hardcoded JWT Token in Code',
            severity: 'high',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 798,
            description: 'JWT token hardcoded as string (eyJ... pattern) — can be used by anyone.',
            remediation: 'Remove hardcoded JWT tokens. Generate at runtime or from env variables.',
            category: 'secrets',
            patterns: {
                all: [
                    { pattern: /['"`]eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}['"`]/gm },
                ],
            }
        },
        {
            id: 'connection-string-hardcoded',
            name: 'Hardcoded Database Connection String',
            severity: 'critical',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 798,
            description: 'Database connection string with credentials hardcoded.',
            remediation: 'Use env variables for connection strings. Remove credentials from code.',
            category: 'secrets',
            patterns: {
                all: [
                    { pattern: new RegExp('(?:postgres|mysql|mariadb|mongodb|redis):\/\/[^:]+:[^@]+@', 'gmi') },
                    { pattern: /Server=.*;Database=.*;User\s*Id=/gmi },
                ],
            }
        },
    ]
};
