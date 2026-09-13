/**
 * TypeScript-specific pattern rules
 * Addresses the gap where JS patterns don't match TS type-annotated code
 */
module.exports = {
    rules: [
        {
            id: 'ts-missing-auth-route',
            name: 'TypeScript Route Missing Authorization',
            severity: 'high',
            owasp: 'API1:2023 — Broken Object Level Authorization',
            cwe: 862,
            description: 'TypeScript route handler without authorization middleware.',
            remediation: 'Add auth middleware or custom guard. Use dependency injection for auth context.',
            category: 'authorization',
            patterns: {
                typescript: [
                    {
                        pattern: /\.(?:get|post|put|delete|patch)\(\s*['"`]\/[\w\/:]*['"`]\s*,?\s*(?:\r?\n\s*)?(?:async\s*)?\(/gm,
                        contextCheck: (content) =>
                            !/(?:authMiddleware|authenticate|authorize|verifyToken|requireAuth|isAuthenticated|protect|ensureLoggedIn)/.test(content)
                    },
                ],
            }
        },
        {
            id: 'ts-ssrf-via-await',
            name: 'TypeScript SSRF via fetch/axios',
            severity: 'critical',
            owasp: 'API7:2023 — Server Side Request Forgery',
            cwe: 918,
            description: 'User-supplied URL used in HTTP request (TypeScript). Attacker can target internal services.',
            remediation: 'Validate URLs against allowlist. Block private IP ranges. Disable redirect following.',
            category: 'ssrf',
            patterns: {
                typescript: [
                    { pattern: /(?:const|let)\s+\w+Url\s*(?::\s*\w+)?\s*=\s*req\.(?:body|query|params)/gmi },
                    { pattern: /(?:axios|got|node-fetch)\s*[(<]\s*\w+(?:Url|Target)/gmi },
                    { pattern: /(?:const|let)\s+\w+\s*(?::\s*\w+)?\s*=\s*req\.(?:body|query|params)\.(?:url|uri|target|webhook|callback)/gmi },
                ],
            }
        },
        {
            id: 'ts-sql-injection',
            name: 'TypeScript SQL Injection via Template Literal',
            severity: 'critical',
            owasp: 'API8:2023 — Injection',
            cwe: 89,
            description: 'SQL query built with template literal containing TypeScript variable — SQL injection risk.',
            remediation: 'Use parameterized queries with placeholders ($1, $2). Never use backtick template strings for SQL.',
            category: 'injection',
            patterns: {
                typescript: [
                    { pattern: /`SELECT\$\{[^}]*\w+[^}]*\}|`INSERT\$\{[^}]*\w+[^}]*\}|`DELETE\$\{[^}]*\w+[^}]*\}|`UPDATE\$\{[^}]*\w+[^}]*\}/gi },
                ],
            }
        },
        {
            id: 'ts-command-injection',
            name: 'TypeScript Command Injection',
            severity: 'critical',
            owasp: 'API8:2023 — Injection',
            cwe: 78,
            description: 'User input passed to OS command execution in TypeScript.',
            remediation: 'Use execFile/spawn with arguments array. Never use exec with shell interpolation.',
            category: 'injection',
            patterns: {
                typescript: [
                    { pattern: /execSync\([^)]*req\./gmi },
                    { pattern: /exec\([^)]*req\./gmi },
                ],
            }
        },
        {
            id: 'ts-path-traversal',
            name: 'TypeScript Path Traversal',
            severity: 'high',
            owasp: 'API8:2023 — Injection',
            cwe: 22,
            description: 'User input concatenated in file path without TypeScript-safe validation.',
            remediation: 'Use path.resolve with allowlist. Validate path stays within allowed root directory.',
            category: 'injection',
            patterns: {
                typescript: [
                    { pattern: /fs\.(?:readFileSync|readFile|writeFileSync|writeFile)\([^)]*\+/gmi },
                ],
            }
        },
        {
            id: 'ts-idor',
            name: 'TypeScript IDOR — No Ownership Check',
            severity: 'critical',
            owasp: 'API1:2023 — Broken Object Level Authorization',
            cwe: 639,
            description: 'User-supplied resource ID used without confirming ownership.',
            remediation: 'Verify authenticated user owns the resource before access.',
            category: 'authorization',
            patterns: {
                typescript: [
                    { pattern: /req\.params\.(id|userId|objectId)/gmi, contextCheck: (content) =>
                        !/(?:where\s*\{|findFirst|findUnique|author|owner|userId\s*[:=])/.test(content)
                    },
                ],
            }
        },
        {
            id: 'ts-sensitive-exposure',
            name: 'TypeScript Sensitive Data in Response',
            severity: 'high',
            owasp: 'API3:2023 — Broken Object Property Level Authorization',
            cwe: 200,
            description: 'Response object containing sensitive fields (password, ssn) that should be excluded.',
            remediation: 'Use response DTO/interfaces with only non-sensitive fields. Use Omit/Pick types.',
            category: 'information_disclosure',
            patterns: {
                typescript: [
                    { pattern: /password[^a-zA-Z].*res\.json|res\.json.*password/gmi },
                    { pattern: /user\.password|\.password[^a-zA-Z]/gmi, contextCheck: (content) => /res\.(?:json|send)/.test(content) },
                ],
            }
        },
    ]
};
