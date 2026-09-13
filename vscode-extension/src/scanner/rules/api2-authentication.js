/**
 * API2:2023 — Broken Authentication
 * Hardcoded keys, weak JWT, auth bypass, session fixation
 */
module.exports = {
    rules: [
        {
            id: 'hardcoded-api-key',
            name: 'Hardcoded API Key / Secret',
            severity: 'critical',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 798,
            description: 'API credential hardcoded as a string literal — leaks into version control.',
            remediation: 'Store secrets in environment variables: os.environ.get("API_KEY"), process.env.API_KEY, etc.',
            category: 'authentication',
            patterns: {
                python: [
                    { pattern: /(?:api_key|apikey|API_KEY|api_secret|API_SECRET|API_TOKEN|api_token|APP_SECRET)\s*[=:]\s*['"](?!\$\{|os\.environ|os\.getenv|environ\.get|config\()['"]/gmi },
                    { pattern: /(?:JWT_SECRET|jwt_secret|SECRET_KEY|secret_key|AUTH_TOKEN|auth_token)\s*[=:]\s*['"](?!\$\{|os\.environ|os\.getenv)['"]/gm },
                ],
                javascript: [
                    { pattern: /(?:apiKey|api_key|API_KEY|apiSecret|api_secret|apiToken|api_token)\s*[:=]\s*['"`](?!process\.env|\$|config)[^'"`]{4,}/gm },
                    { pattern: /(?:JWT_SECRET|jwtSecret|secretKey|SECRET_KEY|authToken|AUTH_TOKEN)\s*[:=]\s*['"`](?!process\.env|\$)[^'"`]+/gm },
                ],
                typescript: [
                    { pattern: /(?:apiKey|api_key|API_KEY|apiSecret|api_secret|apiToken|api_token)\s*[:=]\s*['"`](?!process\.env|\$)[^'"`]{4,}/gm },
                    { pattern: /(?:JWT_SECRET|jwtSecret|secretKey|SECRET_KEY|authToken)\s*[:=]\s*['"`](?!process\.env|\$)[^'"`]+/gm },
                ],
                go: [
                    { pattern: /(?:APIKey|ApiKey|apiKey|SecretKey|secretKey|AuthToken|authToken)\s*(?:=|:=)\s*["'`][^"'`$]{4,}["'`]/gm },
                ],
                java: [
                    { pattern: /(?:apiKey|api_key|API_KEY|secret|SECRET|apiSecret|authToken)\s*=\s*["'][^"'$]{4,}["']/gm },
                ],
                ruby: [
                    { pattern: /(?:api_key|api_secret|secret_key|jwt_secret|auth_token)\s*[:=]\s*['"](?!ENV|Rails\.application\.credentials)[^'"]{4,}['"]/gmi },
                ],
                php: [
                    { pattern: /(?:api_key|api_secret|secret_key|jwt_secret)\s*[:=]\s*['"](?!getenv|_ENV|config)[^'"]{4,}['"]/gmi },
                ],
                kotlin: [
                    { pattern: /val\s+(?:apiKey|apiSecret|secretKey|jwtSecret)\s*=\s*["'][^"'$]{4,}["']/gm },
                ],
                rust: [
                    { pattern: /let\s+(?:api_key|api_secret|secret_key|jwt_secret)\s*[:=]\s*["'][^"'$]{4,}["']/gmi },
                ],
            }
        },
        {
            id: 'weak-jwt-handling',
            name: 'Weak / Unsafe JWT Handling',
            severity: 'high',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 522,
            description: 'JWT tokens signed with weak/known secrets, algorithm confusion risk, or validation disabled.',
            remediation: 'Use strong random secrets from env, whitelist algorithms (HS256|RS256), verify exp+nbf+iss.',
            category: 'authentication',
            patterns: {
                python: [
                    { pattern: /jwt\.encode\([^)]*['"]secret['"]/gmi },
                    { pattern: /JWT_SECRET\s*=\s*['"](?!os\.environ|os\.getenv|secrets\.)[^'"]{1,20}['"]/gm },
                    { pattern: /algorithm\s*=\s*['"]none['"]/gmi },
                    { pattern: /jwt\.decode\([^)]*verify\s*=\s*False/gmi },
                    { pattern: /jwt\.decode\([^)]*algorithms\s*=\s*None/gmi },
                ],
                javascript: [
                    { pattern: /jwt\.sign\(\s*[^,]+,\s*['"`](?!process\.env)[^'"`]{1,20}['"`]/gmi },
                    { pattern: /secret:\s*['"`](?!process\.env)[^'"`]{1,20}['"`]/gmi },
                    { pattern: /algorithms:\s*\[.*'none'/gmi },
                    { pattern: /(?:verify|ignoreExpiration)\s*[:=]\s*false/gmi },
                ],
                typescript: [
                    { pattern: /secret:\s*['"`](?!process\.env)[^'"`]{1,20}['"`]/gmi },
                    { pattern: /algorithms:\s*\[.*'none'/gmi },
                ],
                go: [
                    { pattern: /SigningMethodNone|<nil>/gm },
                    { pattern: /token\.Valid\s*==\s*false/gm },
                ],
                java: [
                    { pattern: /setSigningKey\(["'].{1,20}["']\)/gm },
                    { pattern: /parserBuilder\(\)[^;]*setSigningKey[^;]*;/gm, contextCheck: (content) =>
                        !/io\.jsonwebtoken\.security\.Keys/.test(content)
                    },
                ],
                rust: [
                    { pattern: /from_secret\s*\(\s*["']\w{1,20}["']/gmi },
                ],
            }
        },
        {
            id: 'auth-bypass-pattern',
            name: 'Authentication Bypass / Disabled in Code',
            severity: 'high',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 287,
            description: 'Auth decorators/middleware disabled or bypassed — may leak to production.',
            remediation: 'Never disable auth in production. Use mock objects in tests, not conditional skips.',
            category: 'authentication',
            patterns: {
                python: [
                    { pattern: /(?:login_disabled|auth_disabled|bypass_auth|disable_auth|skip_auth)\s*=?\s*(?:True|true)/gmi },
                    { pattern: /def\s+get_current_user.*return\s+Mock/gmi },
                    { pattern: /@login_required\s*\n\s*def\s+\w+.*\n\s+return\s+['\"]mock/gmi },
                ],
                javascript: [
                    { pattern: /(?:bypassAuth|skipAuth|bypass_auth|noAuth|disableAuth|auth_disabled)\s*[:=]\s*(?:true|false|null)/gmi },
                    { pattern: /\.unless\(\s*(?:isTest|isDev|env\s*===?\s*['"]test['"])/gmi },
                ],
            }
        },
        {
            id: 'session-fixation',
            name: 'Session Fixation Risk',
            severity: 'medium',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 384,
            description: 'Session ID accepted from user input (cookie/param) without regeneration on login.',
            remediation: 'Regenerate session ID on every successful login. Never accept user-supplied session IDs.',
            category: 'authentication',
            patterns: {
                python: [
                    { pattern: /session\[['"]\w+['"]\]\s*=\s*request\.(?:args|form|cookies)\.get\(['"]session/gmi },
                ],
                javascript: [
                    { pattern: /req\.session\s*=\s*req\.(?:query|body|params)\.(?:session|sessionId)/gmi },
                ],
            }
        },
        {
            id: 'password-in-query-string',
            name: 'Password/Credential in Query String',
            severity: 'high',
            owasp: 'API2:2023 — Broken Authentication',
            cwe: 598,
            description: 'Passwords or tokens passed via query string — logged in server logs, referrer headers, browser history.',
            remediation: 'Use POST/PUT with request body or Authorization header. Never pass secrets in URL query.',
            category: 'authentication',
            patterns: {
                javascript: [
                    { pattern: /['"`]password=['"`][^&'"`]+/gmi, contextCheck: (content) => /(?:fetch|axios|ajax|XMLHttpRequest|xhr)/.test(content) },
                ],
                python: [
                    { pattern: /params\s*=\s*\{[^}]*['"]password['"]]/gmi },
                ],
            }
        },
    ]
};
