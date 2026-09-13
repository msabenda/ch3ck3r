/**
 * API8:2023 — Security Misconfiguration
 * CORS, SSL, debug, HSTS, verbose errors, default creds, insecure ciphers
 */
module.exports = {
    rules: [
        {
            id: 'cors-wildcard-allow',
            name: 'Wildcard CORS Policy',
            severity: 'medium',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 942,
            description: 'CORS configured with Allow-Origin: *. Any website can make cross-origin requests to your API.',
            remediation: 'Restrict Access-Control-Allow-Origin to specific trusted origins via env configuration.',
            category: 'cors',
            applyToSpec: true,
            patterns: {
                python: [
                    { pattern: /allow_origins\s*=\s*\[?\s*['"*]['"]\s*\]?/gmi },
                    { pattern: /Access-Control-Allow-Origin:\s*\*/gmi },
                ],
                javascript: [
                    { pattern: /origin:\s*['"`]\*['"`]/gmi },
                    { pattern: /cors\(\s*\)/gm, contextCheck: (content) =>
                        !/(?:origin|allowedOrigins|credentials|methods|exposedHeaders)/.test(content)
                    },
                ],
                go: [
                    { pattern: /AllowedOrigins:\s*\[\s*"\*"\s*\]|AllowAllOrigins/gmi },
                ],
                java: [
                    { pattern: /allowedOrigins\s*\(\s*"\*"\s*\)/gmi },
                    { pattern: /\.allowedOriginPatterns?\s*\(\s*"\*"/gmi },
                ],
                php: [
                    { pattern: /header\(['"]Access-Control-Allow-Origin:\s*\*/gmi },
                ],
                ruby: [
                    { pattern: /origins\s+\*|origins\s+'*'/gmi },
                ],
                kotlin: [
                    { pattern: /allowedOrigins\(".*?\*.*?"\)/gmi },
                ],
            }
        },
        {
            id: 'ssl-verify-disabled',
            name: 'SSL/TLS Certificate Verification Disabled',
            severity: 'critical',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 295,
            description: 'SSL verification disabled — vulnerable to MITM attacks on all outbound connections.',
            remediation: 'Always verify certs: verify=True, rejectUnauthorized: true, InsecureSkipVerify: false.',
            category: 'security_misconfiguration',
            patterns: {
                python: [
                    { pattern: /verify\s*=\s*False/gi },
                    { pattern: /ssl_verify\s*=\s*False/gi },
                    { pattern: /context\.check_hostname\s*=\s*False/gi },
                ],
                javascript: [
                    { pattern: /rejectUnauthorized\s*:\s*false/gmi },
                    { pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/gmi },
                ],
                go: [
                    { pattern: /InsecureSkipVerify\s*=\s*true/gmi },
                ],
                java: [
                    { pattern: /setHostnameVerifier\(.*ALLOW_ALL/gmi },
                    { pattern: /setDefaultHostnameVerifier.*return\s*true/gmi },
                ],
            }
        },
        {
            id: 'debug-mode-enabled',
            name: 'Debug / Development Mode Enabled',
            severity: 'high',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 215,
            description: 'Debug mode enabled — exposes stack traces, env variables, and interactive debuggers.',
            remediation: 'Set debug=False in production. Use env toggle: debug=os.environ.get("DEBUG")',
            category: 'security_misconfiguration',
            patterns: {
                python: [
                    { pattern: /debug\s*=\s*(?:True|true)/gmi },
                    { pattern: /app\.run\([^)]*debug\s*=\s*True/gmi },
                ],
                javascript: [
                    { pattern: /debug\s*:\s*true/gmi },
                    { pattern: /NODE_ENV\s*===?\s*['"`]development['"`]/gmi, contextCheck: (content) =>
                        !/NODE_ENV\s*[!=]==?\s*['"`]production['"`]/.test(content)
                    },
                ],
                go: [
                    { pattern: /gin\.Default|gin\.Mode\s*\(\s*["']debug["']\s*\)/gm },
                ],
                java: [
                    { pattern: /spring\.profiles\.active=dev|spring\.devtools\./gmi },
                ],
            }
        },
        {
            id: 'verbose-error-handling',
            name: 'Verbose Error Messages / Stack Traces Exposed',
            severity: 'medium',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 209,
            description: 'Detailed error messages / stack traces returned to client — leaks internals, paths, schema.',
            remediation: 'Return generic error messages. Use custom error handlers that mask internals.',
            category: 'security_misconfiguration',
            patterns: {
                python: [
                    { pattern: /return\s+(?:str|repr)\([^)]*error/gmi },
                    { pattern: /traceback\.format_exc|traceback\.print_exc/gmi },
                ],
                javascript: [
                    { pattern: /stack\s*:\s*err\.stack|res\.send\(\s*err\.message\s*\)|res\.json\(\s*err\s*\)/gmi },
                ],
            }
        },
        {
            id: 'hsts-missing',
            name: 'Missing HTTP Strict Transport Security (HSTS)',
            severity: 'medium',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 319,
            description: 'No Strict-Transport-Security header. Allows downgrade attacks on HTTPS connections.',
            remediation: 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains',
            category: 'security_misconfiguration',
            patterns: {
                python: [
                    { pattern: /@app\.(?:after_request|after_request|middleware)/gmi, contextCheck: (content) =>
                        !/Strict-Transport-Security/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /app\.(?:use|get)\(/gm, contextCheck: (content) =>
                        !/Strict-Transport-Security|hsts|helmet/.test(content)
                    },
                ],
                go: [
                    { pattern: /r\.(?:Use|Handle)/gm, contextCheck: (content) =>
                        !/Strict-Transport-Security|hsts/.test(content)
                    },
                ],
            }
        },
        {
            id: 'default-credentials',
            name: 'Default/Weak Credentials Detected',
            severity: 'high',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 1392,
            description: 'Default credentials (admin:admin, root:root, test:test) found in code or config.',
            remediation: 'Change all default credentials. Enforce password policy on first login.',
            category: 'security_misconfiguration',
            patterns: {
                all: [
                    { pattern: /['"`](?:admin|root|user)\s*\/\s*(?:admin|root|password|123456|test|changeme)['"`]/gmi },
                    { pattern: /username\s*[:=]\s*['"`](?:admin|root|test)['"`].*password\s*[:=]\s*['"`](?:admin|root|password|123456|test)['"`]/gmi },
                ],
                python: [
                    { pattern: /(?:DEFAULT_USER|DEFAULT_PASS|DUMMY_PASSWORD)\s*=\s*['"][^'"]+['"]/gmi },
                ],
            }
        },
        {
            id: 'missing-security-headers',
            name: 'Missing Security Headers (CSP / X-Frame / XSS-Protection)',
            severity: 'low',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 693,
            description: 'Security response headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options) not found.',
            remediation: 'Set security headers via middleware: helmet (Node), talisman (Python), or nginx config.',
            category: 'security_misconfiguration',
            patterns: {
                python: [
                    { pattern: /@app\.(?:after_request|before_request)/gmi, contextCheck: (content) =>
                        !/(?:Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|X-XSS-Protection)/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /app\.(?:use|get|listen)/gm, contextCheck: (content) =>
                        !/(?:helmet|csp|cspHeader|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options)/.test(content)
                    },
                ],
            }
        },
        {
            id: 'insecure-cookie',
            name: 'Insecure Session Cookie Configuration',
            severity: 'high',
            owasp: 'API8:2023 — Security Misconfiguration',
            cwe: 614,
            description: 'Session cookies without Secure, HttpOnly, or SameSite flags — can be stolen by XSS / MITM.',
            remediation: 'Set cookie flags: Secure=true, HttpOnly=true, SameSite=Lax/Strict.',
            category: 'security_misconfiguration',
            patterns: {
                python: [
                    { pattern: /set_cookie|set-cookie/gmi, contextCheck: (content) =>
                        !/Secure|HttpOnly|SameSite/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /res\.cookie\(|res\.setHeader\([^)]*Set-Cookie/gmi, contextCheck: (content) =>
                        !/(?:secure|httpOnly|sameSite)/i.test(content)
                    },
                    { pattern: /express\.session\(/gm, contextCheck: (content) =>
                        !/(?:secure|httpOnly|sameSite)/i.test(content)
                    },
                ],
                go: [
                    { pattern: /http\.SetCookie/gmi, contextCheck: (content) =>
                        !/Secure|HttpOnly|SameSite/.test(content)
                    },
                ],
            }
        },
    ]
};
