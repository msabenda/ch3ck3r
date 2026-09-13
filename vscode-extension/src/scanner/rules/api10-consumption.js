/**
 * API10:2023 — Unsafe Consumption of APIs
 * Third-party API call without input validation, no timeout, no retry
 */
module.exports = {
    rules: [
        {
            id: 'unsafe-api-consumption',
            name: 'Unsafe Third-Party API Response Handling',
            severity: 'medium',
            owasp: 'API10:2023 — Unsafe Consumption of APIs',
            cwe: 20,
            description: 'Third-party API response consumed without validation or safe access. Malformed/untrusted responses can cause injection bugs.',
            remediation: 'Validate external API responses. Use optional chaining, .get() with defaults, or parse with schema validation.',
            category: 'api_consumption',
            patterns: {
                python: [
                    { pattern: /response\.json\(\)\s*\[/gmi, contextCheck: (content) =>
                        !content.includes('.get(') && !content.includes('get(')
                    },
                ],
                javascript: [
                    { pattern: /response\.data/gmi, contextCheck: (content) =>
                        !content.includes('?.') && !content.includes('if') && !content.includes('try') && !content.includes('catch')
                    },
                ],
                go: [
                    { pattern: /json\.Unmarshal\([^)]*resp/gmi, contextCheck: (content) =>
                        !/fields|validate|sanitize/.test(content)
                    },
                ],
            }
        },
        {
            id: 'http-request-timeout-missing',
            name: 'HTTP Request Without Timeout',
            severity: 'medium',
            owasp: 'API10:2023 — Unsafe Consumption of APIs',
            cwe: 770,
            description: 'Outbound HTTP request without timeout — connection can hang forever, exhausting resources.',
            remediation: 'Set reasonable timeout on all outbound HTTP requests (5-30s). Abort on timeout.',
            category: 'api_consumption',
            patterns: {
                python: [
                    { pattern: /requests\.(?:get|post|put|delete|head|options|patch)\(/gm, contextCheck: (content) =>
                        !/timeout\s*=/.test(content)
                    },
                    { pattern: /httpx\.(?:get|post|put|delete)\(/gm, contextCheck: (content) =>
                        !/timeout\s*=/.test(content)
                    },
                    { pattern: /urllib\.request\.urlopen/gm, contextCheck: (content) =>
                        !/timeout/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /axios\.(?:get|post|put|delete|patch|request)\(/gm, contextCheck: (content) =>
                        !/timeout\s*[:=]/.test(content)
                    },
                    { pattern: /fetch\(/gm, contextCheck: (content) =>
                        !/AbortController|abort|timeout|signal/.test(content)
                    },
                ],
                go: [
                    { pattern: /http\.(?:Get|Post|Head)\(/gm, contextCheck: (content) =>
                        !/Timeout|context\.WithTimeout/.test(content)
                    },
                ],
                java: [
                    { pattern: /RestTemplate|WebClient|HttpClient/gmi, contextCheck: (content) =>
                        !/connectTimeout|readTimeout|timeout/.test(content)
                    },
                ],
            }
        },
        {
            id: 'api-key-in-url-call',
            name: 'API Key Exposed in Third-Party URL',
            severity: 'high',
            owasp: 'API10:2023 — Unsafe Consumption of APIs',
            cwe: 200,
            description: 'API key/secret passed in URL or as query parameter — leaked in logs, referrer headers.',
            remediation: 'Pass API keys in Authorization header or request body. Never in URL query.',
            category: 'api_consumption',
            patterns: {
                javascript: [
                    { pattern: /['"`][^'"]*\b(?:api_key|apikey|token|secret)\b[^'"]*=\s*(?:\$\{|process\.env)/gmi, contextCheck: (content) =>
                        /\.get\(|\.post\(|fetch\(/.test(content)
                    },
                ],
                python: [
                    { pattern: /params\s*=\s*\{[^}]*['"](?:api_key|apikey|token|secret)['"]/gmi },
                ],
            }
        },
        {
            id: 'uncontrolled-redirect-follow',
            name: 'Automatic Redirect Following on External Request',
            severity: 'low',
            owasp: 'API10:2023 — Unsafe Consumption of APIs',
            cwe: 601,
            description: 'HTTP client follows redirects automatically — attacker can redirect to malicious/phishing site.',
            remediation: 'Disable redirect following on external requests, or validate redirect URL against allowlist.',
            category: 'api_consumption',
            patterns: {
                python: [
                    { pattern: /requests\.(?:get|post|put|delete|head|options|patch)\(/gm, contextCheck: (content) =>
                        !content.includes('allow_redirects=False') && !content.includes('allow_redirects=False')
                    },
                ],
            }
        },
    ]
};
