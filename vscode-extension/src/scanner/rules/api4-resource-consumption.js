/**
 * API4:2023 — Unrestricted Resource Consumption
 * Rate limiting, pagination, body size limits
 */
module.exports = {
    rules: [
        {
            id: 'no-rate-limit',
            name: 'Endpoint Missing Rate Limiting',
            severity: 'medium',
            owasp: 'API4:2023 — Unrestricted Resource Consumption',
            cwe: 770,
            description: 'API handler without rate-limiting — attackers can brute-force or brute-force credentials.',
            remediation: 'Apply rate-limit middleware: express-rate-limit, flask-limiter, throttler. Return 429 on quota exceeded.',
            category: 'rate_limiting',
            patterns: {
                python: [
                    { pattern: /@(?:app|blueprint|route)\.(?:get|post|put|delete|patch|route)\(/gm, contextCheck: (content) =>
                        !/(?:@limit|@rate_limit|limiter\.|throttle|ratelimit|@throttle)/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /(?:router|app|route)\.(?:get|post|put|delete|patch)\(/gm, contextCheck: (content) =>
                        !/(?:rateLimit|rate_limit|express-rate-limit|throttle|ratelimit|limiter|bottleneck)/.test(content)
                    },
                ],
                go: [
                    { pattern: /func\s+\w+Handler/gm, contextCheck: (content) =>
                        !/(?:throttle|rateLimit|RateLimit|limiter|LimitMiddleware)/.test(content)
                    },
                ],
                java: [
                    { pattern: /@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)\(/gm, contextCheck: (content) =>
                        !/(?:RateLimiter|@Throttling|throttle|rate_limit)/.test(content)
                    },
                ],
            }
        },
        {
            id: 'pagination-missing',
            name: 'Missing Pagination on List Endpoint',
            severity: 'low',
            owasp: 'API4:2023 — Unrestricted Resource Consumption',
            cwe: 770,
            description: 'List endpoint returns all records without pagination — risk of OOM or slow responses.',
            remediation: 'Implement pagination (limit/offset or cursor-based). Set max page size. Never .all() in production.',
            category: 'resource_consumption',
            patterns: {
                python: [
                    { pattern: /\.all\(\)|\.fetchall\(\)/gmi, contextCheck: (content, m) =>
                        content.slice(m.index, m.index + 1000).includes('return') &&
                        !/(?:paginate|limit|offset|page_size|PageNumberPagination|QueryPagination)/.test(content)
                    },
                    { pattern: /return\s+\w+\.query\.all/gmi },
                ],
                javascript: [
                    { pattern: /\.find\(\)|\.findAll\(\)|\.fetchAll\(\)|\.all\(\)/gm, contextCheck: (content, m) =>
                        !/(?:skip|limit|pagination|paginate|page|pageSize|offset|\.paginate)/.test(content.slice(0, m.index + 500))
                    },
                ],
            }
        },
        {
            id: 'no-request-size-limit',
            name: 'No Request Body Size Limit',
            severity: 'medium',
            owasp: 'API4:2023 — Unrestricted Resource Consumption',
            cwe: 770,
            description: 'No limit on request body size — attacker can exhaust memory with large payloads.',
            remediation: 'Set request body limits: Flask MAX_CONTENT_LENGTH, Express body-parser limit, Nginx client_max_body_size.',
            category: 'resource_consumption',
            patterns: {
                python: [
                    { pattern: /request\.(?:get_json|json|data|form|files)/gmi, contextCheck: (content) =>
                        !/MAX_CONTENT_LENGTH/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /express\.(?:json|urlencoded)\(/gmi, contextCheck: (content) =>
                        !/limit\s*[:=]/.test(content)
                    },
                    { pattern: /bodyParser\.(?:json|urlencoded)\(/gmi, contextCheck: (content) =>
                        !/limit\s*[:=]/.test(content)
                    },
                ],
                go: [
                    { pattern: /r\.(?:Post|HandleFunc)/gm, contextCheck: (content) =>
                        !/MaxBytesReader|LimitReader|http\.MaxBytesHandler/.test(content)
                    },
                ],
            }
        },
        {
            id: 'unbounded-file-upload',
            name: 'Unrestricted File Upload Size',
            severity: 'high',
            owasp: 'API4:2023 — Unrestricted Resource Consumption',
            cwe: 400,
            description: 'File upload without size or type restrictions — risk of fill disk, malware upload, or DoS.',
            remediation: 'Limit file size and type on server. Validate MIME type, scan with antivirus. Store outside webroot.',
            category: 'resource_consumption',
            patterns: {
                python: [
                    { pattern: /request\.files/gmi, contextCheck: (content) =>
                        !/MAX_CONTENT_LENGTH|request\.files\[|\.content_length/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /multer|formidable|busboy|fileUpload/gmi, contextCheck: (content) =>
                        !/(?:limits|fileSize|maxFileSize|maxFieldsSize)/.test(content)
                    },
                ],
                go: [
                    { pattern: /r\.MultipartForm|r\.FormFile/gmi, contextCheck: (content) =>
                        !/MaxBytesReader|LimitReader/.test(content)
                    },
                ],
            }
        },
        {
            id: 'recursive-function-no-limit',
            name: 'Potentially Unbounded Recursive/Async Operation',
            severity: 'medium',
            owasp: 'API4:2023 — Unrestricted Resource Consumption',
            cwe: 674,
            description: 'Recursive or async function without depth/page limit — can cause stack overflow or resource drain.',
            remediation: 'Enforce recursion depth limit, use iterative approaches, or set async pool concurrency cap.',
            category: 'resource_consumption',
            patterns: {
                javascript: [
                    { pattern: /async\s+(?:function\s+\w+|\(\w+)\s*\{[^}]*Promise\.all\([^)]+\.map/gmi },
                    { pattern: /while\s*\(true\)\s*{|setTimeout\([^)]*,\s*0\)/gm },
                ],
                python: [
                    { pattern: /async\s+def.*await\s+asyncio\.(?:gather|wait)\([^)]*for/gmi },
                ],
            }
        },
    ]
};
