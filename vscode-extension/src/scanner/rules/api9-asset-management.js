/**
 * API9:2023 — Improper Assets Management
 * Deprecated endpoints, unversioned APIs, zombie endpoints
 */
module.exports = {
    rules: [
        {
            id: 'deprecated-endpoint-active',
            name: 'Deprecated / Legacy API Endpoint Active',
            severity: 'low',
            owasp: 'API9:2023 — Improper Assets Management',
            cwe: 1104,
            description: 'Deprecated or legacy endpoints still active — unmaintained code may have unpatched vulnerabilities.',
            remediation: 'Remove deprecated endpoints. Use versioned APIs with sunset headers.',
            category: 'deprecated',
            applyToSpec: true,
            patterns: {
                python: [
                    { pattern: /@deprecated|deprecated|legacy|v0|unstable/gmi },
                ],
                javascript: [
                    { pattern: /deprecated|DEPRECATED|@deprecated|legacy|v0|unstable/gmi },
                ],
            }
        },
        {
            id: 'unversioned-api',
            name: 'Unversioned API Routes',
            severity: 'low',
            owasp: 'API9:2023 — Improper Assets Management',
            cwe: 1104,
            description: 'API routes without version prefix (v1, v2) — breaking changes affect all clients at once.',
            remediation: 'Add version prefix to routes: /api/v1/, /api/v2/. Maintain backward-compatible versions.',
            category: 'deprecated',
            patterns: {
                python: [
                    { pattern: /@(?:app|blueprint)\.(?:get|post|put|delete|patch)\(['"]\/(?:api\/)/gm, contextCheck: (content, m) =>
                        !/\/api\/v[0-9]/.test(content.slice(m.index, m.index + 100))
                    },
                ],
                javascript: [
                    { pattern: /['"`]\/(?:api\/)/gm, contextCheck: (content, m) =>
                        !/\/api\/v[0-9]/.test(content) && /(?:router|app|route)\.(?:get|post|put|delete|patch)\(/.test(content)
                    },
                ],
            }
        },
        {
            id: 'openapi-missing-version',
            name: 'OpenAPI Spec Missing Version Management',
            severity: 'low',
            owasp: 'API9:2023 — Improper Assets Management',
            cwe: 1104,
            description: 'OpenAPI spec missing version field or has vague version — leads to asset management issues.',
            remediation: 'Add semver version field to OpenAPI spec. Maintain versioned spec files.',
            category: 'deprecated',
            patterns: {
                openapi: [
                    { pattern: /"?(?:openapi|swagger)"?\s*:/gm, contextCheck: (content) =>
                        !/"?version"?\s*:\s*['"]?\d+\.\d+\.\d+/.test(content)
                    },
                ],
            }
        },
        {
            id: 'docs-endpoint-exposed',
            name: 'Auto-generated Documentation Endpoint Exposed',
            severity: 'low',
            owasp: 'API9:2023 — Improper Assets Management',
            cwe: 200,
            description: 'API docs (Swagger UI, ReDoc) exposed in production — reveals full API surface to attackers.',
            remediation: 'Disable documentation in production or protect with authentication.',
            category: 'deprecated',
            patterns: {
                python: [
                    { pattern: /swagger|redoc|docs_url|openapi_url/gmi, contextCheck: (content) =>
                        !/(?:docs_url\s*=\s*None|openapi_url\s*=\s*None|include_schema\s*=\s*False)/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /swaggerUi|swagger-ui|redoc|apiDocs|openapi/gmi, contextCheck: (content, m) =>
                        !/NODE_ENV.*production/.test(content.slice(0, m.index + 200))
                    },
                ],
                go: [
                    { pattern: /swagger|openapi.*handler/gmi, contextCheck: (content) =>
                        !/gin\.Mode.*release|env.*production/.test(content)
                    },
                ],
            }
        },
    ]
};
