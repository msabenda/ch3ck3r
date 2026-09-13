/**
 * API5:2023 — Broken Function Level Authorization
 * Admin endpoints without RBAC, internal endpoints exposed
 */
module.exports = {
    rules: [
        {
            id: 'admin-endpoint-no-role-check',
            name: 'Admin Endpoint Missing Role Verification',
            severity: 'high',
            owasp: 'API5:2023 — Broken Function Level Authorization',
            cwe: 285,
            description: 'Admin route prefix without role-based access control. Regular users can access admin functions.',
            remediation: 'Add RBAC middleware. Verify user has admin/role claim before processing admin requests.',
            category: 'authorization',
            patterns: {
                python: [
                    { pattern: /\/admin/gmi, contextCheck: (content) =>
                        !/(?:admin_required|admin_only|is_admin|role|@admin\.route|user\.is_admin)/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /\/admin/gmi, contextCheck: (content) =>
                        !/(?:isAdmin|adminOnly|requireAdmin|requireRole|role\s*===?\s*["']admin["']|is_admin|\.admin)/.test(content)
                    },
                ],
                go: [
                    { pattern: /\/admin/gmi, contextCheck: (content) =>
                        !/(?:IsAdmin|AdminRequired|RequireRole|RoleCheck|Middleware.*admin)/.test(content)
                    },
                ],
                java: [
                    { pattern: /\/admin/gmi, contextCheck: (content) =>
                        !/(?:@PreAuthorize.*admin|@Secured.*admin|hasRole.*admin|hasAuthority.*admin)/.test(content)
                    },
                ],
            }
        },
        {
            id: 'internal-endpoint-exposed',
            name: 'Internal/Privileged Endpoint Externally Accessible',
            severity: 'high',
            owasp: 'API5:2023 — Broken Function Level Authorization',
            cwe: 285,
            description: 'Internal endpoint visible in routes without privilege check or IP restriction.',
            remediation: 'Apply strict role/IP checks. Move internal endpoints to separate port/interface.',
            category: 'authorization',
            patterns: {
                python: [
                    { pattern: /['"`](?:\/internal\/|\/admin\/|\/manage\/|\/dashboard\/|\/api\/v[12]\/admin)/gmi, contextCheck: (content) =>
                        !/(?:ip_restrict|internal_only|admin_required|@admin|whitelist)/.test(content)
                    },
                    { pattern: /HealthView|HealthEndpoint|metrics_endpoint/gmi, contextCheck: (content) =>
                        !/(?:@login_required|@jwt_required|auth)/.test(content)
                    },
                ],
                javascript: [
                    { pattern: /['"`](?:\/internal\/|\/admin\/|\/manage\/|\/dashboard\/)/gmi, contextCheck: (content) =>
                        !/(?:isAdmin|requireAdmin|ipWhitelist|internal_only|requireRole)/.test(content)
                    },
                ],
            }
        },
    ]
};
