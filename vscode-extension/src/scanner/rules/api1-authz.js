/**
 * API1:2023 — Broken Object Level Authorization
 * IDOR, missing auth checks, resource ownership
 */
module.exports = {
    rules: [
        {
            id: 'missing-auth-check',
            name: 'Missing Authorization Check on Endpoint',
            severity: 'high',
            owasp: 'API1:2023 — Broken Object Level Authorization',
            cwe: 862,
            description: 'Route handler without visible authentication guard. Attackers can access endpoints without proving identity.',
            remediation: 'Add auth decorator/middleware: @jwt_required(), requireAuth, isAuthenticated, or middleware-level authz.',
            category: 'authorization',
            patterns: {
                python: [{ pattern: /@(?:app|blueprint)\.(?:get|post|put|delete|patch|route)\(/gm, contextCheck: (content, m) => {
                    const after = content.slice(m.index + m[0].length, m.index + m[0].length + 800);
                    return !/(?:@jwt_required|@login_required|@permission_required|@auth_required|@requires_auth|@roles_required|@admin_required)/.test(after);
                }}],
                javascript: [{ pattern: /(?:router|app|route)\.(?:get|post|put|delete|patch)\(\s*['"`]\/[^'"`]+['"`]/gm, contextCheck: (content) =>
                    !/(?:authenticate|authorize|verifyToken|authMiddleware|isAuthenticated|protect|requireAuth|ensureLoggedIn|jwt)/.test(content)
                }],
                typescript: [{ pattern: /(?:router|app|route)\.(?:get|post|put|delete|patch)\(\s*['"`]\/[^'"`]+['"`]/gm, contextCheck: (content) =>
                    !/(?:authenticate|authorize|verifyToken|authMiddleware|isAuthenticated|protect|requireAuth|ensureLoggedIn|jwt)/.test(content)
                }],
                go: [{ pattern: /func\s+\w+Handler.*http\.ResponseWriter/gm, contextCheck: (content) =>
                    !/(?:AuthMiddleware|Authenticate|Authorize|RequireAuth|JWTAuth)/.test(content)
                }],
                java: [{ pattern: /@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\(/gm, contextCheck: (content, m) => {
                    const after = content.slice(m.index + m[0].length, m.index + m[0].length + 600);
                    return !/(?:@PreAuthorize|@Secured|@RolesAllowed|security\s*=\s*@|@Authenticated)/.test(after);
                }}],
                ruby: [{ pattern: /(?:get|post|put|delete|patch)\s+['"`](?:\/[^'"`]+)/gm, contextCheck: (content) =>
                    !/(?:before_action.*authenticate|before_action.*authorize|authenticate_user|authorize_user|authenticate!|authorize!)/.test(content)
                }],
                php: [{ pattern: /Route::(?:get|post|put|delete|patch)\([^)]*[^)]\)/gm, contextCheck: (content) =>
                    !/(?:auth:api|auth:sanctum|middleware.*auth|Auth::require|can:)/.test(content)
                }],
                kotlin: [{ pattern: /fun\s+\w+\(@(?:RequestBody|PathVariable|RequestParam)/gm, contextCheck: (content) =>
                    !/(?:@PreAuthorize|@Secured|@RolesAllowed|security)/.test(content)
                }],
                rust: [{ pattern: /#\[\w+(?:_handler)?\]/gm, contextCheck: (content) =>
                    !/(?:AuthMiddleware|Authenticate|Authorize|RequireAuth|JWTAuth|validate)/.test(content)
                }],
            }
        },
        {
            id: 'idor-vulnerability',
            name: 'Insecure Direct Object Reference (IDOR)',
            severity: 'critical',
            owasp: 'API1:2023 — Broken Object Level Authorization',
            cwe: 639,
            description: 'User-supplied object ID used in data access without proof of ownership. Attacker can tamper with IDs to access others\' resources.',
            remediation: 'Verify the authenticated user owns the requested object. Use relationship-based checks — never trust raw IDs.',
            category: 'authorization',
            patterns: {
                python: [
                    { pattern: /\.(?:get|filter|fetch)\((?:\w+\s*=\s*)?request\.(?:json|args|form|view_args)\.(?:get|__getitem__)\(['"](?:id|user_id|account_id|object_id|document_id|order_id|task_id)['"]\)/gmi },
                    { pattern: /\/<int:\w+id>|\/<string:\w+id>|<uuid:\w+id>|\/<int:\w+_id>/g },
                ],
                javascript: [
                    { pattern: /(?:findById|findOne|getById|fetchById|getItem|findUnique)\s*\(?\s*req\.(?:params|query|body)\.(?:id|userId|objectId|accountId|documentId|orderId|taskId)/g },
                    { pattern: /\/:(?:id|userId|objectId|accountId|documentId|orderId|taskId)\//g },
                ],
                typescript: [
                    { pattern: /(?:findById|findOne|getById|fetchById|getItem|findUnique)\s*\(?\s*req\.(?:params|query|body)\.(?:id|userId|objectId|accountId|documentId|orderId)/g },
                    { pattern: /\/:(?:id|userId|objectId|accountId|documentId|orderId)\//g },
                ],
                go: [
                    { pattern: /mux\.Vars\(req\)\["(?:id|userId|objectId|accountId)"\]/g },
                    { pattern: /c\.Param\(["'](?:id|userId|objectId|accountId)["']\)/g },
                ],
                java: [
                    { pattern: /@PathVariable\s*\(\s*["'](?:id|userId|accountId|objectId)["']?\s*\)/g },
                    { pattern: /request\.getParameter\(["'](?:id|userId|objectId)["']\)/g },
                ],
                ruby: [
                    { pattern: /params\[['":](?:id|user_id|account_id)['":]\]/g },
                    { pattern: /find_by!?\(?\s*(?:id|user_id):?\s*params/gmi },
                ],
                rust: [
                    { pattern: /Path<(\w+)>/g, contextCheck: (content, m) => /(?:id|Id)/.test(m[1]) },
                ],
                php: [
                    { pattern: /\$(?:request|input|get)\(['"](?:id|user_id|account_id)['"]\)/gmi },
                ],
            }
        },
    ]
};
