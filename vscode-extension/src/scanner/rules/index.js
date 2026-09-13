/**
 * SecurityRules — composite loader for all rule modules.
 * OWASP API Top 10 + CWE Top 25 + Cloud + Secrets.
 */
const path = require('path');

const ruleModules = [
    require('./api1-authz'),
    require('./api2-authentication'),
    require('./api3-property-authz'),
    require('./api4-resource-consumption'),
    require('./api5-function-authz'),
    require('./api6-business-flows'),
    require('./api7-ssrf'),
    require('./api8-misconfiguration'),
    require('./api9-asset-management'),
    require('./api10-consumption'),
    require('./cross-cutting'),
    require('./graphql'),
    require('./container'),
    require('./secrets'),
    require('./cloud'),
    require('./typescript'),
];

const MAX_MATCHES_PER_PATTERN = 1000;
const MAX_FINDINGS_PER_RUN = 5000;

class SecurityRules {
    constructor() {
        this._cache = new Map();
        this.rules = [];
        this.specRules = [];
        this.configRules = [];
        for (const mod of ruleModules) {
            if (mod.rules) this.rules.push(...mod.rules);
            if (mod.specRules) this.specRules.push(...mod.specRules);
            if (mod.configRules) this.configRules.push(...mod.configRules);
        }
    }

    clearCache() { this._cache.clear(); }

    analyzeCode(language, content, filePath) {
        return _runRules(this.rules, 'patterns', language, content, filePath);
    }

    analyzeApiSpec(language, content, filePath) {
        const dedicatedRules = this.rules.filter(rule =>
            rule.applyToSpec === true || Boolean(rule.patterns?.openapi));
        return [
            _runRules(this.specRules, 'patterns', language, content, filePath, ['openapi']),
            _runRules(dedicatedRules, 'patterns', language, content, filePath, ['openapi']),
        ].flat();
    }

    analyzeConfig(language, content, filePath) {
        return [
            _runRules(this.rules, 'patterns', language, content, filePath),
            _runRules(this.configRules, 'patterns', language, content, filePath),
        ].flat();
    }

    analyzeContainerfile(content, filePath) {
        const basename = path.basename(filePath);
        const lang = basename === 'Dockerfile' ? 'dockerfile' : null;
        return _runRules(this.rules, 'patterns', lang, content, filePath);
    }
}

/** Run global + language/alias-specific patterns once each. */
function _runRules(rules, patternKey, language, content, filePath, aliases = []) {
    const findings = [];
    const lines = content.split('\n');

    for (const rule of rules) {
        const patterns = rule?.[patternKey];
        if (!patterns) continue;
        const patternDefs = _patternDefinitions(patterns, language, aliases);

        for (const patternDef of patternDefs) {
            if (!(patternDef?.pattern instanceof RegExp)) continue;
            try {
                patternDef.pattern.lastIndex = 0;
                let match;
                let matchCount = 0;
                while (matchCount < MAX_MATCHES_PER_PATTERN &&
                       (match = patternDef.pattern.exec(content)) !== null) {
                    matchCount += 1;
                    // Defensive handling for zero-length global expressions.
                    if (match[0].length === 0) patternDef.pattern.lastIndex += 1;
                    if (patternDef.contextCheck) {
                        try {
                            if (!patternDef.contextCheck(content, match, filePath)) continue;
                        } catch { continue; }
                    }

                    const beforeMatch = content.slice(0, match.index);
                    const line = (beforeMatch.match(/\n/g) || []).length + 1;
                    const column = match.index - beforeMatch.lastIndexOf('\n');
                    const snippetStart = Math.max(0, line - 3);
                    const snippetEnd = Math.min(lines.length, line + 2);
                    const rawMatch = match[0].substring(0, 200);
                    const rawSnippet = lines.slice(snippetStart, snippetEnd).join('\n');
                    const sensitive = _isSensitiveRule(rule);
                    const safeMatch = sensitive ? '[REDACTED]' : _redactSecrets(rawMatch);
                    let safeSnippet = _redactSecrets(rawSnippet);
                    if (sensitive && rawMatch) {
                        safeSnippet = safeSnippet.split(rawMatch).join('[REDACTED]');
                    }

                    findings.push({
                        ruleId: rule.id,
                        title: rule.name,
                        description: rule.description,
                        severity: rule.severity,
                        category: rule.category,
                        owasp_category: rule.owasp,
                        cwe_id: rule.cwe,
                        line,
                        column: column > 0 ? column : 1,
                        match: safeMatch.substring(0, 180),
                        snippet: safeSnippet,
                        remediation: rule.remediation,
                        evidence: { match: safeMatch, line },
                    });
                    if (findings.length >= MAX_FINDINGS_PER_RUN) return findings;
                }
            } catch { /* malformed or unsupported regex: skip this pattern */ }
        }
    }
    return findings;
}

function _patternDefinitions(patterns, language, aliases) {
    const definitions = [];
    const seen = new Set();
    for (const key of ['all', language, ...aliases]) {
        if (!key || !Array.isArray(patterns[key])) continue;
        for (const definition of patterns[key]) {
            if (!seen.has(definition)) {
                seen.add(definition);
                definitions.push(definition);
            }
        }
    }
    return definitions;
}

function _isSensitiveRule(rule) {
    return rule.category === 'secrets' ||
        /(?:secret|password|credential|private-key|token|connection-string)/i.test(`${rule.id} ${rule.name}`);
}

/** Mask common credential material even when it appears beside another finding. */
function _redactSecrets(value) {
    if (!value) return '';
    return String(value)
        .replace(/-----BEGIN\s+(?:(?:RSA|EC|OPENSSH)\s+)?PRIVATE\s+KEY-----[\s\S]*?(?:-----END\s+(?:(?:RSA|EC|OPENSSH)\s+)?PRIVATE\s+KEY-----|$)/gi,
            '[REDACTED PRIVATE KEY]')
        .replace(/\b(?:gh[opusr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprse]-[A-Za-z0-9-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|sk-[A-Za-z0-9]{20,}|pk-[A-Za-z0-9]{20,})\b/g,
            '[REDACTED]')
        .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
            '[REDACTED JWT]')
        .replace(/\b(postgres|mysql|mariadb|mongodb|redis):\/\/[^\s:@/]+:[^\s@/]+@/gi,
            '$1://[REDACTED]@')
        .replace(/((?:password|passwd|pwd|secret(?:_key)?|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|aws_secret_access_key)\s*[:=]\s*)(["'`]?)([^\s,"'`;}{]+|[^"'`\n]*)(\2)/gi,
            (_whole, prefix, quote) => `${prefix}${quote}[REDACTED]${quote}`);
}

module.exports = { SecurityRules };
