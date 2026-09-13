'use strict';

/**
 * ReportGenerator — generates redacted reports in SARIF, JSON, Markdown, and
 * HTML formats. Report input is untrusted: findings may originate in scanned
 * source code or a remote backend.
 */
const path = require('path');
const { pathToFileURL } = require('url');
const EXTENSION_VERSION = require('../../package.json').version;

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const SENSITIVE_KEY = /(?:^|[_-])(authorization|cookie|credential|password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret)(?:$|[_-])/i;
const COMPACT_SENSITIVE_KEY = /^(?:authorization|cookie|credentials?|password|passwd|passphrase|secret|token|accesstoken|refreshtoken|apikey|privatekey|clientsecret)$/i;
const MAX_FIELD_LENGTH = 20_000;
const MAX_FINDINGS = 50_000;

function redactString(value) {
    return String(value == null ? '' : value)
        .replace(/-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY-----/gi, '[REDACTED PRIVATE KEY]')
        .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [REDACTED]')
        .replace(/\b(?:gh[opusr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b/g, '[REDACTED]')
        .replace(/((?:access[_-]?token|api[_-]?key|authorization|client[_-]?secret|password|passwd|passphrase|secret|token)\s*[=:]\s*)(["'`])[^\r\n]*?\2/gi, '$1$2[REDACTED]$2')
        .replace(/((?:access[_-]?token|api[_-]?key|authorization|client[_-]?secret|password|passwd|passphrase|secret|token)\s*[=:]\s*)[^\s,;}&]+/gi, '$1[REDACTED]')
        .replace(/([?&](?:access[_-]?token|api[_-]?key|key|password|secret|token)=)[^&#\s]*/gi, '$1[REDACTED]')
        .slice(0, MAX_FIELD_LENGTH);
}

function sanitizeValue(value, key = '', seen = new WeakSet(), depth = 0) {
    const keyText = String(key);
    if (SENSITIVE_KEY.test(keyText) || COMPACT_SENSITIVE_KEY.test(keyText.replace(/[^A-Za-z0-9]/g, ''))) return '[REDACTED]';
    if (typeof value === 'string') return redactString(value);
    if (value == null || typeof value === 'boolean') return value;
    if (typeof value === 'number') return Number.isFinite(value) ? value : null;
    if (typeof value === 'bigint') return String(value);
    if (typeof value !== 'object') return String(value).slice(0, MAX_FIELD_LENGTH);
    if (depth >= 8 || seen.has(value)) return '[TRUNCATED]';

    seen.add(value);
    if (Array.isArray(value)) {
        const result = value.slice(0, 10_000).map(item => sanitizeValue(item, '', seen, depth + 1));
        seen.delete(value);
        return result;
    }

    const result = {};
    let entries;
    try {
        entries = Object.entries(value).slice(0, 1_000);
    } catch (_) {
        seen.delete(value);
        return '[UNREADABLE]';
    }
    for (const [entryKey, entryValue] of entries) {
        result[String(entryKey).slice(0, 200)] = sanitizeValue(entryValue, entryKey, seen, depth + 1);
    }
    seen.delete(value);
    return result;
}

function asText(value, fallback = '') {
    if (value == null) return fallback;
    return redactString(typeof value === 'string' ? value : String(value));
}

function positiveInt(value, fallback = 1) {
    const number = Number(value);
    return Number.isSafeInteger(number) && number > 0 ? number : fallback;
}

function normalizeSeverity(value) {
    const severity = asText(value, 'info').toLowerCase();
    return SEVERITIES.has(severity) ? severity : 'info';
}

function normalizeFindings(findings) {
    if (!Array.isArray(findings)) return [];
    return findings.slice(0, MAX_FINDINGS).map((raw, index) => {
        const clean = sanitizeValue(raw && typeof raw === 'object' ? raw : { description: raw });
        const ruleId = asText(clean.ruleId || clean.rule_id || `ch3ck3r-finding-${index + 1}`);
        return {
            ...clean,
            id: asText(clean.id || `${ruleId}:${index + 1}`),
            ruleId,
            title: asText(clean.title, 'Untitled finding'),
            description: asText(clean.description),
            remediation: asText(clean.remediation),
            severity: normalizeSeverity(clean.severity),
            category: asText(clean.category),
            owasp_category: asText(clean.owasp_category),
            cwe_id: asText(clean.cwe_id),
            file: asText(clean.file),
            line: positiveInt(clean.line),
            column: positiveInt(clean.column),
            snippet: asText(clean.snippet || clean.match),
            match: asText(clean.match || clean.snippet),
        };
    });
}

function escapeHtml(value) {
    return asText(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function escapeMarkdown(value) {
    // Keep all untrusted prose on one logical line, then escape every Markdown
    // structural character (including HTML delimiters and link syntax).
    return asText(value)
        .replace(/[\r\n\u2028\u2029]+/g, ' ')
        .replace(/([\\`*_{}\[\]()<>#+\-.!|])/g, '\\$1');
}

function markdownCodeBlock(value) {
    const lines = asText(value).replace(/\r\n?/g, '\n').split('\n');
    return lines.map(line => `    ${line}`).join('\n');
}

function safeRuleId(finding, index = 0) {
    const candidate = asText(finding.ruleId || finding.title || `ch3ck3r-finding-${index + 1}`)
        .trim()
        .replace(/[^A-Za-z0-9._-]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 128);
    return candidate || `ch3ck3r-finding-${index + 1}`;
}

function encodeRelativePath(filePath) {
    const parts = filePath.replace(/\\/g, '/').split('/').filter(part => part && part !== '.');
    return parts.map(part => encodeURIComponent(part === '..' ? '_up_' : part)).join('/');
}

function safeArtifactUri(value) {
    const file = asText(value).replace(/\0/g, '').trim();
    if (!file) return undefined;

    try {
        const parsed = new URL(file);
        if (parsed.protocol === 'file:') return pathToFileURL(path.normalize(decodeURIComponent(parsed.pathname))).href;
        // Never emit attacker-selected javascript:, data:, or remote schemes.
        return encodeRelativePath(`${parsed.hostname}${parsed.pathname}`) || undefined;
    } catch (_) {
        // It is a filesystem path, not a URL.
    }

    if (/^[A-Za-z]:[\\/]/.test(file)) {
        const drive = file[0].toUpperCase();
        return `file:///${drive}:/${encodeRelativePath(file.slice(3))}`;
    }
    if (path.isAbsolute(file)) return pathToFileURL(path.normalize(file)).href;
    return encodeRelativePath(file) || undefined;
}

function severityScore(severity) {
    return ({ critical: '9.8', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' })[severity] || '0.0';
}

class ReportGenerator {
    /** Generate SARIF format (Static Analysis Results Interchange Format). */
    generateSarif(input) {
        const findings = normalizeFindings(input);
        const sarif = {
            $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
            version: '2.1.0',
            runs: [{
                tool: {
                    driver: {
                        name: 'Ch3ck3r',
                        fullName: 'Ch3ck3r API Security SAST',
                        version: EXTENSION_VERSION,
                        informationUri: 'https://github.com/msabenda/ch3ck3r',
                        rules: this._buildSarifRules(findings),
                    }
                },
                results: this._buildSarifResults(findings),
                properties: {
                    scannedAt: new Date().toISOString(),
                    totalFindings: findings.length,
                }
            }]
        };
        return JSON.stringify(sarif, null, 2);
    }

    _buildSarifRules(findings) {
        const rules = new Map();
        findings.forEach((finding, index) => {
            const id = safeRuleId(finding, index);
            if (rules.has(id)) return;
            const description = asText(finding.description).slice(0, 5_000);
            const remediation = asText(finding.remediation).slice(0, 5_000);
            rules.set(id, {
                id,
                name: asText(finding.title, id).slice(0, 256),
                shortDescription: { text: description.slice(0, 200) || asText(finding.title, id).slice(0, 200) },
                fullDescription: { text: description },
                help: { text: remediation, markdown: escapeMarkdown(remediation) },
                properties: {
                    severity: finding.severity,
                    category: asText(finding.category),
                    owasp: asText(finding.owasp_category),
                    cwe: asText(finding.cwe_id),
                    'security-severity': severityScore(finding.severity),
                }
            });
        });
        return Array.from(rules.values());
    }

    _buildSarifResults(findings) {
        return findings.map((finding, index) => {
            const uri = safeArtifactUri(finding.file);
            const result = {
                ruleId: safeRuleId(finding, index),
                level: ['critical', 'high'].includes(finding.severity) ? 'error' : finding.severity === 'medium' ? 'warning' : 'note',
                message: { text: `${asText(finding.title)}: ${asText(finding.description).slice(0, 300)}` },
                locations: uri ? [{
                    physicalLocation: {
                        artifactLocation: { uri },
                        region: {
                            startLine: positiveInt(finding.line),
                            startColumn: positiveInt(finding.column),
                            snippet: { text: asText(finding.snippet || finding.match).slice(0, 1_000) }
                        }
                    }
                }] : [],
                properties: {
                    severity: finding.severity,
                    owasp_category: asText(finding.owasp_category),
                    cwe_id: asText(finding.cwe_id),
                    remediation: asText(finding.remediation),
                }
            };
            return result;
        });
    }

    /** Generate plain JSON report. */
    generateJson(input) {
        const findings = normalizeFindings(input);
        const report = {
            tool: `Ch3ck3r SAST v${EXTENSION_VERSION}`,
            scannedAt: new Date().toISOString(),
            summary: {
                total: findings.length,
                critical: findings.filter(f => f.severity === 'critical').length,
                high: findings.filter(f => f.severity === 'high').length,
                medium: findings.filter(f => f.severity === 'medium').length,
                low: findings.filter(f => f.severity === 'low').length,
                info: findings.filter(f => f.severity === 'info').length,
            },
            owaspCoverage: this._owaspCoverage(findings),
            findings,
        };
        return JSON.stringify(report, null, 2);
    }

    _owaspCoverage(findings) {
        const cats = new Map();
        for (const finding of findings) {
            const owasp = asText(finding.owasp_category, 'Uncategorized') || 'Uncategorized';
            if (!cats.has(owasp)) cats.set(owasp, []);
            cats.get(owasp).push(finding);
        }
        return Array.from(cats, ([category, items]) => ({
            category,
            count: items.length,
            severityBreakdown: {
                critical: items.filter(f => f.severity === 'critical').length,
                high: items.filter(f => f.severity === 'high').length,
                medium: items.filter(f => f.severity === 'medium').length,
                low: items.filter(f => f.severity === 'low').length,
            }
        }));
    }

    /** Generate a Markdown report with untrusted structure neutralized. */
    generateMarkdown(input) {
        const findings = normalizeFindings(input);
        const summary = this._getSummary(findings);
        let md = '# 🛡️ Ch3ck3r API Security Scan Report\n\n';
        md += `**Scan Date:** ${new Date().toISOString()}\n\n`;
        md += '## Summary\n\n| Severity | Count |\n|----------|------:|\n';
        for (const [severity, count] of Object.entries(summary.bySeverity)) {
            const emoji = severity === 'critical' ? '🔴' : severity === 'high' ? '🟠' : severity === 'medium' ? '🟡' : severity === 'low' ? '🟢' : '⚪';
            md += `| ${emoji} ${escapeMarkdown(severity.charAt(0).toUpperCase() + severity.slice(1))} | ${count} |\n`;
        }
        md += `| **Total** | **${summary.total}** |\n\n`;
        md += '## OWASP API Top 10 Coverage\n\n';
        for (const category of summary.owaspCategories) md += `- **${escapeMarkdown(category.category)}**: ${category.count} issue(s)\n`;

        md += '\n## Findings\n\n';
        const sorted = this._sort(findings);
        sorted.forEach((finding, index) => {
            const emoji = finding.severity === 'critical' ? '🔴' : finding.severity === 'high' ? '🟠' : finding.severity === 'medium' ? '🟡' : finding.severity === 'low' ? '🟢' : '⚪';
            md += `### ${index + 1}. ${emoji} ${escapeMarkdown(finding.title)}\n\n`;
            md += `- **Severity:** ${escapeMarkdown(finding.severity.toUpperCase())}\n`;
            md += `- **OWASP:** ${escapeMarkdown(finding.owasp_category || 'N/A')}\n`;
            if (finding.cwe_id) md += `- **CWE:** ${escapeMarkdown(`CWE-${finding.cwe_id}`)}\n`;
            if (finding.file) md += `- **File:** ${escapeMarkdown(finding.file)}${finding.line ? `:${finding.line}` : ''}\n`;
            md += `\n**Description:** ${escapeMarkdown(finding.description)}\n\n`;
            md += `**Remediation:** ${escapeMarkdown(finding.remediation)}\n\n`;
            if (finding.snippet) md += `${markdownCodeBlock(finding.snippet.slice(0, 500))}\n\n`;
            md += '---\n\n';
        });
        return md;
    }

    /** Generate a static HTML report. Every dynamic value is HTML escaped. */
    generateHtml(input) {
        const findings = normalizeFindings(input);
        const summary = this._getSummary(findings);
        let findingsHtml = '';

        for (const finding of this._sort(findings)) {
            const colors = { critical: '#dc3545', high: '#fd7e14', medium: '#ffc107', low: '#28a745', info: '#17a2b8' };
            const bg = colors[finding.severity] || '#6c757d';
            findingsHtml += `
            <div class="finding" style="border-left:4px solid ${bg};margin-bottom:16px;padding:12px;background:#1a1a2e;border-radius:4px">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                    <span style="background:${bg};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;text-transform:uppercase">${escapeHtml(finding.severity)}</span>
                    <strong style="color:#e0e0e0">${escapeHtml(finding.title)}</strong>
                </div>
                ${finding.owasp_category ? `<div style="font-size:12px;color:#888;margin-bottom:4px">OWASP: ${escapeHtml(finding.owasp_category)}</div>` : ''}
                ${finding.file ? `<div style="font-size:12px;color:#888;margin-bottom:4px">File: ${escapeHtml(finding.file)}${finding.line ? `:${finding.line}` : ''}</div>` : ''}
                <p style="margin:8px 0;color:#ccc;font-size:13px">${escapeHtml(finding.description)}</p>
                ${finding.remediation ? `<div style="background:#0d1b2a;padding:8px;border-radius:4px;font-size:12px;color:#7ec8e3"><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</div>` : ''}
                ${finding.snippet ? `<pre style="background:#0a0a1a;padding:8px;border-radius:4px;font-size:11px;color:#c9d1d9;overflow-x:auto;margin-top:8px">${escapeHtml(finding.snippet.slice(0, 500))}</pre>` : ''}
            </div>`;
        }

        const severityColors = { critical: '#dc3545', high: '#fd7e14', medium: '#ffc107', low: '#28a745', info: '#17a2b8' };
        let summaryBars = '';
        for (const [severity, count] of Object.entries(summary.bySeverity)) {
            if (count <= 0) continue;
            const pct = summary.total ? (count / summary.total * 100).toFixed(1) : '0.0';
            const color = severityColors[severity] || '#888';
            summaryBars += `<div style="margin-bottom:4px"><span style="color:${color};text-transform:capitalize;font-size:12px">${escapeHtml(severity)}</span><div style="background:#333;height:20px;border-radius:4px;overflow:hidden"><div style="background:${color};width:${pct}%;height:100%;line-height:20px;padding-left:8px;color:white;font-size:11px">${count}</div></div></div>`;
        }

        const owaspHtml = summary.owaspCategories.map(category => `<div style="margin-bottom:4px;font-size:12px;color:#aaa"><span style="color:#e0e0e0">${escapeHtml(category.category)}:</span> ${category.count} (C:${category.severityBreakdown.critical} H:${category.severityBreakdown.high} M:${category.severityBreakdown.medium} L:${category.severityBreakdown.low})</div>`).join('');
        const fileItems = summary.files.map(file => `<li>${escapeHtml(file)}</li>`).join('');

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ch3ck3r API Security Report</title>
    <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a1a;color:#e0e0e0;margin:0;padding:20px}.container{max-width:900px;margin:0 auto}h1{color:#00d4aa;border-bottom:2px solid #00d4aa;padding-bottom:8px}h2{color:#00bcd4;margin-top:24px}.card{background:#111128;border-radius:8px;padding:16px;margin-bottom:16px}</style>
</head>
<body><div class="container">
<h1>🛡️ Ch3ck3r API Security Scan Report</h1><p style="color:#888">Generated: ${new Date().toISOString()}</p>
<div class="card"><h2>Summary</h2><p>${summary.total} total finding(s)</p>${summaryBars}</div>
<div class="card"><h2>OWASP API Top 10 Coverage</h2>${owaspHtml || '<p style="color:#888">No OWASP categorization available.</p>'}</div>
<div class="card"><h2>Files Scanned</h2><p style="color:#888;font-size:12px">${summary.files.length} file(s) with findings</p><ul>${fileItems}</ul></div>
<h2>Findings (${findings.length})</h2>${findingsHtml}
</div></body></html>`;
    }

    _sort(findings) {
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return [...findings].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
    }

    _getSummary(findings) {
        const bySeverity = {};
        for (const finding of findings) bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
        return {
            total: findings.length,
            bySeverity,
            owaspCategories: this._owaspCoverage(findings),
            files: [...new Set(findings.map(finding => finding.file).filter(Boolean))],
        };
    }
}

module.exports = { ReportGenerator };
