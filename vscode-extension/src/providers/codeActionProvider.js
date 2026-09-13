/**
 * CodeActionProvider — intelligent quick-fix actions for Ch3ck3r findings
 * 
 * Provides:
 *  - One-click "Apply Fix" with the correct secure code
 *  - "Why is this dangerous?" explanation dialog
 *  - "View CWE" documentation links
 *  - "Dismiss" / "Mark false positive" options
 */
const vscode = require('vscode');
const { SmartRemediator } = require('../intel/smartRemediator');

class CodeActionProvider {
    constructor(configManager, findingsStore) {
        this.configManager = configManager;
        this.findingsStore = findingsStore;
        this.remediator = new SmartRemediator(findingsStore, configManager);
    }

    provideCodeActions(document, range, context, token) {
        const actions = [];

        // Process Ch3ck3r diagnostics on this line
        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'Ch3ck3r') continue;

            const ruleId = typeof diagnostic.code?.value === 'string' ? diagnostic.code.value : '';
            if (!ruleId) continue;

            // Find the corresponding finding
            const findings = this._findingsAtLine(document, range.start.line + 1, ruleId);
            if (findings.length === 0) continue;

            const finding = findings[0];
            const codeActions = this.remediator.buildCodeActions(document, range, finding);
            actions.push(...codeActions);
        }

        // Proactive security hints (even without diagnostics triggered)
        const line = document.lineAt(range.start.line);
        const text = line.text;

        const proactiveHints = [
            { pattern: /api[-_]?key\s*[=:]\s*['"][a-zA-Z0-9_-]{8,}['"]/i, title: 'Hardcoded API Key', ruleId: 'hardcoded-api-key' },
            { pattern: /password\s*[=:]\s*['"][^'"]{4,}['"]/i, title: 'Hardcoded Password', ruleId: 'hardcoded-api-key' },
            { pattern: /secret\s*[=:]\s*['"][^'"]{8,}['"]/i, title: 'Hardcoded Secret', ruleId: 'weak-jwt-secret' },
            { pattern: /verify[=:]\s*(False|false|0)/, title: 'SSL Verification Disabled', ruleId: 'disable-ssl-verification' },
            { pattern: /['"]\*['"]\s*(?:\||,)/, title: 'CORS Wildcard Origin', ruleId: 'cors-wildcard' },
        ];

        for (const hint of proactiveHints) {
            if (hint.pattern.test(text)) {
                const action = new vscode.CodeAction(
                    `🛡️ Ch3ck3r: Fix ${hint.title}`,
                    vscode.CodeActionKind.QuickFix
                );
                action.command = {
                    command: 'ch3ck3r.remediateFinding',
                    title: 'Remediate',
                    arguments: [{
                        ruleId: hint.ruleId,
                        title: hint.title,
                        file: document.uri.fsPath,
                        line: range.start.line + 1,
                        match: text.trim(),
                        severity: 'high',
                    }],
                };
                actions.push(action);
                break;
            }
        }

        return actions;
    }

    _findingsAtLine(document, lineNum, ruleId) {
        const filePath = document.uri.fsPath;
        const allFindings = this.findingsStore.getAll().filter(f => f.file === filePath);
        return allFindings.filter(f => f.line === lineNum && (f.ruleId === ruleId || !ruleId));
    }
}

module.exports = { CodeActionProvider };
