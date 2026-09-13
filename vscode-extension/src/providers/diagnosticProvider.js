/**
 * DiagnosticProvider — translates findings into precise inline diagnostics
 * with intelligent highlights, severity tags, and actionable remediation messages.
 */
const vscode = require('vscode');
const { SmartRemediator } = require('../intel/smartRemediator');

class DiagnosticProvider {
    constructor(configManager, findingsStore) {
        this.configManager = configManager;
        this.findingsStore = findingsStore;
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('ch3ck3r');
        this.remediator = new SmartRemediator(findingsStore, configManager);
    }

    /**
     * Update diagnostics — highlights the EXACT offending expression on each line
     */
    updateDiagnostics() {
        this.diagnosticCollection.clear();

        if (!this.configManager.get('showInlineDiagnostics', true)) return;

        const findings = this.findingsStore.getAll();
        const fileMap = new Map();
        for (const f of findings) {
            if (!f.file) continue;
            if (!fileMap.has(f.file)) fileMap.set(f.file, []);
            fileMap.get(f.file).push(f);
        }

        for (const [filePath, fileFindings] of fileMap) {
            const uri = vscode.Uri.file(filePath);
            try {
                // Open document to get precise ranges
                const document = vscode.workspace.textDocuments.find(
                    doc => doc.uri.fsPath === filePath
                );
                const diagnostics = document
                    ? fileFindings.map(f => this.remediator.buildDiagnostic(document, f))
                    : fileFindings.map(f => this._fallbackDiagnostic(f));
                this.diagnosticCollection.set(uri, diagnostics);
            } catch {
                // Fallback: line-level highlighting
                this.diagnosticCollection.set(uri, fileFindings.map(f => this._fallbackDiagnostic(f)));
            }
        }
    }

    /**
     * Diagnostics for a single file (called on file scan)
     */
    updateForFile(filePath, findings) {
        const uri = vscode.Uri.file(filePath);
        const document = vscode.workspace.textDocuments.find(
            doc => doc.uri.fsPath === filePath
        );

        if (document && this.configManager.get('showInlineDiagnostics', true)) {
            const diagnostics = findings.map(f => this.remediator.buildDiagnostic(document, f));
            this.diagnosticCollection.set(uri, diagnostics);
        } else {
            this.clear();
        }
    }

    clear() {
        this.diagnosticCollection.clear();
    }

    dispose() {
        this.diagnosticCollection.dispose();
    }

    /**
     * Fallback when document isn't open — highlights the whole line
     */
    _fallbackDiagnostic(finding) {
        const sevMap = {
            critical: vscode.DiagnosticSeverity.Error,
            high: vscode.DiagnosticSeverity.Error,
            medium: vscode.DiagnosticSeverity.Warning,
            low: vscode.DiagnosticSeverity.Information,
        };
        const severity = sevMap[finding.severity] || vscode.DiagnosticSeverity.Warning;
        const line = Math.max(0, (finding.line || 1) - 1);
        const range = new vscode.Range(line, 0, line, 1000);

        const diagnostic = new vscode.Diagnostic(
            range,
            `🛡️ [Ch3ck3r] ${finding.title}${finding.ruleId ? ` (${finding.ruleId})` : ''}`,
            severity
        );
        diagnostic.source = 'Ch3ck3r';
        diagnostic.code = {
            value: finding.ruleId || 'ch3ck3r',
            target: vscode.Uri.parse('https://github.com/msabenda/ch3ck3r'),
        };
        diagnostic.tags = (finding.severity === 'critical' || finding.severity === 'high')
            ? [vscode.DiagnosticTag.Unnecessary]
            : [];
        return diagnostic;
    }
}

module.exports = { DiagnosticProvider };
