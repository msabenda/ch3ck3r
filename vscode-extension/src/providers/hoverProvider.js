/**
 * HoverProvider — provides intelligent security hover hints
 * Shows danger explanation, fix code snippet, and quick actions
 * when hovering over flagged code.
 */
const vscode = require('vscode');
const { SmartRemediator } = require('../intel/smartRemediator');

class HoverProvider {
    constructor(configManager, findingsStore) {
        this.configManager = configManager;
        this.findingsStore = findingsStore;
        this.remediator = new SmartRemediator(findingsStore, configManager);
    }

    provideHover(document, position, token) {
        const findings = this._findingsAtPosition(document, position);
        if (findings.length === 0) return null;

        // If multiple findings on same line, show the highest severity
        const sorted = findings.sort((a, b) => {
            const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
            return (order[a.severity] || 99) - (order[b.severity] || 99);
        });

        const finding = sorted[0];
        const language = document.languageId;
        const content = this.remediator.buildHoverContent(finding, language);

        return new vscode.Hover(content);
    }

    /**
     * Find all findings at the given position
     */
    _findingsAtPosition(document, position) {
        const filePath = document.uri.fsPath;
        const lineNum = position.line + 1;
        const col = position.character + 1;

        const allFindings = this.findingsStore.getAll().filter(f => f.file === filePath);

        // Exact line match
        const lineMatches = allFindings.filter(f => f.line === lineNum);
        if (lineMatches.length > 0) return lineMatches;

        // Column range match (if available)
        return allFindings.filter(f => {
            if (!f.line) return false;
            const fLine = Math.max(0, (f.line || 1) - 1);
            return Math.abs(fLine - position.line) <= 1;
        });
    }
}

module.exports = { HoverProvider };
