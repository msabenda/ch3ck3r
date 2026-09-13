/**
 * Scanning analysis data models used throughout the extension
 */

class AnalysisFinding {
    constructor(data) {
        this.id = data.id;
        this.ruleId = data.ruleId;
        this.title = data.title;
        this.description = data.description;
        this.severity = data.severity || 'info';
        this.category = data.category || 'general';
        this.owasp_category = data.owasp_category;
        this.cwe_id = data.cwe_id;
        this.file = data.file;
        this.line = data.line || 1;
        this.column = data.column || 1;
        this.match = data.match || '';
        this.snippet = data.snippet || '';
        this.remediation = data.remediation;
        this.evidence = data.evidence || {};
        this.falsePositive = data.falsePositive || false;
        this.timestamp = data.timestamp || new Date().toISOString();
    }
}

class AnalysisResult {
    constructor(data) {
        this.plugin_name = data.plugin_name || 'ch3ck3r-sast';
        this.target = data.target;
        this.status = data.status || 'completed';
        this.findings = (data.findings || []).map(f => new AnalysisFinding(f));
        this.risk_score = data.risk_score || 0;
        this.error_message = data.error_message;
        this.started_at = data.started_at;
        this.completed_at = data.completed_at;
    }
}

module.exports = { AnalysisFinding, AnalysisResult };
