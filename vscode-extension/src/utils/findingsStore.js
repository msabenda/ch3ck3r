'use strict';

/**
 * FindingsStore — persists workspace-local, minimal, redacted findings while
 * retaining compatibility with legacy globalState/string suppression records.
 */
const crypto = require('crypto');

const KEYS = {
    findings: 'ch3ck3r.findings',
    dismissed: 'ch3ck3r.dismissedIds',
    falsePositives: 'ch3ck3r.falsePositives',
};
const MAX_FINDINGS = 50_000;
const MAX_TEXT = 20_000;
const PERSISTED_FIELDS = [
    'id', 'ruleId', 'title', 'description', 'remediation', 'severity', 'category',
    'owasp_category', 'cwe_id', 'file', 'line', 'column', 'endLine', 'endColumn',
    'language', 'source', 'fingerprint', 'falsePositive',
];

function redactText(value) {
    return String(value == null ? '' : value)
        .replace(/-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY-----/gi, '[REDACTED PRIVATE KEY]')
        .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [REDACTED]')
        .replace(/\b(?:gh[opusr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b/g, '[REDACTED]')
        .replace(/((?:access[_-]?token|api[_-]?key|authorization|client[_-]?secret|password|passwd|passphrase|secret|token)\s*[=:]\s*)(["'`])[^\r\n]*?\2/gi, '$1$2[REDACTED]$2')
        .replace(/((?:access[_-]?token|api[_-]?key|authorization|client[_-]?secret|password|passwd|passphrase|secret|token)\s*[=:]\s*)[^\s,;}&]+/gi, '$1[REDACTED]')
        .replace(/([?&](?:access[_-]?token|api[_-]?key|key|password|secret|token)=)[^&#\s]*/gi, '$1[REDACTED]')
        .slice(0, MAX_TEXT);
}

function safeScalar(value) {
    if (typeof value === 'string') return redactText(value);
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
    if (typeof value === 'bigint') return String(value);
    return undefined;
}

function minimalFinding(finding) {
    if (!finding || typeof finding !== 'object') return null;
    const result = {};
    try {
        for (const key of PERSISTED_FIELDS) {
            const descriptor = Object.getOwnPropertyDescriptor(finding, key);
            // Never execute accessor code supplied by an untrusted finding.
            if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) continue;
            const value = safeScalar(descriptor.value);
            if (value !== undefined) result[key] = value;
        }
    } catch (_) {
        return null;
    }
    if (!result.id) return null;
    return result;
}

function validState(state) {
    return Boolean(state && typeof state.get === 'function' && typeof state.update === 'function');
}

function expirationTime(value) {
    if (value == null || value === '') return null;
    const timestamp = typeof value === 'number' ? value : Date.parse(value);
    return Number.isFinite(timestamp) ? timestamp : null;
}

class FindingsStore {
    constructor(context = {}) {
        this.context = context;
        this.state = validState(context.workspaceState)
            ? context.workspaceState
            : validState(context.globalState) ? context.globalState : null;
        this.legacyState = this.state !== context.globalState && validState(context.globalState)
            ? context.globalState : null;
        this.findings = [];
        this.dismissedIds = new Set();
        this.falsePositives = new Set();
        this._dismissedRecords = new Map();
        this._falsePositiveRecords = new Map();
    }

    _read(key, fallback) {
        if (!this.state) return fallback;
        try {
            const value = this.state.get(key, undefined);
            if (value !== undefined) return value;
            if (this.legacyState) {
                const legacy = this.legacyState.get(key, undefined);
                if (legacy !== undefined) return legacy;
            }
        } catch (_) {
            return fallback;
        }
        return fallback;
    }

    load() {
        this.findings = [];
        this.dismissedIds = new Set();
        this.falsePositives = new Set();
        this._dismissedRecords = new Map();
        this._falsePositiveRecords = new Map();

        try {
            const stored = this._read(KEYS.findings, []);
            if (Array.isArray(stored)) {
                this.findings = stored.slice(0, MAX_FINDINGS).map(minimalFinding).filter(Boolean);
            }
            this._loadRecords(this._read(KEYS.dismissed, []), this.dismissedIds, this._dismissedRecords);
            this._loadRecords(this._read(KEYS.falsePositives, []), this.falsePositives, this._falsePositiveRecords);
            for (const finding of this.findings) {
                if (finding.falsePositive === true) this._recordFalsePositive(finding);
            }
            this._refreshStableStates();
            this.findings = this.findings.filter(finding => !this._recordForFinding(this._dismissedRecords, finding));
        } catch (_) {
            this.findings = [];
            this.dismissedIds.clear();
            this.falsePositives.clear();
            this._dismissedRecords.clear();
            this._falsePositiveRecords.clear();
        }
        return this.findings;
    }

    _loadRecords(value, idSet, recordMap) {
        if (!Array.isArray(value)) return;
        const now = Date.now();
        for (const entry of value.slice(0, MAX_FINDINGS)) {
            const raw = typeof entry === 'string' || typeof entry === 'number' ? { id: String(entry) } : entry;
            if (!raw || typeof raw !== 'object') continue;
            const id = redactText(raw.id).slice(0, 1_000);
            if (!id) continue;
            const expiresAt = expirationTime(raw.expiresAt);
            if (expiresAt !== null && expiresAt <= now) continue;
            const record = {
                id,
                fingerprint: typeof raw.fingerprint === 'string' ? raw.fingerprint.slice(0, 128) : undefined,
                createdAt: expirationTime(raw.createdAt) || now,
                expiresAt,
            };
            idSet.add(id);
            recordMap.set(id, record);
        }
    }

    _fingerprint(finding) {
        if (!finding || typeof finding !== 'object') return '';
        try {
            if (typeof finding.fingerprint === 'string' && finding.fingerprint) return finding.fingerprint.slice(0, 128);
            const stableParts = [finding.file, finding.ruleId || finding.rule_id, finding.title, finding.description]
                .map(value => redactText(value).trim().toLowerCase());
            if (!stableParts.some(Boolean)) return '';
            return crypto.createHash('sha256').update(stableParts.join('\0')).digest('hex');
        } catch (_) {
            return '';
        }
    }

    _recordForFinding(recordMap, finding) {
        const id = finding && finding.id != null ? String(finding.id) : '';
        if (id && recordMap.has(id)) return recordMap.get(id);
        const fingerprint = this._fingerprint(finding);
        if (!fingerprint) return null;
        for (const record of recordMap.values()) {
            if (record.fingerprint === fingerprint) return record;
        }
        return null;
    }

    _refreshStableStates() {
        this._purgeExpired();
        for (const finding of this.findings) {
            const id = finding && finding.id != null ? String(finding.id) : '';
            if (!id) continue;
            const dismissed = this._recordForFinding(this._dismissedRecords, finding);
            if (dismissed) this.dismissedIds.add(id);
            const falsePositive = this._recordForFinding(this._falsePositiveRecords, finding);
            if (falsePositive) this.falsePositives.add(id);
        }
    }

    _purgeExpired() {
        const now = Date.now();
        for (const [id, record] of this._dismissedRecords) {
            if (record.expiresAt !== null && record.expiresAt <= now) {
                this._dismissedRecords.delete(id);
                this.dismissedIds.delete(id);
            }
        }
        for (const [id, record] of this._falsePositiveRecords) {
            if (record.expiresAt !== null && record.expiresAt <= now) {
                this._falsePositiveRecords.delete(id);
                this.falsePositives.delete(id);
                if (record.fingerprint) {
                    for (const finding of this.findings) {
                        if (this._fingerprint(finding) === record.fingerprint) {
                            this.falsePositives.delete(String(finding.id));
                        }
                    }
                }
            }
        }
    }

    _syncPublicSets() {
        const findingsById = new Map(this.findings.map(finding => [String(finding.id), finding]));
        for (const id of this.dismissedIds) {
            if (!this._dismissedRecords.has(String(id))) {
                const finding = findingsById.get(String(id));
                this._dismissedRecords.set(String(id), this._makeRecord(String(id), finding));
            }
        }
        for (const id of this.falsePositives) {
            if (!this._falsePositiveRecords.has(String(id))) {
                const finding = findingsById.get(String(id));
                this._falsePositiveRecords.set(String(id), this._makeRecord(String(id), finding));
            }
        }
    }

    _makeRecord(id, finding, options = {}) {
        let expiresAt = expirationTime(options.expiresAt);
        if (expiresAt === null && Number.isFinite(options.durationMs) && options.durationMs > 0) {
            expiresAt = Date.now() + options.durationMs;
        }
        return {
            id: redactText(id).slice(0, 1_000),
            fingerprint: this._fingerprint(finding) || undefined,
            createdAt: Date.now(),
            expiresAt,
        };
    }

    _persistedRecords(records) {
        return Array.from(records.values()).slice(0, MAX_FINDINGS).map(record => ({
            id: record.id,
            ...(record.fingerprint ? { fingerprint: record.fingerprint } : {}),
            createdAt: record.createdAt,
            ...(record.expiresAt !== null ? { expiresAt: record.expiresAt } : {}),
        }));
    }

    save() {
        if (!this.state) return Promise.resolve(false);
        this._purgeExpired();
        this._syncPublicSets();
        const persistedFindings = this.findings.slice(0, MAX_FINDINGS).map(minimalFinding).filter(Boolean);
        // False-positive state is persisted in expiration-aware records below.
        // The finding flag is accepted on legacy load but omitted from new data,
        // otherwise an expired record would be recreated as permanent.
        for (const finding of persistedFindings) delete finding.falsePositive;
        let updates;
        try {
            updates = [
                this.state.update(KEYS.findings, persistedFindings),
                this.state.update(KEYS.dismissed, this._persistedRecords(this._dismissedRecords)),
                this.state.update(KEYS.falsePositives, this._persistedRecords(this._falsePositiveRecords)),
            ];
        } catch (_) {
            return Promise.resolve(false);
        }
        return Promise.all(updates.map(update => Promise.resolve(update))).then(() => true, () => false);
    }

    _normalizeFinding(finding) {
        if (!finding || typeof finding !== 'object') return null;
        try {
            const copy = { ...finding };
            if (copy.id == null || !String(copy.id)) {
                const fingerprint = this._fingerprint(copy);
                if (!fingerprint) return null;
                copy.id = `finding:${fingerprint}`;
            } else {
                copy.id = String(copy.id);
            }
            return copy;
        } catch (_) {
            return null;
        }
    }

    _addWithoutSaving(newFindings) {
        if (!Array.isArray(newFindings)) return;
        this._purgeExpired();
        const existingIds = new Set(this.findings.map(finding => String(finding.id)));
        for (const raw of newFindings.slice(0, MAX_FINDINGS)) {
            const finding = this._normalizeFinding(raw);
            if (!finding || existingIds.has(finding.id)) continue;
            if (this._recordForFinding(this._dismissedRecords, finding) || this.dismissedIds.has(finding.id)) continue;
            this.findings.push(finding);
            existingIds.add(finding.id);
            if (finding.falsePositive === true || this._recordForFinding(this._falsePositiveRecords, finding)) {
                this.falsePositives.add(finding.id);
            }
            if (this.findings.length >= MAX_FINDINGS) break;
        }
    }

    addFindings(newFindings, options = {}) {
        if (options && typeof options.file === 'string') {
            return this.replaceFindingsForFile(options.file, newFindings);
        }
        this._addWithoutSaving(newFindings);
        return this.save();
    }

    /** Replace all current findings for one file without disturbing other files. */
    replaceFindingsForFile(filePath, newFindings) {
        if (typeof filePath !== 'string' || !filePath) return Promise.resolve(false);
        this.findings = this.findings.filter(finding => finding.file !== filePath);
        const replacements = Array.isArray(newFindings)
            ? newFindings.map(finding => finding && typeof finding === 'object' ? { ...finding, file: filePath } : finding)
            : [];
        this._addWithoutSaving(replacements);
        this._refreshStableStates();
        return this.save();
    }

    // Compatibility-friendly alias for consumers that prefer a shorter name.
    replaceByFile(filePath, newFindings) {
        return this.replaceFindingsForFile(filePath, newFindings);
    }

    remove(id, options = {}) {
        const normalizedId = String(id == null ? '' : id);
        if (!normalizedId) return Promise.resolve(false);
        const finding = this.findings.find(item => String(item.id) === normalizedId);
        this.dismissedIds.add(normalizedId);
        this._dismissedRecords.set(normalizedId, this._makeRecord(normalizedId, finding, options));
        this.findings = this.findings.filter(item => String(item.id) !== normalizedId);
        return this.save();
    }

    markFalsePositive(findingOrId, options = {}) {
        const finding = typeof findingOrId === 'object'
            ? findingOrId
            : this.findings.find(item => String(item.id) === String(findingOrId));
        const id = String(finding && finding.id != null ? finding.id : findingOrId == null ? '' : findingOrId);
        if (!id) return Promise.resolve(false);
        this.falsePositives.add(id);
        this._falsePositiveRecords.set(id, this._makeRecord(id, finding, options));
        const stored = this.findings.find(item => String(item.id) === id);
        if (stored) stored.falsePositive = true;
        return this.save();
    }

    _recordFalsePositive(finding) {
        const id = String(finding.id);
        this.falsePositives.add(id);
        if (!this._falsePositiveRecords.has(id)) {
            this._falsePositiveRecords.set(id, this._makeRecord(id, finding));
        }
    }

    update(finding) {
        const normalized = this._normalizeFinding(finding);
        if (!normalized) return Promise.resolve(false);
        const index = this.findings.findIndex(item => String(item.id) === normalized.id);
        if (index < 0) return Promise.resolve(false);
        this.findings[index] = normalized;
        if (normalized.falsePositive === true) this._recordFalsePositive(normalized);
        else if (normalized.falsePositive === false) {
            this.falsePositives.delete(normalized.id);
            this._falsePositiveRecords.delete(normalized.id);
        }
        return this.save();
    }

    clear() {
        this.findings = [];
        this.dismissedIds.clear();
        this.falsePositives.clear();
        this._dismissedRecords.clear();
        this._falsePositiveRecords.clear();
        return this.save();
    }

    getAll() {
        this._purgeExpired();
        return this.findings.filter(finding => !this.falsePositives.has(String(finding.id)));
    }

    getAllIncludingFalsePositives() {
        this._purgeExpired();
        return this.findings;
    }

    count() {
        return this.getAll().length;
    }

    getBySeverity(severity) {
        return this.getAll().filter(finding => finding.severity === severity);
    }

    getByOwaspCategory(category) {
        return this.getAll().filter(finding => finding.owasp_category === category);
    }

    getByFile(filePath) {
        return this.getAll().filter(finding => finding.file === filePath);
    }

    getSummary() {
        const all = this.getAll();
        return {
            total: all.length,
            critical: all.filter(finding => finding.severity === 'critical').length,
            high: all.filter(finding => finding.severity === 'high').length,
            medium: all.filter(finding => finding.severity === 'medium').length,
            low: all.filter(finding => finding.severity === 'low').length,
            info: all.filter(finding => finding.severity === 'info').length,
            categories: [...new Set(all.map(finding => finding.owasp_category).filter(Boolean))],
            files: [...new Set(all.map(finding => finding.file).filter(Boolean))],
        };
    }
}

module.exports = { FindingsStore };
