const assert = require('node:assert/strict');
const test = require('node:test');

const { SecurityRules } = require('../../src/scanner/rules');

const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const SUPPORTED_PATTERN_KEYS = new Set([
    'all', 'javascript', 'typescript', 'python', 'go', 'java', 'ruby', 'rust',
    'php', 'kotlin', 'openapi', 'yaml', 'json', 'dockerfile', 'terraform',
    'kubernetes',
]);

test('every scanner rule has valid, unique, actionable metadata', () => {
    const registry = new SecurityRules();
    const groups = [registry.rules, registry.specRules, registry.configRules];
    const rules = groups.flat();
    const ids = new Set();

    assert.ok(rules.length >= 50, 'expected a substantial built-in rule set');

    for (const rule of rules) {
        assert.match(rule.id, /^[a-z0-9][a-z0-9-]+$/, `invalid rule id: ${rule.id}`);
        assert.ok(!ids.has(rule.id), `duplicate rule id: ${rule.id}`);
        ids.add(rule.id);

        assert.ok(rule.name?.trim(), `${rule.id}: missing name`);
        assert.ok(rule.description?.trim(), `${rule.id}: missing description`);
        assert.ok(rule.remediation?.trim(), `${rule.id}: missing remediation`);
        assert.ok(rule.category?.trim(), `${rule.id}: missing category`);
        assert.ok(VALID_SEVERITIES.has(rule.severity), `${rule.id}: invalid severity`);
        assert.ok(rule.cwe || rule.owasp, `${rule.id}: missing CWE/OWASP mapping`);
        assert.ok(rule.patterns && typeof rule.patterns === 'object', `${rule.id}: missing patterns`);

        let patternCount = 0;
        for (const [language, definitions] of Object.entries(rule.patterns)) {
            assert.ok(SUPPORTED_PATTERN_KEYS.has(language), `${rule.id}: unknown pattern language ${language}`);
            assert.ok(Array.isArray(definitions), `${rule.id}/${language}: patterns must be an array`);
            for (const definition of definitions) {
                assert.ok(definition.pattern instanceof RegExp, `${rule.id}/${language}: pattern must be RegExp`);
                patternCount += 1;
            }
        }
        assert.ok(patternCount > 0, `${rule.id}: no executable patterns`);
    }
});
