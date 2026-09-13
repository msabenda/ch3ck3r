'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { ReportGenerator } = require('../../src/utils/reportGenerator');

function hostileFinding() {
    return {
        id: 'evil-1',
        ruleId: 'evil rule<script>',
        severity: 'critical',
        title: '<img src=x onerror=alert(1)>\n# injected heading',
        description: 'password="hunter2" <script>alert(1)</script> [click](javascript:alert(1))',
        remediation: 'Use `safe`\n</textarea><svg onload=alert(1)>',
        owasp_category: 'API1 | injected',
        cwe_id: '79',
        file: 'javascript:alert(1)',
        line: -10,
        column: 'bad',
        snippet: 'const api_key = "very-secret-key";\n```\n# breakout',
        token: 'raw-token-value',
        nested: { password: 'nested-password-value' },
    };
}

function assertSecretsRedacted(output) {
    for (const secret of ['hunter2', 'very-secret-key', 'raw-token-value', 'nested-password-value']) {
        assert.doesNotMatch(output, new RegExp(secret));
    }
    assert.match(output, /REDACTED/);
}

test('all report formats redact secret values', () => {
    const generator = new ReportGenerator();
    const finding = hostileFinding();
    for (const output of [
        generator.generateJson([finding]),
        generator.generateMarkdown([finding]),
        generator.generateHtml([finding]),
        generator.generateSarif([finding]),
    ]) {
        assertSecretsRedacted(output);
    }
});

test('HTML escapes every untrusted finding value', () => {
    const html = new ReportGenerator().generateHtml([hostileFinding()]);
    assert.doesNotMatch(html, /<img src=x/);
    assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
    assert.doesNotMatch(html, /<svg onload/);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
    assert.match(html, /&lt;\/textarea&gt;&lt;svg onload=alert\(1\)&gt;/);
    assert.match(html, /Content-Security-Policy/);
});

test('Markdown neutralizes headings, tables, links, HTML, and fence breakouts', () => {
    const markdown = new ReportGenerator().generateMarkdown([hostileFinding()]);
    assert.doesNotMatch(markdown, /\n# injected heading/);
    assert.doesNotMatch(markdown, /\[click\]\(javascript:/);
    assert.match(markdown, /\\<img src=x onerror=alert\\\(1\\\)\\>/);
    assert.match(markdown, /API1 \\| injected/);
    assert.match(markdown, /    ```\n    # breakout/);
});

test('SARIF has correct security-severity and safe artifact URIs', () => {
    const generator = new ReportGenerator();
    const sarif = JSON.parse(generator.generateSarif([
        hostileFinding(),
        {
            id: 'safe', ruleId: 'safe-rule', title: 'Safe', description: 'Description',
            severity: 'high', file: '/tmp/project/a file.js', line: 2,
        },
        {
            id: 'relative', ruleId: 'relative-rule', title: 'Relative', description: 'Description',
            severity: 'medium', file: '../src/a#b.js', line: 3,
        },
    ]));
    const run = sarif.runs[0];
    const criticalRule = run.tool.driver.rules.find(rule => rule.id.startsWith('evil-rule'));
    assert.equal(criticalRule.properties['security-severity'], '9.8');
    assert.equal(Object.hasOwn(criticalRule.properties, 'securitySeeverity'), false);
    assert.equal(run.results[0].level, 'error');
    assert.doesNotMatch(run.results[0].locations[0].physicalLocation.artifactLocation.uri, /javascript:/i);
    assert.match(run.results[1].locations[0].physicalLocation.artifactLocation.uri, /^file:\/\/\//);
    assert.match(run.results[1].locations[0].physicalLocation.artifactLocation.uri, /a%20file\.js$/);
    assert.equal(run.results[2].locations[0].physicalLocation.artifactLocation.uri, '_up_/src/a%23b.js');
});

test('reports handle non-array input and cyclic/unexpected field types safely', () => {
    const generator = new ReportGenerator();
    assert.equal(JSON.parse(generator.generateJson(null)).summary.total, 0);
    const cyclic = { id: 'cycle', title: 'Cycle', severity: 'nonsense' };
    cyclic.extra = cyclic;
    const report = JSON.parse(generator.generateJson([cyclic, 42]));
    assert.equal(report.summary.total, 2);
    assert.equal(report.findings[0].severity, 'info');
    assert.equal(report.findings[0].extra, '[TRUNCATED]');
});
