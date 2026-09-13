'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { ScannerEngine } = require('../../src/scanner/engine');
const { SecurityRules } = require('../../src/scanner/rules');

function config(values = {}) {
    return { get: key => values[key] };
}

function tempDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'ch3ck3r-scanner-'));
}

test('external tool probing rejects command injection and never uses a shell', async () => {
    let calls = 0;
    const injected = new ScannerEngine(config({ semgrepPath: 'semgrep;touch-pwned' }), null, {
        isWorkspaceTrusted: () => true,
        execFile: () => { calls += 1; },
    });
    assert.deepEqual(await injected.checkExternalTools(), { semgrep: false });
    assert.equal(calls, 0, 'invalid executable must be rejected before process creation');

    let invocation;
    const valid = new ScannerEngine(config({ semgrepPath: 'semgrep' }), null, {
        isWorkspaceTrusted: () => true,
        execFile: (file, args, options, callback) => {
            invocation = { file, args, options };
            callback(null, '1.0.0', '');
            return { kill() {} };
        },
    });
    assert.deepEqual(await valid.checkExternalTools(), { semgrep: true });
    assert.equal(invocation.file, 'semgrep');
    assert.deepEqual(invocation.args, ['--version']);
    assert.equal(invocation.options.shell, false);
    assert.ok(invocation.options.timeout <= 30000);
    assert.ok(invocation.options.maxBuffer <= 1024 * 1024);

    calls = 0;
    const untrusted = new ScannerEngine(config({ semgrepPath: 'semgrep' }), null, {
        workspaceTrusted: false,
        execFile: () => { calls += 1; },
    });
    assert.deepEqual(await untrusted.checkExternalTools(), { semgrep: false });
    assert.equal(calls, 0, 'untrusted workspaces cannot start external tools');
});

test('all-language patterns are dispatched together with language patterns', () => {
    const rules = new SecurityRules();
    const findings = rules.analyzeCode(
        'javascript',
        'const metadata = "http://169.254.169.254/latest/meta-data";',
        'app.js');
    assert.ok(findings.some(finding => finding.ruleId === 'ssrf-cloud-metadata'));
});

test('dedicated OpenAPI rules dispatch for YAML and JSON specs', async t => {
    const rules = new SecurityRules();
    const yaml = 'openapi: 3.0.0\ninfo:\n  title: Example\npaths: {}\n';
    const json = JSON.stringify({ openapi: '3.0.0', info: { title: 'Example' }, paths: {} });

    assert.ok(rules.analyzeApiSpec('yaml', yaml, 'openapi.yaml')
        .some(finding => finding.ruleId === 'openapi-missing-version'));
    assert.ok(rules.analyzeApiSpec('json', json, 'openapi.json')
        .some(finding => finding.ruleId === 'openapi-missing-version'));

    const root = tempDir();
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const specPath = path.join(root, 'openapi.json');
    fs.writeFileSync(specPath, json);
    const result = await new ScannerEngine(config(), null).scanOpenApi(specPath, { rootPath: root });
    assert.ok(result.findings.some(finding => finding.ruleId === 'openapi-missing-version'));
});

test('discovery and reads enforce count, size, symlink, containment, and cancellation limits', async t => {
    const root = tempDir();
    const outside = tempDir();
    t.after(() => {
        fs.rmSync(root, { recursive: true, force: true });
        fs.rmSync(outside, { recursive: true, force: true });
    });

    for (const name of ['a.js', 'b.js', 'c.js']) {
        fs.writeFileSync(path.join(root, name), 'const host = "169.254.169.254";\n');
    }
    fs.writeFileSync(path.join(root, 'large.js'), 'x'.repeat(4096));
    fs.writeFileSync(path.join(outside, 'outside.js'), 'const host = "169.254.169.254";\n');
    fs.symlinkSync(path.join(outside, 'outside.js'), path.join(root, 'escape.js'));

    const engine = new ScannerEngine(config({ severityThreshold: 'info' }), null);
    const hardCapped = engine._getLimits({
        maxFiles: Number.MAX_SAFE_INTEGER,
        maxFileSizeBytes: Number.MAX_SAFE_INTEGER,
        concurrency: Number.MAX_SAFE_INTEGER,
    });
    assert.equal(hardCapped.maxFiles, 10000);
    assert.equal(hardCapped.maxFileSizeBytes, 5 * 1024 * 1024);
    assert.equal(hardCapped.concurrency, 16);

    const limited = engine._getLimits({ maxFiles: 2, maxFileSizeBytes: 128 });
    const discovered = await engine._discoverFiles(root, { limits: limited });
    assert.equal(discovered.length, 2, 'file discovery must stop at maxFiles');
    assert.ok(discovered.every(file => !file.endsWith('escape.js')), 'symlinks must not be discovered');

    const oversized = await engine.scanFiles([path.join(root, 'large.js')], {
        rootPath: root,
        limits: { maxFileSizeBytes: 128 },
    });
    assert.equal(oversized.length, 0, 'oversized files must be skipped before reading into memory');

    const escaped = await engine.scanFiles([path.join(outside, 'outside.js')], { rootPath: root });
    assert.equal(escaped.length, 0, 'explicit files outside the workspace must be rejected');

    const cancelled = await engine._discoverFiles(root, {
        token: { isCancellationRequested: true },
        limits: engine._getLimits(),
    });
    assert.deepEqual(cancelled, []);
});

test('finding IDs are stable fingerprints and change when file content changes', async t => {
    const root = tempDir();
    const mirror = tempDir();
    t.after(() => {
        fs.rmSync(root, { recursive: true, force: true });
        fs.rmSync(mirror, { recursive: true, force: true });
    });
    const source = 'const host = "169.254.169.254";\n';
    const firstPath = path.join(root, 'app.js');
    const mirrorPath = path.join(mirror, 'app.js');
    fs.writeFileSync(firstPath, source);
    fs.writeFileSync(mirrorPath, source);

    const engine = new ScannerEngine(config({ severityThreshold: 'info' }), null);
    const first = (await engine.scanFiles([firstPath], { rootPath: root }))[0].findings[0];
    const again = (await engine.scanFiles([firstPath], { rootPath: root }))[0].findings[0];
    const mirrored = (await engine.scanFiles([mirrorPath], { rootPath: mirror }))[0].findings[0];
    assert.equal(first.id, again.id);
    assert.equal(first.fingerprint, again.fingerprint);
    assert.equal(first.id, mirrored.id, 'absolute machine paths must not affect fingerprints');

    fs.appendFileSync(firstPath, '// content changed\n');
    const changed = (await engine.scanFiles([firstPath], { rootPath: root }))[0].findings[0];
    assert.notEqual(first.id, changed.id, 'content changes must invalidate the fingerprint');
});

test('secret findings redact match, evidence, and snippets', () => {
    const rules = new SecurityRules();
    const secret = 'ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN';
    const finding = rules.analyzeCode('javascript', `const token = "${secret}";`, 'app.js')
        .find(item => item.ruleId === 'exposed-git-token');

    assert.ok(finding);
    assert.equal(finding.match, '[REDACTED]');
    assert.equal(finding.evidence.match, '[REDACTED]');
    assert.ok(!finding.snippet.includes(secret));
});

test('Dockerfiles are not scanned twice', async t => {
    const root = tempDir();
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const dockerfile = path.join(root, 'Dockerfile');
    fs.writeFileSync(dockerfile, 'FROM node:latest\nRUN echo ok\n');

    const engine = new ScannerEngine(config({ severityThreshold: 'info' }), null);
    const findings = (await engine.scanFiles([dockerfile], { rootPath: root }))[0].findings;
    assert.equal(findings.filter(item => item.ruleId === 'container-root-user').length, 1);
    assert.equal(new Set(findings.map(item => item.id)).size, findings.length);
});
