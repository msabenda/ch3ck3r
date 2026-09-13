'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { FindingsStore } = require('../../src/utils/findingsStore');

class MemoryState {
    constructor(initial = {}) {
        this.data = new Map(Object.entries(initial));
        this.updates = [];
    }
    get(key, fallback) {
        return this.data.has(key) ? this.data.get(key) : fallback;
    }
    update(key, value) {
        this.data.set(key, value);
        this.updates.push([key, value]);
        return Promise.resolve();
    }
}

function finding(id, file = '/workspace/a.js', overrides = {}) {
    return {
        id,
        ruleId: 'hardcoded-secret',
        title: 'Hardcoded secret',
        description: 'password="do-not-persist"',
        remediation: 'Use a secret store',
        severity: 'high',
        owasp_category: 'API2',
        cwe_id: '798',
        file,
        line: 10,
        snippet: 'const password = "snippet-secret"',
        arbitraryBackendPayload: { token: 'payload-secret' },
        ...overrides,
    };
}

test('FindingsStore prefers workspaceState, falls back to legacy globalState, and persists minimally', async () => {
    const workspaceState = new MemoryState();
    const globalState = new MemoryState({
        'ch3ck3r.findings': [finding('legacy')],
        'ch3ck3r.dismissedIds': [],
        'ch3ck3r.falsePositives': [],
    });
    const store = new FindingsStore({ workspaceState, globalState });
    store.load();
    assert.equal(store.count(), 1, 'legacy global findings remain readable during migration');

    await store.addFindings([finding('new', '/workspace/b.js')]);
    assert.ok(workspaceState.updates.length >= 3);
    assert.equal(globalState.updates.length, 0, 'new writes are workspace-local');

    const persisted = workspaceState.data.get('ch3ck3r.findings');
    assert.equal(persisted.length, 2);
    assert.equal(Object.hasOwn(persisted[1], 'snippet'), false);
    assert.equal(Object.hasOwn(persisted[1], 'arbitraryBackendPayload'), false);
    assert.doesNotMatch(JSON.stringify(persisted), /do-not-persist|snippet-secret|payload-secret/);
    assert.match(persisted[1].description, /REDACTED/);
});

test('FindingsStore replaces findings for one file without disturbing other files', async () => {
    const state = new MemoryState();
    const store = new FindingsStore({ workspaceState: state });
    await store.addFindings([
        finding('a-old', '/workspace/a.js'),
        finding('b-stays', '/workspace/b.js'),
    ]);
    await store.replaceFindingsForFile('/workspace/a.js', [
        finding('a-new', '/workspace/a.js', { line: 20, description: 'new issue' }),
    ]);

    assert.deepEqual(store.getByFile('/workspace/a.js').map(item => item.id), ['a-new']);
    assert.deepEqual(store.getByFile('/workspace/b.js').map(item => item.id), ['b-stays']);
    assert.equal(store.count(), 2);
});

test('dismissal and false-positive state survive changed IDs using stable fingerprints', async () => {
    const dismissedStore = new FindingsStore({ workspaceState: new MemoryState() });
    const old = finding('old-id');
    await dismissedStore.addFindings([old]);
    await dismissedStore.remove(old.id);
    await dismissedStore.replaceFindingsForFile(old.file, [finding('new-id')]);
    assert.equal(dismissedStore.count(), 0, 'dismissal survives a line/ID change');

    const fpState = new MemoryState();
    const fpStore = new FindingsStore({ workspaceState: fpState });
    await fpStore.addFindings([old]);
    await fpStore.update({ ...old, falsePositive: true });
    await fpStore.replaceFindingsForFile(old.file, [finding('new-id')]);
    assert.equal(fpStore.getAll().length, 0);
    assert.equal(fpStore.getAllIncludingFalsePositives().length, 1);
    assert.equal(fpStore.falsePositives.has('new-id'), true);

    const reloaded = new FindingsStore({ workspaceState: fpState });
    reloaded.load();
    assert.equal(reloaded.getAll().length, 0, 'false positive survives reload');
});

test('FindingsStore accepts legacy strings and expiration-compatible records', async () => {
    const now = Date.now();
    const state = new MemoryState({
        'ch3ck3r.findings': [],
        'ch3ck3r.dismissedIds': [
            'legacy-id',
            { id: 'expired-id', expiresAt: now - 1 },
            { id: 'active-id', expiresAt: now + 60_000 },
        ],
        'ch3ck3r.falsePositives': [{ id: 'fp-active', expiresAt: now + 60_000 }],
    });
    const store = new FindingsStore({ workspaceState: state });
    store.load();
    assert.equal(store.dismissedIds.has('legacy-id'), true);
    assert.equal(store.dismissedIds.has('expired-id'), false);
    assert.equal(store.dismissedIds.has('active-id'), true);
    assert.equal(store.falsePositives.has('fp-active'), true);

    await store.addFindings([
        finding('legacy-id'),
        finding('expired-id', '/workspace/expired.js'),
        finding('active-id', '/workspace/active.js'),
    ]);
    assert.deepEqual(store.getAll().map(item => item.id), ['expired-id']);
    const records = state.data.get('ch3ck3r.dismissedIds');
    assert.ok(records.every(record => typeof record === 'object' && typeof record.id === 'string'));
});

test('expiration removes propagated false-positive state instead of making it permanent', async () => {
    const state = new MemoryState();
    const store = new FindingsStore({ workspaceState: state });
    const item = finding('expires');
    await store.addFindings([item]);
    await store.markFalsePositive(item, { durationMs: 5 });
    assert.equal(store.getAll().length, 0);
    assert.equal(Object.hasOwn(state.data.get('ch3ck3r.findings')[0], 'falsePositive'), false);

    await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(store.getAll().length, 1);
});
