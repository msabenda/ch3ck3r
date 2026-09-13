'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const Module = require('node:module');

function disposable() { return { dispose() {} }; }

function createVscodeStub() {
    const registeredCodeActionMetadata = [];
    const diagnosticCollection = { clear() {}, set() {}, dispose() {} };
    const configuration = {
        get(_key, fallback) { return fallback; },
        update() { return Promise.resolve(); },
    };
    class EventEmitter {
        constructor() { this.event = () => disposable(); }
        fire() {}
        dispose() {}
    }
    return {
        EventEmitter,
        CodeActionKind: { QuickFix: 'quickfix' },
        StatusBarAlignment: { Left: 1 },
        languages: {
            createDiagnosticCollection() { return diagnosticCollection; },
            registerHoverProvider() { return disposable(); },
            registerCodeActionsProvider(_selector, _provider, metadata) {
                assert.ok(Array.isArray(metadata?.providedCodeActionKinds),
                    'providedCodeActionKinds must be an array accepted by VS Code');
                registeredCodeActionMetadata.push(metadata);
                return disposable();
            },
        },
        commands: {
            registerCommand() { return disposable(); },
            executeCommand() { return Promise.resolve(); },
        },
        workspace: {
            isTrusted: false,
            workspaceFolders: undefined,
            textDocuments: [],
            getConfiguration() { return configuration; },
            onDidSaveTextDocument() { return disposable(); },
            onDidOpenTextDocument() { return disposable(); },
        },
        window: {
            createTreeView() { return disposable(); },
            createStatusBarItem() {
                return { text: '', tooltip: '', command: '', show() {}, hide() {}, dispose() {} };
            },
            showInformationMessage() { return Promise.resolve(undefined); },
        },
        Uri: { file(value) { return { fsPath: value }; }, parse(value) { return { value }; } },
        __test: { registeredCodeActionMetadata },
    };
}

function state() {
    const values = new Map();
    return {
        get(key, fallback) { return values.has(key) ? values.get(key) : fallback; },
        update(key, value) { values.set(key, value); return Promise.resolve(); },
    };
}

test('extension activates in an untrusted workspace without probing external tools', async (t) => {
    const vscode = createVscodeStub();
    const originalLoad = Module._load;
    Module._load = function(request, parent, isMain) {
        if (request === 'vscode') return vscode;
        return originalLoad.call(this, request, parent, isMain);
    };
    t.after(() => { Module._load = originalLoad; });

    const extensionPath = require.resolve('../../src/extension');
    delete require.cache[extensionPath];
    const extension = require(extensionPath);
    const context = {
        subscriptions: [],
        workspaceState: state(),
        globalState: state(),
        secrets: { get: async () => undefined, store: async () => {}, delete: async () => {} },
    };

    await extension.activate(context);
    assert.ok(context.subscriptions.length >= 10, 'activation should register providers and commands');
    assert.equal(vscode.__test.registeredCodeActionMetadata.length, 1,
        'activation should register code actions with valid metadata');
    assert.deepEqual(vscode.__test.registeredCodeActionMetadata[0].providedCodeActionKinds, ['quickfix']);
    assert.equal(typeof extension.deactivate, 'function');
    extension.deactivate();
});
