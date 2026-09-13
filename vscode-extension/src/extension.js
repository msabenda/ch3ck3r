/**
 * Ch3ck3r SAST - VS Code Extension Entry Point
 * API Security & Web Security Static Analysis Tool
 * OWASP API Top 10 Detection
 */

const vscode = require('vscode');
const { ScannerEngine } = require('./scanner/engine');
const { FindingsProvider } = require('./ui/resultsTree');
const { SummaryProvider } = require('./providers/summaryProvider');
const { DiagnosticProvider } = require('./providers/diagnosticProvider');
const { HoverProvider } = require('./providers/hoverProvider');
const { CodeActionProvider } = require('./providers/codeActionProvider');
const { BackendClient } = require('./utils/backendClient');
const { ReportGenerator } = require('./utils/reportGenerator');
const { FindingsStore } = require('./utils/findingsStore');
const { ConfigManager } = require('./utils/configManager');
const { StatusBarManager } = require('./ui/statusBar');
const { ResultsTreeDataProvider } = require('./ui/resultsTree');
const { SecurityRules } = require('./scanner/rules');
const { SmartRemediator } = require('./intel/smartRemediator');

let scannerEngine;
let findingsStore;
let configManager;
let statusBarManager;
let diagnosticProvider;
let findingsTreeProvider;
let summaryProvider;
let smartRemediator;
let extensionContext;

const BACKEND_TOKEN_KEY = 'ch3ck3r.backendToken';
const EXTENSION_VERSION = require('../package.json').version;

/**
 * @param {vscode.ExtensionContext} context
 */
async function activate(context) {
    extensionContext = context;
    console.log(`[Ch3ck3r] Activating extension v${EXTENSION_VERSION}`);

    // Initialize core components
    configManager = new ConfigManager();
    findingsStore = new FindingsStore(context);
    scannerEngine = new ScannerEngine(configManager, findingsStore);
    statusBarManager = new StatusBarManager();
    smartRemediator = new SmartRemediator(findingsStore, configManager);

    // Initialize providers (intelligent versions)
    diagnosticProvider = new DiagnosticProvider(configManager, findingsStore);
    findingsTreeProvider = new FindingsProvider(configManager, findingsStore, context);
    summaryProvider = new SummaryProvider(configManager, findingsStore);

    // DiagnosticProvider owns its DiagnosticCollection and is disposable.
    context.subscriptions.push(diagnosticProvider);

    // Register hover provider for security hints
    const hoverProvider = new HoverProvider(configManager, findingsStore);
    const hoverDisposable = vscode.languages.registerHoverProvider(
        [
            { scheme: 'file', language: 'javascript' },
            { scheme: 'file', language: 'typescript' },
            { scheme: 'file', language: 'python' },
            { scheme: 'file', language: 'go' },
            { scheme: 'file', language: 'java' },
            { scheme: 'file', language: 'ruby' },
            { scheme: 'file', language: 'rust' },
            { scheme: 'file', language: 'yaml' },
            { scheme: 'file', language: 'json' },
            { scheme: 'file', language: 'dockerfile' },
            { scheme: 'file', language: 'terraform' },
        ],
        hoverProvider
    );
    context.subscriptions.push(hoverDisposable);

    // Register code action provider
    const codeActionProvider = new CodeActionProvider(configManager, findingsStore);
    const codeActionDisposable = vscode.languages.registerCodeActionsProvider(
        [
            { scheme: 'file', language: 'javascript' },
            { scheme: 'file', language: 'typescript' },
            { scheme: 'file', language: 'python' },
            { scheme: 'file', language: 'go' },
            { scheme: 'file', language: 'java' },
            { scheme: 'file', language: 'ruby' },
            { scheme: 'file', language: 'rust' },
            { scheme: 'file', language: 'yaml' },
            { scheme: 'file', language: 'json' },
        ],
        codeActionProvider,
        { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    );
    context.subscriptions.push(codeActionDisposable);

    // Register tree data providers
    const findingsTreeView = vscode.window.createTreeView('ch3ck3rFindings', {
        treeDataProvider: findingsTreeProvider,
        showCollapseAll: true,
    });
    context.subscriptions.push(findingsTreeView);

    const summaryTreeView = vscode.window.createTreeView('ch3ck3rSummary', {
        treeDataProvider: summaryProvider,
    });
    context.subscriptions.push(summaryTreeView);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('ch3ck3r.scanFile', () => handleScanFile()),
        vscode.commands.registerCommand('ch3ck3r.scanFolder', () => handleScanFolder()),
        vscode.commands.registerCommand('ch3ck3r.scanOpenApi', () => handleScanOpenApi()),
        vscode.commands.registerCommand('ch3ck3r.connectBackend', () => handleConnectBackend()),
        vscode.commands.registerCommand('ch3ck3r.clearBackendToken', () => handleClearBackendToken()),
        vscode.commands.registerCommand('ch3ck3r.showReport', () => handleShowReport()),
        vscode.commands.registerCommand('ch3ck3r.clearFindings', () => handleClearFindings()),
        vscode.commands.registerCommand('ch3ck3r.excludeFile', () => handleExcludeFile()),
        vscode.commands.registerCommand('ch3ck3r.toggleInlineDiagnostics', () => handleToggleDiagnostics()),
        vscode.commands.registerCommand('ch3ck3r.runFullScan', () => handleRunFullScan()),
        vscode.commands.registerCommand('ch3ck3r.openFinding', (finding) => handleOpenFinding(finding)),
        vscode.commands.registerCommand('ch3ck3r.dismissFinding', (finding) => handleDismissFinding(finding)),
        vscode.commands.registerCommand('ch3ck3r.markFalsePositive', (finding) => handleMarkFalsePositive(finding)),
        vscode.commands.registerCommand('ch3ck3r.copyFindingDetails', (finding) => handleCopyFinding(finding)),
        vscode.commands.registerCommand('ch3ck3r.remediateFinding', (finding) => handleRemediateFinding(finding)),
        vscode.commands.registerCommand('ch3ck3r.showExplanation', (finding, remediation) =>
            handleShowExplanation(finding, remediation)
        )
    );

    // Set up auto-scan on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            if (configManager.get('autoScanOnSave') && configManager.get('enabled')) {
                scheduleScan(document.uri.fsPath);
            }
        })
    );

    // Set up auto-scan on open
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument((document) => {
            if (configManager.get('autoScanOnOpen') && configManager.get('enabled')) {
                scheduleScan(document.uri.fsPath);
            }
        })
    );

    // Initialize status bar
    statusBarManager.create(context);
    statusBarManager.setIdle();

    // Auto-scan workspace if there's an open folder
    if (vscode.workspace.workspaceFolders && configManager.get('enabled')) {
        const autoScanOnStart = vscode.workspace.getConfiguration('ch3ck3r').get('autoScanOnStart');
        if (autoScanOnStart) {
            setTimeout(() => {
                vscode.commands.executeCommand('ch3ck3r.scanFolder');
            }, 3000);
        }
    }

    // Load persisted findings
    findingsStore.load();
    updateAllProviders();

    // Never execute workspace-configured tools before the user trusts the workspace.
    if (vscode.workspace.isTrusted) {
        scannerEngine.checkExternalTools({ trusted: true }).then(tools => {
            if (!tools.semgrep) {
                console.log('[Ch3ck3r] Semgrep not found — using built-in rules only');
            }
        });
    }

    console.log('[Ch3ck3r] Extension activated successfully');

    // Show welcome message on first activation
    const hasActivated = context.globalState.get('ch3ck3r.hasActivated');
    if (!hasActivated) {
        context.globalState.update('ch3ck3r.hasActivated', true);
        vscode.window.showInformationMessage(
            '🛡️ Ch3ck3r SAST is active — scanning for OWASP API Top 10 vulnerabilities. ' +
            'Configure via Settings → Ch3ck3r SAST or click the shield in the activity bar.',
            'Scan Current File',
            'View Settings'
        ).then(selection => {
            if (selection === 'Scan Current File') {
                vscode.commands.executeCommand('ch3ck3r.scanFile');
            } else if (selection === 'View Settings') {
                vscode.commands.executeCommand('workbench.action.openSettings', 'ch3ck3r');
            }
        });
    }
}

function deactivate() {
    console.log('[Ch3ck3r] Deactivating extension');
    if (findingsStore) {
        findingsStore.save();
    }
    if (statusBarManager) {
        statusBarManager.dispose();
    }
}

/**
 * Debounced scan scheduling
 */
const scanQueue = new Map();
let scanTimeout = null;

function storeScanResults(results) {
    for (const result of results || []) {
        if (!result?.file) continue;
        if (typeof findingsStore.replaceFindingsForFile === 'function') {
            findingsStore.replaceFindingsForFile(result.file, result.findings || []);
        } else if (typeof findingsStore.replaceByFile === 'function') {
            findingsStore.replaceByFile(result.file, result.findings || []);
        } else {
            findingsStore.addFindings(result.findings || []);
        }
    }
}

function scheduleScan(filePath) {
    if (!filePath) return;

    const config = vscode.workspace.getConfiguration('ch3ck3r');
    const excludePatterns = config.get('excludePatterns', []);
    const { MiniGlob } = require('./utils/minimatch');

    // Check exclusion patterns
    for (const pattern of excludePatterns) {
        if (MiniGlob.match(filePath, pattern)) {
            return;
        }
    }

    // The scanner engine enforces file-size, containment, and symlink limits
    // asynchronously. Avoid blocking the extension host here.
    scanQueue.set(filePath, Date.now());

    if (scanTimeout) {
        clearTimeout(scanTimeout);
    }

    scanTimeout = setTimeout(async () => {
        const filesToScan = Array.from(scanQueue.keys());
        scanQueue.clear();
        scanTimeout = null;

        if (filesToScan.length === 0) return;

        statusBarManager.setScanning(`Scanning ${filesToScan.length} file(s)`);

        try {
            const results = await scannerEngine.scanFiles(filesToScan);
            storeScanResults(results);
            const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);

            if (totalFindings > 0) {
                updateAllProviders();
                statusBarManager.setHasIssues(totalFindings);
            } else {
                statusBarManager.setSecure();
            }

            diagnosticProvider.updateDiagnostics(findingsStore.getAll());
        } catch (error) {
            console.error('[Ch3ck3r] Scan error:', error);
            statusBarManager.setError(error.message);
        }
    }, config.get('scanDebounceMs', 500));
}

/**
 * Handle scanning a single file
 */
async function handleScanFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No file is currently open.');
        return;
    }

    const filePath = editor.document.uri.fsPath;
    statusBarManager.setScanning('Scanning file...');

    try {
        const results = await scannerEngine.scanFiles([filePath]);
        const result = results[0] || { file: filePath, findings: [] };
        storeScanResults([result]);

        if (result.findings.length > 0) {
            updateAllProviders();
            statusBarManager.setHasIssues(findingsStore.count());

            const severityCounts = {};
            result.findings.forEach(f => {
                severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
            });
            const summary = Object.entries(severityCounts)
                .map(([sev, count]) => `${sev}: ${count}`)
                .join(', ');

            vscode.window.showWarningMessage(
                `🛡️ Ch3ck3r: Found ${result.findings.length} issue(s) in ${result.findings[0].file || filePath} — ${summary}`,
                'View Findings',
                'Show Report'
            ).then(selection => {
                if (selection === 'View Findings') {
                    vscode.commands.executeCommand('ch3ck3rFindings.focus');
                } else if (selection === 'Show Report') {
                    vscode.commands.executeCommand('ch3ck3r.showReport');
                }
            });
        } else {
            statusBarManager.setSecure();
            vscode.window.showInformationMessage(
                `🛡️ Ch3ck3r: No API security issues found in ${require('path').basename(filePath)}`
            );
        }

        diagnosticProvider.updateDiagnostics(findingsStore.getAll());
    } catch (error) {
        statusBarManager.setError(error.message);
        vscode.window.showErrorMessage(`Ch3ck3r scan failed: ${error.message}`);
    }
}

/**
 * Handle scanning entire workspace folder
 */
async function handleScanFolder() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showWarningMessage('No workspace folder is open.');
        return;
    }

    const targetFolder = workspaceFolders.length === 1
        ? workspaceFolders[0]
        : await vscode.window.showWorkspaceFolderPick({
            placeHolder: 'Select folder to scan'
        });

    if (!targetFolder) return;

    statusBarManager.setScanning('Scanning workspace...');

    // Show progress
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Ch3ck3r: Scanning workspace for API security issues',
        cancellable: true
    }, async (progress, token) => {
        try {
            const results = await scannerEngine.scanWorkspace(targetFolder.uri.fsPath, progress, token);
            storeScanResults(results);
            const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);

            if (token.isCancellationRequested) return;

            if (totalFindings > 0) {
                updateAllProviders();
                statusBarManager.setHasIssues(totalFindings);

                const criticalCount = results.reduce((sum, r) =>
                    sum + r.findings.filter(f => f.severity === 'critical').length, 0);
                const highCount = results.reduce((sum, r) =>
                    sum + r.findings.filter(f => f.severity === 'high').length, 0);

                vscode.window.showWarningMessage(
                    `🛡️ Ch3ck3r: Found ${totalFindings} API security issues` +
                    (criticalCount > 0 ? ` (${criticalCount} critical)` : '') +
                    (highCount > 0 ? ` (${highCount} high)` : ''),
                    'View Findings',
                    'Show Report'
                ).then(selection => {
                    if (selection === 'View Findings') {
                        vscode.commands.executeCommand('ch3ck3rFindings.focus');
                    } else if (selection === 'Show Report') {
                        vscode.commands.executeCommand('ch3ck3r.showReport');
                    }
                });
            } else {
                statusBarManager.setSecure();
                const scannedCount = results.length;
                vscode.window.showInformationMessage(
                    `🛡️ Ch3ck3r: No API security issues found across ${scannedCount} file(s)`
                );
            }

            diagnosticProvider.updateDiagnostics(findingsStore.getAll());
        } catch (error) {
            statusBarManager.setError(error.message);
            vscode.window.showErrorMessage(`Ch3ck3r workspace scan failed: ${error.message}`);
        }
    });
}

/**
 * Handle scanning an OpenAPI spec file
 */
async function handleScanOpenApi() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('Open an OpenAPI/Swagger YAML or JSON file first.');
        return;
    }

    const filePath = editor.document.uri.fsPath;
    statusBarManager.setScanning('Analyzing OpenAPI spec...');

    try {
        const results = await scannerEngine.scanOpenApi(filePath);
        const findings = results.findings;
        storeScanResults([{ file: filePath, findings }]);

        if (findings.length > 0) {
            updateAllProviders();
            statusBarManager.setHasIssues(findingsStore.count());

            const highSeverity = findings.filter(f => f.severity === 'critical' || f.severity === 'high');

            vscode.window.showWarningMessage(
                `🛡️ Ch3ck3r: OpenAPI spec has ${findings.length} issue(s)` +
                (highSeverity.length > 0 ? ` (${highSeverity.length} high/critical)` : ''),
                'View Findings',
                'Show Report'
            ).then(selection => {
                if (selection === 'View Findings') {
                    vscode.commands.executeCommand('ch3ck3rFindings.focus');
                } else if (selection === 'Show Report') {
                    vscode.commands.executeCommand('ch3ck3r.showReport');
                }
            });
        } else {
            statusBarManager.setSecure();
            vscode.window.showInformationMessage(
                '🛡️ Ch3ck3r: OpenAPI spec looks clean — no misconfigurations detected'
            );
        }

        diagnosticProvider.updateDiagnostics(findingsStore.getAll());
    } catch (error) {
        statusBarManager.setError(error.message);
        vscode.window.showErrorMessage(`OpenAPI scan failed: ${error.message}`);
    }
}

/**
 * Handle connecting to a Ch3ck3r backend
 */
async function handleConnectBackend() {
    if (!vscode.workspace.isTrusted) {
        vscode.window.showWarningMessage('Trust this workspace before connecting Ch3ck3r to a backend.');
        return;
    }

    const config = vscode.workspace.getConfiguration('ch3ck3r');
    const currentUrl = config.get('backendUrl') || 'http://localhost:8000';

    const url = await vscode.window.showInputBox({
        prompt: 'Enter Ch3ck3r Backend URL',
        value: currentUrl,
        placeHolder: 'http://localhost:8000',
        validateInput: (value) => {
            try {
                const parsed = new URL(value);
                if (parsed.username || parsed.password) return 'Credentials are not allowed in backend URLs';
                const loopback = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
                if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) {
                    return 'Use HTTPS (HTTP is allowed only for loopback development)';
                }
                return null;
            } catch {
                return 'Please enter a valid URL';
            }
        }
    });

    if (!url) return;

    const token = await vscode.window.showInputBox({
        prompt: 'Enter a replacement API token, or leave empty to keep the stored token',
        password: true,
        placeHolder: 'Stored securely in VS Code SecretStorage'
    });

    const storedToken = token || await extensionContext.secrets.get(BACKEND_TOKEN_KEY) || '';

    // Test connection
    statusBarManager.setScanning('Connecting...');
    try {
        const client = new BackendClient(url, storedToken);
        const health = await client.checkHealth();
        await config.update('backendUrl', url, vscode.ConfigurationTarget.Global);
        if (token) await extensionContext.secrets.store(BACKEND_TOKEN_KEY, token);
        statusBarManager.setConnected(url);
        vscode.window.showInformationMessage(
            `✅ Connected to Ch3ck3r backend at ${url} (v${health.version || '?'})`
        );
    } catch (error) {
        statusBarManager.setError('Connection failed');
        vscode.window.showErrorMessage(`Failed to connect to Ch3ck3r backend: ${error.message}`);
    }
}

async function handleClearBackendToken() {
    const confirm = await vscode.window.showWarningMessage(
        'Delete the stored Ch3ck3r backend token?',
        { modal: true },
        'Delete Token'
    );
    if (confirm !== 'Delete Token') return;
    await extensionContext.secrets.delete(BACKEND_TOKEN_KEY);
    vscode.window.showInformationMessage('Stored Ch3ck3r backend token deleted.');
}

/**
 * Handle showing scan report
 */
async function handleShowReport() {
    const findings = findingsStore.getAll();
    if (findings.length === 0) {
        vscode.window.showInformationMessage('No findings to report. Scan a file or folder first.');
        return;
    }

    const format = configManager.get('reportFormat') || 'sarif';

    const reportGenerator = new ReportGenerator();
    let content;
    let language;

    switch (format) {
        case 'sarif':
            content = reportGenerator.generateSarif(findings);
            language = 'json';
            break;
        case 'json':
            content = reportGenerator.generateJson(findings);
            language = 'json';
            break;
        case 'markdown':
            content = reportGenerator.generateMarkdown(findings);
            language = 'markdown';
            break;
        case 'html':
            content = reportGenerator.generateHtml(findings);
            language = 'html';
            break;
        default:
            content = reportGenerator.generateJson(findings);
            language = 'json';
    }

    const doc = await vscode.workspace.openTextDocument({
        content: content,
        language: language
    });
    vscode.window.showTextDocument(doc);
}

/**
 * Handle clearing all findings
 */
async function handleClearFindings() {
    const count = findingsStore.count();
    if (count === 0) return;

    const confirm = await vscode.window.showWarningMessage(
        `Clear all ${count} findings?`,
        { modal: true },
        'Clear'
    );

    if (confirm === 'Clear') {
        findingsStore.clear();
        diagnosticProvider.clear();
        updateAllProviders();
        statusBarManager.setIdle();
        vscode.window.showInformationMessage('All Ch3ck3r findings cleared.');
    }
}

/**
 * Handle excluding a file from scanning
 */
async function handleExcludeFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const filePath = editor.document.uri.fsPath;
    const config = vscode.workspace.getConfiguration('ch3ck3r');
    const patterns = config.get('excludePatterns', []);

    // Create a relative glob pattern
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(editor.document.uri);
    let pattern;
    if (workspaceFolder) {
        const relativePath = require('path').relative(workspaceFolder.uri.fsPath, filePath);
        pattern = `**/${relativePath}`;
    } else {
        pattern = `**/${require('path').basename(filePath)}`;
    }

    if (!patterns.includes(pattern)) {
        patterns.push(pattern);
        await config.update('excludePatterns', patterns, vscode.ConfigurationTarget.Workspace);
        vscode.window.showInformationMessage(`Added "${pattern}" to Ch3ck3r exclusion list.`);
    } else {
        vscode.window.showInformationMessage('File is already excluded.');
    }
}

/**
 * Handle toggling inline diagnostics
 */
async function handleToggleDiagnostics() {
    const current = configManager.get('showInlineDiagnostics');
    await vscode.workspace.getConfiguration('ch3ck3r').update(
        'showInlineDiagnostics',
        !current,
        vscode.ConfigurationTarget.Global
    );

    if (!current) {
        diagnosticProvider.updateDiagnostics(findingsStore.getAll());
        statusBarManager.updateText();
    } else {
        diagnosticProvider.clear();
    }

    vscode.window.showInformationMessage(
        `Ch3ck3r inline diagnostics: ${!current ? 'enabled' : 'disabled'}`
    );
}

/**
 * Handle running a full scan via the Ch3ck3r backend
 */
async function handleRunFullScan() {
    if (!vscode.workspace.isTrusted) {
        vscode.window.showWarningMessage('Trust this workspace before sending scan requests to a backend.');
        return;
    }

    const config = vscode.workspace.getConfiguration('ch3ck3r');
    const backendUrl = config.get('backendUrl');
    const backendToken = await extensionContext.secrets.get(BACKEND_TOKEN_KEY) || '';

    if (!backendUrl) {
        const connect = await vscode.window.showWarningMessage(
            'No Ch3ck3r backend configured. Connect to one first?',
            'Connect Now'
        );
        if (connect) {
            await vscode.commands.executeCommand('ch3ck3r.connectBackend');
        }
        return;
    }

    const target = await vscode.window.showInputBox({
        prompt: 'Enter target URL or file path for full scan',
        placeHolder: 'https://api.example.com/openapi.json',
        value: vscode.window.activeTextEditor?.document.getText().includes('openapi') &&
               vscode.window.activeTextEditor?.document.uri.scheme === 'file'
               ? vscode.window.activeTextEditor.document.uri.fsPath
               : ''
    });

    if (!target) return;

    const consent = await vscode.window.showWarningMessage(
        `Send this scan target to ${backendUrl}?\n\n${target}`,
        { modal: true },
        'Send Scan Request'
    );
    if (consent !== 'Send Scan Request') return;

    statusBarManager.setScanning('Running full backend scan...');

    try {
        const client = new BackendClient(backendUrl, backendToken);
        const result = await client.runFullScan(target);

        if (result.findings && result.findings.length > 0) {
            findingsStore.addFindings(result.findings);
            updateAllProviders();
            statusBarManager.setHasIssues(findingsStore.count());

            vscode.window.showWarningMessage(
                `🛡️ Ch3ck3r: Backend scan found ${result.findings.length} issues`,
                'View in Dashboard'
            );
        } else {
            statusBarManager.setSecure();
            vscode.window.showInformationMessage('Backend scan completed — no issues found.');
        }
    } catch (error) {
        statusBarManager.setError(error.message);
        vscode.window.showErrorMessage(`Backend scan failed: ${error.message}`);
    }
}

/**
 * Handle opening a finding location
 */
function handleOpenFinding(finding) {
    if (finding && finding.file) {
        const uri = vscode.Uri.file(finding.file);
        const line = (finding.line || 1) - 1;
        const column = (finding.column || 1) - 1;

        vscode.window.showTextDocument(uri, {
            selection: new vscode.Range(line, column, line, column + 1),
            preview: true
        });
    }
}

/**
 * Handle dismissing a single finding
 */
function handleDismissFinding(finding) {
    findingsStore.remove(finding.id);
    updateAllProviders();
    diagnosticProvider.updateDiagnostics(findingsStore.getAll());
    statusBarManager.setHasIssues(findingsStore.count());
}

/**
 * Handle marking a finding as false positive
 */
function handleMarkFalsePositive(finding) {
    if (typeof findingsStore.markFalsePositive === 'function') {
        findingsStore.markFalsePositive(finding, { reason: 'Marked by developer' });
    } else {
        finding.falsePositive = true;
        findingsStore.update(finding);
    }
    updateAllProviders();
    diagnosticProvider.updateDiagnostics();
}

/**
 * Handle copying finding details
 */
async function handleCopyFinding(finding) {
    const text = [
        `[Ch3ck3r] ${finding.title}`,
        `Severity: ${finding.severity}`,
        `OWASP: ${finding.owasp_category || 'N/A'}`,
        `File: ${finding.file}:${finding.line}`,
        `Description: ${finding.description}`,
        `Remediation: ${finding.remediation || 'N/A'}`,
    ].join('\n');

    await vscode.env.clipboard.writeText(text);
    vscode.window.showInformationMessage('Finding details copied to clipboard.');
}

/**
 * Update all view providers
 */
function updateAllProviders() {
    findingsTreeProvider.refresh();
    summaryProvider.refresh();
}

/**
 * Handle showing a detailed security explanation dialog
 */
function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

async function handleShowExplanation(finding, remediation) {
    if (!remediation && finding && smartRemediator) {
        remediation = smartRemediator.getRemediation(finding, 'javascript');
    }

    if (!remediation) {
        vscode.window.showInformationMessage('No detailed explanation available for this finding.');
        return;
    }

    const panel = vscode.window.createWebviewPanel(
        'ch3ck3rExplanation',
        `Ch3ck3r: ${finding.title || 'Security Finding'}`,
        vscode.ViewColumn.Beside,
        { enableScripts: false, enableCommandUris: false, localResourceRoots: [] }
    );

    const emoji = finding.severity === 'critical' ? '🔴' :
                  finding.severity === 'high' ? '🟠' :
                  finding.severity === 'medium' ? '🟡' : '🟢';
    const severity = ['critical', 'high', 'medium', 'low'].includes(finding.severity)
        ? finding.severity : 'medium';
    const safeReferences = (remediation.references || []).filter((reference) => {
        try { return new URL(reference.url).protocol === 'https:'; } catch { return false; }
    });

    panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ch3ck3r Security Explanation</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            padding: 20px;
            max-width: 700px;
            line-height: 1.6;
            color: var(--vscode-editor-foreground);
            background: var(--vscode-editor-background);
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .critical { background: #dc3545; color: white; }
        .high { background: #fd7e14; color: white; }
        .medium { background: #ffc107; color: black; }
        .low { background: #28a745; color: white; }
        h1 { margin: 16px 0 8px; font-size: 22px; }
        h2 { margin: 24px 0 8px; font-size: 18px; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 4px; }
        .danger-box {
            background: rgba(220, 53, 69, 0.1);
            border-left: 4px solid #dc3545;
            padding: 12px 16px;
            margin: 16px 0;
            border-radius: 4px;
        }
        .code-block {
            background: var(--vscode-textCodeBlock-background);
            padding: 12px;
            border-radius: 4px;
            font-family: 'Cascadia Code', 'Fira Code', monospace;
            font-size: 13px;
            overflow-x: auto;
            white-space: pre-wrap;
            border: 1px solid var(--vscode-panel-border);
        }
        .bad {
            background: rgba(220, 53, 69, 0.15);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }
        .good {
            background: rgba(40, 167, 69, 0.15);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }
        table { width: 100%; border-collapse: collapse; margin: 12px 0; }
        td { padding: 8px; border: 1px solid var(--vscode-panel-border); }
        td:first-child { font-weight: 600; width: 120px; }
        .ref-link {
            display: inline-block;
            margin: 4px 8px 4px 0;
            padding: 6px 12px;
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            text-decoration: none;
            border-radius: 4px;
            font-size: 13px;
        }
        .ref-link:hover { opacity: 0.9; }
    </style>
</head>
<body>
    <span class="severity-badge ${severity}">${emoji} ${escapeHtml(severity)}</span>
    <h1>${escapeHtml(finding.title || 'Security Finding')}</h1>

    <div class="danger-box">
        <strong>⚠️ The Danger</strong>
        <p>${escapeHtml(remediation.explanation)}</p>
    </div>

    <h2>🔍 Why This Happens</h2>
    <p>${escapeHtml(remediation.detailExplanation)}</p>

    <h2>💡 How to Fix It</h2>
    <table>
        <tr>
            <td>🚫 Bad</td>
            <td class="bad">${escapeHtml((finding.match || '…').substring(0, 120))}</td>
        </tr>
        <tr>
            <td>✅ Guidance</td>
            <td class="good"><pre style="margin:0;background:transparent;padding:0">${escapeHtml(remediation.fixCode)}</pre></td>
        </tr>
    </table>

    <h2>📋 References</h2>
    <p>
        ${safeReferences.map(r => `<span class="ref-link">${escapeHtml(r.label)} — ${escapeHtml(r.url)}</span>`).join('')}
    </p>
</body>
</html>`;
}

/**
 * Apply only explicitly allowlisted, deterministic remediations.
 * Heuristic findings remain guidance-only.
 */
async function handleRemediateFinding(finding) {
    if (!finding || !finding.file) {
        vscode.window.showWarningMessage('Cannot remediate — no file reference.');
        return;
    }

    const deterministicRules = new Set([
        'disable-ssl-verification',
        'cors-wildcard',
        'cors-wildcard-allow',
    ]);
    if (!deterministicRules.has(finding.ruleId)) {
        vscode.window.showInformationMessage(
            'This finding requires human review. Ch3ck3r will show remediation guidance but will not alter the file automatically.'
        );
        await handleShowExplanation(finding);
        return;
    }

    try {
        const document = await vscode.workspace.openTextDocument(finding.file);
        const remediation = smartRemediator.getRemediation(finding, document.languageId);
        if (!remediation?.fixCode || remediation.fixCode.includes('Fix required')) {
            vscode.window.showWarningMessage('No deterministic fix is available for this finding.');
            return;
        }

        const preview = remediation.fixCode.length > 400
            ? `${remediation.fixCode.slice(0, 400)}…`
            : remediation.fixCode;
        const confirm = await vscode.window.showWarningMessage(
            `Review the proposed Ch3ck3r edit:\n\n${preview}`,
            { modal: true },
            'Apply Reviewed Fix'
        );
        if (confirm !== 'Apply Reviewed Fix') return;

        const editor = await vscode.window.showTextDocument(document);
        const range = smartRemediator.getHighlightRange(document, finding);
        const applied = await editor.edit((editBuilder) => editBuilder.replace(range, remediation.fixCode));
        if (!applied) throw new Error('VS Code rejected the edit');
        await document.save();

        // Never dismiss automatically. Rescan the changed file and replace its diagnostics.
        const results = await scannerEngine.scanFiles([finding.file]);
        const rescanned = results[0]?.findings || [];
        if (typeof findingsStore.replaceFindingsForFile === 'function') {
            findingsStore.replaceFindingsForFile(finding.file, rescanned);
        } else if (typeof findingsStore.replaceByFile === 'function') {
            findingsStore.replaceByFile(finding.file, rescanned);
        } else {
            findingsStore.remove(finding.id);
            findingsStore.addFindings(rescanned);
        }
        updateAllProviders();
        diagnosticProvider.updateDiagnostics();
        vscode.window.showInformationMessage(`Applied and rescanned: ${finding.title}`, 'Undo');
    } catch (error) {
        vscode.window.showErrorMessage(`Remediation failed: ${error.message}`);
    }
}

module.exports = {
    activate,
    deactivate,
};
