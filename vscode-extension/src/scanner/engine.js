/**
 * Ch3ck3r Scanner Engine v2
 * Bounded, asynchronous analysis engine with modular rule dispatch.
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const childProcess = require('child_process');
const { MiniGlob } = require('../utils/minimatch');
const { SecurityRules } = require('./rules');

const DEFAULT_LIMITS = Object.freeze({
    maxFileSizeBytes: 500 * 1024,
    hardMaxFileSizeBytes: 5 * 1024 * 1024,
    maxFiles: 5000,
    hardMaxFiles: 10000,
    maxDirectories: 10000,
    maxDepth: 64,
    concurrency: 4,
    hardMaxConcurrency: 16,
    maxFindingsPerFile: 1000,
    toolTimeoutMs: 5000,
    hardToolTimeoutMs: 30000,
    toolMaxBufferBytes: 64 * 1024,
});

class ScannerEngine {
    constructor(configManager, findingsStore, options = {}) {
        this.configManager = configManager;
        this.findingsStore = findingsStore;
        this.options = typeof options === 'function'
            ? { isWorkspaceTrusted: options }
            : (options || {});
        this.rules = this.options.rules || new SecurityRules();
        this._execFile = this.options.execFile || childProcess.execFile;
    }

    /**
     * Probe optional tools without invoking a shell. Workspace Trust is supplied
     * by the caller (or constructor callback), keeping this module VS Code-free.
     */
    async checkExternalTools(options = {}) {
        const tools = { semgrep: false };
        if (!(await this._isWorkspaceTrusted(options))) return tools;

        try {
            const configured = this.configManager?.get?.('semgrepPath');
            const executable = await this._validateExecutable(configured || 'semgrep');
            const limits = this._getLimits(options.limits);
            await this._runExecutable(executable, ['--version'], {
                timeoutMs: limits.toolTimeoutMs,
                maxBufferBytes: limits.toolMaxBufferBytes,
                token: options.token,
            });
            tools.semgrep = true;
        } catch { /* unavailable, invalid, cancelled, or timed out */ }
        return tools;
    }

    /**
     * Scan explicit files. The optional second argument accepts rootPath,
     * token, limits, and onFile without changing existing call sites.
     */
    async scanFiles(filePaths, options = {}) {
        if (!Array.isArray(filePaths) || filePaths.length === 0) return [];

        const limits = this._getLimits(options.limits);
        const token = options.token;
        const rootContext = options.rootContext ||
            (options.rootPath || this.options.workspaceRoot
                ? await this._createRootContext(options.rootPath || this.options.workspaceRoot)
                : null);
        const candidates = filePaths.slice(0, limits.maxFiles);
        const results = new Array(candidates.length);
        let cursor = 0;

        const worker = async () => {
            while (!this._isCancelled(token)) {
                const index = cursor++;
                if (index >= candidates.length) return;
                const filePath = candidates[index];
                try {
                    const loaded = await this._readFileBounded(filePath, rootContext, limits, token);
                    if (!loaded || this._isCancelled(token)) continue;
                    results[index] = this._scanContent(loaded.path, loaded.content, rootContext, limits);
                } catch (err) {
                    if (!this._isCancellationError(err) && err.code !== 'ENOENT') {
                        // Deliberately omit source content and keep scanning other files.
                        console.error(`[Ch3ck3r] skipped ${path.basename(String(filePath))}: ${err.message}`);
                    }
                } finally {
                    options.onFile?.(filePath, index, candidates.length);
                }
            }
        };

        const workerCount = Math.min(limits.concurrency, candidates.length);
        await Promise.all(Array.from({ length: workerCount }, worker));
        return results.filter(Boolean);
    }

    async scanWorkspace(folderPath, progress, token, options = {}) {
        const limits = this._getLimits(options.limits);
        const rootContext = await this._createRootContext(folderPath);
        const files = await this._discoverFiles(folderPath, { token, limits, rootContext });
        let completed = 0;

        return this.scanFiles(files, {
            ...options,
            token,
            limits,
            rootContext,
            onFile: (filePath) => {
                completed += 1;
                progress?.report({
                    message: `${completed}/${files.length} — ${path.basename(filePath)}`,
                    increment: files.length ? 100 / files.length : 0,
                });
                options.onFile?.(filePath, completed - 1, files.length);
            },
        });
    }

    async scanOpenApi(filePath, options = {}) {
        const startedAt = new Date().toISOString();
        const limits = this._getLimits(options.limits);
        const rootContext = options.rootContext ||
            (options.rootPath || this.options.workspaceRoot
                ? await this._createRootContext(options.rootPath || this.options.workspaceRoot)
                : null);
        const loaded = await this._readFileBounded(filePath, rootContext, limits, options.token);
        if (!loaded) throw new Error('OpenAPI file is not scannable');

        const ext = path.extname(loaded.path).toLowerCase();
        const lang = ext === '.json' ? 'json' : 'yaml';
        const findings = this.rules.analyzeApiSpec(lang, loaded.content, loaded.path);
        // Preserve the dedicated OpenAPI API: it historically returned all severities.
        const enriched = this._enrichFindings(findings, loaded.path, loaded.content, rootContext, limits, false);
        return {
            plugin_name: 'openapi',
            target: loaded.path,
            status: 'completed',
            findings: enriched,
            risk_score: enriched.length
                ? Math.min(10, enriched.reduce((sum, finding) => {
                    const weight = { critical: 10, high: 7.5, medium: 5, low: 2.5, info: 0.5 };
                    return sum + (weight[finding.severity] || 0);
                }, 0) / enriched.length) : 0,
            started_at: startedAt,
            completed_at: new Date().toISOString(),
        };
    }

    async _discoverFiles(rootPath, options = {}) {
        const limits = options.limits || this._getLimits();
        const token = options.token;
        const rootContext = options.rootContext || await this._createRootContext(rootPath);
        const excludes = this.configManager?.get?.('excludePatterns') || [];
        const results = [];
        const queue = [{ dir: rootContext.resolved, depth: 0 }];
        let directories = 0;

        while (queue.length && results.length < limits.maxFiles && !this._isCancelled(token)) {
            const current = queue.shift();
            if (current.depth > limits.maxDepth || ++directories > limits.maxDirectories) break;

            try {
                await this._assertContainedDirectory(current.dir, rootContext);
                const dir = await fs.promises.opendir(current.dir);
                try {
                    for await (const entry of dir) {
                        if (this._isCancelled(token) || results.length >= limits.maxFiles) break;
                        const full = path.resolve(current.dir, entry.name);
                        if (!this._isWithin(rootContext.resolved, full)) continue;
                        const relative = path.relative(rootContext.resolved, full).split(path.sep).join('/');
                        if (excludes.some(pattern =>
                            MiniGlob.match(relative, pattern) || MiniGlob.match(full, pattern))) continue;

                        // Dirent checks do not follow links. Unknown/special entries are skipped.
                        if (entry.isSymbolicLink()) continue;
                        if (entry.isDirectory()) {
                            if (current.depth < limits.maxDepth) {
                                queue.push({ dir: full, depth: current.depth + 1 });
                            }
                        } else if (entry.isFile() && this._isScanable(full)) {
                            results.push(full);
                        }
                    }
                } finally {
                    // for-await normally closes the handle; close only if it remains open.
                    await dir.close().catch(() => {});
                }
            } catch (err) {
                if (this._isCancellationError(err)) break;
                // Permission errors and concurrent tree mutations are safe to skip.
            }
        }

        return results.sort();
    }

    _scanContent(filePath, content, rootContext, limits) {
        const ext = path.extname(filePath).toLowerCase();
        const base = path.basename(filePath);
        const lang = this._getLanguage(filePath);
        if (!lang) return null;

        let findings = [];
        const isDockerfile = lang === 'dockerfile';
        if (this._isCodeExt(ext)) {
            findings.push(...this.rules.analyzeCode(lang, content, filePath));
        }
        if (this._isConfigFileExt(ext, base)) {
            // This includes Dockerfile rules, so do not dispatch Dockerfiles again.
            findings.push(...this.rules.analyzeConfig(lang, content, filePath));
        } else if (isDockerfile) {
            findings.push(...this.rules.analyzeContainerfile(content, filePath));
        }
        if (this._isApiSpecish(content)) {
            findings.push(...this.rules.analyzeApiSpec(lang, content, filePath));
        }

        return {
            file: filePath,
            findings: this._enrichFindings(findings, filePath, content, rootContext, limits),
        };
    }

    _enrichFindings(findings, filePath, content, rootContext, limits, filterSeverity = true) {
        const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
        const configuredThreshold = this.configManager?.get?.('severityThreshold') || 'medium';
        const minIdx = severityOrder.indexOf(configuredThreshold);
        const thresholdIdx = minIdx >= 0 ? minIdx : severityOrder.indexOf('medium');
        const contentHash = crypto.createHash('sha256').update(content).digest('hex');
        const relativePath = rootContext
            ? path.relative(rootContext.real, path.resolve(filePath)).split(path.sep).join('/')
            : path.basename(filePath);
        const seen = new Set();
        const enriched = [];

        for (const finding of findings) {
            if (enriched.length >= limits.maxFindingsPerFile) break;
            const severityIdx = severityOrder.indexOf(finding.severity);
            if (severityIdx < 0 || (filterSeverity && severityIdx > thresholdIdx)) continue;

            const line = this._positiveInteger(finding.line, 1);
            const column = this._positiveInteger(finding.column, 1);
            const fingerprint = crypto.createHash('sha256').update(JSON.stringify({
                rule: finding.ruleId || 'unknown',
                path: relativePath,
                line,
                column,
                content: contentHash,
            })).digest('hex');

            // Also removes duplicate config/spec dispatch and the historical Dockerfile duplicate.
            if (seen.has(fingerprint)) continue;
            seen.add(fingerprint);
            enriched.push({
                ...finding,
                file: filePath,
                line,
                column,
                fingerprint,
                id: `ch3ck3r-${fingerprint.slice(0, 32)}`,
                timestamp: new Date().toISOString(),
            });
        }
        return enriched;
    }

    async _readFileBounded(filePath, rootContext, limits, token) {
        this._throwIfCancelled(token);
        const resolved = path.resolve(String(filePath));
        if (rootContext && !this._isWithin(rootContext.resolved, resolved)) {
            throw this._scannerError('ESCANOUTSIDE', 'file is outside the workspace');
        }
        await this._assertNoSymlinkComponents(resolved, rootContext?.resolved);

        const real = await fs.promises.realpath(resolved);
        if (rootContext && !this._isWithin(rootContext.real, real)) {
            throw this._scannerError('ESCANOUTSIDE', 'canonical file path is outside the workspace');
        }

        const noFollow = fs.constants.O_NOFOLLOW || 0;
        const handle = await fs.promises.open(resolved, fs.constants.O_RDONLY | noFollow);
        try {
            const stat = await handle.stat();
            if (!stat.isFile()) throw this._scannerError('ESCANTYPE', 'not a regular file');
            if (stat.size > limits.maxFileSizeBytes) {
                throw this._scannerError('ESCANSIZE', 'file exceeds scan size limit');
            }

            const chunks = [];
            let total = 0;
            let position = 0;
            while (total <= limits.maxFileSizeBytes) {
                this._throwIfCancelled(token);
                const remaining = limits.maxFileSizeBytes + 1 - total;
                const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, remaining));
                const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
                if (!bytesRead) break;
                chunks.push(buffer.subarray(0, bytesRead));
                total += bytesRead;
                position += bytesRead;
            }
            if (total > limits.maxFileSizeBytes) {
                throw this._scannerError('ESCANSIZE', 'file grew beyond scan size limit');
            }
            return { path: real, content: Buffer.concat(chunks, total).toString('utf8') };
        } finally {
            await handle.close();
        }
    }

    async _createRootContext(rootPath) {
        const resolved = path.resolve(String(rootPath));
        const stat = await fs.promises.lstat(resolved);
        if (stat.isSymbolicLink() || !stat.isDirectory()) {
            throw this._scannerError('ESCANROOT', 'workspace root must be a real directory');
        }
        const real = await fs.promises.realpath(resolved);
        return { resolved, real };
    }

    async _assertContainedDirectory(dirPath, rootContext) {
        if (!this._isWithin(rootContext.resolved, dirPath)) {
            throw this._scannerError('ESCANOUTSIDE', 'directory is outside the workspace');
        }
        await this._assertNoSymlinkComponents(dirPath, rootContext.resolved);
        const stat = await fs.promises.lstat(dirPath);
        if (stat.isSymbolicLink() || !stat.isDirectory()) {
            throw this._scannerError('ESCANTYPE', 'not a real directory');
        }
        const real = await fs.promises.realpath(dirPath);
        if (!this._isWithin(rootContext.real, real)) {
            throw this._scannerError('ESCANOUTSIDE', 'canonical directory is outside the workspace');
        }
    }

    async _assertNoSymlinkComponents(targetPath, boundaryPath) {
        const boundary = boundaryPath ? path.resolve(boundaryPath) : path.parse(targetPath).root;
        if (!this._isWithin(boundary, targetPath)) {
            throw this._scannerError('ESCANOUTSIDE', 'path is outside the scan boundary');
        }
        const relative = path.relative(boundary, targetPath);
        const parts = relative ? relative.split(path.sep).filter(Boolean) : [];
        let current = boundary;

        const boundaryStat = await fs.promises.lstat(current);
        if (boundaryStat.isSymbolicLink()) {
            throw this._scannerError('ESCANSYMLINK', 'symbolic links are not scanned');
        }
        for (const part of parts) {
            current = path.join(current, part);
            const stat = await fs.promises.lstat(current);
            if (stat.isSymbolicLink()) {
                throw this._scannerError('ESCANSYMLINK', 'symbolic links are not scanned');
            }
        }
    }

    async _isWorkspaceTrusted(options) {
        if (typeof options === 'function') return (await options()) === true;
        const explicit = options.trusted ?? options.workspaceTrusted;
        if (typeof explicit === 'boolean') return explicit;
        const explicitProvider = options.isWorkspaceTrusted ?? options.workspaceTrust;
        if (typeof explicitProvider === 'function') return (await explicitProvider()) === true;
        if (typeof explicitProvider === 'boolean') return explicitProvider;
        const provider = this.options.isWorkspaceTrusted ??
            this.options.workspaceTrusted ?? this.options.workspaceTrust;
        if (typeof provider === 'function') return (await provider()) === true;
        return provider === true;
    }

    async _validateExecutable(value) {
        if (typeof value !== 'string') throw new Error('invalid executable');
        const executable = value.trim();
        if (!executable || executable.length > 4096 || executable.includes('\0')) {
            throw new Error('invalid executable');
        }

        const hasSeparator = executable.includes('/') || executable.includes('\\');
        if (!hasSeparator) {
            if (executable.length > 128 || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(executable)) {
                throw new Error('invalid executable name');
            }
            return executable;
        }

        if (!path.isAbsolute(executable)) throw new Error('executable path must be absolute');
        const stat = await fs.promises.lstat(executable);
        if (stat.isSymbolicLink() || !stat.isFile()) throw new Error('executable must be a regular file');
        await fs.promises.access(executable, fs.constants.X_OK);
        return executable;
    }

    _runExecutable(executable, args, options) {
        this._throwIfCancelled(options.token);
        return new Promise((resolve, reject) => {
            let settled = false;
            let disposeCancellation;
            const finish = (error, stdout, stderr) => {
                if (settled) return;
                settled = true;
                disposeCancellation?.();
                if (error) reject(error);
                else resolve({ stdout, stderr });
            };

            let child;
            try {
                child = this._execFile(executable, args, {
                    shell: false,
                    windowsHide: true,
                    timeout: options.timeoutMs,
                    maxBuffer: options.maxBufferBytes,
                    encoding: 'utf8',
                }, finish);
            } catch (err) {
                finish(err);
                return;
            }

            if (!settled) {
                const subscription = options.token?.onCancellationRequested?.(() => {
                    try { child?.kill?.(); } catch { /* already exited */ }
                    finish(this._scannerError('ABORT_ERR', 'operation cancelled'));
                });
                if (subscription) disposeCancellation = () => subscription.dispose?.();
            }
        });
    }

    _getLimits(overrides = {}) {
        const configuredSizeKB = Number(this.configManager?.get?.('maxFileSizeKB'));
        const requestedSize = Number.isFinite(configuredSizeKB) && configuredSizeKB > 0
            ? configuredSizeKB * 1024
            : DEFAULT_LIMITS.maxFileSizeBytes;
        const requestedFiles = Number(overrides.maxFiles ?? this.configManager?.get?.('maxWorkspaceFiles'));
        const requestedConcurrency = Number(overrides.concurrency ?? this.configManager?.get?.('maxScanConcurrency'));
        const requestedToolTimeout = Number(overrides.toolTimeoutMs ?? this.options.toolTimeoutMs);

        return {
            maxFileSizeBytes: this._boundedInteger(
                overrides.maxFileSizeBytes ?? requestedSize,
                1,
                DEFAULT_LIMITS.hardMaxFileSizeBytes,
                DEFAULT_LIMITS.maxFileSizeBytes),
            maxFiles: this._boundedInteger(requestedFiles, 1, DEFAULT_LIMITS.hardMaxFiles, DEFAULT_LIMITS.maxFiles),
            maxDirectories: this._boundedInteger(overrides.maxDirectories, 1, 50000, DEFAULT_LIMITS.maxDirectories),
            maxDepth: this._boundedInteger(overrides.maxDepth, 0, 256, DEFAULT_LIMITS.maxDepth),
            concurrency: this._boundedInteger(requestedConcurrency, 1, DEFAULT_LIMITS.hardMaxConcurrency, DEFAULT_LIMITS.concurrency),
            maxFindingsPerFile: this._boundedInteger(overrides.maxFindingsPerFile, 1, 5000, DEFAULT_LIMITS.maxFindingsPerFile),
            toolTimeoutMs: this._boundedInteger(requestedToolTimeout, 100, DEFAULT_LIMITS.hardToolTimeoutMs, DEFAULT_LIMITS.toolTimeoutMs),
            toolMaxBufferBytes: this._boundedInteger(
                overrides.toolMaxBufferBytes,
                1024,
                1024 * 1024,
                DEFAULT_LIMITS.toolMaxBufferBytes),
        };
    }

    _boundedInteger(value, min, max, fallback) {
        const number = Number(value);
        if (!Number.isFinite(number)) return fallback;
        return Math.max(min, Math.min(max, Math.floor(number)));
    }

    _positiveInteger(value, fallback) {
        const number = Number(value);
        return Number.isInteger(number) && number > 0 ? number : fallback;
    }

    _isWithin(root, candidate) {
        const relative = path.relative(path.resolve(root), path.resolve(candidate));
        return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
    }

    _isCancelled(token) {
        return token?.isCancellationRequested === true;
    }

    _throwIfCancelled(token) {
        if (this._isCancelled(token)) throw this._scannerError('ABORT_ERR', 'operation cancelled');
    }

    _isCancellationError(error) {
        return error?.code === 'ABORT_ERR';
    }

    _scannerError(code, message) {
        const error = new Error(message);
        error.code = code;
        return error;
    }

    _isScanable(filePath) {
        const exts = new Set([
            '.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.java',
            '.rb', '.rs', '.yaml', '.yml', '.json', '.env', '.tf',
            '.graphql', '.gql', '.php', '.kt', '.kts',
        ]);
        const ext = path.extname(filePath).toLowerCase();
        const base = path.basename(filePath);
        return exts.has(ext) ||
               base === 'Dockerfile' ||
               base === 'docker-compose.yml' ||
               base === 'docker-compose.yaml';
    }

    _isCodeExt(ext) {
        return new Set(['.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.java', '.rb', '.rs', '.php', '.kt', '.kts']).has(ext);
    }

    _isConfigFileExt(ext, base) {
        return new Set(['.env', '.tf', '.yaml', '.yml', '.json']).has(ext) || base === 'Dockerfile';
    }

    _isApiSpecish(content) {
        return /(?:^|\n)\s*(?:openapi|swagger|paths|components)\s*:|"(?:openapi|swagger|paths|components)"\s*:/m.test(content);
    }

    _getLanguage(filePath) {
        const map = {
            '.js': 'javascript', '.jsx': 'javascript',
            '.ts': 'typescript', '.tsx': 'typescript',
            '.py': 'python', '.go': 'go', '.java': 'java',
            '.rb': 'ruby', '.rs': 'rust',
            '.yaml': 'yaml', '.yml': 'yaml', '.json': 'json',
            '.env': 'dotenv', '.tf': 'terraform',
            '.graphql': 'graphql', '.gql': 'graphql',
            '.php': 'php', '.kt': 'kotlin', '.kts': 'kotlin',
        };
        const ext = path.extname(filePath).toLowerCase();
        const base = path.basename(filePath);
        if (base === 'Dockerfile') return 'dockerfile';
        return map[ext] || null;
    }
}

module.exports = { ScannerEngine, DEFAULT_LIMITS };
