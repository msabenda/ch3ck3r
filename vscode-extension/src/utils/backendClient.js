'use strict';

/**
 * BackendClient — communicates with the Ch3ck3r backend API.
 *
 * Network defaults are deliberately conservative because the URL and backend
 * response can both be controlled outside the extension.
 */
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_REQUEST_BYTES = 512 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_TIMEOUT_MS = 120_000;
const HARD_MAX_REQUEST_BYTES = 5 * 1024 * 1024;
const HARD_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
const MAX_ERROR_CHARS = 512;

function isLoopbackHostname(hostname) {
    const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
    if (host === 'localhost' || host === '::1') return true;
    const match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    return Boolean(match && match.slice(1).every(part => Number(part) <= 255) && Number(match[1]) === 127);
}

function validateBaseUrl(value) {
    if (typeof value !== 'string' || !value.trim()) {
        throw new TypeError('Backend URL must be a non-empty absolute URL');
    }

    let url;
    try {
        url = new URL(value.trim());
    } catch (_) {
        throw new TypeError('Backend URL must be a valid absolute URL');
    }

    if (url.username || url.password) {
        throw new TypeError('Backend URL must not contain credentials');
    }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopbackHostname(url.hostname))) {
        throw new TypeError('Backend URL must use HTTPS (HTTP is allowed only for loopback hosts)');
    }
    if (url.search || url.hash) {
        throw new TypeError('Backend URL must not contain a query string or fragment');
    }

    url.pathname = url.pathname.replace(/\/+$/, '');
    return url;
}

function positiveInteger(value, fallback, name, maximum) {
    if (value === undefined) return fallback;
    if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
        throw new TypeError(`${name} must be a positive integer no greater than ${maximum}`);
    }
    return value;
}

function redactText(value, secrets = []) {
    let text = String(value == null ? '' : value);
    for (const secret of secrets) {
        if (secret) text = text.split(String(secret)).join('[REDACTED]');
    }
    text = text
        .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [REDACTED]')
        .replace(/([?&](?:access_?token|api_?key|key|password|secret)=)[^&#\s]*/gi, '$1[REDACTED]')
        .replace(/((?:access_?token|api_?key|authorization|password|passwd|secret)\s*[=:]\s*["']?)[^\s,"'};]+/gi, '$1[REDACTED]');
    return text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').slice(0, MAX_ERROR_CHARS);
}

function safeError(message, cause, secrets) {
    const detail = cause && cause.message ? `: ${cause.message}` : '';
    const error = new Error(redactText(`${message}${detail}`, secrets));
    error.name = cause && cause.name === 'AbortError' ? 'AbortError' : 'BackendClientError';
    return error;
}

function buildRequestUrl(baseUrl, requestPath) {
    if (typeof requestPath !== 'string' || !requestPath.startsWith('/') || requestPath.startsWith('//')) {
        throw new TypeError('Backend request path must be an absolute path');
    }
    const basePath = baseUrl.pathname === '/' ? '' : baseUrl.pathname;
    const url = new URL(baseUrl.href);
    const pathAndQuery = new URL(requestPath, 'https://request.invalid');
    url.pathname = `${basePath}${pathAndQuery.pathname}`.replace(/\/{2,}/g, '/');
    url.search = pathAndQuery.search;
    url.hash = '';
    return url;
}

function raceWithAbort(operation, signal) {
    if (signal.aborted) {
        const error = new Error(signal.reason && signal.reason.message ? signal.reason.message : 'request aborted');
        error.name = 'AbortError';
        return Promise.reject(error);
    }
    return new Promise((resolve, reject) => {
        const onAbort = () => {
            const error = new Error(signal.reason && signal.reason.message ? signal.reason.message : 'request aborted');
            error.name = 'AbortError';
            reject(error);
        };
        signal.addEventListener('abort', onAbort, { once: true });
        Promise.resolve(operation).then(
            value => {
                signal.removeEventListener('abort', onAbort);
                resolve(value);
            },
            error => {
                signal.removeEventListener('abort', onAbort);
                reject(error);
            }
        );
    });
}

async function readBoundedResponse(response, maxBytes) {
    const declaredLength = Number(response.headers && response.headers.get('content-length'));
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
        if (response.body && typeof response.body.cancel === 'function') await response.body.cancel().catch(() => {});
        throw new Error(`Backend response exceeds ${maxBytes} bytes`);
    }

    if (!response.body || typeof response.body.getReader !== 'function') {
        const text = await response.text();
        if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error(`Backend response exceeds ${maxBytes} bytes`);
        return text;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let size = 0;
    let text = '';
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > maxBytes) {
                await reader.cancel().catch(() => {});
                throw new Error(`Backend response exceeds ${maxBytes} bytes`);
            }
            text += decoder.decode(value, { stream: true });
        }
        text += decoder.decode();
        return text;
    } finally {
        reader.releaseLock();
    }
}

class BackendClient {
    constructor(baseUrl, token, options = {}) {
        const settings = options && typeof options === 'object' ? options : {};
        this._baseUrl = validateBaseUrl(baseUrl);
        this.baseUrl = this._baseUrl.href.replace(/\/$/, '');
        this.token = typeof token === 'string' ? token : '';
        this.timeoutMs = positiveInteger(settings.timeoutMs, DEFAULT_TIMEOUT_MS, 'timeoutMs', MAX_TIMEOUT_MS);
        this.maxRequestBytes = positiveInteger(settings.maxRequestBytes, DEFAULT_MAX_REQUEST_BYTES, 'maxRequestBytes', HARD_MAX_REQUEST_BYTES);
        this.maxResponseBytes = positiveInteger(settings.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES, 'maxResponseBytes', HARD_MAX_RESPONSE_BYTES);
        this._fetch = settings.fetch || globalThis.fetch;
        if (typeof this._fetch !== 'function') throw new TypeError('A Fetch-compatible implementation is required');
    }

    async _request(method, requestPath, body, options = {}) {
        const normalizedMethod = String(method || '').toUpperCase();
        if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(normalizedMethod)) {
            throw new TypeError('Unsupported backend request method');
        }

        const url = buildRequestUrl(this._baseUrl, requestPath);
        const headers = { Accept: 'application/json' };
        if (this.token) headers.Authorization = `Bearer ${this.token}`;

        let encodedBody;
        if (body !== undefined) {
            if (normalizedMethod === 'GET') throw new TypeError('GET requests cannot include a body');
            try {
                encodedBody = JSON.stringify(body);
            } catch (_) {
                throw new TypeError('Backend request body must be JSON-serializable');
            }
            if (encodedBody === undefined) throw new TypeError('Backend request body must be JSON-serializable');
            if (Buffer.byteLength(encodedBody, 'utf8') > this.maxRequestBytes) {
                throw new RangeError(`Backend request exceeds ${this.maxRequestBytes} bytes`);
            }
            headers['Content-Type'] = 'application/json';
        }

        const controller = new AbortController();
        const externalSignal = options && options.signal;
        const abortFromExternal = () => controller.abort(externalSignal.reason);
        if (externalSignal) {
            if (externalSignal.aborted) abortFromExternal();
            else externalSignal.addEventListener('abort', abortFromExternal, { once: true });
        }
        const timeout = setTimeout(() => controller.abort(new Error('request timed out')), this.timeoutMs);

        try {
            let response;
            try {
                response = await raceWithAbort(this._fetch(url.href, {
                    method: normalizedMethod,
                    headers,
                    body: encodedBody,
                    redirect: 'manual',
                    signal: controller.signal,
                }), controller.signal);
            } catch (error) {
                const label = controller.signal.aborted
                    ? (externalSignal && externalSignal.aborted ? 'Backend request cancelled' : 'Backend request timed out')
                    : 'Backend request failed';
                throw safeError(label, error, [this.token]);
            }

            if (!response || !Number.isInteger(response.status)) {
                throw safeError('Backend returned an invalid response', null, [this.token]);
            }
            if (response.status >= 300 && response.status < 400) {
                if (response.body && typeof response.body.cancel === 'function') await response.body.cancel().catch(() => {});
                throw safeError(`Backend redirect rejected (${response.status})`, null, [this.token]);
            }

            let text;
            try {
                text = await raceWithAbort(readBoundedResponse(response, this.maxResponseBytes), controller.signal);
            } catch (error) {
                const label = controller.signal.aborted
                    ? (externalSignal && externalSignal.aborted ? 'Backend request cancelled' : 'Backend request timed out')
                    : 'Unable to read backend response';
                throw safeError(label, error, [this.token]);
            }

            if (!response.ok) {
                // Deliberately omit the untrusted response body: it can contain
                // credentials, source code, or attacker-controlled terminal text.
                throw safeError(`Backend error ${response.status}`, null, [this.token]);
            }
            if (!text.trim()) throw safeError('Backend returned an empty JSON response', null, [this.token]);

            let data;
            try {
                data = JSON.parse(text);
            } catch (_) {
                throw safeError('Backend returned invalid JSON', null, [this.token]);
            }
            if (data === null || (typeof data !== 'object')) {
                throw safeError('Backend JSON response must be an object or array', null, [this.token]);
            }
            return data;
        } finally {
            clearTimeout(timeout);
            if (externalSignal) externalSignal.removeEventListener('abort', abortFromExternal);
        }
    }

    async checkHealth() {
        const data = await this._request('GET', '/api/v1/health/live');
        if (Array.isArray(data)) throw new Error('Backend health response must be an object');
        return data;
    }

    async getScans(limit = 10) {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new TypeError('Scan limit must be an integer from 1 to 1000');
        return this._request('GET', `/api/v1/scans?limit=${encodeURIComponent(String(limit))}`);
    }

    async createScan(projectId, scanType, target) {
        for (const [name, value] of Object.entries({ projectId, scanType, target })) {
            if (typeof value !== 'string' || !value.trim() || value.length > 4096) throw new TypeError(`${name} must be a non-empty bounded string`);
        }
        return this._request('POST', '/api/v1/scans', {
            project_id: projectId,
            scan_type: scanType,
            target,
        });
    }

    async runFullScan(target) {
        if (typeof target !== 'string' || !target.trim() || target.length > 4096) throw new TypeError('target must be a non-empty bounded string');
        return this._request('POST', '/api/v1/scans/full-scan', { target });
    }

    async getFindings(scanId) {
        if (!['string', 'number'].includes(typeof scanId) || !String(scanId).trim() || String(scanId).length > 256) {
            throw new TypeError('scanId must be a non-empty bounded identifier');
        }
        return this._request('GET', `/api/v1/findings?scan_id=${encodeURIComponent(String(scanId))}`);
    }

    async getProjects() {
        return this._request('GET', '/api/v1/projects');
    }
}

module.exports = { BackendClient, validateBaseUrl };
