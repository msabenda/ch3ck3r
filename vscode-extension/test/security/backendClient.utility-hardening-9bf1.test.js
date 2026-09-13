'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { BackendClient } = require('../../src/utils/backendClient');

test('BackendClient validates secure backend URLs and forbids URL credentials', () => {
    assert.doesNotThrow(() => new BackendClient('https://backend.example.test/api', '', { fetch: async () => new Response('{}') }));
    assert.doesNotThrow(() => new BackendClient('http://localhost:8080', '', { fetch: async () => new Response('{}') }));
    assert.doesNotThrow(() => new BackendClient('http://127.9.8.7:8080', '', { fetch: async () => new Response('{}') }));
    assert.doesNotThrow(() => new BackendClient('http://[::1]:8080', '', { fetch: async () => new Response('{}') }));

    assert.throws(() => new BackendClient('http://backend.example.test', '', { fetch: async () => new Response('{}') }), /HTTPS/);
    assert.throws(() => new BackendClient('ftp://backend.example.test', '', { fetch: async () => new Response('{}') }), /HTTPS/);
    assert.throws(() => new BackendClient('https://user:pass@backend.example.test', '', { fetch: async () => new Response('{}') }), /credentials/);
    assert.throws(() => new BackendClient('https://backend.example.test?token=x', '', { fetch: async () => new Response('{}') }), /query string/);
});

test('BackendClient rejects redirects and never exposes its bearer token', async () => {
    const token = 'super-secret-token-value';
    let requestOptions;
    const client = new BackendClient('https://backend.example.test', token, {
        fetch: async (_url, options) => {
            requestOptions = options;
            return new Response('redirect body token=server-secret', {
                status: 302,
                headers: { location: 'https://evil.example.test' },
            });
        },
    });

    await assert.rejects(client.checkHealth(), error => {
        assert.match(error.message, /redirect rejected/);
        assert.doesNotMatch(error.message, /super-secret-token-value|server-secret/);
        assert.ok(error.message.length <= 512);
        return true;
    });
    assert.equal(requestOptions.redirect, 'manual');
    assert.equal(requestOptions.headers.Authorization, `Bearer ${token}`);
});

test('BackendClient enforces timeout and caller cancellation', async () => {
    const abortAwareFetch = (_url, options) => new Promise((_resolve, reject) => {
        options.signal.addEventListener('abort', () => reject(new DOMException('secret-token-on-abort', 'AbortError')), { once: true });
    });
    const timed = new BackendClient('https://backend.example.test', 'secret-token-on-abort', {
        timeoutMs: 15,
        fetch: abortAwareFetch,
    });
    await assert.rejects(timed.checkHealth(), error => {
        assert.match(error.message, /timed out/);
        assert.doesNotMatch(error.message, /secret-token-on-abort/);
        return true;
    });

    const nonCompliantFetch = () => new Promise(() => {});
    const stillTimesOut = new BackendClient('https://backend.example.test', '', {
        timeoutMs: 15,
        fetch: nonCompliantFetch,
    });
    await assert.rejects(stillTimesOut.checkHealth(), /timed out/);

    const hangingBody = new BackendClient('https://backend.example.test', '', {
        timeoutMs: 15,
        fetch: async () => new Response(new ReadableStream({ start() {} })),
    });
    await assert.rejects(hangingBody.checkHealth(), /timed out/);

    const controller = new AbortController();
    const cancellable = new BackendClient('https://backend.example.test', '', {
        timeoutMs: 5_000,
        fetch: nonCompliantFetch,
    });
    const request = cancellable._request('GET', '/api/v1/projects', undefined, { signal: controller.signal });
    controller.abort();
    await assert.rejects(request, /cancelled/);
});

test('BackendClient rejects malformed/unexpected JSON and bounds request and response bytes', async () => {
    const invalidJson = new BackendClient('https://backend.example.test', '', {
        fetch: async () => new Response('{not json', { headers: { 'content-type': 'application/json' } }),
    });
    await assert.rejects(invalidJson.checkHealth(), /invalid JSON/);

    const primitiveJson = new BackendClient('https://backend.example.test', '', {
        fetch: async () => new Response('"string"', { headers: { 'content-type': 'application/json' } }),
    });
    await assert.rejects(primitiveJson.checkHealth(), /object or array/);

    const oversizedResponse = new BackendClient('https://backend.example.test', '', {
        maxResponseBytes: 8,
        fetch: async () => new Response('{"long":"response"}'),
    });
    await assert.rejects(oversizedResponse.checkHealth(), /exceeds 8 bytes/);

    const oversizedRequest = new BackendClient('https://backend.example.test', '', {
        maxRequestBytes: 8,
        fetch: async () => new Response('{}'),
    });
    await assert.rejects(oversizedRequest.runFullScan('a'.repeat(20)), /exceeds 8 bytes/);
});

test('BackendClient omits malicious response bodies and bounds/redacts transport errors', async () => {
    const secret = 'client-token-should-not-leak';
    const backendError = new BackendClient('https://backend.example.test', secret, {
        fetch: async () => new Response(`password=backend-password ${'x'.repeat(2_000)}`, { status: 500 }),
    });
    await assert.rejects(backendError.checkHealth(), error => {
        assert.equal(error.message, 'Backend error 500');
        assert.doesNotMatch(error.message, /backend-password|client-token/);
        return true;
    });

    const transportError = new BackendClient('https://backend.example.test', secret, {
        fetch: async () => { throw new Error(`${secret} Bearer attack-token ${'z'.repeat(2_000)}`); },
    });
    await assert.rejects(transportError.checkHealth(), error => {
        assert.doesNotMatch(error.message, /client-token-should-not-leak|attack-token/);
        assert.ok(error.message.length <= 512);
        return true;
    });
});
