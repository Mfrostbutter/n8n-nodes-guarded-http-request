import assert from 'node:assert/strict';
import { test } from 'node:test';

import { effectiveCaps, effectiveNetworkRules, evaluate, parseTarget, summarize, type ParsedTarget } from '../nodes/GuardedHttpRequest/policy/evaluate';
import type { Policy, PolicyLayer, RequestFacts } from '../nodes/GuardedHttpRequest/policy/types';

function facts(over: Partial<RequestFacts> = {}): RequestFacts {
	return {
		method: 'GET',
		url: 'https://api.example.com/v1/users',
		urlIsExpression: false,
		headerNames: [],
		queryNames: [],
		hasBody: false,
		bodyBytes: 0,
		authMode: 'none',
		skipSslVerification: false,
		usesProxy: false,
		ignoreResponseCode: false,
		followRedirects: true,
		responseFormat: 'autodetect',
		...over,
	};
}

function target(url = 'https://api.example.com/v1/users'): ParsedTarget {
	const t = parseTarget(url);
	if (typeof t === 'string') throw new Error(t);
	return t;
}

function layer(policy: Partial<Policy>, name = 'test', source: PolicyLayer['source'] = 'credential'): PolicyLayer {
	return { source, name, policy: { version: 1, ...policy } };
}

const codes = (v: Array<{ code: string }>) => v.map((x) => x.code).sort();

test('parseTarget rejects non-http schemes, user info and relative URLs', () => {
	assert.match(parseTarget('ftp://x.y/z') as string, /scheme/);
	assert.match(parseTarget('https://user:pw@x.y/z') as string, /user info/);
	assert.match(parseTarget('/relative') as string, /absolute/);
	const t = target('https://API.example.com:8443/a/../b?x=1');
	assert.equal(t.hostname, 'api.example.com');
	assert.equal(t.port, 8443);
	assert.equal(t.path, '/b');
});

test('empty policy allows everything', () => {
	assert.deepEqual(evaluate([layer({})], facts(), target()), []);
});

test('method, scheme, host, port, path checks', () => {
	const l = layer({
		methods: ['GET'],
		schemes: ['https'],
		hosts: { allow: ['api.example.com'], deny: ['*.evil.com'] },
		ports: [443],
		paths: { allow: ['/v1/**'], deny: ['/v1/admin/**'] },
	});
	assert.deepEqual(evaluate([l], facts(), target()), []);
	assert.deepEqual(codes(evaluate([l], facts({ method: 'POST' }), target())), ['method']);
	assert.deepEqual(codes(evaluate([l], facts(), target('http://api.example.com/v1/x'))), ['port', 'scheme']);
	assert.deepEqual(codes(evaluate([l], facts(), target('https://other.example.com/v1/x'))), ['host']);
	assert.deepEqual(codes(evaluate([l], facts(), target('https://api.example.com/v2/x'))), ['path']);
	assert.deepEqual(codes(evaluate([l], facts(), target('https://api.example.com/v1/admin/x'))), ['path-denied']);
	assert.deepEqual(codes(evaluate([l], facts(), target('https://a.evil.com/v1/x'))), ['host', 'host-denied']);
});

test('per-host rules with paths and ports', () => {
	const l = layer({ hosts: { allow: [{ host: 'api.example.com', paths: ['/v1/read/**'], ports: [443] }, 'files.example.com:8443'] } });
	assert.deepEqual(evaluate([l], facts(), target('https://api.example.com/v1/read/x')), []);
	assert.deepEqual(codes(evaluate([l], facts(), target('https://api.example.com/v1/write/x'))), ['host']);
	assert.deepEqual(evaluate([l], facts(), target('https://files.example.com:8443/')), []);
	assert.deepEqual(codes(evaluate([l], facts(), target('https://files.example.com/'))), ['host']);
});

test('headers, query, body, auth and option checks', () => {
	const l = layer({
		headers: { allow: ['accept'], deny: ['authorization'] },
		query: { deny: ['api_key'] },
		body: { allowed: true, maxBytes: 10, contentTypes: ['json'] },
		auth: { required: true, modes: ['predefinedCredentialType'], credentialTypes: ['oAuth2Api'] },
		response: { allowBinary: false },
		options: { allowSkipSslVerification: false, allowProxy: false, allowIgnoreResponseCode: false, maxTimeoutMs: 1000, allowExpressionsInUrl: false },
		redirects: { follow: false },
	});
	const ok = facts({ headerNames: ['Accept'], authMode: 'predefinedCredentialType', credentialType: 'oAuth2Api', followRedirects: false });
	assert.deepEqual(evaluate([l], ok, target()), []);
	const bad = facts({
		headerNames: ['Authorization', 'X-Other'],
		queryNames: ['api_key'],
		hasBody: true,
		bodyBytes: 11,
		contentType: 'raw',
		authMode: 'genericCredentialType',
		credentialType: 'httpBasicAuth',
		responseFormat: 'file',
		skipSslVerification: true,
		usesProxy: true,
		ignoreResponseCode: true,
		timeoutMs: 5000,
		urlIsExpression: true,
		followRedirects: true,
	});
	assert.deepEqual(codes(evaluate([l], bad, target())), [
		'auth-mode', 'auth-type', 'body-content-type', 'body-size', 'header', 'header-denied', 'ignore-status',
		'proxy', 'query-denied', 'redirects', 'response-binary', 'ssl', 'timeout', 'url-expression',
	]);
	assert.deepEqual(codes(evaluate([l], facts({ authMode: 'none', followRedirects: false }), target())), ['auth-mode', 'auth-required']);
});

test('layers compose: a request must pass every layer', () => {
	const floor = layer({ schemes: ['https'], hosts: { allow: ['*.example.com'] } }, 'floor', 'instance-floor');
	const project = layer({ methods: ['GET'], hosts: { allow: ['api.example.com'] } }, 'project');
	assert.deepEqual(evaluate([floor, project], facts(), target()), []);
	const v = evaluate([floor, project], facts({ method: 'POST' }), target('https://api.other.com/'));
	assert.deepEqual(v.map((x) => `${x.layer}:${x.code}`).sort(), ['floor:host', 'project:host', 'project:method']);
});

test('effective network rules OR the blocks and keep metadata blocked unless all layers opt out', () => {
	const a = layer({ network: { blockPrivate: true } });
	const b = layer({ network: { blockLoopback: true, blockMetadata: false } });
	assert.deepEqual(effectiveNetworkRules([a, b]), { blockPrivate: true, blockLoopback: true, blockLinkLocal: false, blockMetadata: true, resolveDns: false });
	assert.equal(effectiveNetworkRules([b]).blockMetadata, false);
	assert.equal(effectiveNetworkRules([]).blockMetadata, true);
});

test('effective caps take the minimum and the strictest flag', () => {
	const a = layer({ redirects: { max: 3 }, response: { maxBytes: 5000 }, options: { maxTimeoutMs: 9000 } });
	const b = layer({ redirects: { max: 10, sameHostOnly: true, forwardAuthCrossHost: true }, response: { maxBytes: 100 }, audit: { log: false } });
	const caps = effectiveCaps([a, b]);
	assert.equal(caps.maxRedirects, 3);
	assert.equal(caps.maxResponseBytes, 100);
	assert.equal(caps.maxTimeoutMs, 9000);
	assert.equal(caps.sameHostOnly, true);
	assert.equal(caps.forwardAuthCrossHost, true);
	assert.equal(caps.auditLog, false);
	const c = layer({ redirects: { forwardAuthCrossHost: false } });
	assert.equal(effectiveCaps([b, c]).forwardAuthCrossHost, false);
});

test('summary intersects lists', () => {
	const s = summarize([layer({ methods: ['GET', 'POST'] }), layer({ methods: ['GET', 'DELETE'] })]);
	assert.deepEqual(s.methods, ['GET']);
	assert.equal(s.schemes, 'any');
});
