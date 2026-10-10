import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parseInstanceConfig, parsePolicy, parsePolicyJson, PolicySchemaError } from '../nodes/GuardedHttpRequest/policy/schema';

test('minimal policy parses', () => {
	const p = parsePolicy({ version: 1 });
	assert.deepEqual(p, { version: 1 });
});

test('full policy parses and lower-cases header names', () => {
	const p = parsePolicy({
		version: 1,
		name: 'x',
		methods: ['GET', 'POST'],
		schemes: ['https'],
		hosts: { allow: ['api.example.com', { host: '*.internal', paths: ['/v1/**'], ports: [443] }], deny: ['bad.internal'] },
		ports: [443],
		paths: { allow: ['/**'], deny: ['/admin/**'] },
		network: { blockPrivate: true, resolveDns: true },
		redirects: { follow: true, max: 3 },
		headers: { allow: ['Accept', 'Content-Type'], deny: ['Authorization'] },
		query: { deny: ['api_key'] },
		body: { allowed: true, maxBytes: 1024, contentTypes: ['json'] },
		auth: { required: true, modes: ['predefinedCredentialType'], credentialTypes: ['oAuth2Api'] },
		response: { maxBytes: 4096, allowBinary: false },
		options: { allowSkipSslVerification: false, maxTimeoutMs: 5000, allowExpressionsInUrl: false, allowProxy: false },
		audit: { log: true },
	});
	assert.deepEqual(p.headers, { allow: ['accept', 'content-type'], deny: ['authorization'] });
	assert.deepEqual(p.hosts?.allow?.[1], { host: '*.internal', paths: ['/v1/**'], ports: [443] });
});

test('rejects unknown keys, bad versions and bad enums', () => {
	assert.throws(() => parsePolicy({ version: 2 }), PolicySchemaError);
	assert.throws(() => parsePolicy({ version: 1, bogus: true }), /unknown key/);
	assert.throws(() => parsePolicy({ version: 1, methods: ['FETCH'] }), /not one of/);
	assert.throws(() => parsePolicy({ version: 1, hosts: { allow: [''] } }), /empty host/);
	assert.throws(() => parsePolicy({ version: 1, ports: [70000] }), /port numbers/);
	assert.throws(() => parsePolicy({ version: 1, body: { maxBytes: -1 } }), /integer/);
	assert.throws(() => parsePolicyJson('{not json'), /invalid JSON/);
});

test('instance config parses floor, named policies and signing keys', () => {
	const c = parseInstanceConfig({
		version: 1,
		floor: { version: 1, schemes: ['https'] },
		policies: { 'finance-readonly': { version: 1, methods: ['GET'] } },
		requirePolicy: true,
		signingKeys: { k1: 'secret' },
	});
	assert.equal(c.floor?.schemes?.[0], 'https');
	assert.equal(c.policies?.['finance-readonly'].methods?.[0], 'GET');
	assert.equal(c.requirePolicy, true);
	assert.throws(() => parseInstanceConfig({ version: 1, policies: { 'bad name!': { version: 1 } } }), /invalid policy name/);
});
