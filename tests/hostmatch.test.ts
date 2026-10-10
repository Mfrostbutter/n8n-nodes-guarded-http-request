import assert from 'node:assert/strict';
import { test } from 'node:test';

import { hostMatches, pathMatches, splitHostPort } from '../nodes/GuardedHttpRequest/policy/hostmatch';

test('exact host match is case-insensitive and ignores trailing dot', () => {
	assert.equal(hostMatches('API.Example.com.', 'api.example.com'), true);
	assert.equal(hostMatches('api.example.com', 'example.com'), false);
});

test('wildcard matches subdomains but not the apex', () => {
	assert.equal(hostMatches('a.example.com', '*.example.com'), true);
	assert.equal(hostMatches('a.b.example.com', '*.example.com'), true);
	assert.equal(hostMatches('example.com', '*.example.com'), false);
	assert.equal(hostMatches('notexample.com', '*.example.com'), false);
	assert.equal(hostMatches('evil-example.com', '*.example.com'), false);
});

test('star alone matches anything', () => {
	assert.equal(hostMatches('anything.io', '*'), true);
});

test('CIDR pattern only matches IP literals', () => {
	assert.equal(hostMatches('10.1.2.3', '10.0.0.0/8'), true);
	assert.equal(hostMatches('11.1.2.3', '10.0.0.0/8'), false);
	assert.equal(hostMatches('internal.corp', '10.0.0.0/8'), false);
});

test('splitHostPort handles ports, v6 and CIDR', () => {
	assert.deepEqual(splitHostPort('api.example.com:8443'), { host: 'api.example.com', port: 8443 });
	assert.deepEqual(splitHostPort('api.example.com'), { host: 'api.example.com' });
	assert.deepEqual(splitHostPort('[::1]:8080'), { host: '::1', port: 8080 });
	assert.deepEqual(splitHostPort('10.0.0.0/8'), { host: '10.0.0.0/8' });
});

test('path globs', () => {
	assert.equal(pathMatches('/v1/users', '/v1/*'), true);
	assert.equal(pathMatches('/v1/users/42', '/v1/*'), false);
	assert.equal(pathMatches('/v1/users/42', '/v1/**'), true);
	assert.equal(pathMatches('/v1', '/v1/**'), true);
	assert.equal(pathMatches('/v2/users', '/v1/**'), false);
	assert.equal(pathMatches('/v1/admin/x', '/v1/admin/**'), true);
	assert.equal(pathMatches('/reports/q3.csv', '/reports/*.csv'), true);
	assert.equal(pathMatches('/reports/q3.json', '/reports/*.csv'), false);
	assert.equal(pathMatches('/', '/'), true);
	assert.equal(pathMatches('/v1/', '/v1'), true);
});
