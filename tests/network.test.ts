import assert from 'node:assert/strict';
import { test } from 'node:test';

import { blockedReason, classifyIp, ipInCidr, resolveAndCheck } from '../nodes/GuardedHttpRequest/policy/network';

test('IPv4 classification', () => {
	assert.equal(classifyIp('8.8.8.8'), 'public');
	assert.equal(classifyIp('10.0.0.1'), 'private');
	assert.equal(classifyIp('172.16.5.5'), 'private');
	assert.equal(classifyIp('172.32.0.1'), 'public');
	assert.equal(classifyIp('192.168.1.1'), 'private');
	assert.equal(classifyIp('100.64.0.1'), 'private');
	assert.equal(classifyIp('127.0.0.1'), 'loopback');
	assert.equal(classifyIp('169.254.1.1'), 'linkLocal');
	assert.equal(classifyIp('169.254.169.254'), 'metadata');
	assert.equal(classifyIp('0.0.0.0'), 'unspecified');
});

test('IPv6 classification including mapped v4', () => {
	assert.equal(classifyIp('::1'), 'loopback');
	assert.equal(classifyIp('::'), 'unspecified');
	assert.equal(classifyIp('fd12::1'), 'private');
	assert.equal(classifyIp('fe80::1'), 'linkLocal');
	assert.equal(classifyIp('fd00:ec2::254'), 'metadata');
	assert.equal(classifyIp('::ffff:10.0.0.1'), 'private');
	assert.equal(classifyIp('::ffff:8.8.8.8'), 'public');
	assert.equal(classifyIp('2001:db8::1'), 'public');
});

test('CIDR containment', () => {
	assert.equal(ipInCidr('10.20.30.40', '10.0.0.0/8'), true);
	assert.equal(ipInCidr('10.20.30.40', '10.20.0.0/16'), true);
	assert.equal(ipInCidr('10.21.30.40', '10.20.0.0/16'), false);
	assert.equal(ipInCidr('fd12:3456::1', 'fd00::/8'), true);
	assert.equal(ipInCidr('2001:db8::1', 'fd00::/8'), false);
	assert.equal(ipInCidr('10.0.0.1', 'fd00::/8'), false);
});

test('blockedReason respects rule flags, metadata blocked by default', () => {
	assert.equal(blockedReason('10.0.0.1', {}), undefined);
	assert.match(blockedReason('10.0.0.1', { blockPrivate: true })!, /private/);
	assert.match(blockedReason('169.254.169.254', {})!, /metadata/);
	assert.equal(blockedReason('169.254.169.254', { blockMetadata: false }), undefined);
	assert.match(blockedReason('127.0.0.1', { blockLoopback: true })!, /loopback/);
});

test('resolveAndCheck: literals and metadata hostnames without DNS', async () => {
	assert.match((await resolveAndCheck('metadata.google.internal', {}))!, /metadata hostname/);
	assert.match((await resolveAndCheck('127.0.0.1', { blockLoopback: true }))!, /loopback/);
	assert.equal(await resolveAndCheck('localhost', { blockLoopback: true }), undefined, 'DNS off: hostnames pass');
});

test('resolveAndCheck: localhost resolves to loopback when DNS is on', async () => {
	const reason = await resolveAndCheck('localhost', { blockLoopback: true, resolveDns: true });
	assert.match(reason!, /loopback/);
});
