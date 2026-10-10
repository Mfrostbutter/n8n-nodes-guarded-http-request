import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { loadInstanceConfig, resetInstanceConfigCache } from '../nodes/GuardedHttpRequest/policy/instance';
import { resolveLayers } from '../nodes/GuardedHttpRequest/policy/resolve';
import { canonicalize, signPolicy, verifyPolicy } from '../nodes/GuardedHttpRequest/policy/signing';

const KEY = 'test-signing-key';

const baseConfig = {
	version: 1,
	floor: { version: 1, name: 'floor', schemes: ['https'] },
	policies: { ro: { version: 1, methods: ['GET'] } },
};

function configFrom(json: unknown, env: Record<string, string> = {}) {
	resetInstanceConfigCache();
	return loadInstanceConfig({ N8N_GUARDED_HTTP_CONFIG_JSON: JSON.stringify(json), ...env });
}

test('no config: no layers, nothing required', () => {
	resetInstanceConfigCache();
	const cfg = loadInstanceConfig({});
	assert.equal(cfg.source, 'none');
	assert.equal(cfg.requirePolicy, false);
	assert.equal(cfg.requireSignedPolicies, false);
	assert.deepEqual(resolveLayers(cfg, undefined), { layers: [], errors: [] });
});

test('floor only, policy required by env', () => {
	const cfg = configFrom(baseConfig, { N8N_GUARDED_HTTP_REQUIRE_POLICY: 'true' });
	const r = resolveLayers(cfg, undefined);
	assert.equal(r.layers.length, 1);
	assert.match(r.errors[0], /requires a Guarded HTTP Policy credential/);
});

test('reference mode resolves a named instance policy', () => {
	const cfg = configFrom(baseConfig);
	const r = resolveLayers(cfg, { mode: 'reference', policyRef: 'ro', policyName: 'Finance RO' });
	assert.deepEqual(r.errors, []);
	assert.deepEqual(r.layers.map((l) => `${l.source}:${l.name}`), ['instance-floor:floor', 'instance-policy:Finance RO']);
	assert.match(resolveLayers(cfg, { mode: 'reference', policyRef: 'nope' }).errors[0], /not defined/);
	assert.match(resolveLayers(cfg, { mode: 'reference', policyRef: '' }).errors[0], /references no/);
});

test('inline mode: unsigned accepted only when no signing key is configured', () => {
	const policy = { version: 1, methods: ['GET'] };
	const cfg = configFrom(baseConfig);
	assert.deepEqual(resolveLayers(cfg, { mode: 'inline', policyJson: JSON.stringify(policy) }).errors, []);
	const signed = configFrom(baseConfig, { N8N_GUARDED_HTTP_SIGNING_KEY: `k1:${KEY}` });
	assert.match(resolveLayers(signed, { mode: 'inline', policyJson: JSON.stringify(policy) }).errors[0], /no signature/);
	const sig = signPolicy(policy, 'k1', KEY);
	assert.deepEqual(resolveLayers(signed, { mode: 'inline', policyJson: JSON.stringify(policy), signature: sig }).errors, []);
	assert.match(resolveLayers(signed, { mode: 'inline', policyJson: JSON.stringify({ ...policy, methods: ['GET', 'DELETE'] }), signature: sig }).errors[0], /does not match/);
	assert.match(resolveLayers(signed, { mode: 'inline', policyJson: JSON.stringify(policy), signature: 'v1.other.00' }).errors[0], /unknown signing key/);
});

test('inline mode can be disabled instance-wide', () => {
	const cfg = configFrom({ ...baseConfig, allowInlinePolicies: false });
	assert.match(resolveLayers(cfg, { mode: 'inline', policyJson: '{"version":1}' }).errors[0], /inline policies are disabled/);
});

test('inline mode rejects malformed documents', () => {
	const cfg = configFrom(baseConfig);
	assert.match(resolveLayers(cfg, { mode: 'inline', policyJson: '{' }).errors[0], /not valid JSON/);
	assert.match(resolveLayers(cfg, { mode: 'inline', policyJson: '{"version":1,"x":1}' }).errors[0], /unknown key/);
});

test('canonicalization is order-independent and signatures verify', () => {
	assert.equal(canonicalize({ b: 1, a: [{ d: 2, c: 3 }] }), canonicalize({ a: [{ c: 3, d: 2 }], b: 1 }));
	const sig = signPolicy({ version: 1 }, 'default', KEY);
	assert.equal(verifyPolicy({ version: 1 }, sig, { default: KEY }).ok, true);
	assert.equal(verifyPolicy({ version: 1 }, 'garbage', { default: KEY }).ok, false);
});

test('sign-policy script agrees with the library', () => {
	const dir = mkdtempSync(join(tmpdir(), 'ghr-'));
	const file = join(dir, 'policy.json');
	const policy = { version: 1, name: 'p', hosts: { allow: ['api.example.com'] } };
	writeFileSync(file, JSON.stringify(policy, null, 2));
	const script = join(__dirname, '..', 'scripts', 'sign-policy.js');
	const out = execFileSync('node', [script, file, '--key-id', 'k1'], { env: { ...process.env, GUARDED_HTTP_SIGNING_KEY: KEY } }).toString().trim();
	assert.equal(out, signPolicy(policy, 'k1', KEY));
	const verify = execFileSync('node', [script, file, '--key-id', 'k1', '--verify', out], { env: { ...process.env, GUARDED_HTTP_SIGNING_KEY: KEY } }).toString().trim();
	assert.equal(verify, 'valid');
});

test('file config reloads when the file changes', () => {
	const dir = mkdtempSync(join(tmpdir(), 'ghr-'));
	const file = join(dir, 'config.json');
	writeFileSync(file, JSON.stringify({ version: 1, requirePolicy: false }));
	resetInstanceConfigCache();
	assert.equal(loadInstanceConfig({ N8N_GUARDED_HTTP_CONFIG: file }).requirePolicy, false);
	writeFileSync(file, JSON.stringify({ version: 1, requirePolicy: true }));
	const future = Date.now() / 1000 + 5;
	require('node:fs').utimesSync(file, future, future);
	assert.equal(loadInstanceConfig({ N8N_GUARDED_HTTP_CONFIG: file }).requirePolicy, true);
});
