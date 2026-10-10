#!/usr/bin/env node
// Sign or verify a policy document with an HMAC key.
//
//   GUARDED_HTTP_SIGNING_KEY=<key> node scripts/sign-policy.js policy.json [--key-id default]
//   GUARDED_HTTP_SIGNING_KEY=<key> node scripts/sign-policy.js policy.json --verify v1.default.<hex>
//
// Prints the signature. The key never appears in output or in the policy file.
const { readFileSync } = require('node:fs');
const { createHmac, timingSafeEqual } = require('node:crypto');

function canonicalize(value) {
	if (value === null || typeof value !== 'object') return JSON.stringify(value);
	if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
	const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
	return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
if (!file) {
	console.error('usage: sign-policy.js <policy.json> [--key-id <id>] [--verify <signature>]');
	process.exit(2);
}
const keyIdIdx = args.indexOf('--key-id');
const keyId = keyIdIdx !== -1 ? args[keyIdIdx + 1] : 'default';
const verifyIdx = args.indexOf('--verify');
const key = process.env.GUARDED_HTTP_SIGNING_KEY;
if (!key) {
	console.error('GUARDED_HTTP_SIGNING_KEY is not set');
	process.exit(2);
}

const policy = JSON.parse(readFileSync(file, 'utf8'));
const mac = createHmac('sha256', key).update(canonicalize(policy)).digest('hex');
const signature = `v1.${keyId}.${mac}`;

if (verifyIdx !== -1) {
	const given = args[verifyIdx + 1] || '';
	const a = Buffer.from(given);
	const b = Buffer.from(signature);
	const ok = a.length === b.length && timingSafeEqual(a, b);
	console.log(ok ? 'valid' : 'INVALID');
	process.exit(ok ? 0 : 1);
}
console.log(signature);
