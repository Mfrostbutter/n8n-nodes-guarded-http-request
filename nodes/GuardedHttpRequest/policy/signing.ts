/** HMAC-SHA256 signatures over canonical policy JSON. Signature format: v1.<keyId>.<hex>. */

import { createHmac, timingSafeEqual } from 'node:crypto';

export function canonicalize(value: unknown): string {
	if (value === null || typeof value !== 'object') return JSON.stringify(value);
	if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
	const obj = value as Record<string, unknown>;
	const keys = Object.keys(obj)
		.filter((k) => obj[k] !== undefined)
		.sort();
	return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

export function signPolicy(policy: unknown, keyId: string, key: string): string {
	const mac = createHmac('sha256', key).update(canonicalize(policy)).digest('hex');
	return `v1.${keyId}.${mac}`;
}

export interface SignatureCheck {
	ok: boolean;
	keyId?: string;
	reason?: string;
}

export function verifyPolicy(policy: unknown, signature: string, keys: Record<string, string>): SignatureCheck {
	const parts = signature.trim().split('.');
	if (parts.length !== 3 || parts[0] !== 'v1') return { ok: false, reason: 'malformed signature' };
	const [, keyId, mac] = parts;
	const key = keys[keyId];
	if (!key) return { ok: false, keyId, reason: `unknown signing key id "${keyId}"` };
	const expected = createHmac('sha256', key).update(canonicalize(policy)).digest('hex');
	const a = Buffer.from(mac, 'hex');
	const b = Buffer.from(expected, 'hex');
	if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false, keyId, reason: 'signature does not match policy' };
	return { ok: true, keyId };
}
