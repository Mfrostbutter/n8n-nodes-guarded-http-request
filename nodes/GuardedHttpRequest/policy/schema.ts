/** Policy document validation. Hand-rolled so the package carries no runtime dependencies. */

import type { AuthMode, ContentType, HostRule, HttpMethod, InstanceConfig, Policy } from './types';

const METHODS: HttpMethod[] = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const AUTH_MODES: AuthMode[] = ['none', 'predefinedCredentialType', 'genericCredentialType'];
const CONTENT_TYPES: ContentType[] = ['json', 'form-urlencoded', 'multipart-form-data', 'raw', 'binaryData'];
const SCHEMES = ['http', 'https'];

export class PolicySchemaError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'PolicySchemaError';
	}
}

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
	return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function fail(path: string, msg: string): never {
	throw new PolicySchemaError(`${path}: ${msg}`);
}

function optBool(o: Obj, key: string, path: string): boolean | undefined {
	const v = o[key];
	if (v === undefined) return undefined;
	if (typeof v !== 'boolean') fail(`${path}.${key}`, 'must be a boolean');
	return v;
}

function optInt(o: Obj, key: string, path: string, min = 0): number | undefined {
	const v = o[key];
	if (v === undefined) return undefined;
	if (typeof v !== 'number' || !Number.isInteger(v) || v < min) fail(`${path}.${key}`, `must be an integer >= ${min}`);
	return v;
}

function optStrList(o: Obj, key: string, path: string): string[] | undefined {
	const v = o[key];
	if (v === undefined) return undefined;
	if (!Array.isArray(v) || v.some((x) => typeof x !== 'string' || x.trim() === '')) {
		fail(`${path}.${key}`, 'must be an array of non-empty strings');
	}
	return (v as string[]).map((s) => s.trim());
}

function optEnumList<T extends string>(o: Obj, key: string, path: string, allowed: readonly T[]): T[] | undefined {
	const list = optStrList(o, key, path);
	if (!list) return undefined;
	for (const item of list) {
		if (!allowed.includes(item as T)) fail(`${path}.${key}`, `"${item}" is not one of ${allowed.join(', ')}`);
	}
	return list as T[];
}

function optIntList(o: Obj, key: string, path: string): number[] | undefined {
	const v = o[key];
	if (v === undefined) return undefined;
	if (!Array.isArray(v) || v.some((x) => typeof x !== 'number' || !Number.isInteger(x) || x < 1 || x > 65535)) {
		fail(`${path}.${key}`, 'must be an array of port numbers');
	}
	return v as number[];
}

function knownKeys(o: Obj, path: string, allowed: string[]): void {
	for (const k of Object.keys(o)) {
		if (!allowed.includes(k)) fail(`${path}.${k}`, 'unknown key');
	}
}

function parseHostAllow(v: unknown, path: string): Array<string | HostRule> | undefined {
	if (v === undefined) return undefined;
	if (!Array.isArray(v)) fail(path, 'must be an array');
	return v.map((entry, i) => {
		const p = `${path}[${i}]`;
		if (typeof entry === 'string') {
			if (entry.trim() === '') fail(p, 'empty host pattern');
			return entry.trim();
		}
		if (!isObj(entry)) fail(p, 'must be a string or { host, paths?, ports? }');
		knownKeys(entry, p, ['host', 'paths', 'ports']);
		if (typeof entry.host !== 'string' || entry.host.trim() === '') fail(`${p}.host`, 'required string');
		const rule: HostRule = { host: entry.host.trim() };
		const paths = optStrList(entry, 'paths', p);
		if (paths) rule.paths = paths;
		const ports = optIntList(entry, 'ports', p);
		if (ports) rule.ports = ports;
		return rule;
	});
}

export function parsePolicy(input: unknown, path = 'policy'): Policy {
	if (!isObj(input)) fail(path, 'must be an object');
	knownKeys(input, path, [
		'version', 'name', 'description', 'methods', 'schemes', 'hosts', 'ports', 'paths', 'network',
		'redirects', 'headers', 'query', 'body', 'auth', 'response', 'options', 'audit',
	]);
	if (input.version !== 1) fail(`${path}.version`, 'must be 1');
	const out: Policy = { version: 1 };
	if (input.name !== undefined) {
		if (typeof input.name !== 'string') fail(`${path}.name`, 'must be a string');
		out.name = input.name;
	}
	if (input.description !== undefined) {
		if (typeof input.description !== 'string') fail(`${path}.description`, 'must be a string');
		out.description = input.description;
	}
	const methods = optEnumList(input, 'methods', path, METHODS);
	if (methods) out.methods = methods;
	const schemes = optEnumList(input, 'schemes', path, SCHEMES as Array<'http' | 'https'>);
	if (schemes) out.schemes = schemes;
	if (input.hosts !== undefined) {
		if (!isObj(input.hosts)) fail(`${path}.hosts`, 'must be an object');
		knownKeys(input.hosts, `${path}.hosts`, ['allow', 'deny']);
		out.hosts = {};
		const allow = parseHostAllow(input.hosts.allow, `${path}.hosts.allow`);
		if (allow) out.hosts.allow = allow;
		const deny = optStrList(input.hosts, 'deny', `${path}.hosts`);
		if (deny) out.hosts.deny = deny;
	}
	const ports = optIntList(input, 'ports', path);
	if (ports) out.ports = ports;
	if (input.paths !== undefined) {
		if (!isObj(input.paths)) fail(`${path}.paths`, 'must be an object');
		knownKeys(input.paths, `${path}.paths`, ['allow', 'deny']);
		out.paths = {};
		const allow = optStrList(input.paths, 'allow', `${path}.paths`);
		if (allow) out.paths.allow = allow;
		const deny = optStrList(input.paths, 'deny', `${path}.paths`);
		if (deny) out.paths.deny = deny;
	}
	if (input.network !== undefined) {
		if (!isObj(input.network)) fail(`${path}.network`, 'must be an object');
		const p = `${path}.network`;
		knownKeys(input.network, p, ['blockPrivate', 'blockLoopback', 'blockLinkLocal', 'blockMetadata', 'resolveDns']);
		out.network = {
			blockPrivate: optBool(input.network, 'blockPrivate', p),
			blockLoopback: optBool(input.network, 'blockLoopback', p),
			blockLinkLocal: optBool(input.network, 'blockLinkLocal', p),
			blockMetadata: optBool(input.network, 'blockMetadata', p),
			resolveDns: optBool(input.network, 'resolveDns', p),
		};
	}
	if (input.redirects !== undefined) {
		if (!isObj(input.redirects)) fail(`${path}.redirects`, 'must be an object');
		const p = `${path}.redirects`;
		knownKeys(input.redirects, p, ['follow', 'max', 'sameHostOnly', 'forwardAuthCrossHost']);
		out.redirects = {
			follow: optBool(input.redirects, 'follow', p),
			max: optInt(input.redirects, 'max', p),
			sameHostOnly: optBool(input.redirects, 'sameHostOnly', p),
			forwardAuthCrossHost: optBool(input.redirects, 'forwardAuthCrossHost', p),
		};
	}
	for (const key of ['headers', 'query'] as const) {
		if (input[key] === undefined) continue;
		const section = input[key];
		if (!isObj(section)) fail(`${path}.${key}`, 'must be an object');
		knownKeys(section, `${path}.${key}`, ['allow', 'deny']);
		const allow = optStrList(section, 'allow', `${path}.${key}`);
		const deny = optStrList(section, 'deny', `${path}.${key}`);
		out[key] = {};
		if (allow) out[key]!.allow = allow.map((s) => s.toLowerCase());
		if (deny) out[key]!.deny = deny.map((s) => s.toLowerCase());
	}
	if (input.body !== undefined) {
		if (!isObj(input.body)) fail(`${path}.body`, 'must be an object');
		const p = `${path}.body`;
		knownKeys(input.body, p, ['allowed', 'maxBytes', 'contentTypes']);
		out.body = {
			allowed: optBool(input.body, 'allowed', p),
			maxBytes: optInt(input.body, 'maxBytes', p),
			contentTypes: optEnumList(input.body, 'contentTypes', p, CONTENT_TYPES),
		};
	}
	if (input.auth !== undefined) {
		if (!isObj(input.auth)) fail(`${path}.auth`, 'must be an object');
		const p = `${path}.auth`;
		knownKeys(input.auth, p, ['required', 'modes', 'credentialTypes']);
		out.auth = {
			required: optBool(input.auth, 'required', p),
			modes: optEnumList(input.auth, 'modes', p, AUTH_MODES),
			credentialTypes: optStrList(input.auth, 'credentialTypes', p),
		};
	}
	if (input.response !== undefined) {
		if (!isObj(input.response)) fail(`${path}.response`, 'must be an object');
		const p = `${path}.response`;
		knownKeys(input.response, p, ['maxBytes', 'allowBinary']);
		out.response = {
			maxBytes: optInt(input.response, 'maxBytes', p),
			allowBinary: optBool(input.response, 'allowBinary', p),
		};
	}
	if (input.options !== undefined) {
		if (!isObj(input.options)) fail(`${path}.options`, 'must be an object');
		const p = `${path}.options`;
		knownKeys(input.options, p, [
			'allowSkipSslVerification', 'maxTimeoutMs', 'allowExpressionsInUrl', 'allowProxy', 'allowIgnoreResponseCode',
		]);
		out.options = {
			allowSkipSslVerification: optBool(input.options, 'allowSkipSslVerification', p),
			maxTimeoutMs: optInt(input.options, 'maxTimeoutMs', p, 1),
			allowExpressionsInUrl: optBool(input.options, 'allowExpressionsInUrl', p),
			allowProxy: optBool(input.options, 'allowProxy', p),
			allowIgnoreResponseCode: optBool(input.options, 'allowIgnoreResponseCode', p),
		};
	}
	if (input.audit !== undefined) {
		if (!isObj(input.audit)) fail(`${path}.audit`, 'must be an object');
		knownKeys(input.audit, `${path}.audit`, ['log']);
		out.audit = { log: optBool(input.audit, 'log', `${path}.audit`) };
	}
	return out;
}

export function parseInstanceConfig(input: unknown): InstanceConfig {
	if (!isObj(input)) fail('config', 'must be an object');
	knownKeys(input, 'config', [
		'version', 'floor', 'policies', 'requirePolicy', 'allowInlinePolicies', 'requireSignedPolicies',
		'signingKeys', 'signingKeyFiles',
	]);
	if (input.version !== 1) fail('config.version', 'must be 1');
	const out: InstanceConfig = { version: 1 };
	if (input.floor !== undefined) out.floor = parsePolicy(input.floor, 'config.floor');
	if (input.policies !== undefined) {
		if (!isObj(input.policies)) fail('config.policies', 'must be an object keyed by policy name');
		out.policies = {};
		for (const [name, value] of Object.entries(input.policies)) {
			if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(name)) fail(`config.policies.${name}`, 'invalid policy name');
			out.policies[name] = parsePolicy(value, `config.policies.${name}`);
		}
	}
	out.requirePolicy = optBool(input, 'requirePolicy', 'config');
	out.allowInlinePolicies = optBool(input, 'allowInlinePolicies', 'config');
	out.requireSignedPolicies = optBool(input, 'requireSignedPolicies', 'config');
	for (const key of ['signingKeys', 'signingKeyFiles'] as const) {
		if (input[key] === undefined) continue;
		const map = input[key];
		if (!isObj(map) || Object.values(map).some((v) => typeof v !== 'string' || v === '')) {
			fail(`config.${key}`, 'must be an object of key id to string');
		}
		out[key] = map as Record<string, string>;
	}
	return out;
}

export function parsePolicyJson(text: string, path = 'policy'): Policy {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch (error) {
		fail(path, `invalid JSON: ${(error as Error).message}`);
	}
	return parsePolicy(parsed, path);
}
