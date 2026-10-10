/** Evaluate request facts against every policy layer. A request must pass all layers. */

import { hostMatches, pathMatches, splitHostPort } from './hostmatch';
import { resolveAndCheck } from './network';
import type { HostRule, Policy, PolicyLayer, RequestFacts, Violation } from './types';

export interface ParsedTarget {
	url: URL;
	scheme: 'http' | 'https';
	hostname: string;
	port: number;
	path: string;
}

export function parseTarget(raw: string): ParsedTarget | string {
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		return `URL "${raw}" is not an absolute URL`;
	}
	const scheme = url.protocol.replace(':', '');
	if (scheme !== 'http' && scheme !== 'https') return `scheme "${scheme}" is not http or https`;
	if (url.username || url.password) return 'URL must not carry user info';
	const hostname = url.hostname.toLowerCase();
	if (!hostname) return 'URL has no host';
	const port = url.port ? Number(url.port) : scheme === 'https' ? 443 : 80;
	return { url, scheme, hostname, port, path: url.pathname };
}

function hostRuleMatches(target: ParsedTarget, entry: string | HostRule): boolean {
	const rule: HostRule = typeof entry === 'string' ? { host: entry } : entry;
	const { host, port } = splitHostPort(rule.host);
	if (!hostMatches(target.hostname, host)) return false;
	if (port !== undefined && port !== target.port) return false;
	if (rule.ports && !rule.ports.includes(target.port)) return false;
	if (rule.paths && rule.paths.length > 0 && !rule.paths.some((p) => pathMatches(target.path, p))) return false;
	return true;
}

/** Synchronous checks: everything except DNS. */
export function evaluateLayer(policy: Policy, layer: string, facts: RequestFacts, target: ParsedTarget): Violation[] {
	const v: Violation[] = [];
	const add = (code: string, message: string) => v.push({ code, layer, message });

	if (policy.methods && !policy.methods.includes(facts.method.toUpperCase() as never)) {
		add('method', `method ${facts.method} is not allowed (allowed: ${policy.methods.join(', ')})`);
	}
	if (policy.schemes && !policy.schemes.includes(target.scheme)) {
		add('scheme', `scheme ${target.scheme} is not allowed (allowed: ${policy.schemes.join(', ')})`);
	}
	if (policy.hosts?.deny) {
		for (const pattern of policy.hosts.deny) {
			const { host, port } = splitHostPort(pattern);
			if (hostMatches(target.hostname, host) && (port === undefined || port === target.port)) {
				add('host-denied', `host ${target.hostname} is denied by pattern ${pattern}`);
				break;
			}
		}
	}
	if (policy.hosts?.allow) {
		if (!policy.hosts.allow.some((entry) => hostRuleMatches(target, entry))) {
			add('host', `host ${target.hostname}:${target.port}${target.path} does not match any allowed host rule`);
		}
	}
	if (policy.ports && !policy.ports.includes(target.port)) {
		add('port', `port ${target.port} is not allowed (allowed: ${policy.ports.join(', ')})`);
	}
	if (policy.paths?.deny?.some((p) => pathMatches(target.path, p))) {
		add('path-denied', `path ${target.path} is denied`);
	}
	if (policy.paths?.allow && !policy.paths.allow.some((p) => pathMatches(target.path, p))) {
		add('path', `path ${target.path} does not match any allowed path`);
	}
	if (policy.options?.allowExpressionsInUrl === false && facts.urlIsExpression) {
		add('url-expression', 'URL must be a static value; expressions in the URL are not allowed');
	}
	if (policy.headers) {
		for (const name of facts.headerNames) {
			const n = name.toLowerCase();
			if (policy.headers.deny?.includes(n)) add('header-denied', `header "${name}" is not allowed`);
			else if (policy.headers.allow && !policy.headers.allow.includes(n)) add('header', `header "${name}" is not in the allowed list`);
		}
	}
	if (policy.query) {
		for (const name of facts.queryNames) {
			const n = name.toLowerCase();
			if (policy.query.deny?.includes(n)) add('query-denied', `query parameter "${name}" is not allowed`);
			else if (policy.query.allow && !policy.query.allow.includes(n)) add('query', `query parameter "${name}" is not in the allowed list`);
		}
	}
	if (facts.hasBody) {
		if (policy.body?.allowed === false) add('body', 'request bodies are not allowed');
		if (policy.body?.maxBytes !== undefined && facts.bodyBytes > policy.body.maxBytes) {
			add('body-size', `body of ${facts.bodyBytes} bytes exceeds the limit of ${policy.body.maxBytes}`);
		}
		if (policy.body?.contentTypes && facts.contentType && !policy.body.contentTypes.includes(facts.contentType)) {
			add('body-content-type', `body content type ${facts.contentType} is not allowed`);
		}
	}
	if (policy.auth) {
		if (policy.auth.required && facts.authMode === 'none') add('auth-required', 'a credential is required');
		if (policy.auth.modes && !policy.auth.modes.includes(facts.authMode)) {
			add('auth-mode', `authentication mode ${facts.authMode} is not allowed`);
		}
		if (policy.auth.credentialTypes && facts.credentialType && !policy.auth.credentialTypes.includes(facts.credentialType)) {
			add('auth-type', `credential type ${facts.credentialType} is not allowed`);
		}
	}
	if (policy.response?.allowBinary === false && facts.responseFormat === 'file') {
		add('response-binary', 'binary (file) responses are not allowed');
	}
	if (policy.options) {
		const o = policy.options;
		if (o.allowSkipSslVerification === false && facts.skipSslVerification) add('ssl', 'skipping SSL verification is not allowed');
		if (o.allowProxy === false && facts.usesProxy) add('proxy', 'custom proxies are not allowed');
		if (o.allowIgnoreResponseCode === false && facts.ignoreResponseCode) add('ignore-status', 'ignoring response codes is not allowed');
		if (o.maxTimeoutMs !== undefined && facts.timeoutMs !== undefined && facts.timeoutMs > o.maxTimeoutMs) {
			add('timeout', `timeout ${facts.timeoutMs}ms exceeds the limit of ${o.maxTimeoutMs}ms`);
		}
	}
	if (policy.redirects?.follow === false && facts.followRedirects) {
		add('redirects', 'following redirects is not allowed');
	}
	return v;
}

export function evaluate(layers: PolicyLayer[], facts: RequestFacts, target: ParsedTarget): Violation[] {
	const out: Violation[] = [];
	for (const layer of layers) out.push(...evaluateLayer(layer.policy, layer.name, facts, target));
	return out;
}

/** DNS and address-class checks, using the strictest network rules across layers. */
export async function evaluateNetwork(layers: PolicyLayer[], target: ParsedTarget): Promise<Violation | undefined> {
	const rules = effectiveNetworkRules(layers);
	const reason = await resolveAndCheck(target.hostname, rules);
	if (reason) return { code: 'network', layer: 'effective', message: reason };
	return undefined;
}

export function effectiveNetworkRules(layers: PolicyLayer[]): Required<NonNullable<Policy['network']>> {
	const r = { blockPrivate: false, blockLoopback: false, blockLinkLocal: false, blockMetadata: true, resolveDns: false };
	for (const { policy } of layers) {
		const n = policy.network;
		if (!n) continue;
		r.blockPrivate = r.blockPrivate || n.blockPrivate === true;
		r.blockLoopback = r.blockLoopback || n.blockLoopback === true;
		r.blockLinkLocal = r.blockLinkLocal || n.blockLinkLocal === true;
		r.resolveDns = r.resolveDns || n.resolveDns === true;
	}
	// Metadata stays blocked unless every layer explicitly opts out.
	if (layers.length > 0 && layers.every((l) => l.policy.network?.blockMetadata === false)) r.blockMetadata = false;
	return r;
}

/** Numeric caps and flags collapsed across layers, for the request sender and the policy summary. */
export interface EffectiveCaps {
	maxRedirects: number;
	followRedirects: boolean;
	sameHostOnly: boolean;
	forwardAuthCrossHost: boolean;
	maxResponseBytes?: number;
	maxBodyBytes?: number;
	maxTimeoutMs?: number;
	auditLog: boolean;
}

export function effectiveCaps(layers: PolicyLayer[]): EffectiveCaps {
	const caps: EffectiveCaps = {
		maxRedirects: 5,
		followRedirects: true,
		sameHostOnly: false,
		forwardAuthCrossHost: false,
		auditLog: true,
	};
	for (const { policy } of layers) {
		const r = policy.redirects;
		if (r) {
			if (r.max !== undefined) caps.maxRedirects = Math.min(caps.maxRedirects, r.max);
			if (r.follow === false) caps.followRedirects = false;
			if (r.sameHostOnly) caps.sameHostOnly = true;
			if (r.forwardAuthCrossHost === true) caps.forwardAuthCrossHost = true;
		}
		if (policy.response?.maxBytes !== undefined) {
			caps.maxResponseBytes = Math.min(caps.maxResponseBytes ?? Infinity, policy.response.maxBytes);
		}
		if (policy.body?.maxBytes !== undefined) {
			caps.maxBodyBytes = Math.min(caps.maxBodyBytes ?? Infinity, policy.body.maxBytes);
		}
		if (policy.options?.maxTimeoutMs !== undefined) {
			caps.maxTimeoutMs = Math.min(caps.maxTimeoutMs ?? Infinity, policy.options.maxTimeoutMs);
		}
		if (policy.audit?.log === false) caps.auditLog = false;
	}
	if (layers.some((l) => l.policy.redirects?.forwardAuthCrossHost === false)) caps.forwardAuthCrossHost = false;
	return caps;
}

/** Human-readable summary of what the layers allow. No secrets involved. */
export function summarize(layers: PolicyLayer[]) {
	const intersect = <T>(pick: (p: Policy) => T[] | undefined): T[] | 'any' => {
		let acc: T[] | undefined;
		for (const { policy } of layers) {
			const list = pick(policy);
			if (!list) continue;
			acc = acc ? acc.filter((x) => list.includes(x)) : [...list];
		}
		return acc ?? 'any';
	};
	return {
		layers: layers.map((l) => ({ source: l.source, name: l.name, description: l.policy.description })),
		methods: intersect((p) => p.methods),
		schemes: intersect((p) => p.schemes),
		hosts: layers.map((l) => ({ layer: l.name, allow: l.policy.hosts?.allow ?? 'any', deny: l.policy.hosts?.deny ?? [] })),
		paths: layers.map((l) => ({ layer: l.name, allow: l.policy.paths?.allow ?? 'any', deny: l.policy.paths?.deny ?? [] })),
		network: effectiveNetworkRules(layers),
		caps: effectiveCaps(layers),
		authModes: intersect((p) => p.auth?.modes),
		credentialTypes: intersect((p) => p.auth?.credentialTypes),
		bodyContentTypes: intersect((p) => p.body?.contentTypes),
		bodyAllowed: !layers.some((l) => l.policy.body?.allowed === false),
		binaryResponses: !layers.some((l) => l.policy.response?.allowBinary === false),
		expressionsInUrl: !layers.some((l) => l.policy.options?.allowExpressionsInUrl === false),
	};
}
