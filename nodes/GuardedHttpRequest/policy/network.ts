/** IP classification and DNS resolution guard. Node built-ins only. */

import { promises as dns } from 'node:dns';
import { isIP } from 'node:net';

export type IpClass = 'public' | 'private' | 'loopback' | 'linkLocal' | 'metadata' | 'unspecified';

const METADATA_HOSTS = new Set(['metadata.google.internal', 'metadata', 'instance-data']);

export function isIpLiteral(host: string): boolean {
	return isIP(stripBrackets(host)) !== 0;
}

function stripBrackets(h: string): string {
	return h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
}

function v4ToInt(ip: string): number {
	const parts = ip.split('.').map(Number);
	return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/** Expand an IPv6 address into 8 16-bit groups. Handles "::" and IPv4-mapped tails. */
function v6ToGroups(ip: string): number[] | null {
	let addr = stripBrackets(ip);
	const zone = addr.indexOf('%');
	if (zone !== -1) addr = addr.slice(0, zone);
	if (addr.includes('.')) {
		const lastColon = addr.lastIndexOf(':');
		const v4 = addr.slice(lastColon + 1);
		if (isIP(v4) !== 4) return null;
		const n = v4ToInt(v4);
		addr = addr.slice(0, lastColon + 1) + ((n >>> 16) & 0xffff).toString(16) + ':' + (n & 0xffff).toString(16);
	}
	const halves = addr.split('::');
	if (halves.length > 2) return null;
	const head = halves[0] ? halves[0].split(':') : [];
	const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
	const missing = 8 - head.length - tail.length;
	if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
	const groups = [...head, ...Array(missing).fill('0'), ...tail].map((g) => parseInt(g, 16));
	if (groups.some((g) => Number.isNaN(g) || g < 0 || g > 0xffff)) return null;
	return groups;
}

export function classifyIp(ip: string): IpClass {
	const addr = stripBrackets(ip);
	const kind = isIP(addr);
	if (kind === 4) {
		const n = v4ToInt(addr);
		if (n === 0 || (n >>> 24) === 0) return 'unspecified';
		if ((n >>> 24) === 127) return 'loopback';
		if ((n >>> 16) === 0xa9fe) {
			return n === v4ToInt('169.254.169.254') ? 'metadata' : 'linkLocal';
		}
		if ((n >>> 24) === 10) return 'private';
		if ((n >>> 20) === 0xac1) return 'private';
		if ((n >>> 16) === 0xc0a8) return 'private';
		if ((n >>> 22) === 0x191) return 'private';
		return 'public';
	}
	if (kind === 6) {
		const g = v6ToGroups(addr);
		if (!g) return 'public';
		const allZeroHead = g.slice(0, 5).every((x) => x === 0);
		if (allZeroHead && g[5] === 0xffff) {
			const v4 = [g[6] >>> 8, g[6] & 0xff, g[7] >>> 8, g[7] & 0xff].join('.');
			return classifyIp(v4);
		}
		if (g.every((x) => x === 0)) return 'unspecified';
		if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return 'loopback';
		if (g[0] === 0xfd00 && g[1] === 0xec2 && g.slice(2, 7).every((x) => x === 0) && g[7] === 0x254) return 'metadata';
		if ((g[0] & 0xfe00) === 0xfc00) return 'private';
		if ((g[0] & 0xffc0) === 0xfe80) return 'linkLocal';
		return 'public';
	}
	return 'public';
}

export function isMetadataHost(host: string): boolean {
	return METADATA_HOSTS.has(host.toLowerCase());
}

/** CIDR containment for IPv4 and IPv6. */
export function ipInCidr(ip: string, cidr: string): boolean {
	const [base, bitsStr] = cidr.split('/');
	const bits = Number(bitsStr);
	const addr = stripBrackets(ip);
	if (isIP(addr) === 4 && isIP(base) === 4) {
		if (bits < 0 || bits > 32) return false;
		const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
		return (v4ToInt(addr) & mask) === (v4ToInt(base) & mask);
	}
	if (isIP(addr) === 6 && isIP(base) === 6) {
		if (bits < 0 || bits > 128) return false;
		const a = v6ToGroups(addr);
		const b = v6ToGroups(base);
		if (!a || !b) return false;
		let remaining = bits;
		for (let i = 0; i < 8; i++) {
			const take = Math.min(16, remaining);
			if (take <= 0) break;
			const mask = take === 16 ? 0xffff : (0xffff << (16 - take)) & 0xffff;
			if ((a[i] & mask) !== (b[i] & mask)) return false;
			remaining -= take;
		}
		return true;
	}
	return false;
}

export interface NetworkRules {
	blockPrivate?: boolean;
	blockLoopback?: boolean;
	blockLinkLocal?: boolean;
	blockMetadata?: boolean;
	resolveDns?: boolean;
}

/** Return a reason string when the address class is blocked by the rules, else undefined. */
export function blockedReason(ip: string, rules: NetworkRules): string | undefined {
	const cls = classifyIp(ip);
	if (cls === 'metadata' && rules.blockMetadata !== false) return `cloud metadata address ${ip}`;
	if (cls === 'loopback' && rules.blockLoopback) return `loopback address ${ip}`;
	if (cls === 'linkLocal' && rules.blockLinkLocal) return `link-local address ${ip}`;
	if (cls === 'private' && rules.blockPrivate) return `private network address ${ip}`;
	if (cls === 'unspecified') return `unspecified address ${ip}`;
	return undefined;
}

/**
 * Resolve a hostname and return the first blocked address reason, if any.
 * Checks every A/AAAA answer so a mixed answer set cannot slip a private address through.
 */
export async function resolveAndCheck(hostname: string, rules: NetworkRules): Promise<string | undefined> {
	if (isMetadataHost(hostname) && rules.blockMetadata !== false) return `cloud metadata hostname ${hostname}`;
	if (isIpLiteral(hostname)) return blockedReason(hostname, rules);
	if (!rules.resolveDns) return undefined;
	let addresses: Array<{ address: string }>;
	try {
		addresses = await dns.lookup(hostname, { all: true, verbatim: true });
	} catch (error) {
		return `DNS resolution failed for ${hostname}: ${(error as Error).message}`;
	}
	if (addresses.length === 0) return `DNS returned no addresses for ${hostname}`;
	for (const { address } of addresses) {
		const reason = blockedReason(address, rules);
		if (reason) return `${hostname} resolves to ${reason}`;
	}
	return undefined;
}
