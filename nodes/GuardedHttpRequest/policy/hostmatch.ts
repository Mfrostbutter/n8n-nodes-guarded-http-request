/** Hostname and path pattern matching. No regex construction from user input. */

import { ipInCidr, isIpLiteral } from './network';

/** Split an optional ":port" suffix off a host pattern. */
export function splitHostPort(pattern: string): { host: string; port?: number } {
	const p = pattern.trim().toLowerCase();
	if (p.startsWith('[')) {
		const end = p.indexOf(']');
		if (end === -1) return { host: p };
		const host = p.slice(1, end);
		const rest = p.slice(end + 1);
		if (rest.startsWith(':')) return { host, port: Number(rest.slice(1)) };
		return { host };
	}
	if (p.includes('/')) return { host: p };
	const idx = p.lastIndexOf(':');
	if (idx === -1 || p.indexOf(':') !== idx) return { host: p };
	return { host: p.slice(0, idx), port: Number(p.slice(idx + 1)) };
}

/**
 * Match a hostname against a pattern.
 * - exact: api.example.com
 * - wildcard: *.example.com (one or more leading labels, not the apex)
 * - CIDR: 10.0.0.0/8 (hostname must be an IP literal)
 * - "*" alone matches any host.
 */
export function hostMatches(hostname: string, pattern: string): boolean {
	const h = hostname.toLowerCase().replace(/\.$/, '');
	const p = pattern.toLowerCase().replace(/\.$/, '');
	if (p === '*') return true;
	if (p.includes('/')) {
		return isIpLiteral(h) ? ipInCidr(h, p) : false;
	}
	if (p.startsWith('*.')) {
		const suffix = p.slice(1);
		return h.length > suffix.length && h.endsWith(suffix);
	}
	return h === p;
}

/** Match a path against a glob: "*" = one segment, "**" = any depth. Trailing "/" is ignored. */
export function pathMatches(path: string, pattern: string): boolean {
	const segs = normalizePath(path).split('/').filter((s) => s.length > 0);
	const pats = normalizePath(pattern).split('/').filter((s) => s.length > 0);
	return matchSegments(segs, 0, pats, 0);
}

function matchSegments(segs: string[], si: number, pats: string[], pi: number): boolean {
	if (pi === pats.length) return si === segs.length;
	const pat = pats[pi];
	if (pat === '**') {
		for (let k = si; k <= segs.length; k++) {
			if (matchSegments(segs, k, pats, pi + 1)) return true;
		}
		return false;
	}
	if (si === segs.length) return false;
	if (!segmentMatches(segs[si], pat)) return false;
	return matchSegments(segs, si + 1, pats, pi + 1);
}

function segmentMatches(seg: string, pat: string): boolean {
	if (pat === '*') return true;
	if (!pat.includes('*')) return seg === pat;
	const parts = pat.split('*');
	let pos = 0;
	for (let i = 0; i < parts.length; i++) {
		const part = parts[i];
		if (part === '') continue;
		const idx = seg.indexOf(part, pos);
		if (idx === -1) return false;
		if (i === 0 && idx !== 0) return false;
		pos = idx + part.length;
	}
	const last = parts[parts.length - 1];
	if (last !== '' && !seg.endsWith(last)) return false;
	return true;
}

function normalizePath(p: string): string {
	let out = p.trim();
	if (!out.startsWith('/')) out = '/' + out;
	if (out.length > 1 && out.endsWith('/')) out = out.slice(0, -1);
	return out;
}
