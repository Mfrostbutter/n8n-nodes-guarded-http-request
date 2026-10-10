/** Instance configuration: loaded from env, cached, reloaded when the file changes. */

import { readFileSync, statSync } from 'node:fs';

import { parseInstanceConfig } from './schema';
import type { InstanceConfig } from './types';

export const ENV_CONFIG_FILE = 'N8N_GUARDED_HTTP_CONFIG';
export const ENV_CONFIG_JSON = 'N8N_GUARDED_HTTP_CONFIG_JSON';
export const ENV_SIGNING_KEY = 'N8N_GUARDED_HTTP_SIGNING_KEY';
export const ENV_REQUIRE_POLICY = 'N8N_GUARDED_HTTP_REQUIRE_POLICY';

interface Cached {
	key: string;
	mtimeMs: number;
	config: InstanceConfig;
}

let cache: Cached | undefined;

export interface ResolvedInstanceConfig extends InstanceConfig {
	source: 'file' | 'env' | 'none';
	signingKeyMap: Record<string, string>;
}

function parseBool(v: string | undefined): boolean | undefined {
	if (v === undefined || v === '') return undefined;
	return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}

function loadRaw(env: NodeJS.ProcessEnv): { config: InstanceConfig; source: 'file' | 'env' | 'none' } {
	const file = env[ENV_CONFIG_FILE];
	if (file) {
		const st = statSync(file);
		if (cache && cache.key === file && cache.mtimeMs === st.mtimeMs) {
			return { config: cache.config, source: 'file' };
		}
		const text = readFileSync(file, 'utf8');
		const config = parseInstanceConfig(JSON.parse(text));
		cache = { key: file, mtimeMs: st.mtimeMs, config };
		return { config, source: 'file' };
	}
	const inline = env[ENV_CONFIG_JSON];
	if (inline) {
		if (cache && cache.key === inline) return { config: cache.config, source: 'env' };
		const config = parseInstanceConfig(JSON.parse(inline));
		cache = { key: inline, mtimeMs: 0, config };
		return { config, source: 'env' };
	}
	return { config: { version: 1 }, source: 'none' };
}

/** Load the instance config. Throws on a malformed file so a bad deploy fails closed. */
export function loadInstanceConfig(env: NodeJS.ProcessEnv = process.env): ResolvedInstanceConfig {
	const { config, source } = loadRaw(env);
	const signingKeyMap: Record<string, string> = { ...(config.signingKeys ?? {}) };
	for (const [id, path] of Object.entries(config.signingKeyFiles ?? {})) {
		signingKeyMap[id] = readFileSync(path, 'utf8').trim();
	}
	const envKey = env[ENV_SIGNING_KEY];
	if (envKey) {
		const idx = envKey.indexOf(':');
		if (idx > 0) signingKeyMap[envKey.slice(0, idx)] = envKey.slice(idx + 1);
		else signingKeyMap.default = envKey;
	}
	const requireFromEnv = parseBool(env[ENV_REQUIRE_POLICY]);
	const hasKeys = Object.keys(signingKeyMap).length > 0;
	return {
		...config,
		requirePolicy: requireFromEnv ?? config.requirePolicy ?? false,
		allowInlinePolicies: config.allowInlinePolicies ?? true,
		requireSignedPolicies: config.requireSignedPolicies ?? hasKeys,
		source,
		signingKeyMap,
	};
}

export function resetInstanceConfigCache(): void {
	cache = undefined;
}
