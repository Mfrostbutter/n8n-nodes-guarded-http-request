/** Build the ordered policy layers for one execution from instance config plus the policy credential. */

import type { ResolvedInstanceConfig } from './instance';
import { parsePolicyJson } from './schema';
import { verifyPolicy } from './signing';
import type { PolicyLayer } from './types';

export interface CredentialPolicyData {
	policyName?: string;
	mode?: 'reference' | 'inline';
	policyRef?: string;
	policyJson?: string;
	signature?: string;
}

export interface ResolvedLayers {
	layers: PolicyLayer[];
	errors: string[];
}

export function resolveLayers(config: ResolvedInstanceConfig, credential: CredentialPolicyData | undefined): ResolvedLayers {
	const layers: PolicyLayer[] = [];
	const errors: string[] = [];

	if (config.floor) {
		layers.push({ source: 'instance-floor', name: config.floor.name ?? 'instance-floor', policy: config.floor });
	}

	if (!credential) {
		if (config.requirePolicy) errors.push('this instance requires a Guarded HTTP Policy credential on every request');
		return { layers, errors };
	}

	const mode = credential.mode ?? 'reference';
	const label = credential.policyName?.trim() || undefined;

	if (mode === 'reference') {
		const ref = (credential.policyRef ?? '').trim();
		if (!ref) {
			errors.push('policy credential references no instance policy name');
			return { layers, errors };
		}
		const policy = config.policies?.[ref];
		if (!policy) {
			errors.push(`policy "${ref}" is not defined in the instance configuration`);
			return { layers, errors };
		}
		layers.push({ source: 'instance-policy', name: label ?? ref, policy });
		return { layers, errors };
	}

	if (!config.allowInlinePolicies) {
		errors.push('inline policies are disabled on this instance; the credential must reference a named instance policy');
		return { layers, errors };
	}
	const text = (credential.policyJson ?? '').trim();
	if (!text) {
		errors.push('policy credential has an empty policy document');
		return { layers, errors };
	}
	let parsedRaw: unknown;
	try {
		parsedRaw = JSON.parse(text);
	} catch (error) {
		errors.push(`policy document is not valid JSON: ${(error as Error).message}`);
		return { layers, errors };
	}
	let policy;
	try {
		policy = parsePolicyJson(text, 'policy');
	} catch (error) {
		errors.push((error as Error).message);
		return { layers, errors };
	}
	if (config.requireSignedPolicies) {
		const sig = (credential.signature ?? '').trim();
		if (!sig) {
			errors.push('this instance requires signed policies and the credential carries no signature');
			return { layers, errors };
		}
		const check = verifyPolicy(parsedRaw, sig, config.signingKeyMap);
		if (!check.ok) {
			errors.push(`policy signature rejected: ${check.reason}`);
			return { layers, errors };
		}
	}
	layers.push({ source: 'credential', name: label ?? policy.name ?? 'credential-policy', policy });
	return { layers, errors };
}
