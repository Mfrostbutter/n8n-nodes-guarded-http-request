import type { IExecuteFunctions, INodeExecutionData, INodeType, INodeTypeDescription } from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

import { nodeProperties } from './description';
import { effectiveCaps, summarize } from './policy/evaluate';
import { loadInstanceConfig } from './policy/instance';
import { resolveLayers, type CredentialPolicyData } from './policy/resolve';
import type { AuthMode, PolicyLayer } from './policy/types';
import { buildRequest, checkPolicy, PolicyViolationError, sendWithPolicy, shapeResponse } from './request';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export class GuardedHttpRequest implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Guarded HTTP Request',
		name: 'guardedHttpRequest',
		icon: 'file:guardedHttp.svg',
		group: ['input'],
		version: 1,
		subtitle: '={{ $parameter["operation"] === "inspectPolicy" ? "inspect policy" : $parameter["method"] + " " + $parameter["url"] }}',
		description: 'HTTP request with admin-controlled, RBAC-scoped policies',
		defaults: { name: 'Guarded HTTP Request' },
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		usableAsTool: true,
		credentials: [
			{
				name: 'guardedHttpPolicyApi',
				required: true,
				displayOptions: { show: { policyMode: ['credential'] } },
			},
		],
		properties: nodeProperties,
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const node = this.getNode();
		const operation = this.getNodeParameter('operation', 0) as string;
		const policyMode = this.getNodeParameter('policyMode', 0) as string;

		let config;
		try {
			config = loadInstanceConfig();
		} catch (error) {
			throw new NodeOperationError(node, `Guarded HTTP instance configuration failed to load: ${(error as Error).message}`, {
				description: 'The node fails closed. Fix the file referenced by N8N_GUARDED_HTTP_CONFIG and restart or wait for the reload.',
			});
		}

		let credential: CredentialPolicyData | undefined;
		if (policyMode === 'credential') {
			credential = await this.getCredentials<CredentialPolicyData>('guardedHttpPolicyApi');
		}
		const { layers, errors } = resolveLayers(config, credential);
		if (errors.length > 0) {
			throw new NodeOperationError(node, `Policy not usable: ${errors.join('; ')}`, {
				description: 'Ask an instance admin to share a valid Guarded HTTP Policy credential with this project.',
			});
		}
		const caps = effectiveCaps(layers);

		if (operation === 'inspectPolicy') {
			return [[{ json: { ...summarize(layers), instanceConfigSource: config.source, requirePolicy: config.requirePolicy } }]];
		}

		const authentication = this.getNodeParameter('authentication', 0, 'none') as AuthMode;
		let credentialType: string | undefined;
		if (authentication === 'predefinedCredentialType') credentialType = this.getNodeParameter('nodeCredentialType', 0) as string;
		else if (authentication === 'genericCredentialType') credentialType = this.getNodeParameter('genericAuthType', 0) as string;
		if (credentialType === 'httpDigestAuth') {
			throw new NodeOperationError(node, 'Digest auth is not supported by this node');
		}

		const batch = (this.getNodeParameter('options.batching.batch', 0, {}) as { batchSize?: number; batchInterval?: number }) ?? {};
		const batchSize = batch.batchSize && batch.batchSize > 0 ? batch.batchSize : 0;
		const batchInterval = batch.batchInterval ?? 0;

		const results: INodeExecutionData[] = [];
		for (let i = 0; i < items.length; i++) {
			if (batchSize > 0 && i > 0 && i % batchSize === 0 && batchInterval > 0) await sleep(batchInterval);
			try {
				const built = await buildRequest(this, i, caps, authentication, credentialType);
				await checkPolicy(layers, built.facts, built.target, 'request');
				const sent = await sendWithPolicy(this, layers, caps, built, credentialType);
				const item = await shapeResponse(this, i, built, sent, layers, caps);
				audit(this, layers, built.facts.method, built.target.hostname, built.target.path, sent.response.statusCode, 'allowed', sent.hops);
				results.push(item);
			} catch (error) {
				const err = error as Error;
				if (err instanceof PolicyViolationError) {
					const url = safeUrl(this, i);
					audit(this, layers, this.getNodeParameter('method', i, '') as string, url.host, url.path, undefined, 'blocked', 0, err.violations.map((v) => v.code));
					const wrapped = new NodeOperationError(node, err.message, {
						itemIndex: i,
						description: 'Run "Inspect Effective Policy" on this node to see what is allowed, or ask an instance admin.',
					});
					if (this.continueOnFail()) {
						results.push({ json: { error: wrapped.message, violations: err.violations }, pairedItem: { item: i } });
						continue;
					}
					throw wrapped;
				}
				if (this.continueOnFail()) {
					results.push({ json: { error: err.message }, pairedItem: { item: i } });
					continue;
				}
				if (err instanceof NodeOperationError) throw err;
				throw new NodeOperationError(node, err, { itemIndex: i });
			}
		}
		return [results];
	}
}

function safeUrl(ctx: IExecuteFunctions, i: number): { host: string; path: string } {
	try {
		const u = new URL(ctx.getNodeParameter('url', i, '') as string);
		return { host: u.hostname, path: u.pathname };
	} catch {
		return { host: '', path: '' };
	}
}

function audit(ctx: IExecuteFunctions, layers: PolicyLayer[], method: string, host: string, path: string, status: number | undefined, decision: 'allowed' | 'blocked', hops: number, codes?: string[]): void {
	if (layers.some((l) => l.policy.audit?.log === false)) return;
	const wf = ctx.getWorkflow();
	const policies = layers.map((l) => `${l.source}:${l.name}`);
	const summary = `guarded-http ${decision} ${method} ${host}${path} status=${status ?? '-'} hops=${hops} policies=${policies.join(',')} workflow=${wf.id ?? '-'} execution=${ctx.getExecutionId()}${codes ? ' violations=' + codes.join(',') : ''}`;
	ctx.logger.info(summary, {
		decision,
		method,
		host,
		path,
		status,
		hops,
		violations: codes,
		policies,
		workflowId: wf.id,
		workflowName: wf.name,
		node: ctx.getNode().name,
		executionId: ctx.getExecutionId(),
	});
}
