/** Build, send and shape one request under policy. */

import type { IDataObject, IExecuteFunctions, IHttpRequestMethods, IHttpRequestOptions, INodeExecutionData } from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';

import { evaluate, evaluateNetwork, parseTarget, type EffectiveCaps, type ParsedTarget } from './policy/evaluate';
import type { AuthMode, ContentType, PolicyLayer, RequestFacts, Violation } from './policy/types';

export class PolicyViolationError extends Error {
	constructor(public readonly violations: Violation[], public readonly stage: string) {
		super(`Request blocked by policy (${stage}): ` + violations.map((v) => `[${v.layer}] ${v.message}`).join('; '));
		this.name = 'PolicyViolationError';
	}
}

interface KeyValue {
	name: string;
	value: string;
}

interface RequestOptions {
	batching?: { batch?: { batchSize?: number; batchInterval?: number } };
	allowUnauthorizedCerts?: boolean;
	includePolicyInfo?: boolean;
	proxy?: string;
	redirect?: { redirect?: { followRedirects?: boolean; maxRedirects?: number } };
	response?: {
		response?: { fullResponse?: boolean; neverError?: boolean; responseFormat?: RequestFacts['responseFormat']; outputPropertyName?: string };
	};
	timeout?: number;
}

export interface BuiltRequest {
	facts: RequestFacts;
	target: ParsedTarget;
	options: IHttpRequestOptions;
	settings: {
		fullResponse: boolean;
		neverError: boolean;
		responseFormat: RequestFacts['responseFormat'];
		outputPropertyName: string;
		followRedirects: boolean;
		maxRedirects: number;
		includePolicyInfo: boolean;
	};
}

function parseJsonParam(ctx: IExecuteFunctions, name: string, i: number): IDataObject {
	const raw = ctx.getNodeParameter(name, i, {}) as unknown;
	if (raw === '' || raw === undefined || raw === null) return {};
	let value: unknown = raw;
	if (typeof raw === 'string') {
		try {
			value = JSON.parse(raw);
		} catch (error) {
			throw new NodeOperationError(ctx.getNode(), `Parameter "${name}" is not valid JSON: ${(error as Error).message}`, { itemIndex: i });
		}
	}
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		throw new NodeOperationError(ctx.getNode(), `Parameter "${name}" must be a JSON object`, { itemIndex: i });
	}
	return value as IDataObject;
}

function keyValues(ctx: IExecuteFunctions, name: string, i: number): IDataObject {
	const col = ctx.getNodeParameter(name, i, {}) as { parameters?: KeyValue[] };
	const out: IDataObject = {};
	for (const kv of col.parameters ?? []) {
		if (!kv.name) continue;
		out[kv.name] = kv.value;
	}
	return out;
}

function parseProxy(ctx: IExecuteFunctions, raw: string, i: number): IHttpRequestOptions['proxy'] {
	let u: URL;
	try {
		u = new URL(raw);
	} catch {
		throw new NodeOperationError(ctx.getNode(), `Proxy "${raw}" is not a valid URL`, { itemIndex: i });
	}
	const proxy: NonNullable<IHttpRequestOptions['proxy']> = {
		host: u.hostname,
		port: u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80,
		protocol: u.protocol.replace(':', ''),
	};
	if (u.username) proxy.auth = { username: decodeURIComponent(u.username), password: decodeURIComponent(u.password) };
	return proxy;
}

export async function buildRequest(ctx: IExecuteFunctions, i: number, caps: EffectiveCaps, authMode: AuthMode, credentialType?: string): Promise<BuiltRequest> {
	const node = ctx.getNode();
	const method = (ctx.getNodeParameter('method', i) as string).toUpperCase() as IHttpRequestMethods;
	const url = (ctx.getNodeParameter('url', i) as string).trim();
	const rawUrl = node.parameters.url;
	const urlIsExpression = typeof rawUrl === 'string' && rawUrl.startsWith('=');
	const opts = ctx.getNodeParameter('options', i, {}) as RequestOptions;

	const headers: IDataObject = {};
	if (ctx.getNodeParameter('sendHeaders', i, false)) {
		const mode = ctx.getNodeParameter('specifyHeaders', i, 'keypair');
		Object.assign(headers, mode === 'json' ? parseJsonParam(ctx, 'jsonHeaders', i) : keyValues(ctx, 'headerParameters', i));
	}
	const qs: IDataObject = {};
	if (ctx.getNodeParameter('sendQuery', i, false)) {
		const mode = ctx.getNodeParameter('specifyQuery', i, 'keypair');
		Object.assign(qs, mode === 'json' ? parseJsonParam(ctx, 'jsonQuery', i) : keyValues(ctx, 'queryParameters', i));
	}

	let body: IHttpRequestOptions['body'];
	let bodyBytes = 0;
	let contentType: ContentType | undefined;
	let json = false;
	const hasBody = ctx.getNodeParameter('sendBody', i, false) as boolean;
	if (hasBody) {
		contentType = ctx.getNodeParameter('contentType', i, 'json') as ContentType;
		if (contentType === 'json' || contentType === 'form-urlencoded') {
			const mode = ctx.getNodeParameter('specifyBody', i, 'keypair');
			const data = mode === 'json' ? parseJsonParam(ctx, 'jsonBody', i) : keyValues(ctx, 'bodyParameters', i);
			if (contentType === 'json') {
				body = data;
				json = true;
				bodyBytes = Buffer.byteLength(JSON.stringify(data));
			} else {
				const params = new URLSearchParams();
				for (const [k, v] of Object.entries(data)) params.append(k, typeof v === 'string' ? v : JSON.stringify(v));
				body = params;
				bodyBytes = Buffer.byteLength(params.toString());
			}
		} else if (contentType === 'multipart-form-data') {
			const fd = new FormData();
			const col = ctx.getNodeParameter('multipartParameters', i, {}) as {
				parameters?: Array<{ parameterType: string; name: string; value?: string; inputDataFieldName?: string }>;
			};
			for (const field of col.parameters ?? []) {
				if (!field.name) continue;
				if (field.parameterType === 'formBinaryData') {
					const prop = field.inputDataFieldName || 'data';
					const meta = ctx.helpers.assertBinaryData(i, prop);
					const buf = await ctx.helpers.getBinaryDataBuffer(i, prop);
					bodyBytes += buf.length;
					fd.append(field.name, new Blob([new Uint8Array(buf)], { type: meta.mimeType }), meta.fileName ?? prop);
				} else {
					const v = field.value ?? '';
					bodyBytes += Buffer.byteLength(v);
					fd.append(field.name, v);
				}
			}
			body = fd;
		} else if (contentType === 'raw') {
			const raw = ctx.getNodeParameter('rawBody', i, '') as string;
			const ct = (ctx.getNodeParameter('rawContentType', i, '') as string).trim();
			if (ct) headers['content-type'] = ct;
			body = raw;
			bodyBytes = Buffer.byteLength(raw);
		} else if (contentType === 'binaryData') {
			const prop = ctx.getNodeParameter('inputDataFieldName', i, 'data') as string;
			const meta = ctx.helpers.assertBinaryData(i, prop);
			const buf = await ctx.helpers.getBinaryDataBuffer(i, prop);
			if (!Object.keys(headers).some((h) => h.toLowerCase() === 'content-type')) headers['content-type'] = meta.mimeType;
			body = buf;
			bodyBytes = buf.length;
		}
	}

	const redirect = opts.redirect?.redirect ?? {};
	const response = opts.response?.response ?? {};
	const userTimeout = opts.timeout;
	const timeout = userTimeout ?? (caps.maxTimeoutMs !== undefined ? Math.min(30000, caps.maxTimeoutMs) : 30000);
	const skipSsl = opts.allowUnauthorizedCerts === true;
	const proxyRaw = (opts.proxy ?? '').trim();

	const facts: RequestFacts = {
		method,
		url,
		urlIsExpression,
		headerNames: Object.keys(headers),
		queryNames: Object.keys(qs),
		hasBody,
		bodyBytes,
		contentType,
		authMode,
		credentialType,
		timeoutMs: userTimeout,
		skipSslVerification: skipSsl,
		usesProxy: proxyRaw !== '',
		ignoreResponseCode: response.neverError === true,
		followRedirects: redirect.followRedirects !== false,
		responseFormat: response.responseFormat ?? 'autodetect',
	};

	const target = parseTarget(url);
	if (typeof target === 'string') {
		throw new PolicyViolationError([{ code: 'url', layer: 'request', message: target }], 'url');
	}
	// The URL object normalizes the target; the request uses the normalized form so checks and sends agree.
	const options: IHttpRequestOptions = {
		method,
		url: target.url.toString(),
		headers,
		qs,
		body,
		json,
		timeout,
		skipSslCertificateValidation: skipSsl,
		disableFollowRedirect: true,
		returnFullResponse: true,
		ignoreHttpStatusErrors: true,
		encoding: 'arraybuffer',
	};
	if (proxyRaw) options.proxy = parseProxy(ctx, proxyRaw, i);

	return {
		facts,
		target,
		options,
		settings: {
			fullResponse: response.fullResponse === true,
			neverError: response.neverError === true,
			responseFormat: facts.responseFormat,
			outputPropertyName: response.outputPropertyName || 'data',
			followRedirects: facts.followRedirects,
			maxRedirects: redirect.maxRedirects ?? 5,
			includePolicyInfo: opts.includePolicyInfo === true,
		},
	};
}

export async function checkPolicy(layers: PolicyLayer[], facts: RequestFacts, target: ParsedTarget, stage: string): Promise<void> {
	const violations = evaluate(layers, facts, target);
	if (violations.length > 0) throw new PolicyViolationError(violations, stage);
	const net = await evaluateNetwork(layers, target);
	if (net) throw new PolicyViolationError([net], stage);
}

interface RawResponse {
	body: unknown;
	headers: Record<string, string | string[] | undefined>;
	statusCode: number;
	statusMessage?: string;
}

export interface SendResult {
	response: RawResponse;
	hops: number;
	finalUrl: string;
}

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

async function doRequest(ctx: IExecuteFunctions, options: IHttpRequestOptions, credentialType?: string): Promise<RawResponse> {
	if (credentialType) {
		return (await ctx.helpers.httpRequestWithAuthentication.call(ctx, credentialType, options)) as RawResponse;
	}
	return (await ctx.helpers.httpRequest(options)) as RawResponse;
}

function headerValue(headers: RawResponse['headers'], name: string): string | undefined {
	const v = headers?.[name] ?? headers?.[name.toLowerCase()];
	return Array.isArray(v) ? v[0] : v;
}

/** Send with manual redirect handling. Every hop is re-checked against policy. */
export async function sendWithPolicy(ctx: IExecuteFunctions, layers: PolicyLayer[], caps: EffectiveCaps, built: BuiltRequest, credentialType?: string): Promise<SendResult> {
	let options = { ...built.options };
	let current = built.target;
	let facts = { ...built.facts };
	let auth = credentialType;
	let hops = 0;
	const follow = built.settings.followRedirects && caps.followRedirects;
	const maxRedirects = Math.min(built.settings.maxRedirects, caps.maxRedirects);

	for (;;) {
		const response = await doRequest(ctx, options, auth);
		if (!follow || !REDIRECT_CODES.has(response.statusCode)) {
			return { response, hops, finalUrl: current.url.toString() };
		}
		const location = headerValue(response.headers, 'location');
		if (!location) return { response, hops, finalUrl: current.url.toString() };
		if (hops >= maxRedirects) {
			throw new PolicyViolationError([{ code: 'redirects', layer: 'effective', message: `more than ${maxRedirects} redirects` }], 'redirect');
		}
		let nextRaw: string;
		try {
			nextRaw = new URL(location, current.url).toString();
		} catch {
			throw new PolicyViolationError([{ code: 'redirects', layer: 'request', message: `invalid redirect location "${location}"` }], 'redirect');
		}
		const next = parseTarget(nextRaw);
		if (typeof next === 'string') throw new PolicyViolationError([{ code: 'redirects', layer: 'request', message: next }], 'redirect');
		if (caps.sameHostOnly && next.hostname !== built.target.hostname) {
			throw new PolicyViolationError([{ code: 'redirects', layer: 'effective', message: `redirect to ${next.hostname} leaves the original host` }], 'redirect');
		}
		const code = response.statusCode;
		const switchToGet = code === 303 || ((code === 301 || code === 302) && facts.method !== 'GET' && facts.method !== 'HEAD');
		const nextMethod = (switchToGet ? 'GET' : facts.method) as IHttpRequestMethods;
		facts = { ...facts, method: nextMethod, url: next.url.toString(), hasBody: switchToGet ? false : facts.hasBody };
		await checkPolicy(layers, facts, next, `redirect hop ${hops + 1}`);

		const crossHost = next.hostname !== built.target.hostname;
		if (crossHost && !caps.forwardAuthCrossHost) {
			auth = undefined;
			const headers = { ...(options.headers ?? {}) };
			for (const h of Object.keys(headers)) {
				if (['authorization', 'cookie', 'proxy-authorization'].includes(h.toLowerCase())) delete headers[h];
			}
			options.headers = headers;
		}
		options = {
			...options,
			url: next.url.toString(),
			method: nextMethod,
			body: switchToGet ? undefined : options.body,
			json: switchToGet ? false : options.json,
			qs: {},
		};
		current = next;
		hops++;
	}
}

function toBuffer(body: unknown): Buffer {
	if (Buffer.isBuffer(body)) return body;
	if (body instanceof ArrayBuffer) return Buffer.from(body);
	if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
	if (typeof body === 'string') return Buffer.from(body);
	if (body === undefined || body === null) return Buffer.alloc(0);
	return Buffer.from(JSON.stringify(body));
}

export async function shapeResponse(ctx: IExecuteFunctions, i: number, built: BuiltRequest, sent: SendResult, layers: PolicyLayer[], caps: EffectiveCaps): Promise<INodeExecutionData> {
	const { response } = sent;
	const buf = toBuffer(response.body);
	if (caps.maxResponseBytes !== undefined && buf.length > caps.maxResponseBytes) {
		throw new PolicyViolationError(
			[{ code: 'response-size', layer: 'effective', message: `response of ${buf.length} bytes exceeds the limit of ${caps.maxResponseBytes}` }],
			'response',
		);
	}
	const status = response.statusCode;
	const contentType = (headerValue(response.headers, 'content-type') ?? '').toLowerCase();
	let format = built.settings.responseFormat;
	if (format === 'autodetect') {
		if (contentType.includes('json')) format = 'json';
		else if (contentType.startsWith('text/') || contentType.includes('xml') || contentType.includes('javascript') || contentType === '') format = 'text';
		else format = 'file';
	}
	const binaryAllowed = !layers.some((l) => l.policy.response?.allowBinary === false);
	if (format === 'file' && !binaryAllowed) {
		throw new PolicyViolationError([{ code: 'response-binary', layer: 'effective', message: `binary response (${contentType || 'unknown type'}) is not allowed` }], 'response');
	}

	const text = format === 'file' ? '' : buf.toString('utf8');
	let bodyOut: unknown;
	if (format === 'json') {
		try {
			bodyOut = text.length ? JSON.parse(text) : null;
		} catch {
			if (built.settings.responseFormat === 'json') {
				throw new NodeOperationError(ctx.getNode(), 'Response is not valid JSON', { itemIndex: i, description: text.slice(0, 500) });
			}
			bodyOut = text;
			format = 'text';
		}
	} else if (format === 'text') {
		bodyOut = text;
	}

	if (!built.settings.neverError && status >= 400) {
		throw new NodeOperationError(ctx.getNode(), `Request failed with status ${status}${response.statusMessage ? ' ' + response.statusMessage : ''}`, {
			itemIndex: i,
			description: format === 'file' ? `${buf.length} bytes, ${contentType}` : text.slice(0, 1000),
		});
	}

	const field = built.settings.outputPropertyName;
	const item: INodeExecutionData = { json: {}, pairedItem: { item: i } };
	if (format === 'file') {
		item.binary = { [field]: await ctx.helpers.prepareBinaryData(buf, undefined, contentType.split(';')[0] || undefined) };
	}
	if (built.settings.fullResponse) {
		item.json = {
			body: format === 'file' ? undefined : (bodyOut as IDataObject),
			headers: response.headers as IDataObject,
			statusCode: status,
			statusMessage: response.statusMessage,
		};
	} else if (format === 'json' && typeof bodyOut === 'object' && bodyOut !== null && !Array.isArray(bodyOut)) {
		item.json = bodyOut as IDataObject;
	} else if (format !== 'file') {
		item.json = { [field]: bodyOut as never };
	}
	if (built.settings.includePolicyInfo) {
		item.json._guardedHttp = { policies: layers.map((l) => l.name), hops: sent.hops, finalUrl: sent.finalUrl, statusCode: status };
	}
	return item;
}
