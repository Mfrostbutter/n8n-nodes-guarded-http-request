/** Policy document. Same shape for the instance floor and for a policy credential. */

export type HttpMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS';

export type AuthMode = 'none' | 'predefinedCredentialType' | 'genericCredentialType';

export type ContentType = 'json' | 'form-urlencoded' | 'multipart-form-data' | 'raw' | 'binaryData';

export interface HostRule {
	host: string;
	paths?: string[];
	ports?: number[];
}

export interface Policy {
	version: 1;
	name?: string;
	description?: string;
	methods?: HttpMethod[];
	schemes?: Array<'http' | 'https'>;
	hosts?: {
		allow?: Array<string | HostRule>;
		deny?: string[];
	};
	ports?: number[];
	paths?: {
		allow?: string[];
		deny?: string[];
	};
	network?: {
		blockPrivate?: boolean;
		blockLoopback?: boolean;
		blockLinkLocal?: boolean;
		blockMetadata?: boolean;
		resolveDns?: boolean;
	};
	redirects?: {
		follow?: boolean;
		max?: number;
		sameHostOnly?: boolean;
		forwardAuthCrossHost?: boolean;
	};
	headers?: {
		allow?: string[];
		deny?: string[];
	};
	query?: {
		allow?: string[];
		deny?: string[];
	};
	body?: {
		allowed?: boolean;
		maxBytes?: number;
		contentTypes?: ContentType[];
	};
	auth?: {
		required?: boolean;
		modes?: AuthMode[];
		credentialTypes?: string[];
	};
	response?: {
		maxBytes?: number;
		allowBinary?: boolean;
	};
	options?: {
		allowSkipSslVerification?: boolean;
		maxTimeoutMs?: number;
		allowExpressionsInUrl?: boolean;
		allowProxy?: boolean;
		allowIgnoreResponseCode?: boolean;
	};
	audit?: {
		log?: boolean;
	};
}

/** Instance configuration file. */
export interface InstanceConfig {
	version: 1;
	floor?: Policy;
	policies?: Record<string, Policy>;
	requirePolicy?: boolean;
	allowInlinePolicies?: boolean;
	requireSignedPolicies?: boolean;
	signingKeys?: Record<string, string>;
	signingKeyFiles?: Record<string, string>;
}

/** One named layer of policy. A request must pass every layer. */
export interface PolicyLayer {
	source: 'instance-floor' | 'instance-policy' | 'credential';
	name: string;
	policy: Policy;
}

export interface Violation {
	code: string;
	layer: string;
	message: string;
}

/** The request as seen by the evaluator, after expressions resolved. */
export interface RequestFacts {
	method: string;
	url: string;
	urlIsExpression: boolean;
	headerNames: string[];
	queryNames: string[];
	hasBody: boolean;
	bodyBytes: number;
	contentType?: ContentType;
	authMode: AuthMode;
	credentialType?: string;
	timeoutMs?: number;
	skipSslVerification: boolean;
	usesProxy: boolean;
	ignoreResponseCode: boolean;
	followRedirects: boolean;
	responseFormat: 'autodetect' | 'json' | 'text' | 'file';
}
