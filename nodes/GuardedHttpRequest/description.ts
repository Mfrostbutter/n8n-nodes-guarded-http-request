import type { INodeProperties } from 'n8n-workflow';

const requestOnly = { show: { operation: ['request'] } };

const keyValueCollection = (name: string, placeholder: string, show: Record<string, unknown>): INodeProperties => ({
	displayName: placeholder.replace('Add ', '') + 's',
	name,
	type: 'fixedCollection',
	typeOptions: { multipleValues: true },
	placeholder,
	default: { parameters: [{ name: '', value: '' }] },
	displayOptions: { show: { operation: ['request'], ...show } },
	options: [
		{
			name: 'parameters',
			displayName: 'Parameter',
			values: [
				{ displayName: 'Name', name: 'name', type: 'string', default: '' },
				{ displayName: 'Value', name: 'value', type: 'string', default: '' },
			],
		},
	],
});

export const nodeProperties: INodeProperties[] = [
	{
		displayName:
			'Requests are checked against the instance floor and the selected policy before they are sent. Run "Inspect Effective Policy" to see what this node may do.',
		name: 'policyNotice',
		type: 'notice',
		default: '',
	},
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		default: 'request',
		options: [
			{ name: 'Send Request', value: 'request', action: 'Send an HTTP request' },
			{ name: 'Inspect Effective Policy', value: 'inspectPolicy', action: 'Inspect the effective policy' },
		],
	},
	{
		displayName: 'Policy',
		name: 'policyMode',
		type: 'options',
		noDataExpression: true,
		default: 'credential',
		options: [
			{ name: 'Policy Credential', value: 'credential', description: 'Instance floor plus a policy credential shared to this project' },
			{ name: 'Instance Floor Only', value: 'instanceOnly', description: 'Only the instance-wide floor applies. Rejected if the instance requires a policy.' },
		],
	},
	{
		displayName: 'Method',
		name: 'method',
		type: 'options',
		default: 'GET',
		displayOptions: requestOnly,
		options: ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT'].map((m) => ({ name: m, value: m })),
	},
	{
		displayName: 'URL',
		name: 'url',
		type: 'string',
		default: '',
		required: true,
		placeholder: 'https://api.example.com/v1/resource',
		displayOptions: requestOnly,
	},
	{
		displayName: 'Authentication',
		name: 'authentication',
		type: 'options',
		noDataExpression: true,
		default: 'none',
		displayOptions: requestOnly,
		options: [
			{ name: 'None', value: 'none' },
			{ name: 'Predefined Credential Type', value: 'predefinedCredentialType' },
			{ name: 'Generic Credential Type', value: 'genericCredentialType' },
		],
	},
	{
		displayName: 'Credential Type',
		name: 'nodeCredentialType',
		type: 'credentialsSelect',
		noDataExpression: true,
		required: true,
		default: '',
		credentialTypes: ['extends:oAuth2Api', 'extends:oAuth1Api', 'has:authenticate'],
		displayOptions: { show: { operation: ['request'], authentication: ['predefinedCredentialType'] } },
	},
	{
		displayName: 'Generic Auth Type',
		name: 'genericAuthType',
		type: 'credentialsSelect',
		required: true,
		default: '',
		credentialTypes: ['has:genericAuth'],
		displayOptions: { show: { operation: ['request'], authentication: ['genericCredentialType'] } },
	},

	// Query
	{
		displayName: 'Send Query Parameters',
		name: 'sendQuery',
		type: 'boolean',
		noDataExpression: true,
		default: false,
		displayOptions: requestOnly,
	},
	{
		displayName: 'Specify Query Parameters',
		name: 'specifyQuery',
		type: 'options',
		default: 'keypair',
		displayOptions: { show: { operation: ['request'], sendQuery: [true] } },
		options: [
			{ name: 'Using Fields Below', value: 'keypair' },
			{ name: 'Using JSON', value: 'json' },
		],
	},
	keyValueCollection('queryParameters', 'Add Query Parameter', { sendQuery: [true], specifyQuery: ['keypair'] }),
	{
		displayName: 'JSON',
		name: 'jsonQuery',
		type: 'json',
		default: '',
		displayOptions: { show: { operation: ['request'], sendQuery: [true], specifyQuery: ['json'] } },
	},

	// Headers
	{
		displayName: 'Send Headers',
		name: 'sendHeaders',
		type: 'boolean',
		noDataExpression: true,
		default: false,
		displayOptions: requestOnly,
	},
	{
		displayName: 'Specify Headers',
		name: 'specifyHeaders',
		type: 'options',
		default: 'keypair',
		displayOptions: { show: { operation: ['request'], sendHeaders: [true] } },
		options: [
			{ name: 'Using Fields Below', value: 'keypair' },
			{ name: 'Using JSON', value: 'json' },
		],
	},
	keyValueCollection('headerParameters', 'Add Header', { sendHeaders: [true], specifyHeaders: ['keypair'] }),
	{
		displayName: 'JSON',
		name: 'jsonHeaders',
		type: 'json',
		default: '',
		displayOptions: { show: { operation: ['request'], sendHeaders: [true], specifyHeaders: ['json'] } },
	},

	// Body
	{
		displayName: 'Send Body',
		name: 'sendBody',
		type: 'boolean',
		noDataExpression: true,
		default: false,
		displayOptions: requestOnly,
	},
	{
		displayName: 'Body Content Type',
		name: 'contentType',
		type: 'options',
		default: 'json',
		displayOptions: { show: { operation: ['request'], sendBody: [true] } },
		options: [
			{ name: 'JSON', value: 'json' },
			{ name: 'Form URL Encoded', value: 'form-urlencoded' },
			{ name: 'Form-Data', value: 'multipart-form-data' },
			{ name: 'Raw', value: 'raw' },
			{ name: 'n8n Binary File', value: 'binaryData' },
		],
	},
	{
		displayName: 'Specify Body',
		name: 'specifyBody',
		type: 'options',
		default: 'keypair',
		displayOptions: { show: { operation: ['request'], sendBody: [true], contentType: ['json', 'form-urlencoded'] } },
		options: [
			{ name: 'Using Fields Below', value: 'keypair' },
			{ name: 'Using JSON', value: 'json' },
		],
	},
	keyValueCollection('bodyParameters', 'Add Parameter', {
		sendBody: [true],
		contentType: ['json', 'form-urlencoded'],
		specifyBody: ['keypair'],
	}),
	{
		displayName: 'JSON',
		name: 'jsonBody',
		type: 'json',
		default: '',
		displayOptions: { show: { operation: ['request'], sendBody: [true], contentType: ['json', 'form-urlencoded'], specifyBody: ['json'] } },
	},
	{
		displayName: 'Form Fields',
		name: 'multipartParameters',
		type: 'fixedCollection',
		typeOptions: { multipleValues: true },
		placeholder: 'Add Field',
		default: { parameters: [{ parameterType: 'formData', name: '', value: '' }] },
		displayOptions: { show: { operation: ['request'], sendBody: [true], contentType: ['multipart-form-data'] } },
		options: [
			{
				name: 'parameters',
				displayName: 'Field',
				values: [
					{
						displayName: 'Type',
						name: 'parameterType',
						type: 'options',
						default: 'formData',
						options: [
							{ name: 'Form Data', value: 'formData' },
							{ name: 'n8n Binary File', value: 'formBinaryData' },
						],
					},
					{ displayName: 'Name', name: 'name', type: 'string', default: '' },
					{ displayName: 'Value', name: 'value', type: 'string', default: '', displayOptions: { show: { parameterType: ['formData'] } } },
					{
						displayName: 'Input Data Field Name',
						name: 'inputDataFieldName',
						type: 'string',
						default: 'data',
						displayOptions: { show: { parameterType: ['formBinaryData'] } },
					},
				],
			},
		],
	},
	{
		displayName: 'Content Type',
		name: 'rawContentType',
		type: 'string',
		default: '',
		placeholder: 'text/plain',
		displayOptions: { show: { operation: ['request'], sendBody: [true], contentType: ['raw'] } },
	},
	{
		displayName: 'Body',
		name: 'rawBody',
		type: 'string',
		default: '',
		typeOptions: { rows: 4 },
		displayOptions: { show: { operation: ['request'], sendBody: [true], contentType: ['raw'] } },
	},
	{
		displayName: 'Input Data Field Name',
		name: 'inputDataFieldName',
		type: 'string',
		default: 'data',
		description: 'Name of the binary property on the input item to send as the body',
		displayOptions: { show: { operation: ['request'], sendBody: [true], contentType: ['binaryData'] } },
	},

	// Options
	{
		displayName: 'Options',
		name: 'options',
		type: 'collection',
		placeholder: 'Add Option',
		default: {},
		displayOptions: requestOnly,
		options: [
			{
				displayName: 'Batching',
				name: 'batching',
				type: 'fixedCollection',
				placeholder: 'Add Batching',
				default: { batch: { batchSize: 50, batchInterval: 1000 } },
				options: [
					{
						displayName: 'Batching',
						name: 'batch',
						values: [
							{ displayName: 'Items per Batch', name: 'batchSize', type: 'number', typeOptions: { minValue: 1 }, default: 50 },
							{ displayName: 'Batch Interval (ms)', name: 'batchInterval', type: 'number', typeOptions: { minValue: 0 }, default: 1000 },
						],
					},
				],
			},
			{
				displayName: 'Ignore SSL Issues (Insecure)',
				name: 'allowUnauthorizedCerts',
				type: 'boolean',
				default: false,
				description: 'Whether to connect even if SSL certificate validation fails. Policy may forbid this.',
			},
			{
				displayName: 'Include Policy Info',
				name: 'includePolicyInfo',
				type: 'boolean',
				default: false,
				description: 'Whether to add a _guardedHttp field with the policies applied, redirect hops and final URL',
			},
			{
				displayName: 'Proxy',
				name: 'proxy',
				type: 'string',
				default: '',
				placeholder: 'http://proxy.internal:3128',
				description: 'HTTP proxy to use. Policy may forbid this.',
			},
			{
				displayName: 'Redirects',
				name: 'redirect',
				type: 'fixedCollection',
				placeholder: 'Add Redirect Settings',
				default: { redirect: { followRedirects: true, maxRedirects: 5 } },
				options: [
					{
						displayName: 'Redirect',
						name: 'redirect',
						values: [
							{ displayName: 'Follow Redirects', name: 'followRedirects', type: 'boolean', default: true },
							{ displayName: 'Max Redirects', name: 'maxRedirects', type: 'number', typeOptions: { minValue: 0 }, default: 5 },
						],
					},
				],
			},
			{
				displayName: 'Response',
				name: 'response',
				type: 'fixedCollection',
				placeholder: 'Add Response Settings',
				default: { response: { fullResponse: false, neverError: false, responseFormat: 'autodetect', outputPropertyName: 'data' } },
				options: [
					{
						displayName: 'Response',
						name: 'response',
						values: [
							{ displayName: 'Include Response Headers and Status', name: 'fullResponse', type: 'boolean', default: false },
							{
								displayName: 'Never Error',
								name: 'neverError',
								type: 'boolean',
								default: false,
								description: 'Whether to succeed on non-2xx status codes. Policy may forbid this.',
							},
							{
								displayName: 'Response Format',
								name: 'responseFormat',
								type: 'options',
								default: 'autodetect',
								options: [
									{ name: 'Autodetect', value: 'autodetect' },
									{ name: 'JSON', value: 'json' },
									{ name: 'Text', value: 'text' },
									{ name: 'File', value: 'file' },
								],
							},
							{
								displayName: 'Put Output in Field',
								name: 'outputPropertyName',
								type: 'string',
								default: 'data',
								description: 'Field name for text and file responses',
							},
						],
					},
				],
			},
			{
				displayName: 'Timeout (ms)',
				name: 'timeout',
				type: 'number',
				typeOptions: { minValue: 1 },
				default: 30000,
				description: 'Policy may cap this',
			},
		],
	},
];
