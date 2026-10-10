import type { ICredentialType, INodeProperties } from 'n8n-workflow';

/**
 * Policy credential. Carries no secret; it carries a request policy.
 * Sharing it to a project is what grants that project the policy, so n8n RBAC governs who may use it.
 */
export class GuardedHttpPolicyApi implements ICredentialType {
	name = 'guardedHttpPolicyApi';

	displayName = 'Guarded HTTP Policy';

	documentationUrl = 'https://github.com/n8n-io/n8n-nodes-guarded-http-request#policy-credential';

	icon = 'file:guardedHttpPolicy.svg' as const;

	properties: INodeProperties[] = [
		{
			displayName:
				'Share this credential to a project to grant that project this policy. The instance floor still applies on top of it. Only the credential owner and instance admins can read the policy; editors can use it.',
			name: 'notice',
			type: 'notice',
			default: '',
		},
		{
			displayName: 'Policy Name',
			name: 'policyName',
			type: 'string',
			default: '',
			placeholder: 'finance-readonly',
			description: 'Label used in audit logs and error messages',
		},
		{
			displayName: 'Policy Source',
			name: 'mode',
			type: 'options',
			default: 'reference',
			options: [
				{
					name: 'Reference an Instance Policy',
					value: 'reference',
					description: 'Point at a policy defined in the instance configuration file (recommended)',
				},
				{
					name: 'Inline Policy Document',
					value: 'inline',
					description: 'Paste a policy JSON document. The instance may require it to be signed.',
				},
			],
		},
		{
			displayName: 'Instance Policy Name',
			name: 'policyRef',
			type: 'string',
			default: '',
			placeholder: 'finance-readonly',
			description: 'Key under "policies" in the instance configuration file',
			displayOptions: { show: { mode: ['reference'] } },
		},
		{
			displayName: 'Policy JSON',
			name: 'policyJson',
			type: 'string',
			default: '{\n  "version": 1,\n  "methods": ["GET"],\n  "hosts": { "allow": ["api.example.com"] }\n}',
			typeOptions: { rows: 14 },
			description: 'Policy document. See the package README for the schema.',
			displayOptions: { show: { mode: ['inline'] } },
		},
		{
			displayName: 'Signature',
			name: 'signature',
			type: 'string',
			default: '',
			placeholder: 'v1.default.3f2a…',
			description: 'HMAC signature produced by the sign-policy script with the instance signing key. Required when the instance enforces signed policies.',
			displayOptions: { show: { mode: ['inline'] } },
		},
	];
}
