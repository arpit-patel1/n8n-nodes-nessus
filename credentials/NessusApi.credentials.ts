import type { Icon, ICredentialType, INodeProperties } from 'n8n-workflow';

export class NessusApi implements ICredentialType {
	name = 'nessusApi';
	displayName = 'Nessus API';
	documentationUrl = 'https://developer.tenable.com/reference/navigate';
	icon: Icon = 'file:nessus-icon.svg';
	properties: INodeProperties[] = [
		{
			displayName: 'Nessus URL',
			name: 'url',
			type: 'string',
			default: '',
			placeholder: 'https://localhost:8834',
		},
		{
			displayName: 'Access Key',
			name: 'accessKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
		},
		{
			displayName: 'Secret Key',
			name: 'secretKey',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
		},
		{
			displayName: 'Allow Self-Signed Certificates',
			name: 'allowUnauthorizedCerts',
			type: 'boolean',
			default: false,
		},
	];
}
