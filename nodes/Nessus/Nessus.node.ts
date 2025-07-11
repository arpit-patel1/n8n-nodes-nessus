import type {
	IExecuteFunctions,
	IDataObject,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeOperationError, NodeConnectionType } from 'n8n-workflow';
import { NessusApi } from './NessusApi';

export class Nessus implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Nessus',
		name: 'nessus',
		icon: 'file:nessus-icon.svg',
		group: ['security'],
		version: 1,
		description: 'Interact with the Nessus API',
		defaults: {
			name: 'Nessus',
		},
		inputs: [NodeConnectionType.Main],
		outputs: [NodeConnectionType.Main],
		credentials: [
			{
				name: 'nessusApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Folder',
						value: 'folder',
					},
					{
						name: 'Plugin',
						value: 'plugin',
					},
					{
						name: 'Policy',
						value: 'policy',
					},
					{
						name: 'Scan',
						value: 'scan',
					},
					{
						name: 'Session',
						value: 'session',
					},
				],
				default: 'scan',
			},
			// Scan Operations
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['scan'],
					},
				},
				options: [
					{
						name: 'Copy',
						value: 'copy',
						description: 'Copy a scan',
						action: 'Copy a scan',
					},
					{
						name: 'Create',
						value: 'create',
						description: 'Create a new scan',
						action: 'Create a new scan',
					},
					{
						name: 'Delete',
						value: 'delete',
						description: 'Delete a scan',
						action: 'Delete a scan',
					},
					{
						name: 'Export',
						value: 'export',
						description: 'Export scan results',
						action: 'Export scan results',
					},
					{
						name: 'Get Details',
						value: 'getDetails',
						description: 'Get details of a specific scan',
						action: 'Get scan details',
					},
					{
						name: 'Launch',
						value: 'launch',
						description: 'Launch a scan',
						action: 'Launch a scan',
					},
					{
						name: 'List',
						value: 'list',
						description: 'List all scans',
						action: 'List all scans',
					},
					{
						name: 'Pause',
						value: 'pause',
						description: 'Pause a running scan',
						action: 'Pause a scan',
					},
					{
						name: 'Resume',
						value: 'resume',
						description: 'Resume a paused scan',
						action: 'Resume a scan',
					},
					{
						name: 'Stop',
						value: 'stop',
						description: 'Stop a running scan',
						action: 'Stop a scan',
					},
				],
				default: 'list',
			},
			// Policy Operations
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['policy'],
					},
				},
				options: [
					{
						name: 'Copy',
						value: 'copy',
						description: 'Copy a policy',
						action: 'Copy a policy',
					},
					{
						name: 'Create',
						value: 'create',
						description: 'Create a new policy',
						action: 'Create a new policy',
					},
					{
						name: 'Delete',
						value: 'delete',
						description: 'Delete a policy',
						action: 'Delete a policy',
					},
					{
						name: 'Get Details',
						value: 'getDetails',
						description: 'Get details of a specific policy',
						action: 'Get policy details',
					},
					{
						name: 'List',
						value: 'list',
						description: 'List all policies',
						action: 'List all policies',
					},
					{
						name: 'Update',
						value: 'update',
						description: 'Update an existing policy',
						action: 'Update a policy',
					},
				],
				default: 'list',
			},
			// Folder Operations
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['folder'],
					},
				},
				options: [
					{
						name: 'List',
						value: 'list',
						description: 'List all folders',
						action: 'List all folders',
					},
					{
						name: 'Create',
						value: 'create',
						description: 'Create a new folder',
						action: 'Create a new folder',
					},
					{
						name: 'Delete',
						value: 'delete',
						description: 'Delete a folder',
						action: 'Delete a folder',
					},
				],
				default: 'list',
			},
			// Plugin Operations
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['plugin'],
					},
				},
				options: [
					{
						name: 'List Families',
						value: 'listFamilies',
						description: 'List all plugin families',
						action: 'List plugin families',
					},
					{
						name: 'List Plugins in Family',
						value: 'listPluginsInFamily',
						description: 'List plugins in a specific family',
						action: 'List plugins in family',
					},
					{
						name: 'Get Plugin Details',
						value: 'getPluginDetails',
						description: 'Get details of a specific plugin',
						action: 'Get plugin details',
					},
				],
				default: 'listFamilies',
			},
			// Session Operations
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['session'],
					},
				},
				options: [
					{
						name: 'Get Details',
						value: 'getDetails',
						description: 'Get session details',
						action: 'Get session details',
					},
					{
						name: 'Edit',
						value: 'edit',
						description: 'Edit session settings',
						action: 'Edit session',
					},
				],
				default: 'getDetails',
			},
			// Common ID Parameters
			{
				displayName: 'Scan ID',
				name: 'scanId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['getDetails', 'launch', 'stop', 'pause', 'resume', 'delete', 'export', 'copy'],
					},
				},
				default: 0,
				description: 'The ID of the scan',
			},
			{
				displayName: 'Policy ID',
				name: 'policyId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['policy'],
						operation: ['getDetails', 'update', 'delete', 'copy'],
					},
				},
				default: 0,
				description: 'The ID of the policy',
			},
			{
				displayName: 'Folder ID',
				name: 'folderId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['folder'],
						operation: ['delete'],
					},
				},
				default: 0,
				description: 'The ID of the folder',
			},
			{
				displayName: 'Plugin Family ID',
				name: 'familyId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['plugin'],
						operation: ['listPluginsInFamily'],
					},
				},
				default: 0,
				description: 'The ID of the plugin family',
			},
			{
				displayName: 'Plugin ID',
				name: 'pluginId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['plugin'],
						operation: ['getPluginDetails'],
					},
				},
				default: 0,
				description: 'The ID of the plugin',
			},
			// Scan Creation Parameters
			{
				displayName: 'Scan Name',
				name: 'scanName',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['create'],
					},
				},
				default: '',
				description: 'Name of the scan',
			},
			{
				displayName: 'Policy UUID',
				name: 'policyUuid',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['create'],
					},
				},
				default: '',
				description: 'UUID of the policy template to use',
			},
			{
				displayName: 'Targets',
				name: 'targets',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['create'],
					},
				},
				default: '',
				description: 'Comma-separated list of targets to scan',
			},
			// Export Parameters
			{
				displayName: 'Export Format',
				name: 'exportFormat',
				type: 'options',
				required: true,
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['export'],
					},
				},
				options: [
					{
						name: 'Nessus',
						value: 'nessus',
					},
					{
						name: 'PDF',
						value: 'pdf',
					},
					{
						name: 'HTML',
						value: 'html',
					},
					{
						name: 'CSV',
						value: 'csv',
					},
				],
				default: 'nessus',
				description: 'Format for the exported scan results',
			},
			// Folder Name for Creation
			{
				displayName: 'Folder Name',
				name: 'folderName',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['folder'],
						operation: ['create'],
					},
				},
				default: '',
				description: 'Name of the folder to create',
			},
			// Copy Parameters
			{
				displayName: 'New Name',
				name: 'newName',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['copy'],
					},
				},
				default: '',
				description: 'Name for the copied scan (optional)',
			},
			{
				displayName: 'Destination Folder ID',
				name: 'destinationFolderId',
				type: 'number',
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['copy'],
					},
				},
				default: 0,
				description: 'ID of the destination folder (optional)',
			},
			// Alternative Targets for Launch
			{
				displayName: 'Alternative Targets',
				name: 'altTargets',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['launch'],
					},
				},
				default: '',
				description: 'Comma-separated list of alternative targets (optional)',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		const resource = this.getNodeParameter('resource', 0) as string;
		const operation = this.getNodeParameter('operation', 0) as string;

		const nessusApi = new NessusApi(this);

		for (let i = 0; i < items.length; i++) {
			try {
				let responseData: any;

				if (resource === 'scan') {
					if (operation === 'list') {
						responseData = await nessusApi.listScans();
					} else if (operation === 'getDetails') {
						const scanId = this.getNodeParameter('scanId', i) as number;
						responseData = await nessusApi.getScanDetails(scanId);
					} else if (operation === 'create') {
						const scanName = this.getNodeParameter('scanName', i) as string;
						const policyUuid = this.getNodeParameter('policyUuid', i) as string;
						const targets = this.getNodeParameter('targets', i) as string;
						
						const scanData = {
							uuid: policyUuid,
							settings: {
								name: scanName,
								text_targets: targets,
								enabled: false,
							},
						};
						responseData = await nessusApi.createScan(scanData);
					} else if (operation === 'launch') {
						const scanId = this.getNodeParameter('scanId', i) as number;
						const altTargets = this.getNodeParameter('altTargets', i) as string;
						const altTargetsList = altTargets ? altTargets.split(',').map(t => t.trim()) : undefined;
						responseData = await nessusApi.launchScan(scanId, altTargetsList);
					} else if (operation === 'stop') {
						const scanId = this.getNodeParameter('scanId', i) as number;
						responseData = await nessusApi.stopScan(scanId);
					} else if (operation === 'pause') {
						const scanId = this.getNodeParameter('scanId', i) as number;
						responseData = await nessusApi.pauseScan(scanId);
					} else if (operation === 'resume') {
						const scanId = this.getNodeParameter('scanId', i) as number;
						responseData = await nessusApi.resumeScan(scanId);
					} else if (operation === 'delete') {
						const scanId = this.getNodeParameter('scanId', i) as number;
						responseData = await nessusApi.deleteScan(scanId);
					} else if (operation === 'export') {
						const scanId = this.getNodeParameter('scanId', i) as number;
						const exportFormat = this.getNodeParameter('exportFormat', i) as string;
						responseData = await nessusApi.exportScan(scanId, exportFormat);
					} else if (operation === 'copy') {
						const scanId = this.getNodeParameter('scanId', i) as number;
						const newName = this.getNodeParameter('newName', i) as string;
						const destinationFolderId = this.getNodeParameter('destinationFolderId', i) as number;
						responseData = await nessusApi.copyScan(
							scanId,
							destinationFolderId || undefined,
							newName || undefined
						);
					}
				} else if (resource === 'policy') {
					if (operation === 'list') {
						responseData = await nessusApi.listPolicies();
					} else if (operation === 'getDetails') {
						const policyId = this.getNodeParameter('policyId', i) as number;
						responseData = await nessusApi.getPolicyDetails(policyId);
					} else if (operation === 'delete') {
						const policyId = this.getNodeParameter('policyId', i) as number;
						responseData = await nessusApi.deletePolicy(policyId);
					} else if (operation === 'copy') {
						const policyId = this.getNodeParameter('policyId', i) as number;
						responseData = await nessusApi.copyPolicy(policyId);
					}
				} else if (resource === 'folder') {
					if (operation === 'list') {
						responseData = await nessusApi.listFolders();
					} else if (operation === 'create') {
						const folderName = this.getNodeParameter('folderName', i) as string;
						responseData = await nessusApi.createFolder(folderName);
					} else if (operation === 'delete') {
						const folderId = this.getNodeParameter('folderId', i) as number;
						responseData = await nessusApi.deleteFolder(folderId);
					}
				} else if (resource === 'plugin') {
					if (operation === 'listFamilies') {
						responseData = await nessusApi.listPluginFamilies();
					} else if (operation === 'listPluginsInFamily') {
						const familyId = this.getNodeParameter('familyId', i) as number;
						responseData = await nessusApi.listPluginsInFamily(familyId);
					} else if (operation === 'getPluginDetails') {
						const pluginId = this.getNodeParameter('pluginId', i) as number;
						responseData = await nessusApi.getPluginDetails(pluginId);
					}
				} else if (resource === 'session') {
					if (operation === 'getDetails') {
						responseData = await nessusApi.getSessionDetails();
					}
				}

				returnData.push({ json: responseData as IDataObject });
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({ json: { error: error.message }, pairedItem: i });
				} else {
					if (error.context) {
						error.context.itemIndex = i;
						throw error;
					}
					throw new NodeOperationError(this.getNode(), error, {
						itemIndex: i,
					});
				}
			}
		}

		return [this.helpers.returnJsonArray(returnData)];
	}
}
