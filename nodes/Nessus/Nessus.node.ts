import type {
	IExecuteFunctions,
	IDataObject,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	ILoadOptionsFunctions,
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
						name: 'List Templates',
						value: 'listTemplates',
						description: 'List available policy templates',
						action: 'List policy templates',
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
				displayName: 'Scan Name or ID',
				name: 'scanId',
				type: 'options',
				typeOptions: {
					loadOptionsMethod: 'getScans',
				},
				required: true,
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['getDetails', 'launch', 'stop', 'pause', 'resume', 'delete', 'export', 'copy'],
					},
				},
				default: '',
				description: 'Select the scan to operate on. Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code/expressions/">expression</a>.',
				placeholder: 'Select a scan...',
			},
			{
				displayName: 'Policy Name or ID',
				name: 'policyId',
				type: 'options',
				typeOptions: {
					loadOptionsMethod: 'getPolicies',
				},
				required: true,
				displayOptions: {
					show: {
						resource: ['policy'],
						operation: ['getDetails', 'update', 'delete', 'copy'],
					},
				},
				default: '',
				description: 'Select the policy to operate on. Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code/expressions/">expression</a>.',
				placeholder: 'Select a policy...',
			},
			{
				displayName: 'Folder Name or ID',
				name: 'folderId',
				type: 'options',
				typeOptions: {
					loadOptionsMethod: 'getFolders',
				},
				required: true,
				displayOptions: {
					show: {
						resource: ['folder'],
						operation: ['delete'],
					},
				},
				default: '',
				description: 'Select the folder to delete. Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code/expressions/">expression</a>.',
				placeholder: 'Select a folder...',
			},
			{
				displayName: 'Plugin Family Name or ID',
				name: 'familyId',
				type: 'options',
				typeOptions: {
					loadOptionsMethod: 'getPluginFamilies',
				},
				required: true,
				displayOptions: {
					show: {
						resource: ['plugin'],
						operation: ['listPluginsInFamily'],
					},
				},
				default: '',
				description: 'Select the plugin family. Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code/expressions/">expression</a>.',
				placeholder: 'Select a plugin family...',
			},
			{
				displayName: 'Plugin Name or ID',
				name: 'pluginId',
				type: 'options',
				typeOptions: {
					loadOptionsMethod: 'getPluginsInFamily',
				},
				required: true,
				displayOptions: {
					show: {
						resource: ['plugin'],
						operation: ['getPluginDetails'],
					},
				},
				default: '',
				description: 'Select the plugin. Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code/expressions/">expression</a>.',
				placeholder: 'Select a plugin...',
			},
			// Scan Creation Parameters
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
				description: 'IP addresses, ranges, or hostnames to scan',
				placeholder: '192.168.1.1, 192.168.1.0/24, example.com',
			},
			{
				displayName: 'Scan Name',
				name: 'scanName',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['create'],
					},
				},
				default: '=Basic Scan - {{new Date().toISOString().split("T")[0]}}',
				description: 'Name of the scan (auto-generated if left empty)',
			},
			{
				displayName: 'Policy Template Name or ID',
				name: 'policyUuid',
				type: 'options',
				typeOptions: {
					loadOptionsMethod: 'getPolicyTemplates',
				},
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['create'],
					},
				},
				default: '',
				description: 'Policy template to use (will auto-select Basic Network Scan if left empty). Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code/expressions/">expression</a>.',
				placeholder: 'Select a policy template...',
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
				description: 'Name for the copied scan (optional - will use original name with "Copy" suffix if not provided)',
				placeholder: 'My Scan Copy',
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
				displayName: 'Destination Folder Name or ID',
				name: 'destinationFolderId',
				type: 'options',
				typeOptions: {
					loadOptionsMethod: 'getFolders',
				},
				displayOptions: {
					show: {
						resource: ['scan'],
						operation: ['copy'],
					},
				},
				default: '',
				description: 'Select the destination folder (optional). Choose from the list, or specify an ID using an <a href="https://docs.n8n.io/code/expressions/">expression</a>.',
				placeholder: 'Select a folder...',
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

	methods = {
		loadOptions: {
			async getPolicyTemplates(this: ILoadOptionsFunctions) {
				const nessusApi = new NessusApi(this as any);
				try {
					const templates = await nessusApi.listScanTemplates();
					const options = templates.templates.map((template: any) => ({
						name: template.title,
						value: template.uuid,
						description: template.description,
					}));
					
					// Sort to put basic scan templates first
					options.sort((a: any, b: any) => {
						if (a.name.toLowerCase().includes('basic') || a.name.toLowerCase().includes('network')) return -1;
						if (b.name.toLowerCase().includes('basic') || b.name.toLowerCase().includes('network')) return 1;
						return a.name.localeCompare(b.name);
					});
					
					return options;
				} catch (error) {
					throw new NodeOperationError(this.getNode(), `Failed to load policy templates: ${error.message}`);
				}
			},
			async getScans(this: ILoadOptionsFunctions) {
				const nessusApi = new NessusApi(this as any);
				try {
					const scans = await nessusApi.listScans();
					const options = scans.scans.map((scan: any) => {
						// Format creation date
						const creationDate = scan.creation_date ? new Date(scan.creation_date * 1000).toLocaleDateString() : 'Unknown';
						
						// Create a more descriptive name
						let statusText = scan.status || 'Unknown';
						if (scan.status === 'running') statusText = '🟢 Running';
						else if (scan.status === 'completed') statusText = '✅ Completed';
						else if (scan.status === 'paused') statusText = '⏸️ Paused';
						else if (scan.status === 'stopped') statusText = '⏹️ Stopped';
						else if (scan.status === 'canceled') statusText = '❌ Canceled';
						
						return {
							name: `${scan.name} (${statusText})`,
							value: scan.id,
							description: `ID: ${scan.id} | Created: ${creationDate} | Owner: ${scan.owner || 'Unknown'}`,
						};
					});
					
					// Sort by status (running first, then by name)
					options.sort((a: any, b: any) => {
						const aRunning = a.name.includes('🟢 Running');
						const bRunning = b.name.includes('🟢 Running');
						if (aRunning && !bRunning) return -1;
						if (!aRunning && bRunning) return 1;
						return a.name.localeCompare(b.name);
					});
					
					return options;
				} catch (error) {
					throw new NodeOperationError(this.getNode(), `Failed to load scans: ${error.message}`);
				}
			},
			async getPolicies(this: ILoadOptionsFunctions) {
				const nessusApi = new NessusApi(this as any);
				try {
					const policies = await nessusApi.listPolicies();
					const options = policies.policies.map((policy: any) => {
						// Format creation date
						const creationDate = policy.creation_date ? new Date(policy.creation_date * 1000).toLocaleDateString() : 'Unknown';
						
						return {
							name: policy.name,
							value: policy.id,
							description: `ID: ${policy.id} | Created: ${creationDate} | Owner: ${policy.owner || 'Unknown'}`,
						};
					});
					
					// Sort by name
					options.sort((a: any, b: any) => a.name.localeCompare(b.name));
					
					return options;
				} catch (error) {
					throw new NodeOperationError(this.getNode(), `Failed to load policies: ${error.message}`);
				}
			},
			async getFolders(this: ILoadOptionsFunctions) {
				const nessusApi = new NessusApi(this as any);
				try {
					const folders = await nessusApi.listFolders();
					const options = folders.folders.map((folder: any) => ({
						name: folder.name,
						value: folder.id,
						description: `ID: ${folder.id} | Type: ${folder.type || 'Unknown'}`,
					}));
					
					// Sort by name
					options.sort((a: any, b: any) => a.name.localeCompare(b.name));
					
					return options;
				} catch (error) {
					throw new NodeOperationError(this.getNode(), `Failed to load folders: ${error.message}`);
				}
			},
			async getPluginFamilies(this: ILoadOptionsFunctions) {
				const nessusApi = new NessusApi(this as any);
				try {
					const families = await nessusApi.listPluginFamilies();
					const options = families.families.map((family: any) => ({
						name: family.name,
						value: family.id,
						description: `ID: ${family.id} | Count: ${family.count || 0} plugins`,
					}));
					
					// Sort by name
					options.sort((a: any, b: any) => a.name.localeCompare(b.name));
					
					return options;
				} catch (error) {
					throw new NodeOperationError(this.getNode(), `Failed to load plugin families: ${error.message}`);
				}
			},
			async getPluginsInFamily(this: ILoadOptionsFunctions) {
				const nessusApi = new NessusApi(this as any);
				try {
					// Get the family ID from the current node parameters
					const familyId = this.getNodeParameter('familyId') as string;
					if (!familyId) {
						return [];
					}
					
					const plugins = await nessusApi.listPluginsInFamily(parseInt(familyId));
					const options = plugins.plugins.map((plugin: any) => ({
						name: `${plugin.name} (ID: ${plugin.id})`,
						value: plugin.id,
						description: `Risk: ${plugin.risk_factor || 'Unknown'} | Family: ${plugin.family_name || 'Unknown'}`,
					}));
					
					// Sort by name
					options.sort((a: any, b: any) => a.name.localeCompare(b.name));
					
					return options;
				} catch (error) {
					throw new NodeOperationError(this.getNode(), `Failed to load plugins: ${error.message}`);
				}
			},
		},
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
					const scanId = parseInt(this.getNodeParameter('scanId', i) as string);
					responseData = await nessusApi.getScanDetails(scanId);
				} else if (operation === 'create') {
						const scanName = this.getNodeParameter('scanName', i) as string;
						let policyUuid = this.getNodeParameter('policyUuid', i) as string;
						const targets = this.getNodeParameter('targets', i) as string;
						
						// If no policy template is selected, use the first available one
						if (!policyUuid) {
							const templates = await nessusApi.listScanTemplates();
							if (templates.templates && templates.templates.length > 0) {
								// Sort templates to prioritize basic network scans
								const sortedTemplates = templates.templates.sort((a: any, b: any) => {
									if (a.title.toLowerCase().includes('basic') || a.title.toLowerCase().includes('network')) return -1;
									if (b.title.toLowerCase().includes('basic') || b.title.toLowerCase().includes('network')) return 1;
									return a.title.localeCompare(b.title);
								});
								policyUuid = sortedTemplates[0].uuid;
							}
						}
						
						// Generate scan name if not provided
						const finalScanName = scanName || `Basic Scan - ${new Date().toISOString().split('T')[0]}`;
						
						const scanData = {
							uuid: policyUuid,
							settings: {
								name: finalScanName,
								text_targets: targets,
								enabled: false,
							},
						};
						responseData = await nessusApi.createScan(scanData);
									} else if (operation === 'launch') {
					const scanId = parseInt(this.getNodeParameter('scanId', i) as string);
					const altTargets = this.getNodeParameter('altTargets', i) as string;
					const altTargetsList = altTargets ? altTargets.split(',').map(t => t.trim()) : undefined;
					responseData = await nessusApi.launchScan(scanId, altTargetsList);
				} else if (operation === 'stop') {
					const scanId = parseInt(this.getNodeParameter('scanId', i) as string);
					responseData = await nessusApi.stopScan(scanId);
				} else if (operation === 'pause') {
					const scanId = parseInt(this.getNodeParameter('scanId', i) as string);
					responseData = await nessusApi.pauseScan(scanId);
				} else if (operation === 'resume') {
					const scanId = parseInt(this.getNodeParameter('scanId', i) as string);
					responseData = await nessusApi.resumeScan(scanId);
				} else if (operation === 'delete') {
					const scanId = parseInt(this.getNodeParameter('scanId', i) as string);
					responseData = await nessusApi.deleteScan(scanId);
				} else if (operation === 'export') {
					const scanId = parseInt(this.getNodeParameter('scanId', i) as string);
					const exportFormat = this.getNodeParameter('exportFormat', i) as string;
					responseData = await nessusApi.exportScan(scanId, exportFormat);
				} else if (operation === 'copy') {
					const scanId = parseInt(this.getNodeParameter('scanId', i) as string);
					const newName = this.getNodeParameter('newName', i) as string;
					const destinationFolderId = this.getNodeParameter('destinationFolderId', i) as string;
					const folderId = destinationFolderId ? parseInt(destinationFolderId) : undefined;
					responseData = await nessusApi.copyScan(
						scanId,
						folderId,
						newName || undefined
					);
				}
				} else if (resource === 'policy') {
					if (operation === 'list') {
						responseData = await nessusApi.listPolicies();
									} else if (operation === 'getDetails') {
					const policyId = parseInt(this.getNodeParameter('policyId', i) as string);
					responseData = await nessusApi.getPolicyDetails(policyId);
				} else if (operation === 'delete') {
					const policyId = parseInt(this.getNodeParameter('policyId', i) as string);
					responseData = await nessusApi.deletePolicy(policyId);
				} else if (operation === 'copy') {
					const policyId = parseInt(this.getNodeParameter('policyId', i) as string);
					responseData = await nessusApi.copyPolicy(policyId);
					} else if (operation === 'listTemplates') {
						responseData = await nessusApi.listScanTemplates();
					}
				} else if (resource === 'folder') {
					if (operation === 'list') {
						responseData = await nessusApi.listFolders();
					} else if (operation === 'create') {
						const folderName = this.getNodeParameter('folderName', i) as string;
						responseData = await nessusApi.createFolder(folderName);
									} else if (operation === 'delete') {
					const folderId = parseInt(this.getNodeParameter('folderId', i) as string);
					responseData = await nessusApi.deleteFolder(folderId);
					}
				} else if (resource === 'plugin') {
					if (operation === 'listFamilies') {
						responseData = await nessusApi.listPluginFamilies();
									} else if (operation === 'listPluginsInFamily') {
					const familyId = parseInt(this.getNodeParameter('familyId', i) as string);
					responseData = await nessusApi.listPluginsInFamily(familyId);
				} else if (operation === 'getPluginDetails') {
					const pluginId = parseInt(this.getNodeParameter('pluginId', i) as string);
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
