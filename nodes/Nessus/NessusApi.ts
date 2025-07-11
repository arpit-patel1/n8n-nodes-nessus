import {
	IExecuteFunctions,
	IDataObject,
	NodeApiError,
	JsonObject,
} from 'n8n-workflow';

interface RequestOptions {
	method: string;
	endpoint: string;
	body?: IDataObject;
	params?: IDataObject;
}

interface PaginationOptions {
	limit?: number;
	offset?: number;
	sort?: string;
	order?: 'asc' | 'desc';
}

export class NessusApi {
	private executeFunctions: IExecuteFunctions;

	constructor(executeFunctions: IExecuteFunctions) {
		this.executeFunctions = executeFunctions;
	}

	private async makeRequest(options: RequestOptions): Promise<any> {
		const { method, endpoint, body, params } = options;
		
		const credentials = await this.executeFunctions.getCredentials('nessusApi') as IDataObject;
		const url = credentials.url as string;
		const accessKey = credentials.accessKey as string;
		const secretKey = credentials.secretKey as string;
		const allowUnauthorizedCerts = credentials.allowUnauthorizedCerts as boolean;

		const requestOptions: any = {
			headers: {
				'X-ApiKeys': `accessKey=${accessKey}; secretKey=${secretKey}`,
				'Content-Type': 'application/json',
			},
			method,
			uri: `${url}${endpoint}`,
			json: true,
			rejectUnauthorized: !allowUnauthorizedCerts,
		};

		if (body) {
			requestOptions.body = body;
		}

		if (params) {
			requestOptions.qs = params;
		}

		try {
			return await this.executeFunctions.helpers.request(requestOptions);
		} catch (error: any) {
			// Enhanced error handling with Nessus-specific error codes
			const errorMessage = this.parseNessusError(error);
			throw new NodeApiError(this.executeFunctions.getNode(), {
				message: errorMessage,
				originalError: error,
				httpCode: error.statusCode,
			} as JsonObject);
		}
	}

	private parseNessusError(error: any): string {
		if (error.response?.body?.error) {
			return `Nessus API Error: ${error.response.body.error}`;
		}
		
		switch (error.statusCode) {
			case 400:
				return 'Bad Request: Invalid parameters provided';
			case 401:
				return 'Unauthorized: Invalid API keys or session expired';
			case 403:
				return 'Forbidden: Insufficient permissions';
			case 404:
				return 'Not Found: The requested resource does not exist';
			case 409:
				return 'Conflict: Resource already exists or is in use';
			case 429:
				return 'Rate Limited: Too many requests, please try again later';
			case 500:
				return 'Internal Server Error: Nessus server error';
			case 503:
				return 'Service Unavailable: Nessus server is temporarily unavailable';
			default:
				return error.message || 'Unknown error occurred';
		}
	}

	private buildPaginationParams(options?: PaginationOptions): IDataObject {
		const params: IDataObject = {};
		
		if (options?.limit) {
			params.limit = options.limit;
		}
		if (options?.offset) {
			params.offset = options.offset;
		}
		if (options?.sort) {
			params.sort = options.sort;
		}
		if (options?.order) {
			params.order = options.order;
		}
		
		return params;
	}

	// Enhanced Scan Operations with pagination support
	async listScans(paginationOptions?: PaginationOptions): Promise<any> {
		const params = this.buildPaginationParams(paginationOptions);
		return await this.makeRequest({ method: 'GET', endpoint: '/scans', params });
	}

	async getScanDetails(scanId: number): Promise<any> {
		this.validateId(scanId, 'Scan ID');
		return await this.makeRequest({ method: 'GET', endpoint: `/scans/${scanId}` });
	}

	async createScan(scanData: IDataObject): Promise<any> {
		this.validateScanData(scanData);
		return await this.makeRequest({ method: 'POST', endpoint: '/scans', body: scanData });
	}

	async launchScan(scanId: number, altTargets?: string[]): Promise<any> {
		this.validateId(scanId, 'Scan ID');
		const body = altTargets ? { alt_targets: altTargets } : {};
		return await this.makeRequest({ method: 'POST', endpoint: `/scans/${scanId}/launch`, body });
	}

	async stopScan(scanId: number): Promise<any> {
		this.validateId(scanId, 'Scan ID');
		return await this.makeRequest({ method: 'POST', endpoint: `/scans/${scanId}/stop` });
	}

	async pauseScan(scanId: number): Promise<any> {
		this.validateId(scanId, 'Scan ID');
		return await this.makeRequest({ method: 'POST', endpoint: `/scans/${scanId}/pause` });
	}

	async resumeScan(scanId: number): Promise<any> {
		this.validateId(scanId, 'Scan ID');
		return await this.makeRequest({ method: 'POST', endpoint: `/scans/${scanId}/resume` });
	}

	async deleteScan(scanId: number): Promise<any> {
		this.validateId(scanId, 'Scan ID');
		return await this.makeRequest({ method: 'DELETE', endpoint: `/scans/${scanId}` });
	}

	async exportScan(scanId: number, format: string, historyId?: number): Promise<any> {
		this.validateId(scanId, 'Scan ID');
		this.validateExportFormat(format);
		
		const body: IDataObject = { format };
		if (historyId) {
			body.history_id = historyId;
		}
		return await this.makeRequest({ method: 'POST', endpoint: `/scans/${scanId}/export`, body });
	}

	async getScanExportStatus(scanId: number, fileId: number): Promise<any> {
		this.validateId(scanId, 'Scan ID');
		this.validateId(fileId, 'File ID');
		return await this.makeRequest({ method: 'GET', endpoint: `/scans/${scanId}/export/${fileId}/status` });
	}

	async downloadScanExport(scanId: number, fileId: number): Promise<any> {
		this.validateId(scanId, 'Scan ID');
		this.validateId(fileId, 'File ID');
		return await this.makeRequest({ method: 'GET', endpoint: `/scans/${scanId}/export/${fileId}/download` });
	}

	async copyScan(scanId: number, folderId?: number, name?: string): Promise<any> {
		this.validateId(scanId, 'Scan ID');
		const body: IDataObject = {};
		if (folderId) body.folder_id = folderId;
		if (name) body.name = name;
		return await this.makeRequest({ method: 'POST', endpoint: `/scans/${scanId}/copy`, body });
	}

	// Enhanced Policy Operations with pagination support
	async listPolicies(paginationOptions?: PaginationOptions): Promise<any> {
		const params = this.buildPaginationParams(paginationOptions);
		return await this.makeRequest({ method: 'GET', endpoint: '/policies', params });
	}

	async getPolicyDetails(policyId: number): Promise<any> {
		this.validateId(policyId, 'Policy ID');
		return await this.makeRequest({ method: 'GET', endpoint: `/policies/${policyId}` });
	}

	async createPolicy(policyData: IDataObject): Promise<any> {
		this.validatePolicyData(policyData);
		return await this.makeRequest({ method: 'POST', endpoint: '/policies', body: policyData });
	}

	async updatePolicy(policyId: number, policyData: IDataObject): Promise<any> {
		this.validateId(policyId, 'Policy ID');
		this.validatePolicyData(policyData);
		return await this.makeRequest({ method: 'PUT', endpoint: `/policies/${policyId}`, body: policyData });
	}

	async deletePolicy(policyId: number): Promise<any> {
		this.validateId(policyId, 'Policy ID');
		return await this.makeRequest({ method: 'DELETE', endpoint: `/policies/${policyId}` });
	}

	async copyPolicy(policyId: number): Promise<any> {
		this.validateId(policyId, 'Policy ID');
		return await this.makeRequest({ method: 'POST', endpoint: `/policies/${policyId}/copy` });
	}

	// Enhanced Folder Operations
	async listFolders(): Promise<any> {
		return await this.makeRequest({ method: 'GET', endpoint: '/folders' });
	}

	async createFolder(name: string): Promise<any> {
		this.validateFolderName(name);
		return await this.makeRequest({ method: 'POST', endpoint: '/folders', body: { name } });
	}

	async deleteFolder(folderId: number): Promise<any> {
		this.validateId(folderId, 'Folder ID');
		return await this.makeRequest({ method: 'DELETE', endpoint: `/folders/${folderId}` });
	}

	// Enhanced Plugin Operations with pagination support
	async listPluginFamilies(paginationOptions?: PaginationOptions): Promise<any> {
		const params = this.buildPaginationParams(paginationOptions);
		return await this.makeRequest({ method: 'GET', endpoint: '/plugins/families', params });
	}

	async listPluginsInFamily(familyId: number, paginationOptions?: PaginationOptions): Promise<any> {
		this.validateId(familyId, 'Family ID');
		const params = this.buildPaginationParams(paginationOptions);
		return await this.makeRequest({ method: 'GET', endpoint: `/plugins/families/${familyId}`, params });
	}

	async getPluginDetails(pluginId: number): Promise<any> {
		this.validateId(pluginId, 'Plugin ID');
		return await this.makeRequest({ method: 'GET', endpoint: `/plugins/plugin/${pluginId}` });
	}

	// Session Operations
	async getSessionDetails(): Promise<any> {
		return await this.makeRequest({ method: 'GET', endpoint: '/session' });
	}

	async editSession(sessionData: IDataObject): Promise<any> {
		return await this.makeRequest({ method: 'PUT', endpoint: '/session', body: sessionData });
	}

	// Editor Templates
	async listScanTemplates(): Promise<any> {
		return await this.makeRequest({ method: 'GET', endpoint: '/editor/scan/templates' });
	}

	async listPolicyTemplates(): Promise<any> {
		return await this.makeRequest({ method: 'GET', endpoint: '/editor/policy/templates' });
	}

	// Validation methods
	private validateId(id: number, fieldName: string): void {
		if (!id || id <= 0) {
			throw new Error(`${fieldName} must be a positive integer`);
		}
	}

	private validateScanData(scanData: IDataObject): void {
		if (!scanData.uuid) {
			throw new Error('Policy UUID is required for scan creation');
		}
		if (!scanData.settings) {
			throw new Error('Scan settings are required');
		}
		
		const settings = scanData.settings as IDataObject;
		if (!settings.name) {
			throw new Error('Scan name is required');
		}
		if (!settings.text_targets) {
			throw new Error('Target list is required');
		}
	}

	private validatePolicyData(policyData: IDataObject): void {
		if (!policyData.uuid) {
			const settings = policyData.settings as IDataObject;
			if (!settings?.name) {
				throw new Error('Policy UUID or name is required');
			}
		}
	}

	private validateFolderName(name: string): void {
		if (!name || name.trim().length === 0) {
			throw new Error('Folder name cannot be empty');
		}
		if (name.length > 255) {
			throw new Error('Folder name cannot exceed 255 characters');
		}
	}

	private validateExportFormat(format: string): void {
		const validFormats = ['nessus', 'pdf', 'html', 'csv', 'db'];
		if (!validFormats.includes(format.toLowerCase())) {
			throw new Error(`Invalid export format. Valid formats: ${validFormats.join(', ')}`);
		}
	}

	// Bulk operations for efficiency
	async deleteManyScans(scanIds: number[]): Promise<any> {
		if (!scanIds || scanIds.length === 0) {
			throw new Error('Scan IDs array cannot be empty');
		}
		return await this.makeRequest({ method: 'DELETE', endpoint: '/scans', body: { ids: scanIds } });
	}

	async deleteManyPolicies(policyIds: number[]): Promise<any> {
		if (!policyIds || policyIds.length === 0) {
			throw new Error('Policy IDs array cannot be empty');
		}
		return await this.makeRequest({ method: 'DELETE', endpoint: '/policies', body: { ids: policyIds } });
	}
}
