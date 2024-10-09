import { GetProvidersDto } from './../dto/getProviderDto';
import { DocumentClient } from 'aws-sdk/clients/dynamodb';
import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import * as Sentry from '@sentry/nestjs';
import { errorCodes } from '../../../utils/constants';
import { Provider } from '../entities/provider.entity';
import { ProviderSchema } from '../entities/provider.schema';
import {
	ChangeStatusProviderDto,
	CreateProviderDto,
	CreateSocketDto,
	UpdateProviderDto,
} from '../dto/provider';
import { convertToCamelCase } from '../../../utils/helpers/convertCamelCase';
import { v4 as uuidv4 } from 'uuid';
import {
	DeleteObjectCommand,
	PutObjectCommand,
	S3Client,
} from '@aws-sdk/client-s3';
import { User } from '../../user/entities/user.entity';
import { UserSchema } from '../../user/entities/user.schema';
import { UpdateUserDto } from '../../user/dto/update-user.dto';
import { buscarValorPorClave } from '../../../utils/helpers/findKeyValue';
import { validarPermisos } from '../../../utils/helpers/getAccessServiceProviders';
import { CreateProviderPaymentParameterDTO } from '../dto/create-provider-payment-parameter.dto';
import { buildFilterExpressionDynamo } from '../../../utils/helpers/buildFilterExpressionDynamo';
import { GetProviderPaymentParametersDTO } from '../dto/getProviderPaymentParametersDto';
import { removeSpaces } from '../../../utils/helpers/removeSpaces';
import { CreateUpdateFeeConfigurationDTO } from '../dto/create-update-fee-configuration.dto';
import { GetPaymentsParametersPaginated } from '../dto/get-payment-parameters-paginated';
import axios from 'axios';
import { SocketKey } from '../entities/socket.entity';
import { SocketKeySchema } from '../entities/socket.schema';

@Injectable()
export class ProviderService {
	private readonly dbInstance: Model<Provider>;
	private dbUserInstance: Model<User>;
	private dbInstanceSocket: Model<SocketKey>;

	constructor() {
		const tableName = 'Providers';
		this.dbInstance = dynamoose.model<Provider>(tableName, ProviderSchema, {
			create: false,
			waitForActive: false,
		});
		this.dbUserInstance = dynamoose.model<User>('Users', UserSchema);
		this.dbInstanceSocket = dynamoose.model<SocketKey>(
			'SocketKeys',
			SocketKeySchema
		);
	}

	async filterRafikiAssetByName(assets: Array<any>, assetName: string) {
		const filteredAsset = assets.find(asset => asset?.code == assetName);

		if (!filteredAsset) {
			return {};
		}

		return filteredAsset;
	}

	async getAndFilterAssetsByName(assetName: string, token: string) {
		try {
			const url = process.env.WALLET_URL + '/api/v1/wallets-rafiki/assets';

			const response = await axios.get(url, {
				headers: {
					Authorization: `Bearer ${token}`,
				},
			});

			const assets = response?.data?.data?.rafikiAssets;

			const assetValue = await this.filterRafikiAssetByName(assets, assetName);

			return assetValue?.id ?? '';
		} catch (error) {
			throw new HttpException(
				error.response?.data || 'Error getting assets',
				error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	async createWalletAddressServiceProvider(
		assetName: string,
		addressName: string,
		token: string,
		providerName: string
	) {
		try {
			const url =
				process.env.WALLET_URL +
				'/api/v1/wallets-rafiki/service-provider-address';

			const assetIdValue = await this.getAndFilterAssetsByName(
				assetName,
				token
			);

			const body = {
				addressName,
				assetId: assetIdValue,
				providerName,
			};

			const response = await axios.post(url, body, {
				headers: {
					Authorization: `Bearer ${token}`,
				},
			});
			return response.data;
		} catch (error) {
			throw new HttpException(
				error.response?.data || 'Error creating wallet address',
				error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	async createSocketKey(
		createSocketKeyDto: CreateSocketDto
	): Promise<SocketKey> {
		const socketKey = {
			PublicKey: createSocketKeyDto.publicKey,
			SecretKey: createSocketKeyDto.secretKey,
			ServiceProviderId: createSocketKeyDto.serviceProviderId,
		};
		return this.dbInstanceSocket.create(socketKey);
	}

	async create(createProviderDto: CreateProviderDto): Promise<Provider> {
		const provider = {
			Name: createProviderDto.name,
			Description: createProviderDto.description,
			Email: createProviderDto.email,
			Phone: createProviderDto.phone,
			EINNumber: createProviderDto.einNumber,
			Country: createProviderDto.country,
			City: createProviderDto.city,
			ZipCode: createProviderDto.zipCode,
			CompanyAddress: createProviderDto.companyAddress,
			WalletAddress: removeSpaces(createProviderDto.walletAddress),
			Logo: createProviderDto.logo,
			ContactInformation: createProviderDto.contactInformation,
			Asset: createProviderDto.asset,
		};
		return this.dbInstance.create(provider);
	}

	async findAll(
		getProvidersDto: GetProvidersDto,
		permissionModule: any,
		requestedModuleId: string,
		requiredMethod: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
	): Promise<{
		providers: { id: string; name: string; logo: string; active: boolean }[];
		currentPage: number;
		total: number;
		totalPages: number;
	}> {
		const { page = 1, items = 10, search } = getProvidersDto;
		const docClient = new DocumentClient();

		const params: DocumentClient.ScanInput = {
			TableName: 'Providers',
		};

		try {
			const result = await docClient.scan(params).promise();
			let providers = convertToCamelCase(result.Items || []);

			const accessMap = {
				GET: 8,
				POST: 4,
				PUT: 2,
				PATCH: 1,
				DELETE: 1,
			};

			const requiredAccess = accessMap[requiredMethod];

			providers = providers.filter(provider => {
				const serviceProviderId = provider.id;
				const serviceProviderAccessLevel = buscarValorPorClave(
					permissionModule[requestedModuleId],
					serviceProviderId
				);

				if (!serviceProviderAccessLevel) {
					return false;
				}

				return (serviceProviderAccessLevel & requiredAccess) === requiredAccess;
			});

			if (search) {
				const regex = new RegExp(search, 'i');
				providers = providers.filter(
					provider =>
						regex.test(provider.email) ||
						regex.test(provider.name) ||
						regex.test(provider.description) ||
						regex.test(provider.companyAddress) ||
						regex.test(provider.contactInformation)
				);
			}

			providers.sort((a, b) => {
				if (a.active !== b.active) {
					return a.active ? -1 : 1;
				}
				const nameA = a?.name || '';
				const nameB = b?.name || '';
				return nameA.localeCompare(nameB);
			});

			const total = providers.length;
			const offset = (Number(page) - 1) * Number(items);
			const paginatedProviders = providers.slice(
				offset,
				offset + Number(items)
			);

			const totalPages = Math.ceil(total / Number(items));

			return {
				providers: paginatedProviders,
				currentPage: Number(page),
				total,
				totalPages,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error fetching providers: ${error.message}`);
		}
	}

	async searchFindOne(id: string) {
		const docClient = new DocumentClient();
		const params: DocumentClient.GetItemInput = {
			TableName: 'Providers',
			Key: { Id: id },
		};

		try {
			const result = await docClient.get(params).promise();

			const getKeysParam: DocumentClient.ScanInput = {
				TableName: 'SocketKeys',
				FilterExpression: '#ServiceProviderId = :ServiceProviderId',
				ExpressionAttributeNames: {
					'#ServiceProviderId': 'ServiceProviderId',
				},
				ExpressionAttributeValues: {
					':ServiceProviderId': id,
				},
			};
			const resultKeys = await docClient.scan(getKeysParam).promise();
			const SocketKeys = resultKeys.Items[0];

			if (!result.Item) {
				throw new HttpException(
					{
						customCode: 'WGE0040',
						...errorCodes.WGE0040,
					},
					HttpStatus.NOT_FOUND
				);
			}

			const provider = convertToCamelCase(result.Item);

			if (SocketKeys) {
				provider.socketKeys = convertToCamelCase(SocketKeys);
			}

			return provider;
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error fetching provider by ID: ${error.message}`);
		}
	}

	async searchFindOneEmail(email: string) {
		try {
			const providers = await this.dbInstance.scan('Email').eq(email).exec();
			return convertToCamelCase(providers[0]);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error retrieving provider: ${error.message}`);
		}
	}

	async searchFindOneWalletAddress(walletAddress: string) {
		try {
			const providers = await this.dbInstance
				.scan('WalletAddress')
				.eq(walletAddress)
				.exec();
			return convertToCamelCase(providers[0]);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error retrieving provider: ${error.message}`);
		}
	}

	async searchFindOneId(id: string) {
		try {
			const roles = await this.dbInstance.scan('Id').eq(id).exec();
			return convertToCamelCase(roles[0]);
		} catch (error) {
			throw new Error(`Error retrieving provider: ${error.message}`);
		}
	}

	async findOne(id: string, role, serviceProviderId) {
		const permisos = validarPermisos({
			role,
			requestedModuleId: 'SP95',
			requiredMethod: 'GET',
			userId: id,
			serviceProviderId,
		});

		if (!permisos.hasAccess) {
			return { customCode: permisos.customCode };
		}

		const docClient = new DocumentClient();
		const params: DocumentClient.GetItemInput = {
			TableName: 'Providers',
			Key: { Id: id },
		};

		const getKeysParam: DocumentClient.ScanInput = {
			TableName: 'SocketKeys',
			FilterExpression: '#ServiceProviderId = :ServiceProviderId',
			ExpressionAttributeNames: {
				'#ServiceProviderId': 'ServiceProviderId',
			},
			ExpressionAttributeValues: {
				':ServiceProviderId': id,
			},
		};
		const result = await docClient.scan(getKeysParam).promise();
		const SocketKeys = result.Items[0];
		try {
			const result = await docClient.get(params).promise();

			if (!result.Item) {
				throw new HttpException(
					{
						customCode: 'WGE0040',
						...errorCodes.WGE0040,
					},
					HttpStatus.NOT_FOUND
				);
			}
			const provider = convertToCamelCase(result.Item);
			if (SocketKeys) {
				provider.socketKeys = convertToCamelCase(SocketKeys);
			}
			return provider;
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error fetching provider by ID: ${error.message}`);
		}
	}

	async update(
		id: string,
		updateProviderDto: UpdateProviderDto,
		role,
		serviceProviderId
	) {
		const permisos = validarPermisos({
			role,
			requestedModuleId: 'SP95',
			requiredMethod: 'PUT',
			userId: id,
			serviceProviderId,
		});

		if (!permisos.hasAccess) {
			return { customCode: permisos.customCode };
		}

		const allowedFields = [
			'name',
			'einNumber',
			'companyAddress',
			'country',
			'city',
			'zipCode',
			'contactInformation',
		];

		const convertToPascalCase = (str: string) =>
			str.charAt(0).toUpperCase() + str.slice(1);

		const docClient = new DocumentClient();
		const updateExpressionParts = [];
		const expressionAttributeNames = {};
		const expressionAttributeValues = {};

		Object.entries(updateProviderDto).forEach(([key, value]) => {
			if (allowedFields.includes(key) && value !== undefined) {
				const pascalKey =
					key == 'einNumber' ? 'EINNumber' : convertToPascalCase(key);
				const attributeKey = `#${pascalKey}`;
				const valueKey = `:${pascalKey}`;

				updateExpressionParts.push(`${attributeKey} = ${valueKey}`);
				expressionAttributeNames[attributeKey] = pascalKey;
				expressionAttributeValues[valueKey] = value;
			}
		});

		if (updateExpressionParts.length === 0) {
			throw new Error('No valid fields to update');
		}

		const updateExpression = `SET ${updateExpressionParts.join(', ')}`;

		const params: DocumentClient.UpdateItemInput = {
			TableName: 'Providers',
			Key: { Id: id },
			UpdateExpression: updateExpression,
			ExpressionAttributeNames: expressionAttributeNames,
			ExpressionAttributeValues: expressionAttributeValues,
			ReturnValues: 'ALL_NEW',
		};

		try {
			const result = await docClient.update(params).promise();
			return convertToCamelCase(result.Attributes || {});
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error updating provider: ${error.message}`);
		}
	}

	async activeInactiveProvider(
		id: string,
		changeStatusProvider: ChangeStatusProviderDto,
		role,
		serviceProviderId
	) {
		const permisos = validarPermisos({
			role,
			requestedModuleId: 'SP95',
			requiredMethod: 'PATCH',
			userId: id,
			serviceProviderId,
		});

		if (!permisos.hasAccess) {
			return { customCode: permisos.customCode };
		}

		const docClient = new DocumentClient();
		const params: DocumentClient.UpdateItemInput = {
			TableName: 'Providers',
			Key: { Id: id },
			UpdateExpression: 'SET #active = :active',
			ExpressionAttributeNames: {
				'#active': 'Active',
			},
			ExpressionAttributeValues: {
				':active': changeStatusProvider.active,
			},
			ReturnValues: 'ALL_NEW',
		};

		try {
			const result = await docClient.update(params).promise();
			return convertToCamelCase(result.Attributes || {});
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error updating status provider: ${error.message}`);
		}
	}

	async uploadImage(id: string, file: Express.Multer.File) {
		try {
			if (file) {
				const fileExtension = file.originalname.split('.').pop().toLowerCase();
				const allowedExtensions = ['jpg', 'jpeg', 'svg', 'png'];

				if (!allowedExtensions.includes(fileExtension)) {
					throw new HttpException(
						{
							statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
							customCode: 'WGE0043',
							customMessage: errorCodes.WGE0043?.description,
							customMessageEs: errorCodes.WGE0043?.descriptionEs,
						},
						HttpStatus.INTERNAL_SERVER_ERROR
					);
				}

				const fileName = `${uuidv4()}.${fileExtension}`;
				const filePath = `service-providers/${id}/${fileName}`;

				const provider = await this.dbInstance.get({ Id: id });
				const currentImageUrl = provider?.ImageUrl;

				const s3Client = new S3Client({
					region: process.env.AWS_REGION,
					credentials: {
						accessKeyId: process.env.AWS_KEY_ID,
						secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
					},
				});

				if (currentImageUrl) {
					const currentImageKey = currentImageUrl.split('.com/')[1];

					const deleteCommand = new DeleteObjectCommand({
						Bucket: process.env.AWS_S3_BUCKET_NAME,
						Key: currentImageKey,
					});

					await s3Client.send(deleteCommand);
				}

				const uploadCommand = new PutObjectCommand({
					Bucket: process.env.AWS_S3_BUCKET_NAME,
					Key: filePath,
					Body: file.buffer,
					ContentType: file.mimetype,
					ACL: 'public-read',
				});

				await s3Client.send(uploadCommand);

				const updatedProvider = {
					Id: id,
					ImageUrl: `https://${process.env.AWS_S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${filePath}`,
				};

				return this.dbInstance.update(updatedProvider);
			}
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0050',
					customMessage: errorCodes?.WGE0050?.description,
					customMessageEs: errorCodes.WGE0050?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	async remove(id: string): Promise<void> {
		try {
			await this.dbInstance.delete(id);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error deleting provider: ${error.message}`);
		}
	}

	async findAllUsers(
		getProvidersDto: GetProvidersDto,
		user?: string,
		providerId?: string
	): Promise<{
		providers: any[];
		total: number;
		totalPages: number;
	}> {
		const { page = 1, items = 10 } = getProvidersDto;
		const userConverted = user as unknown as { Name: string; Value: string }[];
		const email = userConverted[0]?.Value;

		try {
			const users = await this.dbUserInstance.query('Email').eq(email).exec();

			if (users.length === 0) {
				throw new Error('User not found');
			}

			let allData = [];

			if (users[0].Type === 'PROVIDER') {
				const serviceProviderId = users[0].ServiceProviderId;

				const usersProvider = await this.dbUserInstance
					.scan('ServiceProviderId')
					.eq(serviceProviderId)
					.exec();

				allData = usersProvider.map(item => item.toJSON());
				allData.sort((a, b) => a.FirstName.localeCompare(b.FirstName));
			} else if (users[0].Type === 'PLATFORM' && providerId) {
				const platformUsers = await this.dbUserInstance
					.scan('ServiceProviderId')
					.eq(providerId)
					.exec();

				allData = platformUsers.map(item => item.toJSON());

				allData.sort((a, b) => {
					if (a.Email && b.Email) {
						return a.Email.localeCompare(b.Email);
					}
					return 0;
				});
			} else {
				new Error(
					'User type is not supported or providerId is missing for PLATFORM type'
				);
			}

			if (allData.length === 0) {
				throw new Error('No users found');
			}

			const total = allData.length;
			const offset = (page - 1) * items;
			const paginatedUsers = allData.slice(offset, offset + items);
			const totalPages = Math.ceil(total / items);

			return {
				providers: paginatedUsers,
				total,
				totalPages,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error fetching providers: ${error.message}`);
		}
	}

	async updateProviderUsers(
		updateUserDto: UpdateUserDto,
		user?: string,
		id?: string
	) {
		try {
			const userConverted = user as unknown as {
				Name: string;
				Value: string;
			}[];
			const email = userConverted[0]?.Value;

			const userDb = await this.dbUserInstance.query('Email').eq(email).exec();

			let params = {};
			let usersProvider = [];
			if (userDb[0].Type === 'PLATFORM' && id) {
				usersProvider = await this.dbUserInstance
					.scan('ServiceProviderId')
					.eq(id)
					.exec();

				if (usersProvider[0].First) {
					params = {
						Id: usersProvider[0].Id,
						FirstName: updateUserDto.firstName,
						LastName: updateUserDto.lastName,
						Email: updateUserDto.email,
						Phone: updateUserDto.phone,
						RoleId: updateUserDto.roleId,
					};
				} else {
					params = {
						Id: usersProvider[0].Id,
						FirstName: updateUserDto.firstName,
						LastName: updateUserDto.lastName,
						Phone: updateUserDto.phone,
						RoleId: updateUserDto.roleId,
					};
				}
			} else if (userDb[0].Type === 'PROVIDER') {
				usersProvider = await this.dbUserInstance
					.scan('ServiceProviderId')
					.eq(userDb[0].ServiceProviderId)
					.exec();

				if (usersProvider[0].First) {
					params = {
						Id: usersProvider[0].Id,
						FirstName: updateUserDto.firstName,
						LastName: updateUserDto.lastName,
						Email: updateUserDto.email,
						Phone: updateUserDto.phone,
						RoleId: updateUserDto.roleId,
					};
				} else {
					params = {
						Id: usersProvider[0].Id,
						FirstName: updateUserDto.firstName,
						LastName: updateUserDto.lastName,
						Phone: updateUserDto.phone,
						RoleId: updateUserDto.roleId,
					};
				}
			}
			return await this.dbUserInstance.update(params);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error updating provider: ${error.message}`);
		}
	}

	async createOrUpdatePaymentParameter(
		createProviderPaymentParameter: CreateProviderPaymentParameterDTO,
		serviceProvider: any,
		paymentParameter: any,
		timeInterval: any,
		token: string
	): Promise<CreateProviderPaymentParameterDTO> {
		const docClient = new DocumentClient();

		const feeConfigParams = {
			TableName: 'FeeConfigurations',
			IndexName: 'ServiceProviderIdIndex',
			KeyConditionExpression: `ServiceProviderId = :serviceProviderId`,
			ExpressionAttributeValues: {
				':serviceProviderId': serviceProvider?.id,
			},
		};

		const feeConfigurations = await docClient.query(feeConfigParams).promise();

		if (!feeConfigurations.Items) {
			throw new HttpException(
				{
					customCode: 'WGE0140',
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}

		const feeConfig = feeConfigurations.Items?.[0];

		if (!feeConfig) {
			throw new HttpException(
				{
					customCode: 'WGE0145',
					statusCode: HttpStatus.NOT_FOUND,
				},
				HttpStatus.NOT_FOUND
			);
		}

		const wallet = await this.getServiceProviderWallet(
			serviceProvider.walletAddress
		);

		const asset = await this.getAssetByWalletAddress(wallet?.rafikiId, token);

		const params = {
			TableName: 'PaymentParameters',
			Item: {
				Id: createProviderPaymentParameter.paymentParameterId
					? createProviderPaymentParameter.paymentParameterId
					: uuidv4(),
				Name: createProviderPaymentParameter.name,
				...(createProviderPaymentParameter.description && {
					Description: createProviderPaymentParameter.description,
				}),
				Cost: createProviderPaymentParameter.cost,
				Frequency: createProviderPaymentParameter?.frequency,
				Interval: timeInterval?.name,
				Asset: asset?.code,
				ServiceProviderId: serviceProvider?.id,
				Percent: feeConfig.Percent,
				Comision: feeConfig.Comission,
				Base: feeConfig.Base,
				...(!createProviderPaymentParameter.paymentParameterId && {
					Active: true,
				}),
				...(createProviderPaymentParameter.paymentParameterId && {
					Active: paymentParameter.active,
				}),
			},
		};

		await docClient.put(params).promise();

		return createProviderPaymentParameter;
	}

	async getPaymentParameters(paymentParameterId?: string): Promise<any> {
		const docClient = new DocumentClient();

		const params = {
			Key: { Id: paymentParameterId },
			TableName: 'PaymentParameters',
		};

		const paymentParameterQuery = await docClient.get(params).promise();

		return convertToCamelCase(paymentParameterQuery.Item);
	}
	async getTimeIntervals(): Promise<any> {
		const docClient = new DocumentClient();
		const params = {
			TableName: 'TimeIntervals',
		};
		const timeIntervals = await docClient.scan(params).promise();

		return convertToCamelCase(timeIntervals.Items);
	}

	async getTimeIntervalById(id: string): Promise<any> {
		const docClient = new DocumentClient();
		const params = {
			TableName: 'TimeIntervals',
			Key: { Id: id },
		};
		const timeIntervals = await docClient.get(params).promise();

		return convertToCamelCase(timeIntervals?.Item);
	}

	async getFeeConfigurationsByProvider(
		user: string,
		serviceProviderId: string
	): Promise<any> {
		const docClient = new DocumentClient();

		try {
			const userConverted = user as unknown as {
				Name: string;
				Value: string;
			}[];
			const userEmail = userConverted[0]?.Value;

			const users = await this.dbUserInstance
				.query('Email')
				.eq(userEmail)
				.exec();

			const userFind = users?.[0];
			if (userFind && userFind.Type !== 'PLATFORM') {
				throw new HttpException(
					{
						customCode: 'WGE0146',
					},
					HttpStatus.BAD_REQUEST
				);
			}

			await this.searchFindOne(serviceProviderId);
			const params = {
				TableName: 'FeeConfigurations',
				IndexName: 'ServiceProviderIdIndex',
				KeyConditionExpression: `ServiceProviderId = :serviceProviderId`,
				ExpressionAttributeValues: {
					':serviceProviderId': serviceProviderId,
				},
			};

			const feeConfigurations = await docClient.query(params).promise();

			return convertToCamelCase(feeConfigurations.Items?.[0]);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(
				`Error fetching Fee Configuration by Provider ID: ${error.message}`
			);
		}
	}

	async createOrUpdateProviderFeeConfiguration(
		createUpdateFeeConfigurationDTO: CreateUpdateFeeConfigurationDTO,
		user: string
	): Promise<CreateUpdateFeeConfigurationDTO> {
		try {
			const docClient = new DocumentClient();

			const currentDate = Date.now();
			const getProviderParams: DocumentClient.GetItemInput = {
				TableName: 'Providers',
				Key: { Id: createUpdateFeeConfigurationDTO.serviceProviderId },
			};

			let providerFeeConfig;

			const provider = await docClient.get(getProviderParams).promise();

			const userConverted = user as unknown as {
				Name: string;
				Value: string;
			}[];
			const userEmail = userConverted[0]?.Value;

			const users = await this.dbUserInstance
				.query('Email')
				.eq(userEmail)
				.exec();

			const userFind = users?.[0];
			if (userFind && userFind.Type !== 'PLATFORM') {
				throw new HttpException(
					{
						customCode: 'WGE0146',
					},
					HttpStatus.BAD_REQUEST
				);
			}

			if (!provider.Item) {
				throw new HttpException(
					{
						customCode: 'WGE0040',
					},
					HttpStatus.NOT_FOUND
				);
			}

			if (createUpdateFeeConfigurationDTO.feeConfigurationId) {
				providerFeeConfig = await this.getProviderFeeConfiguration(
					createUpdateFeeConfigurationDTO.feeConfigurationId
				);
			}

			const params = {
				TableName: 'FeeConfigurations',
				Item: {
					Id: createUpdateFeeConfigurationDTO.feeConfigurationId
						? createUpdateFeeConfigurationDTO.feeConfigurationId
						: uuidv4(),
					ServiceProviderId: createUpdateFeeConfigurationDTO.serviceProviderId,
					Percent: createUpdateFeeConfigurationDTO.percent,
					Comission: createUpdateFeeConfigurationDTO.comission,
					Base: createUpdateFeeConfigurationDTO.base,
					...(createUpdateFeeConfigurationDTO.feeConfigurationId && {
						CreatedDate: providerFeeConfig.createdDate,
						CreatedBy: providerFeeConfig.createdBy,
						UpdatedBy: userFind.Id,
						UpdatedDate: currentDate,
					}),
					...(!createUpdateFeeConfigurationDTO.feeConfigurationId && {
						UpdatedBy: userFind.Id,
						UpdatedDate: currentDate,
						CreatedDate: currentDate,
						CreatedBy: userFind.Id,
					}),
				},
			};

			await docClient.put(params).promise();

			return convertToCamelCase(params.Item);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error Updating Fee Configuration: ${error.message}`);
		}
	}

	async getProviderFeeConfiguration(feeConfigurationId: string) {
		const docClient = new DocumentClient();

		const getFeeConfigParams: DocumentClient.GetItemInput = {
			TableName: 'FeeConfigurations',
			Key: { Id: feeConfigurationId },
		};

		try {
			const result = await docClient.get(getFeeConfigParams).promise();

			if (!result.Item) {
				throw new HttpException(
					{
						customCode: 'WGE0145',
					},
					HttpStatus.NOT_FOUND
				);
			}

			return convertToCamelCase(result.Item);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(
				`Error fetching Fee Configuration by ID: ${error.message}`
			);
		}
	}

	async getProviderFeeConfigurationByProvider(serviceProviderId: string) {
		const docClient = new DocumentClient();

		const getFeeConfigParams: DocumentClient.QueryInput = {
			TableName: 'FeeConfigurations',
			IndexName: 'ServiceProviderIdIndex',
			KeyConditionExpression: 'ServiceProviderId = :serviceProviderId',
			ExpressionAttributeValues: {
				':serviceProviderId': serviceProviderId,
			},
		};

		try {
			const result = await docClient.query(getFeeConfigParams).promise();

			return convertToCamelCase(result.Items);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(
				`Error fetching payments parameters by serviceProvider: ${error.message}`
			);
		}
	}

	async getPaymentsParametersPaginated(
		getPaymentsParametersPaginated: GetPaymentsParametersPaginated
	): Promise<{
		paymentParameters: {
			id: string;
			name: string;
			active: boolean;
			interval: string;
			frequency: number;
			cost: number;
			asset: string;
		}[];
		currentPage: number;
		total: number;
		totalPages: number;
	}> {
		const {
			page = 1,
			items = 10,
			search,
			serviceProviderId,
		} = getPaymentsParametersPaginated;
		const docClient = new DocumentClient();

		const params: DocumentClient.ScanInput = {
			TableName: 'PaymentParameters',
			IndexName: 'ServiceProviderIdIndex',
			FilterExpression: 'ServiceProviderId = :serviceProviderId', // Expresión de filtro
			ExpressionAttributeValues: {
				':serviceProviderId': serviceProviderId,
			},
		};

		try {
			const result = await docClient.scan(params).promise();
			let paymentParameters = convertToCamelCase(result.Items || []);

			if (search) {
				const regex = new RegExp(search, 'i');
				paymentParameters = paymentParameters.filter(
					paymentParameter =>
						regex.test(paymentParameter.name) ||
						regex.test(paymentParameter.interval) ||
						regex.test(paymentParameter.asset)
				);
			}

			paymentParameters.sort((a, b) => {
				if (a.active !== b.active) {
					return a.active ? -1 : 1;
				}
				const nameA = a?.name || '';
				const nameB = b?.name || '';
				return nameA.localeCompare(nameB);
			});

			const total = paymentParameters.length;
			const offset = (Number(page) - 1) * Number(items);
			let paginatedPaymentParameters = paymentParameters.slice(
				offset,
				offset + Number(items)
			);

			paginatedPaymentParameters = paginatedPaymentParameters.map(
				paymentParameter => ({
					id: paymentParameter?.id,
					name: paymentParameter?.name,
					active: paymentParameter?.active,
					frequency: paymentParameter?.frequency,
					interval: paymentParameter?.interval,
					cost: paymentParameter?.cost,
					asset: paymentParameter?.asset,
				})
			);

			const totalPages = Math.ceil(total / Number(items));

			return {
				paymentParameters: paginatedPaymentParameters,
				currentPage: Number(page),
				total,
				totalPages,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error fetching payments parameters: ${error.message}`);
		}
	}

	async togglePaymentParameter(
		serviceProviderId: string,
		paymentParameterId: string,
		user: string
	) {
		const docClient = new DocumentClient();

		const userConverted = user as unknown as {
			Name: string;
			Value: string;
		}[];
		const email = userConverted[0]?.Value;
		try {
			const userFind = await this.dbUserInstance
				.query('Email')
				.eq(email)
				.exec();

			const userDb = userFind?.[0];

			const providerId =
				userDb && userDb?.Type === 'PROVIDER'
					? userDb?.ServiceProviderId
					: serviceProviderId;

			const params = {
				TableName: 'PaymentParameters',
				IndexName: 'ServiceProviderIdIndex',
				KeyConditionExpression: `ServiceProviderId = :serviceProviderId`,
				FilterExpression: 'Id = :paymentParameterId',
				ExpressionAttributeValues: {
					':serviceProviderId': providerId,
					':paymentParameterId': paymentParameterId,
				},
			};

			if (!userDb) {
				throw new HttpException(
					{
						customCode: 'WGE0040',
						...errorCodes.WGE0040,
					},
					HttpStatus.NOT_FOUND
				);
			}

			const paymentParameter = await docClient.query(params).promise();

			if (!paymentParameter?.Items?.[0]) {
				throw new HttpException(
					{
						customCode: 'WGE0119',
						statusCode: HttpStatus.NOT_FOUND,
					},
					HttpStatus.NOT_FOUND
				);
			}

			const active = !paymentParameter?.Items?.[0].Active;

			const toggleParams = {
				TableName: 'PaymentParameters',
				Key: {
					Id: paymentParameterId,
				},
				UpdateExpression: 'SET Active = :activePaymentParameter',
				ExpressionAttributeValues: {
					':activePaymentParameter': active,
				},
				ReturnValues: 'ALL_NEW',
			};

			const paymentParameterUpdaate = await docClient
				.update(toggleParams)
				.promise();

			return convertToCamelCase(paymentParameterUpdaate.Attributes);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error Toggle payments parameters: ${error.message}`);
		}
	}

	async getProviderId(providerId: string, user: string) {
		const userConverted = user as unknown as {
			Name: string;
			Value: string;
		}[];
		const userEmail = userConverted[0]?.Value;

		const users = await this.dbUserInstance.query('Email').eq(userEmail).exec();

		const userFind = users?.[0];

		const serviceProviderId =
			userFind && userFind?.Type === 'PROVIDER'
				? userFind?.ServiceProviderId
				: providerId;

		return serviceProviderId;
	}

	async getServiceProviderWallet(walletAddress: string) {
		const docClient = new DocumentClient();

		const getFeeConfigParams: DocumentClient.QueryInput = {
			TableName: 'Wallets',
			IndexName: 'WalletAddressIndex',
			KeyConditionExpression: 'WalletAddress = :walletAddress',
			ExpressionAttributeValues: {
				':walletAddress': walletAddress,
			},
		};

		try {
			const result = await docClient.query(getFeeConfigParams).promise();

			return convertToCamelCase(result.Items?.[0]);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(
				`Error fetching wallet address by serviceProvider: ${error.message}`
			);
		}
	}

	async getAssetByWalletAddress(rafikiId: string, token: string) {
		try {
			const url =
				process.env.WALLET_URL + `/api/v1/wallets-rafiki/${rafikiId}/asset`;

			const response = await axios.get(url, {
				headers: {
					Authorization: `Bearer ${token}`,
				},
			});

			const assets = response?.data?.data;

			return assets?.code ?? '';
		} catch (error) {
			throw new HttpException(
				error.response?.data || 'Error getting asset by wallet address',
				error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}
}
