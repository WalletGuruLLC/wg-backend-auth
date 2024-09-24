import { GetProvidersDto } from './../dto/getProviderDto';
import { DocumentClient } from 'aws-sdk/clients/dynamodb';
import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import * as Sentry from '@sentry/nestjs';
import { errorCodes } from '../../../utils/constants';
import { Provider } from '../entities/provider.entity';
import { ProviderSchema } from '../entities/provider.schema';
import {
	CreateProviderDto,
	ChangeStatusProviderDto,
	UpdateProviderDto,
} from '../dto/provider';
import { convertToCamelCase } from '../../../utils/helpers/convertCamelCase';
import { v4 as uuidv4 } from 'uuid';
import {
	S3Client,
	DeleteObjectCommand,
	PutObjectCommand,
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

@Injectable()
export class ProviderService {
	private readonly dbInstance: Model<Provider>;
	private dbUserInstance: Model<User>;

	constructor() {
		const tableName = 'Providers';
		this.dbInstance = dynamoose.model<Provider>(tableName, ProviderSchema, {
			create: false,
			waitForActive: false,
		});
		this.dbUserInstance = dynamoose.model<User>('Users', UserSchema);
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
			let paginatedProviders = providers.slice(offset, offset + Number(items));

			paginatedProviders = paginatedProviders.map(provider => ({
				id: provider?.id,
				name: provider?.name,
				imageUrl: provider?.imageUrl,
				active: provider?.active,
			}));

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

			if (!result.Item) {
				throw new HttpException(
					{
						customCode: 'WGE0040',
						...errorCodes.WGE0040,
					},
					HttpStatus.NOT_FOUND
				);
			}

			return convertToCamelCase(result.Item);
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

			return convertToCamelCase(result.Item);
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
			'walletAddress',
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
			console.log('error', error);
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
		id: string,
		createProviderPaymentParameter: CreateProviderPaymentParameterDTO
	): Promise<CreateProviderPaymentParameterDTO> {
		const docClient = new DocumentClient();
		const existingPaymentParameter = await this.getPaymentParameters(
			createProviderPaymentParameter.serviceProviderId,
			{
				asset: createProviderPaymentParameter.asset,
				frequency: createProviderPaymentParameter.frequency,
			}
		);

		if (existingPaymentParameter.length > 0) {
			throw new HttpException(
				{
					customCode: 'WGE0117',
					statusCode: HttpStatus.BAD_REQUEST,
				},
				HttpStatus.BAD_REQUEST
			);
		}

		const params = {
			TableName: 'PaymentParameters',
			Item: {
				Id: id ? id : uuidv4(),
				Name: createProviderPaymentParameter.name,
				Description: createProviderPaymentParameter.description,
				Cost: createProviderPaymentParameter.cost,
				Frequency: createProviderPaymentParameter.frequency,
				Interval: createProviderPaymentParameter.interval,
				Asset: createProviderPaymentParameter.asset,
				ServiceProviderId: createProviderPaymentParameter.serviceProviderId,
				Percent: 1,
				Comision: 0,
				Base: 2,
			},
		};

		await docClient.put(params).promise();

		return createProviderPaymentParameter;
	}

	async getPaymentParameters(
		serviceProviderId: string,
		paymentParametersFilter: GetProviderPaymentParametersDTO
	): Promise<any> {
		const docClient = new DocumentClient();

		const expressionFilters = buildFilterExpressionDynamo(
			paymentParametersFilter
		);
		const params = {
			TableName: 'PaymentParameters',
			IndexName: 'ServiceProviderIdIndex',
			KeyConditionExpression: `ServiceProviderId = :serviceProviderId`,
			ExpressionAttributeValues: {
				':serviceProviderId': serviceProviderId,
				...(expressionFilters.expressionValues && {
					...expressionFilters.expressionValues,
				}),
			},
			...(expressionFilters.expression && {
				FilterExpression: expressionFilters.expression,
			}),
		};

		const paymentParameterQuery = await docClient.query(params).promise();

		return convertToCamelCase(paymentParameterQuery.Items);
	}
	async getTimeIntervals(): Promise<any> {
		const docClient = new DocumentClient();
		const params = {
			TableName: 'TimeIntervals',
		};
		const timeIntervals = await docClient.scan(params).promise();

		return convertToCamelCase(timeIntervals.Items);
	}
}
