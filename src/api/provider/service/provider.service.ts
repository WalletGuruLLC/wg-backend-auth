import { GetProvidersDto } from './../dto/getProviderDto';
import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import * as Sentry from '@sentry/nestjs';
import { errorCodes } from '../../../utils/constants';
import { Provider } from '../entities/provider.entity';
import { ProviderSchema } from '../entities/provider.schema';
import {
	CreateProviderDto,
	DeleteProviderDto,
	UpdateProviderDto,
} from '../dto/provider';
import { convertToCamelCase } from '../../../utils/helpers/convertCamelCase';
import { v4 as uuidv4 } from 'uuid';
import {
	S3Client,
	DeleteObjectCommand,
	PutObjectCommand,
} from '@aws-sdk/client-s3';

@Injectable()
export class ProviderService {
	private readonly dbInstance: Model<Provider>;

	constructor() {
		const tableName = 'Providers';
		this.dbInstance = dynamoose.model<Provider>(tableName, ProviderSchema, {
			create: false,
			waitForActive: false,
		});
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
			WalletAddress: createProviderDto.walletAddress,
			Logo: createProviderDto.logo,
			ContactInformation: createProviderDto.contactInformation,
		};
		return this.dbInstance.create(provider);
	}

	async findAll(getProvidersDto: GetProvidersDto): Promise<{
		providers: [];
		currentPage: number;
		total: number;
		totalPages: number;
	}> {
		const { page = 1, items = 10, search } = getProvidersDto;

		const query = this.dbInstance.scan();

		const result = await query.exec();
		let providers = convertToCamelCase(result);

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

		const total = providers.length;
		const offset = (Number(page) - 1) * Number(items);
		const paginatedProviders = providers.slice(offset, offset + Number(items));
		const totalPages = Math.ceil(total / Number(items));

		return {
			providers: paginatedProviders,
			currentPage: Number(page),
			total,
			totalPages,
		};
	}

	async findOne(id: string) {
		const provider = await this.dbInstance.get(id);
		if (!provider) {
			throw new HttpException(
				{
					customCode: 'WGE0040',
					...errorCodes.WGE0040,
				},
				HttpStatus.NOT_FOUND
			);
		}
		return provider;
	}

	async update(id: string, updateProviderDto: UpdateProviderDto) {
		try {
			const updatedProvider = {
				Id: id,
				Name: updateProviderDto.name,
				Description: updateProviderDto.description,
				Email: updateProviderDto.email,
				Phone: updateProviderDto.phone,
				EINNumber: updateProviderDto.einNumber,
				Country: updateProviderDto.country,
				City: updateProviderDto.city,
				ZipCode: updateProviderDto.zipCode,
				CompanyAddress: updateProviderDto.companyAddress,
				WalletAddress: updateProviderDto.walletAddress,
				Logo: updateProviderDto.logo,
				ContactInformation: updateProviderDto.contactInformation,
			};
			return convertToCamelCase(await this.dbInstance.update(updatedProvider));
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error updating provider: ${error.message}`);
		}
	}

	async changeStatus(id: string, deleteProvider: DeleteProviderDto) {
		try {
			const updatedProvider = {
				Id: id,
				Active: deleteProvider.active,
			};
			return convertToCamelCase(await this.dbInstance.update(updatedProvider));
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error updating provider: ${error.message}`);
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
}
