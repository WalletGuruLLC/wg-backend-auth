import {
	Body,
	Controller,
	Delete,
	Get,
	HttpException,
	HttpStatus,
	Param,
	Patch,
	Put,
	Post,
	Query,
	Req,
	Res,
	UseGuards,
	UsePipes,
	ValidationPipe,
	UploadedFile,
	UseInterceptors,
} from '@nestjs/common';
import {
	ApiBearerAuth,
	ApiCreatedResponse,
	ApiForbiddenResponse,
	ApiOkResponse,
	ApiTags,
	ApiOperation,
	ApiResponse,
	ApiParam,
} from '@nestjs/swagger';

import { AuthChangePasswordUserDto } from '../dto/auth-change-password-user.dto';
import { AuthConfirmPasswordUserDto } from '../dto/auth-confirm-password-user.dto';
import { AuthForgotPasswordUserDto } from '../dto/auth-forgot-password-user.dto';
import { CreateUserDto } from '../dto/create-user.dto';
import { SignInDto } from '../dto/signin.dto';
import { SendOtpDto } from '../dto/send-otp-email.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { UserService } from '../service/user.service';
import {
	errorCodes,
	licenseFormats,
	successCodes,
} from '../../../utils/constants';
import { GetUsersDto } from '../dto/get-user.dto';
import { VerifyOtpDto } from '../../auth/dto/verify-otp.dto';
import { CognitoAuthGuard } from '../guard/cognito-auth.guard';
import { UpdateStatusUserDto } from '../dto/update-status-user.dto';
import { validatePassword } from '../../../utils/helpers/validatePassword';
import { ValidateAccessDto } from '../dto/validate-access-middleware.dto';
import { validatePhoneNumber } from 'src/utils/helpers/validatePhone';
import { isValidEmail } from 'src/utils/helpers/validateEmail';
import { FileInterceptor } from '@nestjs/platform-express';
import * as Sentry from '@sentry/nestjs';
import { validateLicense } from 'src/utils/helpers/validateLicenseDriver';

@ApiTags('user')
@Controller('api/v1/users')
@ApiBearerAuth('JWT')
export class UserController {
	constructor(private readonly userService: UserService) {}

	@UseGuards(CognitoAuthGuard)
	@Post('/register')
	@ApiCreatedResponse({
		description: 'The record has been successfully created.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async create(@Body() createUserDto: CreateUserDto, @Res() res, @Req() req) {
		try {
			const userRequest = req.user?.UserAttributes;
			createUserDto.email = createUserDto?.email.toLowerCase();
			if (!isValidEmail(createUserDto?.email)) {
				return res.status(HttpStatus.FORBIDDEN).send({
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0048',
					customMessage: errorCodes?.WGE0048?.description,
					customMessageEs: errorCodes.WGE0048?.descriptionEs,
				});
			}
			const userFind = await this.userService.findOneByEmail(
				createUserDto?.email?.toLowerCase()
			);
			if (userFind) {
				return res.status(HttpStatus.FORBIDDEN).send({
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0003',
					customMessage: errorCodes?.WGE0003?.description,
					customMessageEs: errorCodes.WGE0003?.descriptionEs,
				});
			}

			if (!['WALLET', 'PLATFORM', 'PROVIDER'].includes(createUserDto.type)) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0017',
					customMessage: errorCodes.WGE0017?.description,
					customMessageEs: errorCodes.WGE0017?.descriptionEs,
				});
			}

			if (createUserDto?.type === 'WALLET' && !createUserDto?.passwordHash) {
				return res.status(HttpStatus.PARTIAL_CONTENT).send({
					statusCode: HttpStatus.PARTIAL_CONTENT,
					customCode: 'WGE00018',
					customMessage: errorCodes?.WGE00018?.description,
					customMessageEs: errorCodes.WGE00018?.descriptionEs,
				});
			}

			if (['PLATFORM', 'PROVIDER'].includes(createUserDto.type)) {
				if (
					!createUserDto?.firstName ||
					!createUserDto?.lastName ||
					!createUserDto?.email ||
					!createUserDto?.type ||
					!createUserDto?.roleId ||
					(createUserDto.type !== 'PROVIDER' &&
						!createUserDto?.serviceProviderId) ||
					!createUserDto?.phone
				) {
					return res.status(HttpStatus.PARTIAL_CONTENT).send({
						statusCode: HttpStatus.PARTIAL_CONTENT,
						customCode: 'WGE00018',
						customMessage: errorCodes?.WGE00018?.description,
						customMessageEs: errorCodes.WGE00018?.descriptionEs,
					});
				}
			} else {
				if (
					!createUserDto?.email ||
					!createUserDto?.passwordHash ||
					!createUserDto?.type ||
					!createUserDto?.termsConditions ||
					!createUserDto?.privacyPolicy ||
					createUserDto?.termsConditions !== true ||
					createUserDto?.privacyPolicy !== true
				) {
					return res.status(HttpStatus.PARTIAL_CONTENT).send({
						statusCode: HttpStatus.PARTIAL_CONTENT,
						customCode: 'WGE00018',
						customMessage: errorCodes?.WGE00018?.description,
						customMessageEs: errorCodes.WGE00018?.descriptionEs,
					});
				}
			}

			if (validatePhoneNumber(createUserDto?.phone) === false) {
				return res.status(HttpStatus.PARTIAL_CONTENT).send({
					statusCode: HttpStatus.PARTIAL_CONTENT,
					customCode: 'WGE0113',
				});
			}

			if (createUserDto?.type == 'PROVIDER') {
				const { phone } = createUserDto;

				if (!phone || !phone.trim() || !validatePhoneNumber(phone)) {
					return res.status(HttpStatus.PARTIAL_CONTENT).send({
						statusCode: HttpStatus.PARTIAL_CONTENT,
						customCode: 'WGE0127',
					});
				}
			}

			const userPhone = await this.userService.findOneByPhone(
				createUserDto?.phone
			);

			if (userPhone) {
				return res.status(HttpStatus.FORBIDDEN).send({
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0003',
					customMessage: errorCodes?.WGE0003?.description,
					customMessageEs: errorCodes.WGE0003?.descriptionEs,
				});
			}

			const result = await this.userService.create(createUserDto, userRequest);
			return res.status(HttpStatus.CREATED).send({
				statusCode: HttpStatus.CREATED,
				customCode: 'WGE0018',
				customMessage: successCodes.WGE0018?.description,
				customMessageEs: successCodes.WGE0018?.descriptionEs,
				data: result,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Post('/register-app')
	@ApiCreatedResponse({
		description: 'The record has been successfully created.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async createApp(
		@Body() createUserDto: CreateUserDto,
		@Res() res,
		@Req() req
	) {
		try {
			createUserDto.email = createUserDto?.email.toLowerCase();
			if (!isValidEmail(createUserDto?.email)) {
				return res.status(HttpStatus.FORBIDDEN).send({
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0048',
					customMessage: errorCodes?.WGE0048?.description,
					customMessageEs: errorCodes.WGE0048?.descriptionEs,
				});
			}
			const userFind = await this.userService.findOneByEmail(
				createUserDto?.email
			);
			if (userFind) {
				return res.status(HttpStatus.FORBIDDEN).send({
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0003',
					customMessage: errorCodes?.WGE0003?.description,
					customMessageEs: errorCodes.WGE0003?.descriptionEs,
				});
			}

			if (!['WALLET', 'PLATFORM', 'PROVIDER'].includes(createUserDto.type)) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0017',
					customMessage: errorCodes.WGE0017?.description,
					customMessageEs: errorCodes.WGE0017?.descriptionEs,
				});
			}

			if (createUserDto?.type === 'WALLET' && !createUserDto?.passwordHash) {
				return res.status(HttpStatus.PARTIAL_CONTENT).send({
					statusCode: HttpStatus.PARTIAL_CONTENT,
					customCode: 'WGE00018',
					customMessage: errorCodes?.WGE00018?.description,
					customMessageEs: errorCodes.WGE00018?.descriptionEs,
				});
			}

			if (['PLATFORM', 'PROVIDER'].includes(createUserDto.type)) {
				if (
					!createUserDto?.firstName ||
					!createUserDto?.lastName ||
					!createUserDto?.email ||
					!createUserDto?.type ||
					!createUserDto?.roleId
				) {
					return res.status(HttpStatus.PARTIAL_CONTENT).send({
						statusCode: HttpStatus.PARTIAL_CONTENT,
						customCode: 'WGE00018',
						customMessage: errorCodes?.WGE00018?.description,
						customMessageEs: errorCodes.WGE00018?.descriptionEs,
					});
				}
			} else {
				if (
					!createUserDto?.email ||
					!createUserDto?.passwordHash ||
					!createUserDto?.type ||
					!createUserDto?.termsConditions ||
					!createUserDto?.privacyPolicy ||
					createUserDto?.termsConditions !== true ||
					createUserDto?.privacyPolicy !== true
				) {
					return res.status(HttpStatus.PARTIAL_CONTENT).send({
						statusCode: HttpStatus.PARTIAL_CONTENT,
						customCode: 'WGE00018',
						customMessage: errorCodes?.WGE00018?.description,
						customMessageEs: errorCodes.WGE00018?.descriptionEs,
					});
				}
			}

			const result = await this.userService.create(createUserDto);
			return res.status(HttpStatus.CREATED).send({
				statusCode: HttpStatus.CREATED,
				customCode: 'WGE0018',
				customMessage: successCodes.WGE0018?.description,
				customMessageEs: successCodes.WGE0018?.descriptionEs,
				data: result,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Put('/update-profile/:id')
	@ApiOkResponse({
		description: 'The record has been successfully updated.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async updateAdmin(
		@Param('id') id: string,
		@Body() updateUserDto: UpdateUserDto,
		@Res() res
	) {
		try {
			const userFind = await this.userService.findOne(id);
			if (!userFind) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
				});
			}

			if (
				updateUserDto?.phone &&
				updateUserDto?.phone?.trim() !== '' &&
				validatePhoneNumber(updateUserDto?.phone) === false
			) {
				return res.status(HttpStatus.FORBIDDEN).send({
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0127',
				});
			}

			const userPhone = await this.userService.findOneByPhone(
				updateUserDto?.phone
			);

			if (userPhone) {
				return res.status(HttpStatus.FORBIDDEN).send({
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0113',
				});
			}

			const user = await this.userService.update(id, updateUserDto);
			delete user.passwordHash;

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGS0018',
				data: user,
			});
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Get('/current-user')
	@ApiOkResponse({
		description: 'Successfully returned user info',
	})
	@ApiForbiddenResponse({ description: 'Invalid access token.' })
	async getUserInfo(@Req() req, @Res() res) {
		try {
			const userInfo = req.user;
			const userFind = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);

			let accessLevel = {};
			let platformAccessLevel = {};
			if (userFind?.roleId !== 'EMPTY') {
				accessLevel = await this.userService.listAccessLevels(userFind?.roleId);
				platformAccessLevel =
					await this.userService.listAccessLevelsPlatformModules(
						userFind?.roleId
					);
			}

			userFind.accessLevel = accessLevel;
			userFind.platformAccessLevel = platformAccessLevel;

			delete userFind?.passwordHash;
			delete userFind?.otpTimestamp;

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0022',
				customMessage: successCodes.WGE0022?.description,
				customMessageEs: successCodes.WGE0022?.descriptionEs,
				data: userFind,
			});
		} catch (error) {
			return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
				statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				customCode: 'WGE0021',
				customMessage: errorCodes.WGE0021?.description,
				customMessageEs: errorCodes.WGE0021?.descriptionEs,
			});
		}
	}

	@Post('/verify/register')
	@ApiOkResponse({
		description: 'The user has been successfully verified.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async verifySignUp(@Body() verifyOtpDto: VerifyOtpDto, @Res() res) {
		try {
			const result = await this.userService.verifySignUp(verifyOtpDto);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0013',
				customMessage: successCodes.WGE0013?.description,
				customMessageEs: successCodes.WGE0013?.descriptionEs,
				data: result,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0005',
					customMessage: errorCodes.WGE0005?.description,
					customMessageEs: errorCodes.WGE0005?.descriptionEs,
				},
				HttpStatus.UNAUTHORIZED
			);
		}
	}

	@Get('/:id')
	@ApiOkResponse({
		description: 'The record has been successfully retrieved.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async findOne(@Param('id') id: string, @Res() res) {
		try {
			const user = await this.userService.findOne(id);
			if (!user) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				});
			}
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0019',
				customMessage: successCodes.WGE0019?.description,
				customMessageEs: successCodes.WGE0019?.descriptionEs,
				data: user,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Put('/:id')
	@ApiOkResponse({
		description: 'The record has been successfully updated.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async update(
		@Param('id') id: string,
		@Body() updateUserDto: UpdateUserDto,
		@Req() req,
		@Res() res
	) {
		try {
			const userRequest = req.user?.UserAttributes;
			const userConverted = userRequest as unknown as {
				Name: string;
				Value: string;
			}[];
			const emailRequest = userConverted[0]?.Value;
			const userFind = await this.userService.findOne(id);
			if (!userFind) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				});
			}

			if (emailRequest === userFind.email && userFind.type !== 'WALLET') {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				});
			}

			if (userFind?.first === false && updateUserDto?.email) {
				updateUserDto.email = userFind?.email;
			}

			if (
				updateUserDto?.phone &&
				updateUserDto?.phone?.trim() !== '' &&
				validatePhoneNumber(updateUserDto?.phone) === false
			) {
				return res.status(HttpStatus.PARTIAL_CONTENT).send({
					statusCode: HttpStatus.PARTIAL_CONTENT,
					customCode: 'WGE0113',
					customMessage: errorCodes?.WGE00044?.description,
					customMessageEs: errorCodes?.WGE00044?.descriptionEs,
				});
			}

			if (
				updateUserDto?.identificationType &&
				!updateUserDto?.identificationNumber
			) {
				return res.status(HttpStatus.PARTIAL_CONTENT).send({
					statusCode: HttpStatus.PARTIAL_CONTENT,
					customCode: 'WGE0122',
				});
			}

			if (updateUserDto?.identificationType?.match(/license/i)) {
				const { stateLocation, identificationNumber } = updateUserDto;

				const regex = /^[a-zA-Z0-9]+$/;
				if (updateUserDto?.identificationNumber?.match(regex)) {
					if (
						stateLocation &&
						identificationNumber &&
						licenseFormats[
							stateLocation.trim().replace(/\b\w/g, char => char.toUpperCase())
						]
					) {
						const isValidLicense = await validateLicense(
							stateLocation,
							identificationNumber
						);

						if (!isValidLicense) {
							return res.status(HttpStatus.PARTIAL_CONTENT).send({
								statusCode: HttpStatus.PARTIAL_CONTENT,
								customCode: 'WGE0159',
							});
						}
					}
				} else {
					return res.status(HttpStatus.PARTIAL_CONTENT).send({
						statusCode: HttpStatus.PARTIAL_CONTENT,
						customCode: 'WGE0158',
					});
				}
			}

			const user = await this.userService.update(id, updateUserDto);
			delete user.passwordHash;

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0020',
				customMessage: successCodes.WGE0020?.description,
				customMessageEs: successCodes.WGE0020?.descriptionEs,
				data: user,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Put(':id/toggle-first')
	@ApiOperation({ summary: 'Toggle the first field of a user' })
	@ApiParam({ name: 'id', description: 'ID of the user', type: String })
	@ApiResponse({
		status: 200,
		description: 'User first field toggled successfully.',
	})
	@ApiResponse({
		status: 404,
		description: 'User not found.',
	})
	async toggleFirst(@Param('id') id: string) {
		try {
			const user = await this.userService.toggleFirst(id);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0020',
				customMessage: successCodes.WGE0020?.description,
				customMessageEs: successCodes.WGE0020?.descriptionEs,
				data: user,
			};
		} catch (error) {
			if (
				error instanceof HttpException &&
				error.getStatus() === HttpStatus.INTERNAL_SERVER_ERROR
			) {
				throw new HttpException(
					{
						customCode: 'WGE0016',
						...errorCodes.WGE0016,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
			throw error;
		}
	}

	@Delete('/:id')
	@ApiOkResponse({
		description: 'The record has been successfully deleted.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async remove(@Param('id') id: string, @Res() res) {
		try {
			const userFind = await this.userService.findOne(id);
			if (!userFind) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				});
			}
			await this.userService.remove(id);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0021',
				customMessage: successCodes.WGE0021?.description,
				customMessageEs: successCodes.WGE0021?.descriptionEs,
			});
		} catch (error) {
			if (error.message === 'User not found in database') {
				throw new HttpException(
					{
						statusCode: HttpStatus.NOT_FOUND,
						customCode: 'WGE0002',
						customMessage: errorCodes.WGE0002?.description,
						customMessageEs: errorCodes.WGE0002?.descriptionEs,
					},
					HttpStatus.NOT_FOUND
				);
			} else {
				throw new HttpException(
					{
						statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
						customCode: 'WGE0016',
						customMessage: errorCodes.WGE0016?.description,
						customMessageEs: errorCodes.WGE0016?.descriptionEs,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
		}
	}

	@Post('/signin')
	@ApiOkResponse({
		description: 'The user has been successfully signed in.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async signin(@Body() signinDto: SignInDto, @Res() res) {
		signinDto.email = signinDto?.email.toLowerCase();
		try {
			const userFind = await this.userService.findOneByEmail(
				signinDto?.email?.toLowerCase()
			);
			if (!userFind) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				});
			}
			if (!userFind?.active) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE00108',
					customMessage: errorCodes.WGE00108?.description,
					customMessageEs: errorCodes.WGE00108?.descriptionEs,
				});
			}
			await this.userService.signin(signinDto);
			return res.status(HttpStatus.OK).json({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0018',
				customMessage: successCodes.WGE0018?.description,
				customMessageEs: successCodes.WGE0018?.descriptionEs,
			});
		} catch (error) {
			throw new HttpException(
				{
					customCode: 'WGE0001',
					...errorCodes.WGE0001,
					message: error.message,
				},
				HttpStatus.UNAUTHORIZED
			);
		}
	}

	@Post('/verify/otp/mfa')
	@ApiOkResponse({
		description: 'The user has been successfully signed in.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async verifyOtp(@Body() verifyOtpDto: VerifyOtpDto, @Res() res) {
		try {
			verifyOtpDto.email = verifyOtpDto?.email.toLowerCase();
			const result = await this.userService.verifyOtp(verifyOtpDto);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0014',
				customMessage: successCodes.WGE0014?.description,
				customMessageEs: successCodes.WGE0014?.descriptionEs,
				data: result,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0005',
					customMessage: errorCodes.WGE0005?.description,
					customMessageEs: errorCodes.WGE0005?.descriptionEs,
				},
				HttpStatus.UNAUTHORIZED
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Post('/change-password')
	@ApiOkResponse({
		description: 'The password has been successfully changed.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async changePassword(
		@Body() authChangePasswordUserDto: AuthChangePasswordUserDto,
		@Req() req,
		@Res() res
	) {
		try {
			const userInfo = req.user;
			const userFind = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);
			if (!userFind) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				});
			}
			if (!validatePassword(authChangePasswordUserDto?.newPassword)) {
				return res.status(HttpStatus.BAD_REQUEST).send({
					statusCode: HttpStatus.BAD_REQUEST,
					customCode: 'WGE0008',
					customMessage: errorCodes.WGE0008?.description,
					customMessageEs: errorCodes.WGE0008?.descriptionEs,
				});
			}
			const changePassworFormat = {
				token: req.token,
				currentPassword: authChangePasswordUserDto?.currentPassword,
				newPassword: authChangePasswordUserDto?.newPassword,
			};
			await this.userService.changeUserPassword(changePassworFormat);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0009',
				customMessage: successCodes.WGE0009?.description,
				customMessageEs: successCodes.WGE0009?.descriptionEs,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0007',
					customMessage: errorCodes.WGE0007?.description,
					customMessageEs: errorCodes.WGE0007?.descriptionEs,
				},
				HttpStatus.UNAUTHORIZED
			);
		}
	}

	@Post('/forgot-password')
	@UsePipes(ValidationPipe)
	@ApiOkResponse({
		description: 'The password reset request has been successfully processed.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async forgotPassword(
		@Body() authForgotPasswordUserDto: AuthForgotPasswordUserDto,
		@Res() res
	) {
		try {
			const userFind = await this.userService.findOneByEmail(
				authForgotPasswordUserDto?.email?.toLowerCase()
			);
			if (!userFind) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				});
			}
			await this.userService.forgotUserPassword(authForgotPasswordUserDto);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0018',
				customMessage: successCodes.WGE0018?.description,
				customMessageEs: successCodes.WGE0018?.descriptionEs,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Post('/confirm-password')
	@UsePipes(ValidationPipe)
	@ApiOkResponse({
		description: 'The password has been successfully confirmed.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async confirmPassword(
		@Body() authConfirmPasswordUserDto: AuthConfirmPasswordUserDto,
		@Res() res
	) {
		try {
			const userFind = await this.userService.findOneByEmail(
				authConfirmPasswordUserDto?.email?.toLowerCase()
			);
			if (!userFind) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				});
			}
			await this.userService.confirmUserPassword(authConfirmPasswordUserDto);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0012',
				customMessage: successCodes.WGE0012?.description,
				customMessageEs: successCodes.WGE0012?.descriptionEs,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Get('/')
	@ApiOkResponse({
		description: 'Successfully returned users',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async getUsers(@Query() getUsersDto: GetUsersDto, @Req() req, @Res() res) {
		try {
			const userRequest = req.user?.UserAttributes;

			const users = await this.userService.getUsersByType(
				getUsersDto,
				userRequest
			);
			if (
				getUsersDto.type &&
				!['WALLET', 'PLATFORM', 'PROVIDER'].includes(getUsersDto.type)
			) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0017',
					customMessage: errorCodes.WGE0017?.description,
					customMessageEs: errorCodes.WGE0017?.descriptionEs,
				});
			}
			if (users?.total > 0 && getUsersDto?.page > users?.totalPages) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0023',
					customMessage: errorCodes.WGE0023?.description,
					customMessageEs: errorCodes.WGE0023?.descriptionEs,
				});
			}

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0019',
				customMessage: successCodes.WGE0019?.description,
				customMessageEs: successCodes.WGE0019?.descriptionEs,
				data: users,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Patch('/update-status/:id')
	@ApiOkResponse({
		description: 'The user has been successfully updated.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async changeStatusUser(
		@Body() updateUserDto: UpdateStatusUserDto,
		@Req() req,
		@Res() res
	) {
		try {
			const userRequest = req.user?.UserAttributes;
			const userConverted = userRequest as unknown as {
				Name: string;
				Value: string;
			}[];
			const emailRequest = userConverted[0]?.Value;

			const userFind = await this.userService.findOneByEmail(
				updateUserDto?.email?.toLowerCase()
			);
			if (!userFind) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				});
			}
			if (emailRequest === userFind.email) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				});
			}
			const user = await this.userService.changeStatusUser(updateUserDto);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0020',
				customMessage: successCodes.WGE0020?.description,
				customMessageEs: successCodes.WGE0020?.descriptionEs,
				data: user,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Post('send-otp')
	@ApiOkResponse({
		description: successCodes.WGE0071?.description,
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async sendOtpEmail(@Body() sendOtpDto: SendOtpDto) {
		try {
			const foundUser = await this.userService.findOneByEmail(sendOtpDto.email);
			if (!foundUser) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				};
			}
			await this.userService.resendOtp(foundUser);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0071',
				customMessage: successCodes.WGE0071?.description,
				customMessageEs: successCodes.WGE0071?.descriptionEs,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0070',
					customMessage: errorCodes.WGE0070?.description,
					customMessageEs: errorCodes.WGE0070?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Post('/logout')
	@ApiOkResponse({
		description: 'Logout successfully.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async revokeTokenLogout(@Req() req, @Res() res) {
		try {
			const token = req.token;
			await this.userService.revokeTokenLogout(token);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0072',
				customMessage: successCodes.WGE0072?.description,
				customMessageEs: successCodes.WGE0072?.descriptionEs,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.BAD_REQUEST,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				},
				HttpStatus.BAD_REQUEST
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Post('/validate-access')
	@ApiOkResponse({ description: 'Validate access successfully.' })
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async validateAccess(
		@Body() validateAccess: ValidateAccessDto,
		@Req() req,
		@Res() res
	) {
		try {
			const resultAccess = await this.userService.validateAccess(
				req.token,
				validateAccess.path,
				validateAccess.method
			);

			if (resultAccess?.customCode) {
				return res.status(resultAccess?.statusCode).send(resultAccess);
			}

			if (!resultAccess.hasAccess) {
				return res.status(HttpStatus.UNAUTHORIZED).send({
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0038',
				});
			}

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0078',
			});
		} catch (error) {
			const statusCode = error.status || HttpStatus.BAD_REQUEST;
			const customCode = error.customCode || 'WGE0016';
			const customMessage = error.customMessage || 'An error occurred.';

			return res.status(statusCode).send({
				statusCode,
				customCode,
				customMessage,
			});
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Put('upload-image/:id')
	@UsePipes(ValidationPipe)
	@UseInterceptors(FileInterceptor('file'))
	@ApiOperation({ summary: 'Update user profile image' })
	@ApiParam({ name: 'id', description: 'ID of the provider', type: String })
	@ApiResponse({ status: 200, description: 'Provider updated successfully.' })
	@ApiResponse({ status: 500, description: 'Error updating provider.' })
	async uploadImage(
		@Param('id') id: string,
		@UploadedFile() file: Express.Multer.File
	) {
		try {
			const provider = await this.userService.uploadImage(id, file);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0083',
				customMessage: successCodes?.WGE0083?.description,
				customMessageEs: successCodes.WGE0083?.descriptionEs,
				data: provider,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0050',
					customMessage: errorCodes?.WGE0050?.description,
					customMessageEs: errorCodes.WGE0050?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Patch(':id/toggle-contact')
	@ApiOperation({ summary: 'Toggle the first field of a user' })
	@ApiParam({ name: 'id', description: 'ID of the user', type: String })
	@ApiResponse({
		status: 200,
		description: 'User first field toggled successfully.',
	})
	@ApiResponse({
		status: 404,
		description: 'User not found.',
	})
	async toggleContact(@Param('id') id: string) {
		try {
			const user = await this.userService.toggleContact(id);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0020',
				customMessage: successCodes.WGE0020?.description,
				customMessageEs: successCodes.WGE0020?.descriptionEs,
				data: { user: user },
			};
		} catch (error) {
			if (
				error instanceof HttpException &&
				error.getStatus() === HttpStatus.INTERNAL_SERVER_ERROR
			) {
				throw new HttpException(
					{
						customCode: 'WGE0016',
						...errorCodes.WGE0016,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
			throw error;
		}
	}
}
