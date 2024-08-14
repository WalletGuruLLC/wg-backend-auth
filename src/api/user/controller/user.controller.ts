import {
	Body,
	Controller,
	Delete,
	Get,
	HttpException,
	HttpStatus,
	Param,
	Patch,
	Post,
	Req,
	UseGuards,
	UsePipes,
	ValidationPipe,
} from '@nestjs/common';
import {
	ApiCreatedResponse,
	ApiForbiddenResponse,
	ApiOkResponse,
	ApiTags,
} from '@nestjs/swagger';

import { AuthChangePasswordUserDto } from '../dto/auth-change-password-user.dto';
import { AuthConfirmPasswordUserDto } from '../dto/auth-confirm-password-user.dto';
import { AuthForgotPasswordUserDto } from '../dto/auth-forgot-password-user.dto';
import { CreateUserDto } from '../dto/create-user.dto';
import { SignInDto } from '../dto/signin.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { UserService } from '../service/user.service';
import { errorCodes, successCodes } from '../../../utils/constants';
import { GetUsersDto } from '../dto/get-user.dto';
import { VerifyOtpDto } from '../../auth/dto/verify-otp.dto';
import { CognitoAuthGuard } from '../guard/cognito-auth.guard';
import { UpdateStatusUserDto } from '../dto/update-status-user.dto';

@ApiTags('user')
@Controller('api/v1/users')
export class UserController {
	constructor(private readonly userService: UserService) {}

	@Post()
	@ApiCreatedResponse({
		description: 'The record has been successfully created.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async create(@Body() createUserDto: CreateUserDto) {
		try {
			const userFind = await this.userService.findOneByEmail(
				createUserDto?.email
			);
			if (userFind) {
				return {
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0003',
					customMessage: errorCodes?.WGE0003?.description,
					customMessageEs: errorCodes.WGE0003?.descriptionEs,
				};
			}

			if (!['WALLET', 'PLATFORM', 'PROVIDER'].includes(createUserDto.type)) {
				return {
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0017',
					customMessage: errorCodes.WGE0017?.description,
					customMessageEs: errorCodes.WGE0017?.descriptionEs,
				};
			}

			if (createUserDto?.type === 'WALLET' && !createUserDto?.passwordHash) {
				return {
					statusCode: HttpStatus.PARTIAL_CONTENT,
					customCode: 'WGE00018',
					customMessage: errorCodes?.WGE00018?.description,
					customMessageEs: errorCodes.WGE00018?.descriptionEs,
				};
			}

			const result = await this.userService.create(createUserDto);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0018',
				customMessage: successCodes.WGE0018?.description,
				customMessageEs: successCodes.WGE0018?.descriptionEs,
				data: result,
			};
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

	@Post('/verify/register/user')
	@ApiOkResponse({
		description: 'The user has been successfully verified.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async verifySignUp(@Body() verifyOtpDto: VerifyOtpDto) {
		try {
			const result = await this.userService.verifySignUp(verifyOtpDto);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0013',
				customMessage: successCodes.WGE0013?.description,
				customMessageEs: successCodes.WGE0013?.descriptionEs,
				data: result,
			};
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
	async findOne(@Param('id') id: string) {
		try {
			const user = await this.userService.findOne(id);
			if (!user) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				};
			}
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0019',
				customMessage: successCodes.WGE0019?.description,
				customMessageEs: successCodes.WGE0019?.descriptionEs,
				data: user,
			};
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

	@Patch('/:id')
	@ApiOkResponse({
		description: 'The record has been successfully updated.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
		try {
			const userFind = await this.userService.findOne(id);
			if (!userFind) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				};
			}
			const user = await this.userService.update(id, updateUserDto);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0020',
				customMessage: successCodes.WGE0020?.description,
				customMessageEs: successCodes.WGE0020?.descriptionEs,
				data: user,
			};
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

	@Delete('/:id')
	@ApiOkResponse({
		description: 'The record has been successfully deleted.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async remove(@Param('id') id: string) {
		try {
			const userFind = await this.userService.findOne(id);
			if (!userFind) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				};
			}
			await this.userService.remove(id);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0021',
				customMessage: successCodes.WGE0021?.description,
				customMessageEs: successCodes.WGE0021?.descriptionEs,
			};
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
	async signin(@Body() signinDto: SignInDto) {
		try {
			const userFind = await this.userService.findOneByEmail(signinDto?.email);
			if (!userFind) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				};
			}
			const result = await this.userService.signin(signinDto);

			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0018',
				customMessage: successCodes.WGE0018?.description,
				customMessageEs: successCodes.WGE0018?.descriptionEs,
				data: result,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0001',
					customMessage: error?.message,
					customMessageEs: errorCodes.WGE0001?.descriptionEs,
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
	async verifyOtp(@Body() verifyOtpDto: VerifyOtpDto) {
		try {
			const result = await this.userService.verifyOtp(verifyOtpDto);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0014',
				customMessage: successCodes.WGE0014?.description,
				customMessageEs: successCodes.WGE0014?.descriptionEs,
				data: result,
			};
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

	@Post('/change-password')
	@UsePipes(ValidationPipe)
	@ApiOkResponse({
		description: 'The password has been successfully changed.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async changePassword(
		@Body() authChangePasswordUserDto: AuthChangePasswordUserDto
	) {
		try {
			const userFind = await this.userService.findOneByEmail(
				authChangePasswordUserDto?.email
			);
			if (!userFind) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				};
			}
			const message = await this.userService.changeUserPassword(
				authChangePasswordUserDto
			);
			return {
				statusCode: HttpStatus.OK,
				message,
			};
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

	@Post('/forgot-password')
	@UsePipes(ValidationPipe)
	@ApiOkResponse({
		description: 'The password reset request has been successfully processed.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async forgotPassword(
		@Body() authForgotPasswordUserDto: AuthForgotPasswordUserDto
	) {
		try {
			const userFind = await this.userService.findOneByEmail(
				authForgotPasswordUserDto?.email
			);
			if (!userFind) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				};
			}
			const message = await this.userService.forgotUserPassword(
				authForgotPasswordUserDto
			);
			return {
				statusCode: HttpStatus.OK,
				message,
			};
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
		@Body() authConfirmPasswordUserDto: AuthConfirmPasswordUserDto
	) {
		try {
			const userFind = await this.userService.findOneByEmail(
				authConfirmPasswordUserDto?.email
			);
			if (!userFind) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				};
			}
			const message = await this.userService.confirmUserPassword(
				authConfirmPasswordUserDto
			);
			return {
				statusCode: HttpStatus.OK,
				message,
			};
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

	@Post('/get/all')
	@ApiOkResponse({
		description: 'Successfully returned users',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async getUsers(@Body() getUsersDto: GetUsersDto) {
		try {
			const users = await this.userService.getUsersByType(getUsersDto);
			if (!['WALLET', 'PLATFORM', 'PROVIDER'].includes(getUsersDto.type)) {
				return {
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0017',
					customMessage: errorCodes.WGE0017?.description,
					customMessageEs: errorCodes.WGE0017?.descriptionEs,
				};
			}
			return {
				statusCode: HttpStatus.OK,
				message: 'Successfully returned users',
				data: users,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Get('/get/info/access')
	@ApiOkResponse({
		description: 'Successfully returned user info',
	})
	@ApiForbiddenResponse({ description: 'Invalid access token.' })
	async getUserInfo(@Req() req) {
		try {
			const userInfo = req.user;
			const userFind = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);

			delete userFind?.PasswordHash;
			delete userFind?.OtpTimestamp;

			return {
				statusCode: HttpStatus.OK,
				message: 'Successfully returned user info',
				data: userFind,
			};
		} catch (error) {
			return {
				statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				customCode: 'WGE0021',
				customMessage: errorCodes.WGE0021?.description,
				customMessageEs: errorCodes.WGE0021?.descriptionEs,
			};
		}
	}

	@Patch('/update/status/:id')
	@ApiOkResponse({
		description: 'The user has been successfully updated.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async changeStatusUser(@Body() updateUserDto: UpdateStatusUserDto) {
		try {
			const userFind = await this.userService.findOneByEmail(
				updateUserDto?.email
			);
			if (!userFind) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					customMessage: errorCodes.WGE0002?.description,
					customMessageEs: errorCodes.WGE0002?.descriptionEs,
				};
			}
			const user = await this.userService.changeStatusUser(updateUserDto);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0020',
				customMessage: successCodes.WGE0020?.description,
				customMessageEs: successCodes.WGE0020?.descriptionEs,
				data: user,
			};
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
}
