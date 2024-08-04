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
	UsePipes,
	ValidationPipe,
} from '@nestjs/common';
import { AuthChangePasswordUserDto } from '../dto/auth-change-password-user.dto';
import { AuthConfirmPasswordUserDto } from '../dto/auth-confirm-password-user.dto';
import { AuthForgotPasswordUserDto } from '../dto/auth-forgot-password-user.dto';
import { CreateUserDto } from '../dto/create-user.dto';
import { SignInDto } from '../dto/signin.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { UserService } from '../service/user.service';
import {
	ApiCreatedResponse,
	ApiForbiddenResponse,
	ApiOkResponse,
	ApiTags,
} from '@nestjs/swagger';

@ApiTags('user')
@Controller('user')
export class UserController {
	constructor(private readonly userService: UserService) {}

	@Post()
	@ApiCreatedResponse({
		description: 'The record has been successfully created.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async create(@Body() createUserDto: CreateUserDto) {
		try {
			const user = await this.userService.create(createUserDto);
			return {
				statusCode: HttpStatus.CREATED,
				message: 'User created successfully',
				data: user,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error creating user: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Get(':id')
	@ApiOkResponse({
		description: 'The record has been successfully retrieved.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async findOne(@Param('id') id: string) {
		try {
			const user = await this.userService.findOne(id);
			if (!user) {
				throw new HttpException('User not found', HttpStatus.NOT_FOUND);
			}
			return {
				statusCode: HttpStatus.OK,
				message: 'User found',
				data: user,
			};
		} catch (error) {
			if (error.status === HttpStatus.NOT_FOUND) {
				throw error; // Re-throw 404 errors as they are
			}
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error retrieving user: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Patch(':id')
	@ApiOkResponse({
		description: 'The record has been successfully updated.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
		try {
			const user = await this.userService.update(id, updateUserDto);
			return {
				statusCode: HttpStatus.OK,
				message: 'User updated successfully',
				data: user,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error updating user: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Delete(':id')
	@ApiOkResponse({
		description: 'The record has been successfully deleted.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async remove(@Param('id') id: string) {
		try {
			await this.userService.remove(id);
			return {
				statusCode: HttpStatus.OK,
				message: 'User deleted successfully',
			};
		} catch (error) {
			if (error.message === 'User not found in database') {
				throw new HttpException(
					{
						statusCode: HttpStatus.NOT_FOUND,
						message: error.message,
					},
					HttpStatus.NOT_FOUND
				);
			} else {
				throw new HttpException(
					{
						statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
						message: `Error deleting user: ${error.message}`,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
		}
	}

	@Post('signin')
	@ApiOkResponse({
		description: 'The user has been successfully signed in.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async signin(@Body() signinDto: SignInDto) {
		try {
			const result = await this.userService.signin(signinDto);
			return {
				statusCode: HttpStatus.OK,
				message: 'Sign-in successful',
				data: result,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					message: error.message,
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
					message: error,
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
					message: error,
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
					message: error,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}
}
