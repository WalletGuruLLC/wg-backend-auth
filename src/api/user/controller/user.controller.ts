import {
	Controller,
	Get,
	Post,
	Body,
	Patch,
	Param,
	Delete,
	UsePipes,
	ValidationPipe,
} from '@nestjs/common';
import { CreateUserDto } from '../dto/create-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { UserService } from '../service/user.service';
import { SignInDto } from '../dto/signin.dto';
import { AuthConfirmPasswordUserDto } from '../dto/auth-confirm-password-user.dto';
import { AuthForgotPasswordUserDto } from '../dto/auth-forgot-password-user.dto';
import { AuthChangePasswordUserDto } from '../dto/auth-change-password-user.dto';
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
	create(@Body() createUserDto: CreateUserDto) {
		return this.userService.create(createUserDto);
	}

	@Get(':id')
	@ApiOkResponse({
		description: 'The record has been successfully retrieved.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	findOne(@Param('id') id: string) {
		return this.userService.findOne(id);
	}

	@Patch(':id')
	@ApiOkResponse({
		description: 'The record has been successfully updated.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
		return this.userService.update(id, updateUserDto);
	}

	@Delete(':id')
	@ApiOkResponse({
		description: 'The record has been successfully deleted.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	remove(@Param('id') id: string) {
		return this.userService.remove(id);
	}

	@Post('signin')
	@ApiOkResponse({
		description: 'The user has been successfully signed in.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	signin(@Body() signinDto: SignInDto) {
		return this.userService.signin(signinDto);
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
		const result = await this.userService.changeUserPassword(
			authChangePasswordUserDto
		);

		if (result == 'SUCCESS') {
			return { status: 'success' };
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
		return await this.userService.forgotUserPassword(authForgotPasswordUserDto);
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
		return await this.userService.confirmUserPassword(
			authConfirmPasswordUserDto
		);
	}
}
