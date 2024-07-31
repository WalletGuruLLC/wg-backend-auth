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

@Controller('user')
export class UserController {
	constructor(private readonly userService: UserService) {}

	@Post()
	create(@Body() createUserDto: CreateUserDto) {
		return this.userService.create(createUserDto);
	}

	@Get(':id')
	findOne(@Param('id') id: string) {
		return this.userService.findOne(id);
	}

	@Patch(':id')
	update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
		return this.userService.update(id, updateUserDto);
	}

	@Delete(':id')
	remove(@Param('id') id: string) {
		return this.userService.remove(id);
	}

	@Post('signin')
	signin(@Body() signinDto: SignInDto) {
		return this.userService.signin(signinDto);
	}

	@Post('/change-password')
	@UsePipes(ValidationPipe)
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
	async forgotPassword(
		@Body() authForgotPasswordUserDto: AuthForgotPasswordUserDto
	) {
		return await this.userService.forgotUserPassword(authForgotPasswordUserDto);
	}

	@Post('/confirm-password')
	@UsePipes(ValidationPipe)
	async confirmPassword(
		@Body() authConfirmPasswordUserDto: AuthConfirmPasswordUserDto
	) {
		return await this.userService.confirmUserPassword(
			authConfirmPasswordUserDto
		);
	}
}
