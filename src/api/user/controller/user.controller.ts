import {
	Controller,
	Get,
	Post,
	Body,
	Patch,
	Param,
	Delete,
} from '@nestjs/common';
import { CreateUserDto } from '../dto/create-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { UserService } from '../service/user.service';
import { SignInDto } from '../dto/signin.dto';
import { ForgotPasswordDto, VerifyOtpDto } from '../dto/forgotPassword.dto';

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

	@Post('forgot/password')
	forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
		return this.userService.forgotPassword(forgotPasswordDto);
	}

	@Post('verify/password')
	verifyOtp(@Body() verifyOtpDto: VerifyOtpDto) {
		return this.userService.verifyOtp(verifyOtpDto);
	}
}
