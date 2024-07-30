//import { sendEmail } from './../../../utils/helpers/sendEmail';
import * as dynamoose from 'dynamoose';
import * as bcrypt from 'bcrypt';
import { Injectable } from '@nestjs/common';
import { Model } from 'dynamoose/dist/Model';
import { CreateUserDto } from '../dto/create-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { User } from '../entities/user.entity';
import * as crypto from 'crypto';
import { UserSchema } from '../entities/user.schema';
import { CognitoService } from '../cognito/cognito.service';
import { ForgotPasswordDto, VerifyOtpDto } from '../dto/forgotPassword.dto';
import { SignInDto } from '../dto/signin.dto';
import { UpdateUserPasswordDto } from '../dto/update-password-user.dto copy';
import { sendEmailNodemailer } from '../../../utils/helpers/sendEmailNodemailer';

@Injectable()
export class UserService {
	private dbInstance: Model<User>;
	private cognitoService: CognitoService;

	constructor() {
		const tableName = 'users';
		this.dbInstance = dynamoose.model<User>(tableName, UserSchema);
		this.cognitoService = new CognitoService();
	}

	async create(createUserDto: CreateUserDto) {
		const saltRounds = 8;
		const hashedPassword = await bcrypt.hash(
			createUserDto.PasswordHash,
			saltRounds
		);

		// Create user in Cognito
		await this.cognitoService.createUser(
			createUserDto.Email,
			createUserDto.PasswordHash,
			createUserDto.Email
		);
		// Create user in DynamoDB
		const newUser = await this.dbInstance.create({
			Id: createUserDto.Id,
			Username: createUserDto.Username,
			Email: createUserDto.Email,
			PasswordHash: hashedPassword,
			MfaEnabled: createUserDto.MfaEnabled,
			MfaType: createUserDto.MfaType,
			Rol: createUserDto.Rol,
		});

		const payload = {
			id: newUser.Id,
			username: newUser.Username,
			email: newUser.Email,
		};

		return newUser;
	}

	async findOne(id: string) {
		return await this.dbInstance.get({ Id: id });
	}

	async findOneByEmail(email: string) {
		try {
			const users = await this.dbInstance.query('Email').eq(email).exec();
			return users[0];
		} catch (error) {
			if (
				error.message.includes(
					'The provided key element does not match the schema'
				)
			) {
				console.log('Key schema mismatch:', error);
			} else {
				console.log('Error getting user:', error);
			}
		}
	}

	async findOneByEmailAndUpdate(
		email: string,
		updateUserDto: UpdateUserPasswordDto
	) {
		const users = await this.dbInstance.query('Email').eq(email).exec();

		await this.dbInstance.update({
			Id: users?.[0]?.Id,
			Otp: updateUserDto?.Otp,
			OtpTimestamp: updateUserDto?.OtpTimestamp,
		});

		return users?.[0];
	}

	async update(id: string, updateUserDto: UpdateUserDto) {
		return await this.dbInstance.update({
			Id: id,
			Username: updateUserDto.Username,
			Email: updateUserDto.Email,
			PasswordHash: updateUserDto.PasswordHash,
			MfaEnabled: updateUserDto.MfaEnabled,
			MfaType: updateUserDto.MfaType,
			Rol: updateUserDto.Rol,
		});
	}

	async remove(id: string): Promise<void> {
		try {
			const user = await this.findOne(id);
			if (!user) {
				throw new Error('User not found in database');
			}

			try {
				await this.cognitoService.deleteUser(user.Email);
			} catch (error) {
				throw new Error(`Error deleting user from Cognito: ${error.message}`);
			}

			try {
				await this.dbInstance.delete({ Id: id });
			} catch (error) {
				throw new Error(`Error deleting user from database: ${error.message}`);
			}
		} catch (error) {
			throw new Error(`Failed to remove user: ${error.message}`);
		}
	}

	async signin(signinDto: SignInDto) {
		const user = await this.findOneByEmail(signinDto.email);
		if (!user) {
			return 'User not found';
		}

		try {
			const authResult = await this.cognitoService.authenticateUser(
				signinDto.email,
				signinDto.password
			);
			const token = authResult.AuthenticationResult?.AccessToken;

			if (!token) {
				return 'Invalid credentials';
			}

			return { token, user };
		} catch (error) {
			throw new Error(`Authentication failed: ${error.message}`);
		}
	}

	async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
		const { email } = forgotPasswordDto;
		const otp = crypto.randomInt(100000, 999999).toString();
		const saltRounds = 8;
		const hashedOtp = await bcrypt.hash(otp, saltRounds);
		const user = await this.findOneByEmailAndUpdate(email, {
			Otp: hashedOtp,
			OtpTimestamp: new Date(),
		});

		if (!user) {
			throw new Error('User not found');
		}

		const ToAddress = email;
		const Subject = 'Recovery passoword - OTP Code';
		const Html = `<p>Your OTP code is <strong>${otp}</strong>. It is valid for 10 minutes.</p>`;

		try {
			await sendEmailNodemailer(ToAddress, Subject, Subject, Html);
			//await sendEmail(ToAddresses, Subject, Html);
			return { message: 'OTP sent successfully' };
		} catch (error) {
			throw new Error(error.message);
		}
	}

	async verifyOtp(verifyOtpDto: VerifyOtpDto) {
		const { email, otp } = verifyOtpDto;
		const user = await this.findOneByEmail(email);

		if (!user) {
			throw new Error('User not found');
		}

		const otpTimestamp = new Date(user.OtpTimestamp);
		const now = new Date();
		const diffInMinutes = (now.getTime() - otpTimestamp.getTime()) / 6000;

		if (diffInMinutes > 60) {
			throw new Error('OTP expired');
		}

		const isOtpValid = await bcrypt.compare(otp, user.Otp);
		if (!isOtpValid) {
			throw new Error('Invalid OTP');
		}

		return { message: 'OTP verified successfully' };
	}	
}
