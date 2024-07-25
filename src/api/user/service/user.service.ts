// src/api/user/service/user.service.ts

import * as dynamoose from 'dynamoose';
import bcrypt from 'bcrypt';
import { Injectable } from '@nestjs/common';
import { Model } from 'dynamoose/dist/Model';
import { CreateUserDto } from '../dto/create-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { User } from '../entities/user.entity';
import { UserSchema } from '../entities/user.schema';
import { CognitoService } from '../cognito/cognito.service';

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
		const saltRounds = 10;
		const hashedPassword = await bcrypt.hash(
			createUserDto.PasswordHash,
			saltRounds
		);

		// Crear usuario en Cognito
		await this.cognitoService.createUser(
			createUserDto.Username,
			createUserDto.PasswordHash,
			createUserDto.Email
		);

		// Crear usuario en DynamoDB
		return await this.dbInstance.create({
			Id: createUserDto.Id,
			Username: createUserDto.Username,
			Email: createUserDto.Email,
			PasswordHash: hashedPassword,
			MfaEnabled: createUserDto.MfaEnabled,
			MfaType: createUserDto.MfaType,
			Rol: createUserDto.Rol,
		});
	}

	async findOne(id: number) {
		return await this.dbInstance.get({ Id: id });
	}

	async update(id: number, updateUserDto: UpdateUserDto) {
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

	async remove(id: number) {
		return await this.dbInstance.delete({ Id: id });
	}
}
