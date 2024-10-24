import { IsOptional, IsString } from 'class-validator';

export class UpdateSettingsDto {
	@IsOptional()
	@IsString()
	value?: string;
}
