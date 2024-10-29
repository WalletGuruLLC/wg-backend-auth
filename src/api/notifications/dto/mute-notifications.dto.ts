import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class MuteNotificationsDto {
	@ApiProperty({
		description: 'Duration to mute notifications',
		example: '30m',
	})
	@IsString()
	duration: string;
}
