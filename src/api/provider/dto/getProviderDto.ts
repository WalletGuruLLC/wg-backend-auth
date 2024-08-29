import { ApiProperty } from '@nestjs/swagger';

export class GetProvidersDto {
	@ApiProperty({ description: 'Page number', required: false })
	page?: number;

	@ApiProperty({ description: 'Number of providers per page', required: false })
	items?: number;

	@ApiProperty({ description: 'Filter by provider name', required: false })
	search?: string;
}
