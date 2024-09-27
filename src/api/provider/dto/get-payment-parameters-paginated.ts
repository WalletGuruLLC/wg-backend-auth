import { ApiProperty } from '@nestjs/swagger';

export class GetPaymentsParametersPaginated {
	@ApiProperty({ description: 'Page number', required: false })
	page?: number;

	@ApiProperty({
		description: 'Number of payments parameters per page',
		required: false,
	})
	items?: number;

	@ApiProperty({
		description: 'Filter by payment parameter name',
		required: false,
	})
	search?: string;

	@ApiProperty({
		description: 'Filter by service provider id',
		required: false,
	})
	serviceProviderId?: string;
}
