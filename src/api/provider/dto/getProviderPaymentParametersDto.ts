import { ApiProperty } from '@nestjs/swagger';

export class GetProviderPaymentParametersDTO {
	@ApiProperty({ description: 'Payment parameter asset code', required: false })
	asset?: string;

	@ApiProperty({ description: 'Payment parameter frequency', required: false })
	frequency?: number;

	@ApiProperty({ description: 'Payment parameter name', required: false })
	name?: string;
}
