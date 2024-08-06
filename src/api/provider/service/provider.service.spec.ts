import { Test, TestingModule } from '@nestjs/testing';
import { ProviderService } from './provider.service';

import * as dynamoose from 'dynamoose';

jest.mock('dynamoose');

describe('ProviderService', () => {
	let service: ProviderService;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [ProviderService],
		}).compile();

		service = module.get<ProviderService>(ProviderService);
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	// Additional tests for CRUD operations can be added here
});
