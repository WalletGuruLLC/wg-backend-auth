import { Test, TestingModule } from '@nestjs/testing';
import { ProviderService } from './provider.service';

import * as dynamoose from 'dynamoose';

jest.mock('dynamoose');

describe('ProviderService', () => {
	let service: ProviderService;

	beforeEach(async () => {
		service = new ProviderService();
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});
});
