import { Test, TestingModule } from '@nestjs/testing';
import { ProviderController } from './provider.controller';
import { ProviderService } from '../service/provider.service';

describe('ProviderController', () => {
	let controller: ProviderController;

	const mockProviderService = {
		create: jest.fn().mockResolvedValue({ id: 'someId', name: 'someProvider' }),
		findAll: jest
			.fn()
			.mockResolvedValue([{ id: 'someId', name: 'someProvider' }]),
		findOne: jest
			.fn()
			.mockResolvedValue({ id: 'someId', name: 'someProvider' }),
		update: jest
			.fn()
			.mockResolvedValue({ id: 'someId', name: 'updatedProvider' }),
		remove: jest.fn().mockResolvedValue(null),
	};
	beforeEach(async () => {
		controller = new ProviderController(mockProviderService);
	});

	it('should be defined', () => {
		expect(controller).toBeDefined();
	});
});
