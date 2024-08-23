import { Test, TestingModule } from '@nestjs/testing';
import { ModuleService } from './module.service';
import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Module } from './entities/module.entity';
import { ModuleSchema } from './entities/module.schema';

jest.mock('dynamoose', () => {
	const scanMock = jest.fn().mockReturnThis();
	const attributesMock = jest.fn().mockReturnThis();
	const execMock = jest.fn();

	return {
		model: jest.fn().mockReturnValue({
			scan: scanMock,
			attributes: attributesMock,
			exec: execMock,
		}),
		Schema: jest.fn().mockImplementation(schema => schema),
	};
});

describe('ModuleService', () => {
	let service: ModuleService;
	let model: Model<Module>;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [ModuleService],
		}).compile();

		service = module.get<ModuleService>(ModuleService);
		model = dynamoose.model<Module>('modules', ModuleSchema);
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('findAll', () => {
		it('should return an array of modules', async () => {
			const mockModules = [
				{ id: '1', description: 'Module 1' },
				{ id: '2', description: 'Module 2' },
			];

			(
				model.scan().attributes(['Id', 'Description']).exec as jest.Mock
			).mockResolvedValue(mockModules);

			const result = await service.findAll();
			expect(result).toEqual(mockModules);
		});
	});
});
