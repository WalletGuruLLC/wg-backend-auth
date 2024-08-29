import { ProviderService } from './provider.service';

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
