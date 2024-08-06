import { RoleService } from './role.service';
import { CreateRoleDto, UpdateRoleDto } from '../dto/role';

describe('RoleService', () => {
	let service: RoleService;

	const mockRole = {
		id: 'someId',
		name: 'someRole',
		description: 'someDescription',
		createdAt: new Date().toISOString(),
		updatedAt: new Date().toISOString(),
	};

	const mockRoleModel = {
		create: jest.fn().mockResolvedValue({
			...mockRole,
			name: 'newRole',
			description: 'newDescription',
		}),
		scan: jest.fn().mockReturnThis(),
		exec: jest.fn().mockResolvedValue([
			{
				...mockRole,
				name: 'newRole',
				description: 'newDescription',
			},
		]),
		get: jest.fn().mockResolvedValue({
			...mockRole,
			name: 'newRole',
			description: 'newDescription',
		}),
		update: jest.fn().mockResolvedValue({
			...mockRole,
			name: 'updatedRole',
			description: 'updatedDescription',
		}),
		delete: jest.fn().mockResolvedValue(null),
	};

	beforeEach(() => {
		service = new RoleService();
		// Mock the model methods directly
		service['model'] = mockRoleModel as any;
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	it('should create a role', async () => {
		const createRoleDto: CreateRoleDto = {
			id: 'someId',
			name: 'newRole',
			description: 'newDescription',
		};
		const result = await service.create(createRoleDto);
		expect(result.id).toEqual('someId');
	});

	it('should find all roles', async () => {
		const result = await service.findAll();
		expect(result[0].description).toEqual('newDescription');
	});

	it('should update a role', async () => {
		const updateRoleDto: UpdateRoleDto = {
			name: 'updatedRole',
			description: 'updatedDescription',
		};
		const result = await service.update('someId', updateRoleDto);
		expect(result.description).toEqual('updatedDescription');
	});
});
