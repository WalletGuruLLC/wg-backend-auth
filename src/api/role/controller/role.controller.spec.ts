import { HttpStatus } from '@nestjs/common';
import { CreateRoleDto, UpdateRoleDto } from '../dto/role';
import { RoleService } from '../service/role.service';
import { RoleController } from './role.controller';

describe('RoleController', () => {
	let controller: RoleController;
	let service: RoleService;

	const mockRole = {
		id: 'someId',
		name: 'someRole',
		description: 'someDescription',
		createdAt: new Date().toISOString(),
		updatedAt: new Date().toISOString(),
	};

	const mockRoleService = {
		create: jest.fn().mockResolvedValue({
			...mockRole,
			name: 'newRole',
			description: 'newDescription',
		}),
		findAll: jest.fn().mockResolvedValue([mockRole]),
		findOne: jest.fn().mockResolvedValue(mockRole),
		update: jest.fn().mockResolvedValue({
			...mockRole,
			name: 'updatedRole',
			description: 'updatedDescription',
			updatedAt: new Date().toISOString(),
		}),
		remove: jest.fn().mockResolvedValue(null),
	};

	beforeEach(async () => {
		controller = new RoleController(mockRoleService as any);
		service = mockRoleService as any;
	});

	it('should be defined', () => {
		expect(controller).toBeDefined();
	});

	it('should create a role', async () => {
		const createRoleDto: CreateRoleDto = {
			id: 'someId',
			name: 'newRole',
			description: 'newDescription',
		};
		const result = await controller.create(createRoleDto);
		expect(result).toEqual({
			statusCode: HttpStatus.CREATED,
			message: 'Role created successfully',
			data: {
				...mockRole,
				name: 'newRole',
				description: 'newDescription',
			},
		});
		expect(service.create).toHaveBeenCalledWith(createRoleDto);
	});

	it('should find all roles', async () => {
		const result = await controller.findAll();
		expect(result).toEqual({
			statusCode: HttpStatus.OK,
			message: 'Roles retrieved successfully',
			data: [mockRole],
		});
		expect(service.findAll).toHaveBeenCalled();
	});

	it('should find a role by id', async () => {
		const result = await controller.findOne('someId');
		expect(result).toEqual({
			statusCode: HttpStatus.OK,
			message: 'Role found',
			data: mockRole,
		});
		expect(service.findOne).toHaveBeenCalledWith('someId');
	});

	it('should update a role', async () => {
		const updateRoleDto: UpdateRoleDto = {
			name: 'updatedRole',
			description: 'updatedDescription',
		};
		const result = await controller.update('someId', updateRoleDto);
		expect(result).toEqual({
			statusCode: HttpStatus.OK,
			message: 'Role updated successfully',
			data: {
				...mockRole,
				name: 'updatedRole',
				description: 'updatedDescription',
				updatedAt: expect.any(String),
			},
		});
		expect(service.update).toHaveBeenCalledWith('someId', updateRoleDto);
	});

	it('should delete a role', async () => {
		const result = await controller.remove('someId');
		expect(result).toEqual({
			statusCode: HttpStatus.OK,
			message: 'Role deleted successfully',
		});
		expect(service.remove).toHaveBeenCalledWith('someId');
	});
});
