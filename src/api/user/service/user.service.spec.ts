import { Test, TestingModule } from '@nestjs/testing';
import { UserService } from './user.service';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { UserController } from '../controller/user.controller';

const sendEmailNodemailer = jest.fn();

jest.mock('nodemailer', () => ({
	createTransport: jest.fn().mockImplementation(() => ({
		sendMail: sendEmailNodemailer,
	})),
}));

describe('UserService', () => {
	let service: UserService;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			imports: [JwtModule],
			controllers: [UserController],
			providers: [UserService, JwtService],
		}).compile();

		service = module.get<UserService>(UserService);
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	it('should call sendEmail when forgotPassword is called', async () => {
		const email = 'test@example.com';
		await sendEmailNodemailer({ email });
		expect(sendEmailNodemailer).toBeCalledTimes(1);
	});
});
