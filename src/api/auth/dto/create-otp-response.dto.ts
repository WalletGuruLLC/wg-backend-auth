export class CreateOtpResponseDto {
	success: boolean;
	message: string;
	otp?: string;
	error?: string;
}
