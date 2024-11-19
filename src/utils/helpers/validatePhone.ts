export function validatePhoneNumber(phoneNumber) {
	const phoneRegex = /^\+\d{1,6}-\d{7,15}$/;
	return phoneRegex.test(phoneNumber);
}
