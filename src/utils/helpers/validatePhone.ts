export function validatePhoneNumber(phoneNumber) {
	const phoneRegex = /^\+\d{1,3}-\d{7,15}$/;
	return phoneRegex.test(phoneNumber);
}
