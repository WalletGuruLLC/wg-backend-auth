export function validatePhoneNumber(phoneNumber) {
	const phoneRegex = /^\+\d{1,3}-\d{7,}$/;

	if (phoneRegex.test(phoneNumber)) {
		return true;
	} else {
		return false;
	}
}
