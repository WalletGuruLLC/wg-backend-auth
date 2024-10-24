export function validarZipCode(zipCode) {
	const zipCodeRegex = /^\d{5,8}$/;

	return zipCodeRegex.test(zipCode);
}
