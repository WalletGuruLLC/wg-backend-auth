export function validarZipCode(zipCode) {
	const zipCodeRegex = /^\d{5}$/;

	return zipCodeRegex.test(zipCode);
}
