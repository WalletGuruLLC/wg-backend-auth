export function validarEIN(ein) {
	const einRegex = /^\d{2}-\d{7}$/;

	return einRegex.test(ein);
}
