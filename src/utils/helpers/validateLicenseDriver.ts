import { licenseFormats } from '../constants';

export function validateLicense(state, licenseNumber) {
	const formattedState = state
		.trim()
		.replace(/\b\w/g, char => char.toUpperCase());

	if (!licenseFormats[formattedState]) {
		return `Estado no reconocido: ${state}`;
	}

	const isValid = licenseFormats[formattedState].test(licenseNumber);

	return isValid
		? 'Número de licencia válido.'
		: 'Número de licencia inválido.';
}
