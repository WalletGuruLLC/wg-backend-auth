import { licenseFormats } from '../constants';

export function validateLicense(state, licenseNumber) {
	const formattedState = state.trim().replace(/\b\w/g, char => char);

	if (!licenseFormats[formattedState]) {
		return false;
	}

	const isValid = licenseFormats[formattedState].test(licenseNumber);

	return isValid ? true : false;
}
