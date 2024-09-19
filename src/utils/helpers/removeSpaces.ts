export function removeSpaces(str) {
	if (typeof str !== 'string' || str.trim() === '') {
		return str;
	}

	return str.replace(/\s+/g, '');
}
