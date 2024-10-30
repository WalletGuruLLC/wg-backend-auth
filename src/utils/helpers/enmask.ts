export function enmaskAttribute(value) {
	const strValue = String(value);

	if (strValue.includes('-')) {
		const [firstPart, secondPart] = strValue.split('-');
		return firstPart.slice(0, 3) + secondPart.replace(/./g, '*');
	}

	return strValue.slice(0, 4).padEnd(strValue.length, '*');
}
