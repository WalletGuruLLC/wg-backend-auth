export function enmaskAttribute(value) {
	const strValue = String(value);

	// Si contiene un guion, dejamos los primeros 4 caracteres y enmascaramos el resto
	if (strValue.includes('-')) {
		const [firstPart, secondPart] = strValue.split('-');
		return firstPart.slice(0, 3) + secondPart.replace(/./g, '*');
	}

	// Si no tiene guion, enmascaramos a partir del quinto carácter
	return strValue.slice(0, 4).padEnd(strValue.length, '*');
}
