export function buscarValorPorClave(objeto, claveBuscada) {
	const aaa = JSON.stringify(objeto);
	const myObj = JSON.parse(aaa);
	console.log(typeof myObj, typeof claveBuscada, claveBuscada);
	console.log('myObj', myObj, myObj[claveBuscada]);

	// console.log('Clave buscada:', claveBuscada);
	// console.log(
	// 	'objeto[claveBuscada]',
	// 	objeto[`${claveBuscada}`],
	// 	objeto[`4b3e22f7-a540-4372-a881-496ee6b6e6ae`]
	// );
	if (objeto[claveBuscada]) {
		return objeto[claveBuscada];
	}
	return null;
}
