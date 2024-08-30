export function isNumberInRange(num) {
	return typeof num === 'number' && !isNaN(num) && num >= 8 && num <= 15;
}
