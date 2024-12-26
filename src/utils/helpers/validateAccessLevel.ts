export function isNumberInRange(num) {
	return typeof num === 'number' && !isNaN(num) && (num === 0 || num <= 15);
}
