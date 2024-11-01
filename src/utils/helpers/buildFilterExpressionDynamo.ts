import { convertKeysToPascalCase } from './convertPascalCase';

export function buildUpdateExpression(expressionFilter) {
	const attributeExpressionsKeys = {};
	const expressionAttributeValues: any = {};
	const expressionConvertedPascal = convertKeysToPascalCase(expressionFilter);
	let updateExpression = '';

	Object.keys(expressionConvertedPascal).map(expressionKey => {
		attributeExpressionsKeys[`#${expressionKey.toLowerCase()}`] = expressionKey;

		expressionAttributeValues[`:${expressionKey.toLowerCase()}`] =
			expressionConvertedPascal[expressionKey];

		updateExpression = !updateExpression
			? `SET #${expressionKey.toLowerCase()} = :${expressionKey.toLowerCase()}`
			: updateExpression.concat(
					', ',
					`#${expressionKey.toLowerCase()} = :${expressionKey.toLowerCase()}`
			  );
	});

	return {
		attributeNames: attributeExpressionsKeys,
		expressionValues: expressionAttributeValues,
		updateExpression: updateExpression,
	};
}
