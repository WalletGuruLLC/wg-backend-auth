import { convertKeysToPascalCase } from './convertPascalCase';

export function buildFilterExpressionDynamo(expressionFilter) {
	const filterExpressionsKeys: string[] = [];
	const expressionAttributeValues: any = {};
	const expressionConvertedPascal = convertKeysToPascalCase(expressionFilter);

	Object.keys(expressionConvertedPascal).map(expressionKey => {
		filterExpressionsKeys.push(
			`${expressionKey} = :${expressionKey.toLowerCase()}`
		);
		expressionAttributeValues[`:${expressionKey.toLowerCase()}`] =
			expressionConvertedPascal[expressionKey];
	});

	const filterExpression =
		filterExpressionsKeys.length > 0
			? filterExpressionsKeys.join(' AND ')
			: null;

	return {
		...(filterExpression !== null && {
			expression: filterExpression,
			expressionValues: expressionAttributeValues,
		}),
	};
}
