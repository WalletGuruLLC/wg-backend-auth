// src/api/user/cognito/cognito.config.ts

export const cognitoConfig = {
	UserPoolId: 'us-east-2_EhbAxcCTT', // Usar el ID de grupo de usuarios de la imagen
	ClientId: process.env.COGNITO_CLIENT_ID, // Debes configurar esto en tus variables de entorno
	Region: 'us-east-2',
};
