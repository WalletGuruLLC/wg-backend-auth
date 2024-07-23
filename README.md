Microservicio de Autenticación Paystream

Descripción

Este microservicio se encarga de la autenticación de usuarios utilizando Node.js y NestJS como framework de desarrollo, DynamoDB como base de datos NoSQL y Dynamoose como ORM para la interacción con DynamoDB. Proporciona funcionalidades como el registro de usuarios, inicio de sesión, y verificación de tokens JWT.


Requisitos

Node.js (v14 o superior)
NestJS (v7 o superior)
AWS DynamoDB
Dynamoose (v2 o superior)
AWS SDK para Node.js

Uso

npm install

Configurar las variables de entorno:

Crear un archivo .env en la raíz del proyecto con el siguiente contenido:

env

AWS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=

Ejecutar 

npm run start
