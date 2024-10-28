# Auth Microservice

This microservice is responsible for user authentication using Node.js and NestJS as the development framework, DynamoDB
as the NoSQL database, and Dynamoose as the ORM for interaction with DynamoDB. It provides functionalities such as user
registration, login, roles, etc.

## Requirements

- Node.js (v14 or higher)
- NestJS (v7 or higher)
- AWS DynamoDB
- Dynamoose (v2 or higher)
- AWS SDK for Node.js

## Installation

    npm install

## Configuration

### Set up the environment variables

Create a .env file in the root of the project following the content of .env.example.

## Running the Application

    npm run start:dev

## Envs for pipeline

- `NODE_ENV`: Environment of the application (development, qa, staging, production)
- `AWS_KEY_ID`: Key ID of the AWS account
- `AWS_SECRET_ACCESS_KEY`: Secret key of the AWS account
- `AWS_REGION`: Region of the AWS account
- `COGNITO_USER_POOL_ID`: ID of the Cognito User Pool
- `COGNITO_CLIENT_ID`: ID of the Cognito Client
- `COGNITO_CLIENT_SECRET_ID`: Secret of the Cognito Client
- `SQS_QUEUE_URL`: URL of the SQS Queue
- `SENTRY_DSN`: DSN of the Sentry project
- `AWS_KEY`: Key of the AWS account for deploy image of docker in ECR
- `AWS_SECRET`: Secret of the AWS account for deploy image of docker in ECR
- `IMAGE`: Name of the image for deploy in ECR
- `CLUSTER_NAME`: Name of the cluster in ECS
- `AWS_ACCESS_KEY_ID_TERRAFORM`: Key ID of the AWS account for Terraform
- `AWS_SECRET_ACCESS_KEY_TERRAFORM`: Secret key of the AWS account for Terraform
- `AWS_S3_BUCKET_NAME`: Name of the S3 bucket for images
- `WALLET_URL`: Wallet url deploy
- `APP_SECRET`: app secret for communication between services
- `SUMSUB_APP_TOKEN`: sum sub app token kyc
- `SUMSUB_SECRET_KEY`: sum sub secret key kyc
