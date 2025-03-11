# Authentication Microservice

This **Authentication Microservice** provides secure user authentication and authorization using **Node.js** and *
*NestJS**. It integrates **DynamoDB** as the NoSQL database with **Dynamoose** as the ORM.

## Dependencies

This microservice uses the following key dependencies:

- [Node.js](https://nodejs.org/) - JavaScript runtime
- [NestJS](https://nestjs.com/) - Progressive Node.js framework
- [DynamoDB](https://aws.amazon.com/dynamodb/) - NoSQL database
- [Dynamoose](https://dynamoosejs.com/) - ORM for DynamoDB
- [AWS SDK](https://aws.amazon.com/sdk-for-node-js/) - AWS integration
- [bcrypt](https://www.npmjs.com/package/bcrypt) - Secure password hashing
- [Wg-infra](https://github.com/ErgonStreamGH/wg-infra) - Deploy services with Terraform

---

## Install

### 1. Clone the Repository

```sh
git clone https://github.com/WalletGuruLLC/wg-backend-auth.git
cd wg-backend-auth
```

### 2. Install Dependencies

```sh
npm install
```

### 3. Create envs in AWS Secrets Manager

Create a secret in AWS Secrets Manager with the name `walletguru-auth-local` and the following key-value pairs:

```
{
   "AWS_ACCESS_KEY_ID":"", # AWS Access Key ID for access to DynamoDB and Cognito
   "AWS_SECRET_ACCESS_KEY":"", # AWS Secret Access Key for access to DynamoDB and Cognito
   "AWS_REGION":"", # AWS Region
   "COGNITO_USER_POOL_ID":"", # Cognito User Pool ID
   "COGNITO_CLIENT_ID":"", # Cognito Client ID
   "COGNITO_CLIENT_SECRET_ID":"", # Cognito Client Secret ID
   "SQS_QUEUE_URL":"", # SQS Queue URL for sending email notifications
   "SENTRY_DSN":"", # Sentry DSN for error tracking
   "AWS_S3_BUCKET_NAME":"", # AWS S3 Bucket Name
   "WALLET_URL":"", # Wallet URL for public access
   "APP_SECRET":"", # App Secret for JWT token
   "NODE_ENV":"development", # Node Environment
   "SUMSUB_APP_TOKEN":"", # Sumsub App Token
   "SUMSUB_SECRET_TOKEN":"", # Sumsub Secret Token
   "URL_UPTIME":"", # URL for uptime monitoring
   "UPTIME_PASSWORD":"", # Password for uptime monitoring
   "UPTIME_USERNAME":"", # Username for uptime monitoring
   "SUMSUB_DIGEST_SECRET_TOKEN":"" # Sumsub Digest Secret Token
}
```

| **Name Env**               | **Description**                                                                                                                                                              | **REQUIRED** |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| AWS_ACCESS_KEY_ID          | AWS Access Key for access to resources and service                                                                                                                           | Yes          |
| AWS_SECRET_ACCESS_KEY      | AWS Secret Key for access to resources and service                                                                                                                           | Yes          |
| AWS_REGION                 | AWS Region for access to resources and service                                                                                                                               | Yes          |
| COGNITO_USER_POOL_ID       | Open https://us-east-2.console.aws.amazon.com/cognito/v2/idp/user-pools and see details of user-auth and get User pool ID                                                    | Yes          |
| COGNITO_CLIENT_ID          | Open https://us-east-2.console.aws.amazon.com/cognito/v2/idp/user-pools and see details of user-auth and open app clients, get Client ID                                     | Yes          |
| COGNITO_CLIENT_SECRET_ID   | Open https://us-east-2.console.aws.amazon.com/cognito/v2/idp/user-pools and see details of user-auth and open app clients see detail of cognito-client and get Client secret | Yes          |
| SQS_QUEUE_URL              | Open https://us-east-2.console.aws.amazon.com/sqs/v3/home?region=us-east-2#/queues and see details of paystreme-notifications-local and and get parameter URL                | Yes          |
| SENTRY_DSN                 | If you use Sentry you can put the dsn for logs                                                                                                                               | No           |
| AWS_S3_BUCKET_NAME         | Open https://us-east-2.console.aws.amazon.com/s3/home and get name of bucket for save static files                                                                           | Yes          |
| WALLET_URL                 | Url for service of wallet for enviroment local is http://localhost:3003                                                                                                      | Yes          |
| APP_SECRET                 | Hash for jwt its the key for create jwt                                                                                                                                      | Yes          |
| NODE_ENV                   | Env for node js                                                                                                                                                              | Yes          |
| SUMSUB_APP_TOKEN           | Token for get information of service sumsub for kyc can you create account https://sumsub.com                                                                                | Yes          |
| SUMSUB_SECRET_TOKEN        | Secret for get information of service sumsub for kyc can you create account https://sumsub.com                                                                               | Yes          |
| SUMSUB_DIGEST_SECRET_TOKEN | Secret for get information of service sumsub for kyc can you create account https://sumsub.com                                                                               | Yes          |
| URL_UPTIME                 | Url for monitoring services with uptime                                                                                                                                      | No           |
| UPTIME_PASSWORD            | Password for monitoring services with uptime                                                                                                                                 | No           |
| UPTIME_USERNAME            | Username for monitoring services with uptime                                                                                                                                 | No           |


### 4. Set Up Environment Variables

Create a `.env` file in the root directory and add:

```ini
AWS_ACCESS_KEY_ID=""
AWS_SECRET_ACCESS_KEY=""
SECRET_NAME="walletguru-auth-local"
```

---

### 5. Run the Application

Using **Docker Compose**:

```sh
docker-compose up
```

## Infrastructure Setup with `wg-infra`

The **wg-infra** repository is responsible for provisioning multiple AWS resources required by this project, including *
*ECR repositories, databases, IAM roles, networking, and other cloud infrastructure**.

## Ensure Consistency Across Microservices

Make sure you follow similar steps when setting up, deploying, and managing the following microservices hosted in the
respective repositories:

| **Microservice**                                | **Repository URL**                                               |
|-------------------------------------------------|------------------------------------------------------------------|
| Authentication Service (`backend-auth`)         | [GitHub Repo](https://github.com/WalletGuruLLC/backend-auth)     |
| Notification Service (`backend-notification`)   | [GitHub Repo](https://github.com/your-org/backend-notification)  |
| Admin Frontend (`frontend-admin`)               | [GitHub Repo](https://github.com/WalletGuruLLC/frontend-admin)   |
| Wallet Service (`backend-wallet`)               | [GitHub Repo](https://github.com/WalletGuruLLC/backend-wallet)   |
| Countries Now Service (`backend-countries-now`) | [GitHub Repo](https://github.com/ErgonStreamGH/wg-countries-now) |
| Codes Service (`backend-codes`)                 | [GitHub Repo](https://github.com/ErgonStreamGH/wg-backend-codes) |

Each microservice should:

1️⃣ Deploy the dependencies using Terraform in the **wg-infra** repository
2️⃣ Store environment variables securely in **AWS Secrets Manager**
3️⃣ Use **Docker Compose** for local development

