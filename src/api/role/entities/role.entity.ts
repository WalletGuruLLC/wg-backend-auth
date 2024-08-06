import * as dynamoose from 'dynamoose';
import { Document } from 'dynamoose/dist/Document';

const RoleSchema = new dynamoose.Schema(
	{
		id: {
			type: String,
			hashKey: true,
		},
		name: String,
		description: String,
	},
	{
		timestamps: true,
	}
);

export const RoleModel = dynamoose.model('Role', RoleSchema);

export interface RoleDocument extends Document {
	id: string;
	name: string;
	description: string;
}
