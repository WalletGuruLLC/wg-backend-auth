import { Document } from 'dynamoose/dist/Document';

export class Attempt extends Document {
	id = '';
	email = '';
	section = '';
	status = 'failure';
}
