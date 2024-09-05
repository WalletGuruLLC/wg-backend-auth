import { Document } from 'dynamoose/dist/Document';

export interface Provider extends Document {
	Id: string;
	Name: string;
	Description: string;
	Email: string;
	Phone: string;
	EINNumber: string;
	Country: string;
	City: string;
	ZipCode: string;
	CompanyAddress: string;
	WalletAddress: string;
	Logo: string;
	ContactInformation: string;
	Active: boolean;
	ImageUrl: string;
}
