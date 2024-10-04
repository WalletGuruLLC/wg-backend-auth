import { v4 as uuidv4 } from 'uuid';

export function generateCleanUUID() {
	const uuid = uuidv4();
	return uuid.replace(/-/g, '');
}
