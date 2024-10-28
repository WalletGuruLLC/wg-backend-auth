import { createHmac } from 'crypto';

export async function createSignature(req, secretKey, token) {
	console.log('secretKey', secretKey);
	const ts = Math.floor(Date.now() / 1000);
	const signature = createHmac('sha256', secretKey);
	console.log('signature', signature);
	console.log('timestamp', ts);

	const headers = {};

	signature.update(ts + req.method.toUpperCase() + req.url);

	headers['content-type'] = 'application/json';
	headers['X-App-Access-Ts'] = ts;
	headers['X-App-Access-Sig'] = signature.digest('hex');
	headers['X-App-Token'] = token;

	return headers;
}
