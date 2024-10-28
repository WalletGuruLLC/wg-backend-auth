import crypto from 'crypto';

export async function createSignature(req, secretKey) {
	const ts = Math.floor(Date.now() / 1000);
	const signature = crypto.createHmac('sha256', secretKey);
	signature.update(ts + req.method.toUpperCase() + req.url);

	if (req.body instanceof FormData) {
		signature.update(req.body.getBuffer());
	} else if (req.body) {
		signature.update(req.body);
	}

	req.headers['X-App-Access-Ts'] = ts;
	req.headers['X-App-Access-Sig'] = signature.digest('hex');

	return req;
}
